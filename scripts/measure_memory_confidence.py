#!/usr/bin/env python3
"""Run a deterministic, offline long-horizon memory confidence gate.

The fixture borrows evaluation dimensions from LongMemEval and LongMemEval-V2,
but is intentionally a small SYNAPSE-S2 regression fixture.  It uses no LLM,
network, operator database, or live image.  Passing is not a LongMemEval score.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import struct
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
while str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

import memory_store as _memory_store_module  # noqa: E402
from bridge_governance import BridgeGovernance  # noqa: E402
from core_client_binding import CoreClientBinding  # noqa: E402
from image_capture import ConversionResult, ImageCaptureCache, validate_media_id  # noqa: E402
from mlx_backend import SpikingAttentionBackend  # noqa: E402
from scripts import measure_retrieval_v2 as retrieval_measurement  # noqa: E402


REPORT_SCHEMA = "synapse-s2.memory-confidence.v1"
REPORT_VERSION = 1
FIXTURE_SCHEMA = "synapse-s2.memory-confidence-fixture.v1"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "memory_confidence" / "benchmark_v1.json"
SYNTHETIC_NOTICE = (
    "This local synthetic regression gate is inspired by LongMemEval and "
    "LongMemEval-V2 dimensions; it is not either full benchmark and does not "
    "establish live-corpus quality or downstream answer accuracy."
)
MAX_LATENCY_SAMPLES = 20
REQUIRED_DIMENSIONS = frozenset(
    {
        "static_state",
        "dynamic_tracking",
        "workflow_knowledge",
        "environment_gotcha",
        "premise_awareness",
        "factual_recall",
        "updates_supersession",
        "temporal_order",
        "abstention",
        "bridge_isolation",
        "image_description_recall",
        "deletion_residue",
    }
)
SAFE_THRESHOLDS = {
    "minimum_dimension_pass_rate": 1.0,
    "maximum_namespace_leakage_count": 0,
    "maximum_logical_deletion_residue_count": 0,
    "maximum_media_residue_count": 0,
}


class ConfidenceMeasurementError(RuntimeError):
    """The fixture or measurement cannot establish its claimed invariants."""


def _canonical_bytes(value: Any) -> bytes:
    return retrieval_measurement.canonical_json_bytes(value)


def _digest(value: Any) -> str:
    import hashlib

    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def load_fixture(path: Path = FIXTURE_PATH) -> dict[str, Any]:
    try:
        fixture = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfidenceMeasurementError("memory confidence fixture is unreadable") from exc
    if not isinstance(fixture, dict):
        raise ConfidenceMeasurementError("memory confidence fixture must be an object")
    if fixture.get("schema") != FIXTURE_SCHEMA or fixture.get("version") != 1:
        raise ConfidenceMeasurementError("memory confidence fixture schema is unsupported")
    required = fixture.get("required_dimensions")
    if not isinstance(required, list) or set(required) != REQUIRED_DIMENSIONS:
        raise ConfidenceMeasurementError("fixture must name every required confidence dimension exactly")
    thresholds = fixture.get("thresholds")
    if thresholds != SAFE_THRESHOLDS:
        raise ConfidenceMeasurementError("fixture acceptance thresholds are missing or weakened")
    backend = fixture.get("backend")
    if not isinstance(backend, dict) or backend.get("embedding_provider") != "semantic-hash":
        raise ConfidenceMeasurementError("fixture must use the offline semantic-hash provider")
    for field in ("dimension", "num_neurons", "default_top_k", "recall_count"):
        if type(backend.get(field)) is not int or int(backend[field]) <= 0:
            raise ConfidenceMeasurementError(f"fixture backend {field} must be a positive exact integer")
    if not isinstance(fixture.get("fixed_epoch"), (int, float)):
        raise ConfidenceMeasurementError("fixture fixed_epoch is required")

    documents = fixture.get("documents")
    if not isinstance(documents, list) or not documents:
        raise ConfidenceMeasurementError("fixture documents are required")
    document_ids: set[str] = set()
    context_tags: set[tuple[str, str]] = set()
    for document in documents:
        if not isinstance(document, dict):
            raise ConfidenceMeasurementError("fixture document must be an object")
        required_fields = ("document_id", "context_id", "tag", "label", "text", "memory_type")
        if any(type(document.get(field)) is not str or not document[field].strip() for field in required_fields):
            raise ConfidenceMeasurementError("fixture document has a blank required field")
        document_id = document["document_id"]
        context_tag = (document["context_id"], document["tag"])
        if document_id in document_ids or context_tag in context_tags:
            raise ConfidenceMeasurementError("fixture document identities must be unique")
        document_ids.add(document_id)
        context_tags.add(context_tag)

    for query_name in ("static_state", "factual", "workflow", "gotcha"):
        query = fixture.get("queries", {}).get(query_name)
        if not isinstance(query, dict) or query.get("expected_document_id") not in document_ids:
            raise ConfidenceMeasurementError(f"fixture query {query_name} is invalid")
        if not str(query.get("prompt") or "").strip():
            raise ConfidenceMeasurementError(f"fixture query {query_name} prompt is blank")
    for query_name in ("premise_awareness", "abstention"):
        query = fixture.get("queries", {}).get(query_name)
        marker = str((query or {}).get("required_marker") or "")
        if not isinstance(query, dict) or not marker or marker not in str(query.get("prompt") or ""):
            raise ConfidenceMeasurementError(f"fixture query {query_name} marker is invalid")
        if any(marker.casefold() in str(document["text"]).casefold() for document in documents):
            raise ConfidenceMeasurementError(f"fixture query {query_name} marker is not absent")

    update = fixture.get("update_case")
    if not isinstance(update, dict) or update.get("retired_marker") == update.get("current_marker"):
        raise ConfidenceMeasurementError("fixture update case is invalid")
    for marker_field, text_field in (("retired_marker", "initial_text"), ("current_marker", "current_text")):
        if str(update.get(marker_field) or "") not in str(update.get(text_field) or ""):
            raise ConfidenceMeasurementError("fixture update markers must occur in their revision text")
    temporal = fixture.get("temporal_case")
    if not isinstance(temporal, dict) or temporal.get("before_document_id") not in document_ids or temporal.get("after_document_id") not in document_ids:
        raise ConfidenceMeasurementError("fixture temporal case is invalid")
    bridge = fixture.get("bridge_case")
    if not isinstance(bridge, dict) or bridge.get("approved_document_id") not in document_ids or bridge.get("isolated_document_id") not in document_ids:
        raise ConfidenceMeasurementError("fixture bridge case is invalid")
    image = fixture.get("image_case")
    try:
        image_media_id = validate_media_id((image or {}).get("media_id"))
    except (TypeError, ValueError):
        image_media_id = ""
    if not isinstance(image, dict) or not image_media_id:
        raise ConfidenceMeasurementError("fixture image case is invalid")
    if str(image.get("prompt") or "").split()[0] not in str(image.get("description") or ""):
        raise ConfidenceMeasurementError("fixture image prompt marker must occur in its description")
    return fixture


def _make_backend(data_root: Path, fixture: dict[str, Any]) -> SpikingAttentionBackend:
    config = fixture["backend"]
    return SpikingAttentionBackend(
        dimension=int(config["dimension"]),
        num_neurons=int(config["num_neurons"]),
        default_top_k=int(config["default_top_k"]),
        recall_count=int(config["recall_count"]),
        compile_graph=False,
        state_path=data_root / "runtime_state.json",
        embedding_provider_name="semantic-hash",
    )


def _binding(repo_root: Path, data_root: Path) -> CoreClientBinding:
    core_root = data_root / "core"
    core_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    core_root.chmod(0o700)
    data_root.chmod(0o700)
    return CoreClientBinding(
        repo_root=repo_root,
        data_root=data_root,
        config_path=core_root / "service.json",
        socket_path=core_root / "service.sock",
        state_path=data_root / "runtime_state.json",
        memory_path=data_root / "memory.sqlite3",
        capture_root=data_root,
        export_root=data_root / "exports",
        backup_root=data_root / "backups",
        recovery_root=data_root / "recovery",
        replication_inbox_root=data_root / "replication" / "inbox",
        core_label="memory-confidence-fixture",
        config_digest="a" * 64,
        config_fingerprint="b" * 64,
        embedding_space_identity="c" * 64,
        layout="canonical",
        authority_mode="authoritative-core-v6",
    )


def _bmp_bytes(width: int = 16, height: int = 16) -> bytes:
    row_stride = ((width * 24 + 31) // 32) * 4
    pixels = bytearray()
    for y in range(height - 1, -1, -1):
        row = bytearray()
        for x in range(width):
            row.extend((((x + y) * 7) % 256, (y * 13) % 256, (x * 17) % 256))
        row.extend(b"\x00" * (row_stride - len(row)))
        pixels.extend(row)
    offset = 54
    return (
        b"BM"
        + struct.pack("<IHHI", offset + len(pixels), 0, 0, offset)
        + struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
        + bytes(pixels)
    )


def _fixture_converter(_source: Path, work_root: Path) -> ConversionResult:
    bmp = work_root / "normalized.bmp"
    thumbnail = work_root / "thumbnail.jpg"
    bmp.write_bytes(_bmp_bytes())
    thumbnail.write_bytes(b"\xff\xd8\xff\xe0memory-confidence-thumbnail\xff\xd9")
    os.chmod(bmp, 0o600)
    os.chmod(thumbnail, 0o600)
    return ConversionResult(16, 16, bmp, thumbnail)


def _active_indices(backend: SpikingAttentionBackend, text: str) -> list[int]:
    spikes = backend.encode_to_spikes_top_k(backend.embed_text(text))
    values = spikes.tolist() if hasattr(spikes, "tolist") else list(spikes)
    return [index for index, value in enumerate(values) if float(value) > 0.0]


def _store_text(
    backend: SpikingAttentionBackend,
    *,
    context_id: str,
    tag: str,
    label: str,
    text: str,
    memory_type: str,
    timestamp: float,
    extra_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = {
        "display_label": label,
        "display_summary": text,
        "display_excerpt": text,
        "memory_type": memory_type,
        "source": "memory-confidence-synthetic-fixture",
        **(extra_metadata or {}),
    }
    with patch.object(_memory_store_module.time, "time", return_value=timestamp):
        return backend.memory_store.upsert_entry(
            tag=tag,
            context_id=context_id,
            source_text=text,
            metadata=metadata,
            embedding_dimensions=backend.dimension,
            spike_indices=_active_indices(backend, text),
            neuron_indices=[],
            registered_at=timestamp,
        )


def _retrieve(
    backend: SpikingAttentionBackend,
    *,
    prompt: str,
    context_id: str,
    recall_scope: str = "local",
) -> dict[str, Any]:
    return backend.retrieve_text_v2(
        prompt,
        context_id=context_id,
        recall_scope=recall_scope,
        result_limit=8,
        candidate_limit=64,
        include_graph_neighbors=True,
    )


def _item_ids(result: dict[str, Any]) -> list[str]:
    return [str(item.get("memory_id") or "") for item in result.get("items", [])]


def _marker_hits(result: dict[str, Any], marker: str) -> list[str]:
    target = marker.casefold()
    hits: list[str] = []
    for item in result.get("items", []):
        visible = " ".join(str(item.get(field) or "") for field in ("tag", "label", "summary", "excerpt"))
        if target in visible.casefold():
            hits.append(str(item.get("memory_id") or ""))
    return hits


def _evidence(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "returned": len(result.get("items", [])),
        "memory_ids": _item_ids(result),
        "context_ids": [str(item.get("context_id") or "") for item in result.get("items", [])],
    }


def _logical_deletion_residue(db_path: Path, memory_id: str) -> dict[str, int]:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        checks = {
            "memory_entries": ("SELECT COUNT(*) FROM memory_entries WHERE memory_id = ?", (memory_id,)),
            "memory_spikes": ("SELECT COUNT(*) FROM memory_spikes WHERE memory_id = ?", (memory_id,)),
            "memory_surface_terms": ("SELECT COUNT(*) FROM memory_surface_terms WHERE memory_id = ?", (memory_id,)),
            "memory_events": ("SELECT COUNT(*) FROM memory_events WHERE memory_id = ?", (memory_id,)),
            "memory_relationships": (
                "SELECT COUNT(*) FROM memory_relationships WHERE source_memory_id = ? OR target_memory_id = ?",
                (memory_id, memory_id),
            ),
        }
        return {name: int(connection.execute(sql, params).fetchone()[0]) for name, (sql, params) in checks.items()}
    finally:
        connection.close()


def acceptance_verdict(report: dict[str, Any], thresholds: dict[str, Any]) -> dict[str, Any]:
    """Fail closed unless every required behavior and zero-residue gate passes."""

    if thresholds != SAFE_THRESHOLDS:
        return {"accepted": False, "verdict": "fail", "failure_codes": ["acceptance-thresholds-weakened"], "checks": []}
    dimensions = report.get("dimensions", {})
    observed = set(dimensions) if isinstance(dimensions, dict) else set()
    passed = sum(1 for name in REQUIRED_DIMENSIONS if bool(dimensions.get(name, {}).get("passed")))
    pass_rate = passed / len(REQUIRED_DIMENSIONS)
    bridge = dimensions.get("bridge_isolation", {}).get("evidence", {})
    deletion = dimensions.get("deletion_residue", {}).get("evidence", {})
    checks = [
        {"id": "required-dimension-set", "passed": observed == REQUIRED_DIMENSIONS},
        {"id": "all-dimensions-pass", "passed": pass_rate >= float(thresholds["minimum_dimension_pass_rate"])},
        {"id": "bridge-has-zero-leakage", "passed": int(bridge.get("namespace_leakage_count", -1)) <= int(thresholds["maximum_namespace_leakage_count"])},
        {"id": "logical-deletion-has-zero-residue", "passed": int(deletion.get("logical_residue_count", -1)) <= int(thresholds["maximum_logical_deletion_residue_count"])},
        {"id": "media-deletion-has-zero-residue", "passed": int(deletion.get("media_residue_count", -1)) <= int(thresholds["maximum_media_residue_count"])},
        {"id": "offline-disposable-execution", "passed": report.get("run_identity", {}).get("offline") is True and report.get("run_identity", {}).get("temporary_store") is True and report.get("run_identity", {}).get("live_database_opened") is False},
        {"id": "synthetic-scope-disclosed", "passed": report.get("synthetic_benchmark_notice") == SYNTHETIC_NOTICE},
    ]
    failures = [str(check["id"]) for check in checks if not check["passed"]]
    return {"accepted": not failures, "verdict": "pass" if not failures else "fail", "failure_codes": failures, "checks": checks, "dimension_pass_rate": round(pass_rate, 8)}


def run_confidence_benchmark(
    *,
    fixture_path: Path = FIXTURE_PATH,
    latency_samples: int = 3,
    timer: Callable[[], int] = time.perf_counter_ns,
    code_commit: str | None = None,
) -> dict[str, Any]:
    if type(latency_samples) is not int or not 1 <= latency_samples <= MAX_LATENCY_SAMPLES:
        raise ConfidenceMeasurementError(f"latency_samples must be between 1 and {MAX_LATENCY_SAMPLES}")
    try:
        code_commit = retrieval_measurement._bounded_identity(code_commit, field="code_commit")
    except retrieval_measurement.MeasurementError as exc:
        raise ConfidenceMeasurementError("code_commit must be a bounded public identifier") from exc
    fixture = load_fixture(fixture_path)
    latencies: list[float] = []
    dimensions: dict[str, dict[str, Any]] = {}

    temporary_parent = Path("/private/tmp")
    with tempfile.TemporaryDirectory(
        prefix="s2-confidence-",
        dir=str(temporary_parent) if temporary_parent.is_dir() else None,
    ) as temporary:
        root = Path(temporary).resolve()
        repo_root = root / "repo"
        data_root = repo_root / ".synapse_s2"
        data_root.mkdir(parents=True, mode=0o700)
        backend = _make_backend(data_root, fixture)
        try:
            fixed_epoch = float(fixture["fixed_epoch"])
            memory_ids: dict[str, str] = {}
            for index, document in enumerate(fixture["documents"]):
                entry = _store_text(
                    backend,
                    context_id=str(document["context_id"]),
                    tag=str(document["tag"]),
                    label=str(document["label"]),
                    text=str(document["text"]),
                    memory_type=str(document["memory_type"]),
                    timestamp=fixed_epoch + index,
                    extra_metadata={"benchmark_document_id": str(document["document_id"])},
                )
                memory_ids[str(document["document_id"])] = str(entry["memory_id"])

            update = fixture["update_case"]
            initial = _store_text(
                backend,
                context_id=update["context_id"], tag=update["tag"], label=update["label"],
                text=update["initial_text"], memory_type="text", timestamp=fixed_epoch + 100,
                extra_metadata={"revision": 1, "status": "retired"},
            )
            current = _store_text(
                backend,
                context_id=update["context_id"], tag=update["tag"], label=update["label"],
                text=update["current_text"], memory_type="text", timestamp=fixed_epoch + 101,
                extra_metadata={"revision": 2, "status": "current", "supersedes_revision": 1},
            )

            temporal = fixture["temporal_case"]
            temporal_relationship = backend.memory_store.upsert_relationship(
                context_id=temporal["context_id"],
                source_memory_id=memory_ids[temporal["before_document_id"]],
                target_memory_id=memory_ids[temporal["after_document_id"]],
                relation_type=temporal["relation_type"], weight=1.0,
                evidence={"method": "memory-confidence-synthetic-fixture"},
            )

            bridge = fixture["bridge_case"]
            governance = BridgeGovernance(
                backend.memory_store,
                require_distinct_reviewer=False,
                allow_compatibility_approval=True,
                allow_test_time=True,
            )
            governance.approve_namespace_link_compat(
                source_context_id=bridge["source_context_id"],
                target_context_id=bridge["target_context_id"],
                relation_type=bridge["relation_type"], direction="bidirectional", weight=1.0,
                evidence={"method": "memory-confidence-synthetic-fixture"},
                approved_by="memory-confidence-fixture", reason="Fixed offline confidence fixture.",
                governance_request_id="memory-confidence-bridge-001", confirm=True,
                now=fixed_epoch + 200,
            )

            image = fixture["image_case"]
            source = root / "synthetic-image.png"
            source.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic-offline-fixture")
            source.chmod(0o600)
            cache = ImageCaptureCache(_binding(repo_root, data_root), converter=_fixture_converter)
            image_cache = cache.capture_image(source, media_id=image["media_id"])
            image_entry = _store_text(
                backend,
                context_id=image["context_id"], tag=image["tag"], label=image["label"],
                text=image["description"], memory_type="image", timestamp=fixed_epoch + 300,
                extra_metadata={
                    "media_id": image["media_id"],
                    "image_artifact": image_cache["public_metadata"],
                    "description_source": "fixture-authored",
                },
            )
            image_memory_id = str(image_entry["memory_id"])

            def timed_query(**kwargs: str) -> dict[str, Any]:
                result: dict[str, Any] | None = None
                for _ in range(latency_samples):
                    started = timer()
                    observed = _retrieve(backend, **kwargs)
                    latencies.append(max(0, timer() - started) / 1_000_000.0)
                    if result is None:
                        result = observed
                    elif _canonical_bytes(result) != _canonical_bytes(observed):
                        raise ConfidenceMeasurementError("repeated confidence query was not deterministic")
                assert result is not None
                return result

            for dimension, query_key in (
                ("static_state", "static_state"),
                ("factual_recall", "factual"),
                ("workflow_knowledge", "workflow"),
                ("environment_gotcha", "gotcha"),
            ):
                query = fixture["queries"][query_key]
                result = timed_query(prompt=query["prompt"], context_id=query["context_id"])
                expected = memory_ids[query["expected_document_id"]]
                dimensions[dimension] = {
                    "passed": expected in _item_ids(result),
                    "evidence": {**_evidence(result), "expected_memory_id": expected},
                }

            current_result = timed_query(prompt=update["current_marker"], context_id=update["context_id"])
            retired_result = timed_query(prompt=update["retired_marker"], context_id=update["context_id"])
            update_evidence = {
                "stable_memory_id": str(initial["memory_id"]) == str(current["memory_id"]),
                "current_marker_hits": _marker_hits(current_result, update["current_marker"]),
                "retired_marker_hits": _marker_hits(retired_result, update["retired_marker"]),
                "stored_revision": backend.memory_store.get_entry(str(current["memory_id"]))["metadata"].get("revision"),
            }
            update_passed = bool(update_evidence["stable_memory_id"] and str(current["memory_id"]) in update_evidence["current_marker_hits"] and not update_evidence["retired_marker_hits"] and update_evidence["stored_revision"] == 2)
            dimensions["dynamic_tracking"] = {"passed": update_passed, "evidence": update_evidence}
            dimensions["updates_supersession"] = {"passed": update_passed, "evidence": update_evidence}

            temporal_result = timed_query(prompt=temporal["prompt"], context_id=temporal["context_id"])
            temporal_ids = _item_ids(temporal_result)
            temporal_passed = (
                memory_ids[temporal["before_document_id"]] in temporal_ids
                and memory_ids[temporal["after_document_id"]] in temporal_ids
                and temporal_relationship["source_memory_id"] == memory_ids[temporal["before_document_id"]]
                and temporal_relationship["target_memory_id"] == memory_ids[temporal["after_document_id"]]
                and temporal_relationship["relation_type"] == "temporal_next"
            )
            dimensions["temporal_order"] = {
                "passed": temporal_passed,
                "evidence": {**_evidence(temporal_result), "relationship_id": temporal_relationship["relationship_id"], "ordered_memory_ids": [temporal_relationship["source_memory_id"], temporal_relationship["target_memory_id"]]},
            }

            for dimension, query_key in (("premise_awareness", "premise_awareness"), ("abstention", "abstention")):
                query = fixture["queries"][query_key]
                result = timed_query(prompt=query["prompt"], context_id=query["context_id"])
                hits = _marker_hits(result, query["required_marker"])
                dimensions[dimension] = {
                    "passed": not hits,
                    "evidence": {**_evidence(result), "qualification": "exact required marker in returned evidence", "qualified_evidence_count": len(hits)},
                }

            local_bridge = timed_query(prompt=bridge["prompt"], context_id=bridge["source_context_id"], recall_scope="local")
            connected_bridge = timed_query(prompt=bridge["prompt"], context_id=bridge["source_context_id"], recall_scope="connected")
            approved_id = memory_ids[bridge["approved_document_id"]]
            isolated_id = memory_ids[bridge["isolated_document_id"]]
            local_ids = _item_ids(local_bridge)
            connected_ids = _item_ids(connected_bridge)
            leakage_count = int(isolated_id in local_ids) + int(isolated_id in connected_ids) + int(approved_id in local_ids)
            dimensions["bridge_isolation"] = {
                "passed": approved_id in connected_ids and leakage_count == 0,
                "evidence": {
                    "approved_memory_id": approved_id, "isolated_memory_id": isolated_id,
                    "local_memory_ids": local_ids, "connected_memory_ids": connected_ids,
                    "namespace_leakage_count": leakage_count,
                },
            }

            image_result = timed_query(prompt=image["prompt"], context_id=image["context_id"])
            stored_image = backend.memory_store.get_entry(image_memory_id)
            image_hits = _marker_hits(image_result, image["prompt"].split()[0])
            image_passed = (
                image_memory_id in image_hits
                and stored_image is not None
                and stored_image["metadata"].get("memory_type") == "image"
                and stored_image["metadata"].get("media_id") == image["media_id"]
                and image_cache["raw_original_stored"] is False
            )
            dimensions["image_description_recall"] = {
                "passed": image_passed,
                "evidence": {**_evidence(image_result), "image_memory_id": image_memory_id, "media_id": image["media_id"], "raw_original_stored": image_cache["raw_original_stored"]},
            }

            deleted = backend.prune_memory(
                context_id=image["context_id"], target_type="memory", memory_id=image_memory_id,
                reason="offline confidence deletion-fidelity fixture", source_surface="confidence-fixture",
                publish_audit=False, confirm=True,
            )
            orphan_audit = cache.audit(referenced_media_ids=[])
            cache.prune_orphans(referenced_media_ids=[], expected_revision=orphan_audit["revision"], confirm=True)
            final_audit = cache.audit(referenced_media_ids=[])
            post_delete = timed_query(prompt=image["prompt"], context_id=image["context_id"])
            logical_residue = _logical_deletion_residue(backend.memory_store.db_path, image_memory_id)
            logical_count = sum(logical_residue.values())
            media_count = int(final_audit["stored_count"]) + int(final_audit["orphan_count"]) + int(final_audit["missing_count"]) + int(final_audit["corrupt_count"])
            deletion_evidence = {
                "deleted": bool(deleted.get("result", {}).get("deleted")),
                "post_delete_marker_hits": _marker_hits(post_delete, image["prompt"].split()[0]),
                "logical_application_tables": logical_residue,
                "logical_residue_count": logical_count,
                "media_residue_count": media_count,
                "orphan_observed_before_governed_cache_prune": orphan_audit["orphan_count"],
                "final_cache_audit": {key: final_audit[key] for key in ("healthy", "stored_count", "orphan_count", "missing_count", "corrupt_count")},
                "scope": "logical application-visible state and node-local derivative cache; not forensic free-space erasure, backups, or replicas",
            }
            dimensions["deletion_residue"] = {
                "passed": bool(deletion_evidence["deleted"] and not deletion_evidence["post_delete_marker_hits"] and logical_count == 0 and media_count == 0),
                "evidence": deletion_evidence,
            }

            report: dict[str, Any] = {
                "schema": REPORT_SCHEMA,
                "version": REPORT_VERSION,
                "status": "pending",
                "synthetic_benchmark_notice": SYNTHETIC_NOTICE,
                "run_identity": {
                    "offline": True,
                    "temporary_store": True,
                    "live_database_opened": False,
                    "network_used": False,
                    "llm_used": False,
                    "embedding_provider": "semantic-hash",
                    "fixture_sha256": _digest(fixture),
                    "code_commit": code_commit,
                },
                "methodology": {
                    "mode": "deterministic-context-gathering-regression",
                    "evidence_qualification": "expected stable memory identity or exact fixture marker",
                    "answer_model": None,
                    "mutations": "disposable-store update, bridge approval, image derivative, and confirmed prune only",
                    "latency_in_acceptance": False,
                },
                "thresholds": fixture["thresholds"],
                "dimensions": dimensions,
                "latency_ms": {
                    "samples": len(latencies),
                    "p50": retrieval_measurement._nearest_rank_percentile(latencies, 0.5),
                    "p95": retrieval_measurement._nearest_rank_percentile(latencies, 0.95),
                    "informational_only": True,
                    "excluded_from_acceptance": True,
                },
                "limitations": [
                    SYNTHETIC_NOTICE,
                    "The gate tests deterministic evidence retrieval, not natural-language answer generation.",
                    "Deletion proof is logical and node-local; it does not certify forensic free-space erasure, remote replicas, or historical backups.",
                    "The fixture is deliberately small and cannot replace periodic live-corpus sampling or the official benchmark suites.",
                ],
            }
            report["acceptance"] = acceptance_verdict(report, fixture["thresholds"])
            report["status"] = "pass" if report["acceptance"]["accepted"] else "fail"
            return report
        finally:
            backend.memory_store.close()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=FIXTURE_PATH)
    parser.add_argument("--latency-samples", type=int, default=3)
    parser.add_argument("--code-commit", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = run_confidence_benchmark(
            fixture_path=args.fixture,
            latency_samples=args.latency_samples,
            code_commit=args.code_commit,
        )
        serialized = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        sys.stdout.write(serialized)
        return 0 if report["acceptance"]["accepted"] else 1
    except (ConfidenceMeasurementError, ValueError, RuntimeError, OSError) as exc:
        sys.stderr.write(f"memory confidence measurement failed: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

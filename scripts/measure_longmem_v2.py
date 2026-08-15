#!/usr/bin/env python3
"""Offline LongMemEval-V2-derived acceptance measurement for SYNAPSE-S2.

Two explicit modes:

* ``synapse-derived`` (default): runs the version-controlled synthetic
  multimodal fixture in ``tests/fixtures/longmem_v2/benchmark_v1.json``.
* ``prepared-corpus``: runs an operator-prepared **local** dataset through
  the same adapter contract.  The dataset is never downloaded; the operator
  must pin its SHA-256, a version label, and the adapter (``longmem_eval.py``)
  SHA-256, and the run still reports ``official_score_claimed: false``
  because the official Qwen reader and GPT judge are never executed here.
  (The old mode name ``official-adapter`` is a fail-closed deprecated alias:
  it is refused with guidance, because this mode never was and never claims
  to be official-harness-compatible.  The genuine official-harness adapter
  lives in ``official_longmem/`` and runs under the pinned official checkout.)

Every run uses a disposable temporary store, performs no network calls,
never opens the operator's live database, and prints one canonical JSON
report to stdout.  There is deliberately no output-path option.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import tracemalloc
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
while str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

import longmem_eval as evaluation  # noqa: E402
from core_client_binding import CoreClientBinding  # noqa: E402
from image_capture import ConversionResult, ImageCaptureCache  # noqa: E402
from scripts import measure_retrieval_v2 as retrieval_measurement  # noqa: E402

MeasurementError = evaluation.EvalError
REPORT_SCHEMA = evaluation.REPORT_SCHEMA
REPORT_VERSION = evaluation.REPORT_VERSION
SAFE_THRESHOLDS = evaluation.SAFE_THRESHOLDS
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "longmem_v2" / "benchmark_v1.json"
MODES = ("synapse-derived", "prepared-corpus")
# Fail-closed deprecated aliases: recognized so operators get an actionable
# error instead of a generic usage failure, but never executed.
DEPRECATED_MODE_ALIASES = {
    "official-adapter": (
        "mode 'official-adapter' was renamed to 'prepared-corpus'; it never "
        "was official-harness-compatible and never claimed an official score. "
        "Use --mode prepared-corpus for pinned local datasets, or the "
        "official_longmem package for the genuine official-harness adapter."
    ),
}
FORBIDDEN_MUTATORS = (
    "_auto_quick_prune_if_due",
    "run_snn_cycle",
    "_persist_runtime_state",
    "_mark_activity",
)
RECOVERY_PROBE_SCOPE = (
    "net-new read-only filesystem probe of the disposable binding recovery "
    "root; it proves node-local hygiene for this run only, not a production "
    "recovery-pipeline audit; if the root was never created the probe is "
    "unexercised and informational, not a zero-residue pass"
)
REPLICATION_PROBE_SCOPE = (
    "net-new read-only filesystem probe of the disposable binding replication "
    "inbox; it proves node-local hygiene for this run only, not a fleet "
    "replication audit; if the root was never created the probe is "
    "unexercised and informational, not a zero-residue pass"
)

canonical_json_bytes = evaluation.canonical_json_bytes


def adapter_source_sha256() -> str:
    return hashlib.sha256(Path(evaluation.__file__).read_bytes()).hexdigest()


def _read_local_bytes(path: Path, *, owner: str) -> bytes:
    """Read one local regular file once, bounded and fd-safe.

    The single ``O_NOFOLLOW`` open refuses a symlink at the final component,
    every precondition (regular file, owned by the invoking user, not group-
    or world-writable, size within the fixed bound) is checked with ``fstat``
    on that same descriptor, and the bytes are read from the same descriptor,
    so the checked file and the returned bytes can never diverge.  A second
    ``fstat`` after the read fails the run if the file identity or size
    changed while it was being read.
    """

    bound = int(evaluation.RESOURCE_BOUNDS["max_dataset_file_bytes"])
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise MeasurementError(
            f"{owner} must be an existing local regular file"
        ) from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise MeasurementError(f"{owner} must be a regular file")
        if before.st_uid != os.getuid():
            raise MeasurementError(f"{owner} must be owned by the invoking user")
        if before.st_mode & 0o022:
            raise MeasurementError(f"{owner} must not be group- or world-writable")
        if before.st_size > bound:
            raise MeasurementError(
                f"{owner} exceeds the fixed dataset file byte bound"
            )
        chunks: list[bytes] = []
        remaining = int(before.st_size)
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if len(raw) != before.st_size or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise MeasurementError(f"{owner} changed while being read")
        return raw
    except OSError as exc:
        raise MeasurementError(f"{owner} could not be read") from exc
    finally:
        os.close(fd)


def _parse_json_bytes(raw: bytes, *, owner: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise MeasurementError(f"{owner} could not be parsed as JSON") from exc


def _read_local_json(path: Path, *, owner: str) -> Any:
    return _parse_json_bytes(_read_local_bytes(path, owner=owner), owner=owner)


def load_fixture(path: Path | None = None) -> dict[str, Any]:
    fixture_path = Path(path) if path is not None else FIXTURE_PATH
    return evaluation.validate_fixture(
        _read_local_json(fixture_path, owner="longmem fixture")
    )


def _require_sha256(value: Any, *, field: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise MeasurementError(f"{field} must be a 64-character lowercase SHA-256 pin")
    return text


def load_prepared_dataset(
    *,
    dataset_path: Path,
    dataset_sha256: str,
    dataset_version: str,
    adapter_sha256: str,
) -> dict[str, Any]:
    """Load an operator-prepared local dataset with mandatory integrity pins."""

    path = Path(dataset_path)
    pinned = _require_sha256(dataset_sha256, field="dataset-sha256")
    # Hash and parse the same bytes: one bounded read serves both the
    # integrity pin and the JSON payload, so the pinned bytes are exactly the
    # evaluated bytes.
    raw = _read_local_bytes(path, owner="prepared dataset")
    observed = hashlib.sha256(raw).hexdigest()
    if observed != pinned:
        raise MeasurementError("dataset-sha256 pin does not match the dataset bytes")
    pinned_version = evaluation.bounded_identity(dataset_version, field="dataset-version")
    if pinned_version is None:
        raise MeasurementError("dataset-version pin is required")
    pinned_adapter = _require_sha256(adapter_sha256, field="adapter-sha256")
    if pinned_adapter != adapter_source_sha256():
        raise MeasurementError("adapter-sha256 pin does not match longmem_eval.py")
    payload = evaluation.validate_prepared_dataset(
        _parse_json_bytes(raw, owner="prepared dataset")
    )
    if str(payload.get("dataset_version") or "") != pinned_version:
        raise MeasurementError(
            "dataset-version pin does not match the prepared dataset metadata"
        )
    return payload


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
    thumbnail.write_bytes(b"\xff\xd8\xff\xe0longmem-v2-thumbnail\xff\xd9")
    os.chmod(bmp, 0o600)
    os.chmod(thumbnail, 0o600)
    return ConversionResult(16, 16, bmp, thumbnail)


def _data_root(root: Path) -> Path:
    """Disposable canonical-layout data root under one temporary store root."""

    data_root = root / "repo" / ".synapse_s2"
    data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    data_root.parent.chmod(0o700)
    data_root.chmod(0o700)
    return data_root


def _binding(root: Path) -> CoreClientBinding:
    data_root = _data_root(root)
    core_root = data_root / "core"
    core_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    core_root.chmod(0o700)
    return CoreClientBinding(
        repo_root=root / "repo",
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
        core_label="longmem-v2-fixture",
        config_digest="a" * 64,
        config_fingerprint="b" * 64,
        embedding_space_identity="c" * 64,
        layout="canonical",
        authority_mode="authoritative-core-v6",
    )


def _construct_backend(data_root: Path, payload: dict[str, Any]) -> Any:
    """Construct one disposable backend behind the exact topology byte bound.

    The exact neural topology size
    ``4 * (dimension*neurons + neurons*neurons + 3*neurons)`` must fit the
    fixed 384 MiB bound before any arrays are allocated, and any construction
    failure is converted to a measurement error so the CLI reports the
    canonical error JSON instead of a traceback.
    """

    evaluation.require_backend_topology(payload["backend"], owner="backend config")
    try:
        return retrieval_measurement._make_backend(data_root, payload)
    except MeasurementError:
        raise
    except Exception as exc:
        raise MeasurementError(f"backend construction failed: {exc}") from exc


def _image_capturer(cache: ImageCaptureCache, source_root: Path) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def capture(turn: dict[str, Any]) -> dict[str, Any]:
        media_id = str(turn["media_id"])
        source = source_root / f"{media_id}.png"
        if not source.exists():
            source.write_bytes(b"\x89PNG\r\n\x1a\nlongmem-v2-offline-" + media_id.encode("ascii"))
            source.chmod(0o600)
        captured = cache.capture_image(source, media_id=media_id)
        public = captured.get("public_metadata", {})
        dimensions = public.get("source_dimensions", {})
        return {
            "media_id": media_id,
            "raw_original_stored": captured.get("raw_original_stored"),
            "artifact": {
                "media_id": media_id,
                "width": dimensions.get("width"),
                "height": dimensions.get("height"),
            },
        }

    return capture


def _populate_store(
    root: Path,
    payload: dict[str, Any],
    *,
    trajectory_order: list[str] | None,
    adapter_factory: Callable[[Any], Any] | None,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    backend = _construct_backend(_data_root(root), payload)
    adapter = (
        evaluation.LongMemInsertQueryAdapter(backend)
        if adapter_factory is None
        else adapter_factory(backend)
    )
    corpus = payload["corpus"]
    cache = ImageCaptureCache(_binding(root), converter=_fixture_converter)
    source_root = root / "image-sources"
    source_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    populate_record = evaluation.populate_corpus(
        adapter,
        corpus,
        fixed_epoch=float(payload["fixed_epoch"]),
        trajectory_order=trajectory_order,
        image_capturer=_image_capturer(cache, source_root),
        provider_label=str(payload["backend"]["embedding_provider"]),
    )
    live_media_ids = [str(item["media_id"]) for item in populate_record["live_media"]]
    orphan_audit = cache.audit(referenced_media_ids=live_media_ids)
    if int(orphan_audit.get("orphan_count", 0)) > 0:
        cache.prune_orphans(
            referenced_media_ids=live_media_ids,
            expected_revision=orphan_audit["revision"],
            confirm=True,
        )
    final_audit = cache.audit(referenced_media_ids=live_media_ids)
    return {
        "backend": backend,
        "adapter": adapter,
        "populate_record": populate_record,
        "media": {
            "pre_prune_audit": {
                key: orphan_audit.get(key)
                for key in ("healthy", "stored_count", "orphan_count", "missing_count", "corrupt_count")
            },
            "final_audit": {
                key: final_audit.get(key)
                for key in ("healthy", "stored_count", "orphan_count", "missing_count", "corrupt_count")
            },
            "expected_stored_count": len(live_media_ids),
        },
    }


def _run_query_set(
    backend: Any,
    adapter: Any,
    corpus: dict[str, Any],
    *,
    latency_samples: int,
    timer: Callable[[], int],
) -> dict[str, Any]:
    """Run every question with read-mutation tripwires armed.

    The warm untimed call provides the graded evidence object; every timed
    repeat must be byte-identical or the run fails.
    """

    results: dict[str, dict[str, Any]] = {}
    latency_by_question: dict[str, list[float]] = {}
    with ExitStack() as stack:
        for method in FORBIDDEN_MUTATORS:

            def _forbidden(*_args: Any, _method: str = method, **_kwargs: Any) -> Any:
                raise MeasurementError(f"query phase invoked forbidden mutator {_method}")

            stack.enter_context(patch.object(backend, method, side_effect=_forbidden))
        for question in corpus["questions"]:
            question_id = str(question["question_id"])
            warm = evaluation.query_call(adapter, question)
            warm_bytes = canonical_json_bytes(warm)
            samples: list[float] = []
            for _ in range(latency_samples):
                started = timer()
                observed = evaluation.query_call(adapter, question)
                samples.append(max(0, timer() - started) / 1_000_000.0)
                if canonical_json_bytes(observed) != warm_bytes:
                    raise MeasurementError(
                        f"repeated query {question_id} was not byte-identical"
                    )
            results[question_id] = warm
            latency_by_question[question_id] = samples
    raw_digest = evaluation.digest_value(
        {question_id: results[question_id] for question_id in sorted(results)}
    )
    return {
        "results": results,
        "latency_by_question": latency_by_question,
        "raw_digest": raw_digest,
    }


def _logical_deletion_residue(db_path: Path, memory_id: str) -> dict[str, int]:
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        checks = {
            "memory_entries": ("SELECT COUNT(*) FROM memory_entries WHERE memory_id = ?", (memory_id,)),
            "memory_spikes": ("SELECT COUNT(*) FROM memory_spikes WHERE memory_id = ?", (memory_id,)),
            "memory_surface_terms": (
                "SELECT COUNT(*) FROM memory_surface_terms WHERE memory_id = ?",
                (memory_id,),
            ),
            "memory_events": ("SELECT COUNT(*) FROM memory_events WHERE memory_id = ?", (memory_id,)),
            "memory_relationships": (
                "SELECT COUNT(*) FROM memory_relationships "
                "WHERE source_memory_id = ? OR target_memory_id = ?",
                (memory_id, memory_id),
            ),
        }
        return {
            name: int(connection.execute(sql, params).fetchone()[0])
            for name, (sql, params) in checks.items()
        }
    finally:
        connection.close()


def _filesystem_residue_probe(root: Path, markers: list[str], *, scope: str) -> dict[str, Any]:
    """Read-only walk counting files that still reference deleted identifiers."""

    files_scanned = 0
    residue_files = []
    root_exists = root.is_dir()
    if root_exists:
        needles = [marker.encode("utf-8") for marker in markers if marker]
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            files_scanned += 1
            try:
                payload = path.read_bytes()
            except OSError:
                residue_files.append(str(path.relative_to(root)))
                continue
            if any(needle in payload for needle in needles):
                residue_files.append(str(path.relative_to(root)))
    return {
        "probed": True,
        "root_exists": root_exists,
        # A root that never existed was never written to by this run; the
        # probe is then unexercised and informational, not a residue pass.
        "exercised": root_exists,
        "informational_only": not root_exists,
        "files_scanned": files_scanned,
        "residue_count": len(residue_files),
        "residue_files": residue_files,
        "scope": scope,
    }


def acceptance_verdict(aggregate: dict[str, Any], thresholds: dict[str, Any]) -> dict[str, Any]:
    """Fail closed unless every fixed hard gate passes.

    ``SAFE_THRESHOLDS`` is the only accepted threshold set; anything else is
    rejected outright so the gates cannot be weakened through configuration.
    """

    if thresholds != SAFE_THRESHOLDS:
        return {
            "accepted": False,
            "verdict": "fail",
            "checks": [],
            "failure_codes": ["acceptance-thresholds-weakened"],
        }
    metrics = aggregate["metrics"]
    determinism = aggregate["determinism"]
    purity = aggregate["purity"]
    residue = aggregate["residue"]
    execution = aggregate["execution"]
    claims = aggregate["claims"]
    checks = [
        (
            "graded-recall-at-k",
            f">= {thresholds['minimum_graded_macro_recall_at_k']}",
            metrics["graded_macro_recall_at_k"],
            metrics["graded_macro_recall_at_k"] >= thresholds["minimum_graded_macro_recall_at_k"],
        ),
        (
            "graded-ndcg-at-k",
            f">= {thresholds['minimum_graded_macro_ndcg_at_k']}",
            metrics["graded_macro_ndcg_at_k"],
            metrics["graded_macro_ndcg_at_k"] >= thresholds["minimum_graded_macro_ndcg_at_k"],
        ),
        (
            "graded-mrr",
            f">= {thresholds['minimum_graded_macro_mrr']}",
            metrics["graded_macro_mrr"],
            metrics["graded_macro_mrr"] >= thresholds["minimum_graded_macro_mrr"],
        ),
        (
            "per-question-recall-floor",
            f">= {thresholds['minimum_per_question_graded_recall_at_k']}",
            aggregate["per_question_minimums"]["graded_recall_at_k"],
            aggregate["per_question_minimums"]["graded_recall_at_k"]
            >= thresholds["minimum_per_question_graded_recall_at_k"],
        ),
        (
            "ability-coverage-complete",
            "all abilities and horizons measured",
            {
                "abilities": sorted(aggregate["by_ability"]),
                "horizons": sorted(aggregate["by_horizon"]),
            },
            set(aggregate["by_ability"]) == evaluation.ABILITIES
            and set(aggregate["by_horizon"]) == evaluation.HORIZONS,
        ),
        (
            "namespace-scope-no-leakage",
            "== 0",
            metrics["namespace_leakage_count"],
            metrics["namespace_leakage_count"] <= thresholds["maximum_namespace_leakage_count"],
        ),
        (
            "scope-provenance-authorized",
            "== 0",
            metrics["scope_provenance_violation_count"],
            metrics["scope_provenance_violation_count"]
            <= thresholds["maximum_scope_provenance_violation_count"],
        ),
        (
            "false-premise-no-marker-support",
            "== 0 marker-bearing items; checks evidence leakage only, "
            "not reader-level premise awareness",
            metrics["false_premise_qualified_support_count"],
            metrics["false_premise_qualified_support_count"]
            <= thresholds["maximum_false_premise_qualified_support_count"],
        ),
        (
            "absent-topic-no-marker-support",
            "== 0 marker-bearing items; checks evidence leakage only, "
            "not reader-level abstention ability",
            metrics["abstention_violation_count"],
            metrics["abstention_violation_count"]
            <= thresholds["maximum_abstention_violation_count"],
        ),
        (
            "answer-decision-consistent",
            "== 0; deterministic evidence decision matches each question's "
            "expected qualified/abstain outcome",
            metrics["answer_decision_violation_count"],
            metrics["answer_decision_violation_count"]
            <= thresholds["maximum_answer_decision_violation_count"],
        ),
        (
            "query-result-contract",
            "== 0; at most result_limit items with unique ordered 1-based ranks",
            metrics["result_contract_violation_count"],
            metrics["result_contract_violation_count"]
            <= thresholds["maximum_result_contract_violation_count"],
        ),
        (
            "current-state-over-retired",
            "== 0",
            metrics["current_over_retired_violation_count"],
            metrics["current_over_retired_violation_count"]
            <= thresholds["maximum_current_over_retired_violation_count"],
        ),
        (
            "temporal-evidence-retrieved",
            "== 0; grades retrieval of both temporal evidence turns with "
            "ordered stored event times, not an ordered-answer judgment",
            metrics["temporal_evidence_violation_count"],
            metrics["temporal_evidence_violation_count"]
            <= thresholds["maximum_temporal_evidence_violation_count"],
        ),
        (
            "image-evidence-grounded",
            f">= {thresholds['minimum_image_evidence_hits']} and all image questions grounded",
            {
                "image_questions": metrics["image_questions"],
                "image_evidence_hits": metrics["image_evidence_hits"],
            },
            metrics["image_evidence_hits"] >= thresholds["minimum_image_evidence_hits"]
            and metrics["image_evidence_hits"] == metrics["image_questions"],
        ),
        (
            "deleted-evidence-never-returned",
            "== 0",
            metrics["deleted_evidence_count"],
            metrics["deleted_evidence_count"] <= thresholds["maximum_deleted_evidence_count"],
        ),
        (
            "duplicate-memory-ids-absent",
            "== 0",
            metrics["duplicate_memory_id_count"],
            metrics["duplicate_memory_id_count"]
            <= thresholds["maximum_duplicate_memory_id_count"],
        ),
        (
            "duplicate-content-rate",
            "== 0.0 with observed source deduplication",
            {
                "duplicate_content_rate": metrics["duplicate_content_rate"],
                "source_content_deduplications": metrics["source_content_deduplications"],
            },
            metrics["duplicate_content_rate"] <= thresholds["maximum_duplicate_content_rate"]
            and metrics["source_content_deduplications"] > 0,
        ),
        (
            "provenance-complete",
            "== 0",
            metrics["provenance_violation_count"],
            metrics["provenance_violation_count"]
            <= thresholds["maximum_provenance_violation_count"],
        ),
        (
            "confidence-remains-uncalibrated",
            "== 0",
            metrics["confidence_violation_count"],
            metrics["confidence_violation_count"]
            <= thresholds["maximum_confidence_violation_count"],
        ),
        (
            "stable-memory-id-tie-break",
            "== 0",
            metrics["tie_ordering_violation_count"],
            metrics["tie_ordering_violation_count"]
            <= thresholds["maximum_tie_ordering_violation_count"],
        ),
        (
            "retrieval-is-pure",
            "runtime digests unchanged across every query phase",
            purity["all_runs_unchanged"],
            purity["all_runs_unchanged"] is True,
        ),
        (
            "canonical-output-deterministic",
            "repeat, fresh-backend, and shuffled-insertion digests all equal",
            determinism,
            determinism["canonical_digest_all_equal"] is True
            and determinism["fresh_backend_raw_equal"] is True
            and determinism["randomized_insertion_raw_equal"] is True
            and determinism["repeated_same_backend_raw_equal"] is True,
        ),
        (
            "zero-logical-deletion-residue",
            "== 0",
            residue["logical_total"],
            residue["logical_total"] <= thresholds["maximum_logical_deletion_residue_count"],
        ),
        (
            "zero-surface-deletion-residue",
            "== 0",
            residue["surface_total"],
            residue["surface_total"] <= thresholds["maximum_surface_deletion_residue_count"],
        ),
        (
            "zero-media-residue",
            "== 0",
            residue["media"]["media_residue_count"],
            residue["media"]["media_residue_count"] <= thresholds["maximum_media_residue_count"],
        ),
        (
            "recovery-residue-probe",
            "== 0 when the probe root was exercised; a never-created root is "
            "an unexercised informational probe, not a zero-residue pass",
            {
                "exercised": residue["recovery"]["exercised"],
                "residue_count": residue["recovery"]["residue_count"],
            },
            residue["recovery"]["probed"] is True
            and (
                residue["recovery"]["exercised"] is False
                or residue["recovery"]["residue_count"]
                <= thresholds["maximum_recovery_residue_count"]
            ),
        ),
        (
            "replication-residue-probe",
            "== 0 when the probe root was exercised; a never-created root is "
            "an unexercised informational probe, not a zero-residue pass",
            {
                "exercised": residue["replication"]["exercised"],
                "residue_count": residue["replication"]["residue_count"],
            },
            residue["replication"]["probed"] is True
            and (
                residue["replication"]["exercised"] is False
                or residue["replication"]["residue_count"]
                <= thresholds["maximum_replication_residue_count"]
            ),
        ),
        (
            "offline-disposable-execution",
            "built-in audited adapter attests offline disposable execution; "
            "an injected test adapter must claim no execution provenance",
            execution,
            (
                execution["adapter_audited"] is True
                and execution["offline"] is True
                and execution["temporary_store"] is True
                and execution["live_database_opened"] is False
                and execution["network_used"] is False
                and execution["llm_used"] is False
            )
            or (
                execution["adapter_audited"] is False
                and execution["offline"] is None
                and execution["temporary_store"] is None
                and execution["live_database_opened"] is None
                and execution["network_used"] is None
                and execution["llm_used"] is None
            ),
        ),
        (
            "official-claim-honest",
            "official_score_claimed is false and no reader/judge ran",
            claims,
            claims["official_score_claimed"] is False
            and claims["reader"] is None
            and claims["judge"] is None,
        ),
        (
            "scope-disclosed",
            "derived-scope disclosure present",
            claims.get("scope_disclosure"),
            "not an official longmemeval-v2 score"
            in str(claims.get("scope_disclosure") or "").casefold(),
        ),
    ]
    rendered = [
        {"check": check, "required": required, "observed": observed, "passed": bool(passed)}
        for check, required, observed, passed in checks
    ]
    failures = [item["check"] for item in rendered if not item["passed"]]
    return {
        "accepted": not failures,
        "verdict": "pass" if not failures else "fail",
        "checks": rendered,
        "failure_codes": failures,
    }


def run_measurement(
    *,
    mode: str = "synapse-derived",
    fixture_path: Path | None = None,
    dataset_path: Path | None = None,
    dataset_sha256: str | None = None,
    dataset_version: str | None = None,
    adapter_sha256: str | None = None,
    code_commit: str | None = None,
    latency_samples: int = 3,
    timer: Callable[[], int] = time.perf_counter_ns,
    adapter_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    if mode in DEPRECATED_MODE_ALIASES:
        raise MeasurementError(DEPRECATED_MODE_ALIASES[mode])
    if mode not in MODES:
        raise MeasurementError(f"mode must be one of {MODES}")
    if not 1 <= int(latency_samples) <= 25:
        raise MeasurementError("latency_samples must be between 1 and 25")
    if mode == "prepared-corpus" and adapter_factory is not None:
        raise MeasurementError(
            "prepared-corpus mode permits only the built-in audited adapter; "
            "injected adapters are a test-only seam"
        )
    commit = evaluation.bounded_identity(code_commit, field="code_commit")
    adapter_injected = adapter_factory is not None

    def _bound_adapter_factory(backend: Any) -> Any:
        """Construct the adapter and bind its identity explicitly."""

        adapter = (
            evaluation.LongMemInsertQueryAdapter(backend)
            if adapter_factory is None
            else adapter_factory(backend)
        )
        if getattr(adapter, "protocol", None) != evaluation.ADAPTER_PROTOCOL:
            raise MeasurementError(
                "adapter does not declare the longmem-insert-query-v1 protocol"
            )
        if evaluation.bounded_identity(
            getattr(adapter, "label", None), field="adapter label"
        ) is None:
            raise MeasurementError("adapter label must be a bounded public identifier")
        return adapter

    dataset_pins: dict[str, Any] | None = None
    if mode == "synapse-derived":
        if dataset_path or dataset_sha256 or dataset_version or adapter_sha256:
            raise MeasurementError("dataset pins are only valid in prepared-corpus mode")
        payload = load_fixture(fixture_path)
        source_kind = "synapse-derived-fixture"
        notice = evaluation.DERIVED_NOTICE
    else:
        if fixture_path is not None:
            raise MeasurementError("prepared-corpus mode does not accept --fixture")
        if not (dataset_path and dataset_sha256 and dataset_version and adapter_sha256):
            raise MeasurementError(
                "prepared-corpus mode requires dataset-path, dataset-sha256, "
                "dataset-version, and adapter-sha256 pins"
            )
        payload = load_prepared_dataset(
            dataset_path=Path(dataset_path),
            dataset_sha256=dataset_sha256,
            dataset_version=dataset_version,
            adapter_sha256=adapter_sha256,
        )
        source_kind = "operator-prepared-local-dataset"
        notice = evaluation.PREPARED_NOTICE
        dataset_pins = {
            "dataset_path": str(Path(dataset_path).resolve()),
            "dataset_sha256": str(dataset_sha256).lower(),
            "dataset_version": str(dataset_version),
            "adapter_sha256": str(adapter_sha256).lower(),
            "dataset_label": payload.get("dataset_label"),
            "preparation": payload.get("preparation"),
        }

    corpus = payload["corpus"]
    index = evaluation.validate_corpus(corpus)
    seed = int(payload["random_seed"])
    natural_order = list(index["trajectory_ids"])
    shuffled_order = list(natural_order)
    random.Random(seed).shuffle(shuffled_order)
    if shuffled_order == natural_order:
        shuffled_order = natural_order[1:] + natural_order[:1]

    temp_kwargs: dict[str, Any] = {"prefix": "s2-longmem-"}
    if Path("/private/tmp").is_dir():
        temp_kwargs["dir"] = "/private/tmp"
    with tempfile.TemporaryDirectory(**temp_kwargs) as temporary:
        workspace = Path(temporary).resolve()
        workspace.chmod(0o700)
        baseline_root = workspace / "baseline"
        randomized_root = workspace / "randomized"

        baseline = _populate_store(
            baseline_root,
            payload,
            trajectory_order=None,
            adapter_factory=_bound_adapter_factory,
        )
        backend = baseline["backend"]
        adapter = baseline["adapter"]
        populate_record = baseline["populate_record"]
        purity_runs: dict[str, dict[str, Any]] = {}
        try:
            before = retrieval_measurement.runtime_digest(backend)
            tracemalloc.start()
            baseline_run = _run_query_set(
                backend, adapter, corpus, latency_samples=latency_samples, timer=timer
            )
            _, peak_tracemalloc = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            after = retrieval_measurement.runtime_digest(backend)
            purity_runs["baseline"] = {
                "before": before,
                "after": after,
                "unchanged": before == after,
            }

            question_evidence = [
                evaluation.evaluate_question(
                    question,
                    baseline_run["results"][str(question["question_id"])],
                    index,
                    populate_record,
                    adapter,
                    baseline_run["latency_by_question"][str(question["question_id"])],
                    provider_label=str(payload["backend"]["embedding_provider"]),
                )
                for question in corpus["questions"]
            ]
            baseline_projection = evaluation.canonical_result_projection(
                corpus, index, baseline_run["results"], populate_record["memory_ids"]
            )
            baseline_projection_digest = evaluation.digest_value(baseline_projection)

            repeat_run = _run_query_set(
                backend, adapter, corpus, latency_samples=1, timer=timer
            )
            repeated_equal = repeat_run["raw_digest"] == baseline_run["raw_digest"]

            db_path = Path(backend.memory_store.db_path)
            deleted_residue = []
            logical_total = 0
            surface_total = 0
            for deleted in populate_record["deleted"]:
                counts = _logical_deletion_residue(db_path, str(deleted["memory_id"]))
                surface = counts.pop("memory_surface_terms")
                deleted_residue.append(
                    {
                        "turn_id": deleted["turn_id"],
                        "memory_id": deleted["memory_id"],
                        "media_id": deleted["media_id"],
                        "logical_counts": counts,
                        "logical_total": sum(counts.values()),
                        "surface_count": surface,
                    }
                )
                logical_total += sum(counts.values())
                surface_total += surface

            deleted_markers = sorted(
                {str(item["memory_id"]) for item in populate_record["deleted"]}
                | {
                    str(item["media_id"])
                    for item in populate_record["deleted"]
                    if item["media_id"]
                }
            )
            binding = _binding(baseline_root)
            recovery_probe = _filesystem_residue_probe(
                Path(binding.recovery_root), deleted_markers, scope=RECOVERY_PROBE_SCOPE
            )
            replication_probe = _filesystem_residue_probe(
                Path(binding.replication_inbox_root).parent,
                deleted_markers,
                scope=REPLICATION_PROBE_SCOPE,
            )
            media_audit = baseline["media"]
            final_audit = media_audit["final_audit"]
            media_residue_count = (
                int(final_audit.get("orphan_count") or 0)
                + int(final_audit.get("missing_count") or 0)
                + int(final_audit.get("corrupt_count") or 0)
                + abs(
                    int(final_audit.get("stored_count") or 0)
                    - int(media_audit["expected_stored_count"])
                )
            )
        finally:
            backend.memory_store.close()

        fresh_backend = _construct_backend(_data_root(baseline_root), payload)
        fresh_adapter = _bound_adapter_factory(fresh_backend)
        try:
            fresh_before = retrieval_measurement.runtime_digest(fresh_backend)
            fresh_run = _run_query_set(
                fresh_backend, fresh_adapter, corpus, latency_samples=1, timer=timer
            )
            fresh_after = retrieval_measurement.runtime_digest(fresh_backend)
            purity_runs["fresh_backend"] = {
                "before": fresh_before,
                "after": fresh_after,
                "unchanged": fresh_before == fresh_after,
            }
            fresh_projection_digest = evaluation.digest_value(
                evaluation.canonical_result_projection(
                    corpus, index, fresh_run["results"], populate_record["memory_ids"]
                )
            )
        finally:
            fresh_backend.memory_store.close()

        randomized = _populate_store(
            randomized_root,
            payload,
            trajectory_order=shuffled_order,
            adapter_factory=_bound_adapter_factory,
        )
        try:
            if randomized["populate_record"]["memory_ids"] != populate_record["memory_ids"]:
                raise MeasurementError(
                    "memory identity was not stable under shuffled trajectory insertion"
                )
            random_before = retrieval_measurement.runtime_digest(randomized["backend"])
            random_run = _run_query_set(
                randomized["backend"],
                randomized["adapter"],
                corpus,
                latency_samples=1,
                timer=timer,
            )
            random_after = retrieval_measurement.runtime_digest(randomized["backend"])
            purity_runs["randomized"] = {
                "before": random_before,
                "after": random_after,
                "unchanged": random_before == random_after,
            }
            random_projection_digest = evaluation.digest_value(
                evaluation.canonical_result_projection(
                    corpus,
                    index,
                    random_run["results"],
                    randomized["populate_record"]["memory_ids"],
                )
            )
        finally:
            randomized["backend"].memory_store.close()

    determinism = {
        "baseline_digest": baseline_projection_digest,
        "fresh_backend_digest": fresh_projection_digest,
        "randomized_insertion_digest": random_projection_digest,
        "canonical_digest_all_equal": len(
            {baseline_projection_digest, fresh_projection_digest, random_projection_digest}
        )
        == 1,
        "fresh_backend_raw_equal": fresh_run["raw_digest"] == baseline_run["raw_digest"],
        "randomized_insertion_raw_equal": random_run["raw_digest"] == baseline_run["raw_digest"],
        "repeated_same_backend_raw_equal": repeated_equal,
        "trajectory_order_baseline": natural_order,
        "trajectory_order_randomized": shuffled_order,
        "random_seed": seed,
    }
    purity = {
        "all_runs_unchanged": all(run["unchanged"] for run in purity_runs.values()),
        "runs": purity_runs,
    }
    residue = {
        "deleted": deleted_residue,
        "logical_total": logical_total,
        "surface_total": surface_total,
        "media": {**media_audit, "media_residue_count": media_residue_count},
        "recovery": recovery_probe,
        "replication": replication_probe,
    }
    all_latencies = [
        sample
        for samples in baseline_run["latency_by_question"].values()
        for sample in samples
    ]
    scope_disclosure = (
        f"{notice} This report is not an official LongMemEval-V2 score."
    )
    # Execution provenance is attested only for the built-in audited adapter.
    # An injected test adapter runs arbitrary code, so the harness refuses to
    # claim offline/live-database/network/LLM provenance on its behalf.
    if adapter_injected:
        execution_claims: dict[str, Any] = {
            "adapter_audited": False,
            "offline": None,
            "temporary_store": None,
            "live_database_opened": None,
            "network_used": None,
            "llm_used": None,
            "provenance": (
                "unverified: injected test adapter; no offline/live/network "
                "claims are made for this run"
            ),
        }
    else:
        execution_claims = {
            "adapter_audited": True,
            "offline": True,
            "temporary_store": True,
            "live_database_opened": False,
            "network_used": False,
            "llm_used": False,
            "provenance": "attested by the built-in audited adapter path",
        }
    aggregate = evaluation.aggregate_questions(question_evidence)
    aggregate.update(
        {
            "verdict": "pending",
            "determinism": determinism,
            "purity": purity,
            "residue": residue,
            "latency_ms": {
                "samples": len(all_latencies),
                "p50": evaluation.nearest_rank_percentile(all_latencies, 0.5),
                "p95": evaluation.nearest_rank_percentile(all_latencies, 0.95),
                "informational_only": True,
                "excluded_from_acceptance": True,
            },
            "memory": {
                "peak_tracemalloc_bytes": int(peak_tracemalloc),
                "phase": "baseline query set",
                "informational_only": True,
                "excluded_from_acceptance": True,
            },
            "execution": dict(execution_claims),
            "claims": {
                "official_score_claimed": False,
                "reader": None,
                "judge": None,
                "scope_disclosure": scope_disclosure,
            },
        }
    )
    acceptance = acceptance_verdict(aggregate, payload["thresholds"])
    aggregate["verdict"] = acceptance["verdict"]

    report = {
        "schema": REPORT_SCHEMA,
        "version": REPORT_VERSION,
        "status": "pass" if acceptance["accepted"] else "fail",
        "mode": mode,
        "official_score_claimed": False,
        "official_contract": evaluation.OFFICIAL_CONTRACT,
        "claim_notice": scope_disclosure,
        "run_identity": {
            "offline": execution_claims["offline"],
            "temporary_store": execution_claims["temporary_store"],
            "live_database_opened": execution_claims["live_database_opened"],
            "network_used": execution_claims["network_used"],
            "llm_used": execution_claims["llm_used"],
            "execution_provenance": execution_claims["provenance"],
            "reader": None,
            "judge": None,
            "embedding_provider": str(payload["backend"]["embedding_provider"]),
            "code_commit": commit,
            "source_kind": source_kind,
            "adapter": {
                "label": str(getattr(adapter, "label", "unknown")),
                "protocol": str(getattr(adapter, "protocol", "unknown")),
                "builtin": not adapter_injected,
                "identity": f"{type(adapter).__module__}.{type(adapter).__qualname__}",
                "source_sha256": None if adapter_injected else adapter_source_sha256(),
                "injected_ablation_adapter": adapter_injected,
            },
            "dataset_pins": dataset_pins,
        },
        "methodology": {
            "insert_contract": "trajectories inserted sequentially per session turn order",
            "query_contract": "compact text/image evidence via retrieve_text_v2",
            "grading": "deterministic fixture judgments; no reader or judge model",
            "determinism_matrix": [
                "repeated queries on the same backend",
                "fresh backend over the same store",
                "fresh store populated in seeded-shuffled trajectory order",
            ],
            "purity": "runtime digests before/after every query phase with mutation tripwires",
            "residue": [
                "logical five-table read-only counts per deleted memory",
                "surface-term counts per deleted memory",
                "media capture audits plus orphan prune",
                recovery_probe["scope"],
                replication_probe["scope"],
            ],
            "latency": "p50/p95 informational only",
            "memory": "tracemalloc peak during baseline query set, informational only",
            "token_estimator": evaluation.TOKEN_ESTIMATOR,
        },
        "population": evaluation.population_summary(corpus, index),
        "thresholds": payload["thresholds"],
        "per_question": question_evidence,
        "aggregate": aggregate,
        "acceptance": acceptance,
        "limitations": [
            scope_disclosure,
            "The official corpus tiers (100/500 trajectories, 451 questions) were "
            "not used unless the operator supplied them locally, and even then no "
            "official reader/judge accuracy is produced.",
            "Deletion evidence is logical and node-local: SQL rows, surface terms, "
            "media artifacts, and disposable recovery/replication roots for this "
            "run's store only.",
            "Recovery and replication residue probes are net-new filesystem probes "
            "introduced by this lane, not audits of any production pipeline; a "
            "probe whose root was never created is unexercised and informational, "
            "not a zero-residue pass.",
            "Premise-awareness and abstention gates grade the deterministic "
            "evidence decision (abstain with zero marker-bearing support within "
            "result_limit); no reader model runs, so they demonstrate evidence "
            "hygiene and decision consistency, not reader-level premise awareness.",
            "Injected test adapters are a library-only seam restricted to "
            "synapse-derived mode; runs using one carry no offline/live/network "
            "execution provenance claims.",
            "Latency and peak-memory figures are informational only and depend on "
            "host load.",
        ],
    }
    canonical_json_bytes(report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Offline LongMemEval-V2-derived acceptance measurement. Prints one "
            "canonical JSON report to stdout; no file output option exists."
        )
    )
    parser.add_argument(
        "--mode",
        choices=MODES + tuple(DEPRECATED_MODE_ALIASES),
        default="synapse-derived",
    )
    parser.add_argument("--fixture", type=Path, default=None)
    parser.add_argument("--dataset-path", type=Path, default=None)
    parser.add_argument("--dataset-sha256", default=None)
    parser.add_argument("--dataset-version", default=None)
    parser.add_argument("--adapter-sha256", default=None)
    parser.add_argument("--code-commit", default=None)
    parser.add_argument("--latency-samples", type=int, default=3)
    options = parser.parse_args(argv)
    try:
        report = run_measurement(
            mode=options.mode,
            fixture_path=options.fixture,
            dataset_path=options.dataset_path,
            dataset_sha256=options.dataset_sha256,
            dataset_version=options.dataset_version,
            adapter_sha256=options.adapter_sha256,
            code_commit=options.code_commit,
            latency_samples=options.latency_samples,
        )
    except MeasurementError as error:
        sys.stdout.write(
            canonical_json_bytes(
                {
                    "schema": REPORT_SCHEMA,
                    "version": REPORT_VERSION,
                    "status": "error",
                    "official_score_claimed": False,
                    "error": str(error),
                }
            ).decode("utf-8")
            + "\n"
        )
        return 2
    sys.stdout.write(canonical_json_bytes(report).decode("utf-8") + "\n")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

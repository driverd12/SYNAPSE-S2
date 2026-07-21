#!/usr/bin/env python3
"""Run the deterministic, offline SYNAPSE-S2 Retrieval v2 acceptance fixture.

This measurement intentionally creates disposable stores and uses the local
``semantic-hash`` embedding provider.  It never opens the operator's live
memory database.  The fixture is synthetic: a passing verdict proves the
specified contracts against this corpus, not retrieval quality on live data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import sqlite3
import stat
import sys
import tempfile
import time
from collections import Counter, defaultdict
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable, Iterable
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
while str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

import memory_store as _memory_store_module  # noqa: E402
from mlx_backend import SpikingAttentionBackend  # noqa: E402


REPORT_SCHEMA = "synapse-s2.retrieval-v2-acceptance.v1"
REPORT_VERSION = 1
FIXTURE_SCHEMA = "synapse-s2.retrieval-v2-fixture.v1"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "retrieval_v2" / "benchmark_v1.json"
SYNTHETIC_NOTICE = (
    "This deterministic synthetic benchmark does not prove retrieval quality "
    "on the live SYNAPSE-S2 corpus."
)
MAX_LATENCY_SAMPLES = 50
REQUIRED_CATEGORIES = frozenset(
    {
        "local",
        "approved-connected",
        "unrelated",
        "distractor",
        "sparse",
        "dense",
        "duplicate",
        "near-duplicate",
        "tie",
    }
)
_OPTIONAL_IDENTITY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-/"
)


class MeasurementError(RuntimeError):
    """The fixture or measurement cannot establish its claimed invariants."""


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize one value using the report's stable JSON wire format."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MeasurementError("measurement contains non-canonical JSON") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bounded_identity(value: str | None, *, field: str) -> str | None:
    if value is None or not str(value).strip():
        return None
    clean = str(value).strip()
    if len(clean) > 160 or any(char not in _OPTIONAL_IDENTITY_CHARS for char in clean):
        raise MeasurementError(f"{field} must be a bounded public identifier")
    return clean


def load_fixture(path: Path = FIXTURE_PATH) -> dict[str, Any]:
    """Load and structurally validate the fixed benchmark fixture."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MeasurementError("retrieval fixture is unreadable") from exc
    if not isinstance(payload, dict):
        raise MeasurementError("retrieval fixture must be a JSON object")
    if payload.get("schema") != FIXTURE_SCHEMA or payload.get("version") != 1:
        raise MeasurementError("retrieval fixture schema or version is unsupported")
    documents = payload.get("documents")
    queries = payload.get("queries")
    thresholds = payload.get("thresholds")
    if not isinstance(documents, list) or not documents:
        raise MeasurementError("retrieval fixture must contain documents")
    if not isinstance(queries, list) or not queries:
        raise MeasurementError("retrieval fixture must contain queries")
    if not isinstance(thresholds, dict):
        raise MeasurementError("retrieval fixture must contain thresholds")

    document_by_id: dict[str, dict[str, Any]] = {}
    context_tags: set[tuple[str, str]] = set()
    contexts: set[str] = set()
    categories: set[str] = set()
    grouped: dict[str, dict[str, list[str]]] = {
        "duplicate_group": defaultdict(list),
        "near_duplicate_group": defaultdict(list),
        "tie_group": defaultdict(list),
    }
    for raw in documents:
        if not isinstance(raw, dict):
            raise MeasurementError("fixture document must be an object")
        document_id = str(raw.get("document_id") or "").strip()
        context_id = str(raw.get("context_id") or "").strip()
        tag = str(raw.get("tag") or "").strip()
        text = str(raw.get("text") or "").strip()
        label = str(raw.get("label") or "").strip()
        raw_categories = raw.get("categories")
        if not all((document_id, context_id, tag, text, label)):
            raise MeasurementError("fixture document has a required blank field")
        if document_id in document_by_id:
            raise MeasurementError("fixture document_id values must be unique")
        if (context_id, tag) in context_tags:
            raise MeasurementError("fixture context/tag pairs must be unique")
        if not isinstance(raw_categories, list) or not raw_categories:
            raise MeasurementError("fixture document categories are required")
        clean_categories = {str(value) for value in raw_categories}
        document_by_id[document_id] = raw
        context_tags.add((context_id, tag))
        contexts.add(context_id)
        categories.update(clean_categories)
        for field in grouped:
            group = str(raw.get(field) or "").strip()
            if group:
                grouped[field][group].append(document_id)
    if len(contexts) < 3:
        raise MeasurementError("retrieval fixture must span at least three namespaces")
    missing_categories = sorted(REQUIRED_CATEGORIES - categories)
    if missing_categories:
        raise MeasurementError(
            "retrieval fixture lacks required categories: " + ", ".join(missing_categories)
        )
    for field, groups in grouped.items():
        if not groups or not any(len(values) >= 2 for values in groups.values()):
            raise MeasurementError(f"retrieval fixture requires a multi-item {field}")

    query_ids: set[str] = set()
    observed_scopes: set[str] = set()
    for raw in queries:
        if not isinstance(raw, dict):
            raise MeasurementError("fixture query must be an object")
        query_id = str(raw.get("query_id") or "").strip()
        context_id = str(raw.get("context_id") or "").strip()
        prompt = str(raw.get("prompt") or "").strip()
        scope = str(raw.get("recall_scope") or "").strip()
        allowed = raw.get("allowed_contexts")
        judgments = raw.get("judgments")
        if not query_id or query_id in query_ids or not prompt or context_id not in contexts:
            raise MeasurementError("fixture query identity is invalid or duplicated")
        if scope not in {"local", "connected", "all"}:
            raise MeasurementError("fixture query recall_scope is invalid")
        if not isinstance(allowed, list) or context_id not in allowed:
            raise MeasurementError("fixture query allowed_contexts are invalid")
        if any(str(value) not in contexts for value in allowed):
            raise MeasurementError("fixture query references an unknown allowed context")
        if not isinstance(judgments, dict) or not judgments:
            raise MeasurementError("fixture query judgments are required")
        for document_id, grade in judgments.items():
            document = document_by_id.get(str(document_id))
            if document is None:
                raise MeasurementError("fixture judgment references an unknown document")
            if type(grade) is not int or grade < 1 or grade > 3:
                raise MeasurementError("fixture relevance grades must be integers from 1 to 3")
            if document["context_id"] not in allowed:
                raise MeasurementError("relevant fixture document is outside its allowed scope")
        for field in ("result_limit", "candidate_limit"):
            if type(raw.get(field)) is not int or int(raw[field]) <= 0:
                raise MeasurementError(f"fixture query {field} must be a positive integer")
        if type(raw.get("include_graph_neighbors")) is not bool:
            raise MeasurementError("include_graph_neighbors must be a boolean")
        query_ids.add(query_id)
        observed_scopes.add(scope)
    if "local" not in observed_scopes or "connected" not in observed_scopes:
        raise MeasurementError("fixture must exercise local and approved-connected recall")

    for link in payload.get("context_links", []):
        if not isinstance(link, dict):
            raise MeasurementError("fixture context link must be an object")
        if str(link.get("source_context_id")) not in contexts or str(
            link.get("target_context_id")
        ) not in contexts:
            raise MeasurementError("fixture context link references an unknown namespace")
        if link.get("enabled") is not True:
            raise MeasurementError("fixture approved context links must be enabled")
    for relationship in payload.get("relationships", []):
        if not isinstance(relationship, dict):
            raise MeasurementError("fixture relationship must be an object")
        source = document_by_id.get(str(relationship.get("source_document_id")))
        target = document_by_id.get(str(relationship.get("target_document_id")))
        context_id = str(relationship.get("context_id") or "")
        if source is None or target is None:
            raise MeasurementError("fixture relationship references an unknown document")
        if source["context_id"] != context_id or target["context_id"] != context_id:
            raise MeasurementError("fixture relationship must stay inside one namespace")

    required_thresholds = {
        "macro_recall_at_k_min",
        "macro_ndcg_at_k_min",
        "macro_mrr_min",
        "per_query_recall_at_k_min",
        "per_query_ndcg_at_k_min",
        "per_query_mrr_min",
        "namespace_leakage_rate_max",
        "duplicate_rate_max",
        "near_duplicate_collision_rate_max",
        "required_positive_signals",
    }
    if not required_thresholds.issubset(thresholds):
        raise MeasurementError("retrieval fixture is missing acceptance thresholds")
    for field in required_thresholds - {"required_positive_signals"}:
        value = thresholds[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise MeasurementError(f"fixture threshold {field} must be numeric")
        if not math.isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
            raise MeasurementError(f"fixture threshold {field} must be within [0, 1]")
    required_signals = thresholds["required_positive_signals"]
    if not isinstance(required_signals, list) or not required_signals:
        raise MeasurementError("fixture required_positive_signals must be non-empty")
    allowed_signals = {"spike_index", "surface_index", "same_context_graph"}
    if any(str(value) not in allowed_signals for value in required_signals):
        raise MeasurementError("fixture names an unsupported score component")
    return payload


def _make_backend(root: Path, fixture: dict[str, Any]) -> SpikingAttentionBackend:
    config = fixture["backend"]
    return SpikingAttentionBackend(
        dimension=int(config["dimension"]),
        num_neurons=int(config["num_neurons"]),
        default_top_k=int(config["default_top_k"]),
        recall_count=int(config["recall_count"]),
        compile_graph=False,
        state_path=root / "runtime_state.json",
        embedding_provider_name=str(config["embedding_provider"]),
    )


def _active_indices(spikes: Any) -> list[int]:
    values = spikes.tolist() if hasattr(spikes, "tolist") else list(spikes)
    return [index for index, value in enumerate(values) if float(value) > 0.0]


def populate_fixture(
    backend: SpikingAttentionBackend,
    fixture: dict[str, Any],
    *,
    document_order: Iterable[str] | None = None,
) -> dict[str, str]:
    """Populate one disposable store with fixture-controlled timestamps."""

    documents = {str(item["document_id"]): item for item in fixture["documents"]}
    ordered_ids = list(documents if document_order is None else document_order)
    if set(ordered_ids) != set(documents) or len(ordered_ids) != len(documents):
        raise MeasurementError("document_order must contain every fixture document once")
    fixed_epoch = float(fixture["fixed_epoch"])
    ordinal = {document_id: index for index, document_id in enumerate(sorted(documents))}
    memory_ids: dict[str, str] = {}
    for document_id in ordered_ids:
        document = documents[document_id]
        embedding = backend.embed_text(str(document.get("embedding_prompt") or document["text"]))
        spikes = backend.encode_to_spikes_top_k(embedding)
        categories = [str(value) for value in document["categories"]]
        metadata = {
            "display_label": str(document["label"]),
            "display_summary": str(document["text"]),
            "display_excerpt": str(document["text"]),
            "facets": categories,
            "source": "retrieval-v2-synthetic-fixture",
            "benchmark_document_id": document_id,
        }
        fixed_time_group = str(document.get("fixed_time_group") or "").strip()
        timestamp = (
            fixed_epoch + 500.0
            if fixed_time_group
            else fixed_epoch + float(ordinal[document_id])
        )
        with patch.object(_memory_store_module.time, "time", return_value=timestamp):
            entry = backend.memory_store.upsert_entry(
                tag=str(document["tag"]),
                context_id=str(document["context_id"]),
                source_text=str(document["text"]),
                metadata=metadata,
                embedding_dimensions=int(fixture["backend"]["dimension"]),
                spike_indices=_active_indices(spikes),
                neuron_indices=[],
                registered_at=timestamp,
            )
        memory_ids[document_id] = str(entry["memory_id"])

    for index, link in enumerate(fixture.get("context_links", [])):
        timestamp = fixed_epoch + 1_000.0 + index
        with patch.object(_memory_store_module.time, "time", return_value=timestamp):
            backend.memory_store.upsert_context_link(
                source_context_id=str(link["source_context_id"]),
                target_context_id=str(link["target_context_id"]),
                relation_type=str(link["relation_type"]),
                direction=str(link["direction"]),
                confidence=float(link["confidence"]),
                evidence={
                    "method": "retrieval-v2-synthetic-fixture",
                    "fixture_schema": FIXTURE_SCHEMA,
                },
                approved_by=str(link["approved_by"]),
                approved_at=timestamp,
                enabled=True,
            )
    for index, relationship in enumerate(fixture.get("relationships", [])):
        timestamp = fixed_epoch + 2_000.0 + index
        with patch.object(_memory_store_module.time, "time", return_value=timestamp):
            backend.memory_store.upsert_relationship(
                context_id=str(relationship["context_id"]),
                source_memory_id=memory_ids[str(relationship["source_document_id"])],
                target_memory_id=memory_ids[str(relationship["target_document_id"])],
                relation_type=str(relationship["relation_type"]),
                weight=float(relationship["weight"]),
                evidence={"method": "retrieval-v2-synthetic-fixture"},
            )
    return memory_ids


def _file_fingerprint(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"present": False, "bytes": 0, "sha256": _sha256_bytes(b"")}
    data = path.read_bytes()
    return {"present": True, "bytes": len(data), "sha256": _sha256_bytes(data)}


def _logical_database_digest(path: Path) -> str:
    """Hash every user-table row independent of SQLite's physical page order."""

    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        table_names = [
            str(row[0])
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name ASC
                """
            ).fetchall()
        ]
        tables: list[dict[str, Any]] = []
        for table_name in table_names:
            quoted = '"' + table_name.replace('"', '""') + '"'
            columns = [
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({quoted})").fetchall()
            ]
            row_digests: list[str] = []
            for row in connection.execute(f"SELECT * FROM {quoted}").fetchall():
                values: list[Any] = []
                for value in row:
                    if isinstance(value, bytes):
                        values.append({"blob_sha256": _sha256_bytes(value), "bytes": len(value)})
                    else:
                        values.append(value)
                row_digests.append(_digest(values))
            tables.append(
                {
                    "table": table_name,
                    "columns": columns,
                    "row_count": len(row_digests),
                    "row_digests": sorted(row_digests),
                }
            )
        return _digest(tables)
    finally:
        connection.close()


def runtime_digest(backend: SpikingAttentionBackend) -> dict[str, Any]:
    """Fingerprint runtime arrays, state file, and durable SQLite material."""

    def array_value(value: Any) -> Any:
        return None if value is None else value.tolist()

    neural = {
        "dimension": int(backend.dimension),
        "w_syn": array_value(backend.W_syn),
        "w_lateral": array_value(backend.W_lateral),
        "mem": array_value(backend.state["mem"]),
        "spk": array_value(backend.state["spk"]),
        "active_traces": array_value(backend.active_traces),
        "global_enabled": bool(backend.global_enabled),
        "context_overrides": backend.context_overrides,
        "registered_traces": backend.registered_traces,
        "surface_cache": backend._surface_recall_cache,
        "quick_pruning_count": int(backend.quick_pruning_count),
        "deep_sleep_count": int(backend.deep_sleep_count),
        "last_pruning_monotonic": float(backend.last_pruning_monotonic),
        "last_activity_monotonic": float(backend.last_activity_monotonic),
        "last_maintenance": backend.last_maintenance,
    }
    database = backend.memory_store.db_path
    # Read the logical database before fingerprinting its physical files.  Opening
    # a WAL-mode SQLite database read-only may materialize empty WAL/SHM
    # coordination files.  Settling that observer side effect first keeps the
    # before/after comparison honest without ignoring any subsequent byte-level
    # change made by retrieval itself.
    database_logical_sha256 = _logical_database_digest(database)
    database_files = {
        "sqlite3": _file_fingerprint(database),
        "wal": _file_fingerprint(Path(str(database) + "-wal")),
        "shm": _file_fingerprint(Path(str(database) + "-shm")),
        "journal": _file_fingerprint(Path(str(database) + "-journal")),
    }
    payload = {
        "neural_sha256": _digest(neural),
        "runtime_state": _file_fingerprint(backend.state_path),
        "database_files": database_files,
        "database_sha256": _digest(database_files),
        "database_logical_sha256": database_logical_sha256,
    }
    return {**payload, "combined_sha256": _digest(payload)}


def _query_call(backend: SpikingAttentionBackend, query: dict[str, Any]) -> dict[str, Any]:
    return backend.retrieve_text_v2(
        str(query["prompt"]),
        context_id=str(query["context_id"]),
        recall_scope=str(query["recall_scope"]),
        result_limit=int(query["result_limit"]),
        candidate_limit=int(query["candidate_limit"]),
        include_graph_neighbors=bool(query["include_graph_neighbors"]),
    )


def _run_query_set(
    backend: SpikingAttentionBackend,
    fixture: dict[str, Any],
    *,
    latency_samples: int,
    timer: Callable[[], int],
    measure_latency: bool,
) -> dict[str, Any]:
    results: dict[str, dict[str, Any]] = {}
    latency: dict[str, list[float]] = {}
    repeated_exact = True
    with ExitStack() as guards:
        for method_name in (
            "_auto_quick_prune_if_due",
            "run_snn_cycle",
            "_persist_runtime_state",
            "_mark_activity",
        ):
            guards.enter_context(
                patch.object(
                    backend,
                    method_name,
                    side_effect=MeasurementError(
                        f"Retrieval v2 reached forbidden mutator {method_name}"
                    ),
                )
            )
        for query in fixture["queries"]:
            query_id = str(query["query_id"])
            # The untimed warm call provides the evidence object and is excluded
            # from p50/p95. Timed calls must remain byte-identical to it.
            result = _query_call(backend, query)
            reference_bytes = canonical_json_bytes(result)
            samples: list[float] = []
            if measure_latency:
                for _sample in range(latency_samples):
                    started = timer()
                    observed = _query_call(backend, query)
                    elapsed = max(0, timer() - started) / 1_000_000.0
                    samples.append(elapsed)
                    if canonical_json_bytes(observed) != reference_bytes:
                        repeated_exact = False
            results[query_id] = result
            latency[query_id] = samples
    return {
        "results": results,
        "latency_ms": latency,
        "repeated_exact": repeated_exact,
        "raw_digest": _digest([results[str(query["query_id"])] for query in fixture["queries"]]),
    }


def _stable_context_link(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    keys = (
        "context_link_id",
        "source_context_id",
        "target_context_id",
        "relation_type",
        "direction",
        "confidence",
        "enabled",
        "approved_by",
    )
    return {key: value.get(key) for key in keys}


def canonical_result_projection(
    fixture: dict[str, Any],
    query_results: dict[str, dict[str, Any]],
    memory_ids: dict[str, str],
) -> dict[str, Any]:
    """Project retrieval semantics while excluding latency and volatile storage times."""

    document_by_memory = {memory_id: document_id for document_id, memory_id in memory_ids.items()}
    projected_queries: list[dict[str, Any]] = []
    for query in fixture["queries"]:
        query_id = str(query["query_id"])
        result = query_results[query_id]
        projected_items: list[dict[str, Any]] = []
        for item in result.get("items", []):
            breakdown = item.get("score_breakdown", {})
            scope = item.get("scope_provenance", {})
            confidence = item.get("confidence", {})
            projected_items.append(
                {
                    "rank": item.get("rank"),
                    "memory_id": item.get("memory_id"),
                    "document_id": document_by_memory.get(str(item.get("memory_id"))),
                    "context_id": item.get("context_id"),
                    "tag": item.get("tag"),
                    "label": item.get("label"),
                    "score": item.get("score"),
                    "signals": breakdown.get("signals"),
                    "contributions": breakdown.get("contributions"),
                    "diversity": breakdown.get("diversity"),
                    "confidence": {
                        "calibrated": confidence.get("calibrated"),
                        "probability": confidence.get("probability"),
                        "signal": confidence.get("signal"),
                    },
                    "scope": {
                        "origin_context_id": scope.get("origin_context_id"),
                        "resolved_context_id": scope.get("resolved_context_id"),
                        "context_link": _stable_context_link(scope.get("context_link")),
                    },
                    "graph_provenance": [
                        {
                            key: edge.get(key)
                            for key in (
                                "relationship_id",
                                "anchor_memory_id",
                                "neighbor_memory_id",
                                "context_id",
                                "relation_type",
                                "weight",
                                "signal",
                            )
                        }
                        for edge in item.get("graph_provenance", [])
                    ],
                }
            )
        projected_queries.append(
            {
                "query_id": query_id,
                "query": {
                    "fingerprint_sha256": result.get("query", {}).get("fingerprint_sha256"),
                    "context_id": result.get("query", {}).get("context_id"),
                    "recall_scope": result.get("query", {}).get("recall_scope"),
                },
                "ranker": result.get("ranker"),
                "items": projected_items,
                "completeness": result.get("completeness"),
            }
        )
    return {
        "schema": REPORT_SCHEMA,
        "fixture_sha256": _digest(fixture),
        "queries": projected_queries,
    }


def _dcg(grades: list[int]) -> float:
    return sum((2**grade - 1) / math.log2(index + 2) for index, grade in enumerate(grades))


def _nearest_rank_percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return round(ordered[rank - 1], 6)


def _size_summary(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": 0, "p50": 0, "p95": 0, "max": 0}
    ordered = sorted(values)
    return {
        "count": len(ordered),
        "min": ordered[0],
        "p50": _nearest_rank_percentile([float(value) for value in ordered], 0.5),
        "p95": _nearest_rank_percentile([float(value) for value in ordered], 0.95),
        "max": ordered[-1],
    }


def evaluate_query(
    query: dict[str, Any],
    result: dict[str, Any],
    fixture: dict[str, Any],
    memory_ids: dict[str, str],
    latency_ms: list[float],
) -> dict[str, Any]:
    document_by_id = {str(item["document_id"]): item for item in fixture["documents"]}
    document_by_memory = {memory_id: document_id for document_id, memory_id in memory_ids.items()}
    judgments = {str(key): int(value) for key, value in query["judgments"].items()}
    items = list(result.get("items", []))
    retrieved_document_ids = [
        document_by_memory.get(str(item.get("memory_id"))) for item in items
    ]
    retrieved_grades = [int(judgments.get(str(document_id), 0)) for document_id in retrieved_document_ids]
    relevant = {document_id for document_id, grade in judgments.items() if grade > 0}
    retrieved_relevant = {str(document_id) for document_id, grade in zip(retrieved_document_ids, retrieved_grades) if document_id and grade > 0}
    recall = len(retrieved_relevant) / max(1, len(relevant))
    ideal_grades = sorted(judgments.values(), reverse=True)[: int(query["result_limit"])]
    ideal_dcg = _dcg(ideal_grades)
    ndcg = _dcg(retrieved_grades) / ideal_dcg if ideal_dcg else 0.0
    reciprocal_rank = next(
        (1.0 / index for index, grade in enumerate(retrieved_grades, start=1) if grade > 0),
        0.0,
    )

    allowed_contexts = {str(value) for value in query["allowed_contexts"]}
    leakage = [
        {
            "rank": int(item.get("rank") or 0),
            "memory_id": str(item.get("memory_id") or ""),
            "context_id": str(item.get("context_id") or ""),
        }
        for item in items
        if str(item.get("context_id") or "") not in allowed_contexts
    ]
    memory_id_counts = Counter(str(item.get("memory_id") or "") for item in items)
    duplicate_id_count = sum(max(0, count - 1) for count in memory_id_counts.values())
    content_counts = Counter(
        _digest(
            {
                "context_id": item.get("context_id"),
                "label": " ".join(str(item.get("label") or "").casefold().split()),
                "summary": " ".join(str(item.get("summary") or "").casefold().split()),
                "excerpt": " ".join(str(item.get("excerpt") or "").casefold().split()),
            }
        )
        for item in items
    )
    duplicate_content_count = sum(max(0, count - 1) for count in content_counts.values())
    near_groups = Counter(
        str(document_by_id[str(document_id)].get("near_duplicate_group") or "")
        for document_id in retrieved_document_ids
        if document_id and document_by_id[str(document_id)].get("near_duplicate_group")
    )
    near_duplicate_collisions = sum(max(0, count - 1) for count in near_groups.values())

    component_counts = Counter()
    component_max: dict[str, float] = defaultdict(float)
    component_contributions: dict[str, float] = defaultdict(float)
    confidence_violations: list[dict[str, Any]] = []
    score_contract_violations: list[dict[str, Any]] = []
    scope_provenance_violations: list[dict[str, Any]] = []
    evidence_items: list[dict[str, Any]] = []
    ranker_weights = result.get("ranker", {}).get("weights", {})
    for item, document_id, grade in zip(items, retrieved_document_ids, retrieved_grades):
        breakdown = item.get("score_breakdown", {})
        signals = breakdown.get("signals", {})
        contributions = breakdown.get("contributions", {})
        numeric_signals: dict[str, float] = {}
        numeric_contributions: dict[str, float] = {}
        for signal_name in ("spike_index", "surface_index", "same_context_graph"):
            try:
                value = float(signals.get(signal_name, 0.0) or 0.0)
                contribution = float(contributions.get(signal_name, 0.0) or 0.0)
                weight = float(ranker_weights.get(signal_name))
            except (TypeError, ValueError, OverflowError):
                value = 0.0
                contribution = 0.0
                weight = math.nan
                score_contract_violations.append(
                    {
                        "rank": item.get("rank"),
                        "memory_id": item.get("memory_id"),
                        "reason": f"non-numeric-{signal_name}",
                    }
                )
            if (
                not math.isfinite(value)
                or not math.isfinite(contribution)
                or not math.isfinite(weight)
                or not 0.0 <= value <= 1.0
                or not 0.0 <= weight <= 1.0
                or abs(contribution - value * weight) > 1e-7
            ):
                score_contract_violations.append(
                    {
                        "rank": item.get("rank"),
                        "memory_id": item.get("memory_id"),
                        "reason": f"invalid-{signal_name}-algebra",
                    }
                )
            numeric_signals[signal_name] = value
            numeric_contributions[signal_name] = contribution
            if value > 0.0:
                component_counts[signal_name] += 1
            component_max[signal_name] = max(component_max[signal_name], value)
            component_contributions[signal_name] += contribution
        try:
            relevance_score = float(breakdown.get("relevance_score"))
            item_score = float(item.get("score"))
        except (TypeError, ValueError, OverflowError):
            relevance_score = math.nan
            item_score = math.nan
        if (
            not math.isfinite(relevance_score)
            or not math.isfinite(item_score)
            or abs(relevance_score - sum(numeric_contributions.values())) > 1e-7
            or abs(item_score - relevance_score) > 1e-8
            or (item_score > 0.0 and not item.get("match_reasons"))
        ):
            score_contract_violations.append(
                {
                    "rank": item.get("rank"),
                    "memory_id": item.get("memory_id"),
                    "reason": "invalid-relevance-or-reason-contract",
                }
            )
        confidence = item.get("confidence", {})
        if confidence.get("calibrated") is not False or confidence.get("probability") is not None:
            confidence_violations.append(
                {
                    "rank": item.get("rank"),
                    "memory_id": item.get("memory_id"),
                    "calibrated": confidence.get("calibrated"),
                    "probability": confidence.get("probability"),
                }
            )
        scope = item.get("scope_provenance", {})
        item_context = str(item.get("context_id") or "")
        origin_context = str(scope.get("origin_context_id") or "")
        resolved_context = str(scope.get("resolved_context_id") or "")
        link = scope.get("context_link")
        scope_valid = origin_context == str(query["context_id"]) and resolved_context == item_context
        if item_context == str(query["context_id"]):
            scope_valid = scope_valid and link is None
        else:
            if not isinstance(link, dict) or link.get("enabled") is not True:
                scope_valid = False
            else:
                source_context = str(link.get("source_context_id") or "")
                target_context = str(link.get("target_context_id") or "")
                direction = str(link.get("direction") or "")
                scope_valid = scope_valid and (
                    (
                        direction == "directed"
                        and source_context == str(query["context_id"])
                        and target_context == item_context
                    )
                    or (
                        direction == "bidirectional"
                        and {source_context, target_context}
                        == {str(query["context_id"]), item_context}
                    )
                )
        if not scope_valid:
            scope_provenance_violations.append(
                {
                    "rank": item.get("rank"),
                    "memory_id": item.get("memory_id"),
                    "context_id": item_context,
                    "reason": "scope-provenance-does-not-authorize-result",
                }
            )
        evidence_items.append(
            {
                "rank": int(item.get("rank") or 0),
                "memory_id": str(item.get("memory_id") or ""),
                "document_id": document_id,
                "context_id": str(item.get("context_id") or ""),
                "label": str(item.get("label") or ""),
                "relevance_grade": grade,
                "score": float(item.get("score") or 0.0),
                "signals": signals,
                "contributions": contributions,
                "confidence": {
                    "calibrated": confidence.get("calibrated"),
                    "probability": confidence.get("probability"),
                    "signal": confidence.get("signal"),
                },
                "scope": {
                    "origin_context_id": scope.get("origin_context_id"),
                    "resolved_context_id": scope.get("resolved_context_id"),
                    "context_link": _stable_context_link(scope.get("context_link")),
                },
                "graph_relationship_ids": [
                    str(edge.get("relationship_id"))
                    for edge in item.get("graph_provenance", [])
                ],
            }
        )

    ranker_confidence = result.get("ranker", {}).get("confidence_semantics", {})
    if ranker_confidence.get("calibrated") is not False or ranker_confidence.get("probability") is not False:
        confidence_violations.append(
            {
                "rank": None,
                "memory_id": None,
                "calibrated": ranker_confidence.get("calibrated"),
                "probability": ranker_confidence.get("probability"),
            }
        )

    tie_violations: list[dict[str, Any]] = []
    tie_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item, document_id in zip(items, retrieved_document_ids):
        if not document_id:
            continue
        tie_group = str(document_by_id[str(document_id)].get("tie_group") or "")
        if tie_group:
            tie_groups[tie_group].append(item)
    for group, members in sorted(tie_groups.items()):
        by_score: dict[float, list[str]] = defaultdict(list)
        for item in members:
            by_score[float(item.get("score") or 0.0)].append(str(item.get("memory_id") or ""))
        for score, ids in sorted(by_score.items()):
            if len(ids) > 1 and ids != sorted(ids):
                tie_violations.append({"tie_group": group, "score": score, "memory_ids": ids})

    result_bytes = len(canonical_json_bytes(result))
    result_set_bytes = len(canonical_json_bytes(items))
    return {
        "query_id": str(query["query_id"]),
        "prompt": str(query["prompt"]),
        "context_id": str(query["context_id"]),
        "recall_scope": str(query["recall_scope"]),
        "k": int(query["result_limit"]),
        "candidate_limit": int(query["candidate_limit"]),
        "allowed_contexts": sorted(allowed_contexts),
        "judgments": [
            {
                "document_id": document_id,
                "memory_id": memory_ids[document_id],
                "grade": grade,
            }
            for document_id, grade in sorted(judgments.items())
        ],
        "retrieved": evidence_items,
        "metrics": {
            "recall_at_k": round(recall, 8),
            "ndcg_at_k": round(ndcg, 8),
            "mrr": round(reciprocal_rank, 8),
            "namespace_leakage_count": len(leakage),
            "namespace_leakage_rate": round(len(leakage) / max(1, len(items)), 8),
            "duplicate_memory_id_count": duplicate_id_count,
            "duplicate_content_count": duplicate_content_count,
            "duplicate_rate": round(duplicate_content_count / max(1, len(items)), 8),
            "near_duplicate_collision_count": near_duplicate_collisions,
            "near_duplicate_collision_rate": round(near_duplicate_collisions / max(1, len(items)), 8),
            "source_content_deduplications": int(
                result.get("work", {}).get("candidate_content_deduplications", 0) or 0
            ),
            "result_bytes": result_bytes,
            "result_set_bytes": result_set_bytes,
        },
        "scope_leakage": leakage,
        "confidence_violations": confidence_violations,
        "score_contract_violations": score_contract_violations,
        "scope_provenance_violations": scope_provenance_violations,
        "tie_ordering_violations": tie_violations,
        "component_signals": {
            "positive_item_count": {
                key: int(component_counts[key])
                for key in ("spike_index", "surface_index", "same_context_graph")
            },
            "maximum_signal": {
                key: round(component_max[key], 8)
                for key in ("spike_index", "surface_index", "same_context_graph")
            },
            "summed_contribution": {
                key: round(component_contributions[key], 8)
                for key in ("spike_index", "surface_index", "same_context_graph")
            },
        },
        "latency_ms": {
            "samples": len(latency_ms),
            "p50": _nearest_rank_percentile(latency_ms, 0.5),
            "p95": _nearest_rank_percentile(latency_ms, 0.95),
            "informational_only": True,
            "excluded_from_acceptance": True,
            "excluded_from_canonical_digest": True,
        },
        "bytes": {
            "result": result_bytes,
            "result_set": result_set_bytes,
            "serializer": "canonical-json-utf8",
        },
        "completeness": result.get("completeness", {}),
    }


def _population(fixture: dict[str, Any]) -> dict[str, Any]:
    documents = fixture["documents"]
    category_counts = Counter(
        str(category) for document in documents for category in document["categories"]
    )
    context_counts = Counter(str(document["context_id"]) for document in documents)
    return {
        "documents": len(documents),
        "queries": len(fixture["queries"]),
        "judgments": sum(len(query["judgments"]) for query in fixture["queries"]),
        "namespaces": len(context_counts),
        "documents_by_namespace": dict(sorted(context_counts.items())),
        "category_counts": dict(sorted(category_counts.items())),
        "approved_context_links": len(fixture.get("context_links", [])),
        "same_context_graph_relationships": len(fixture.get("relationships", [])),
    }


def acceptance_verdict(
    aggregate: dict[str, Any],
    thresholds: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate all fixture-grounded quality and safety gates."""

    metrics = aggregate["metrics"]
    per_query = aggregate["per_query_minimums"]
    determinism = aggregate["determinism"]
    purity = aggregate["purity"]
    components = aggregate["component_signal_coverage"]
    checks = [
        {
            "id": "fixture-recall-at-k",
            "passed": bool(
                metrics["macro_recall_at_k"] >= float(thresholds["macro_recall_at_k_min"])
                and per_query["recall_at_k"] >= float(thresholds["per_query_recall_at_k_min"])
            ),
        },
        {
            "id": "fixture-ndcg-at-k",
            "passed": bool(
                metrics["macro_ndcg_at_k"] >= float(thresholds["macro_ndcg_at_k_min"])
                and per_query["ndcg_at_k"] >= float(thresholds["per_query_ndcg_at_k_min"])
            ),
        },
        {
            "id": "fixture-mrr",
            "passed": bool(
                metrics["macro_mrr"] >= float(thresholds["macro_mrr_min"])
                and per_query["mrr"] >= float(thresholds["per_query_mrr_min"])
            ),
        },
        {
            "id": "namespace-scope-no-leakage",
            "passed": bool(
                metrics["namespace_leakage_rate"]
                <= float(thresholds["namespace_leakage_rate_max"])
                and metrics["namespace_leakage_count"] == 0
                and metrics["scope_provenance_violation_count"] == 0
            ),
        },
        {
            "id": "retrieval-is-pure",
            "passed": bool(purity["all_runs_unchanged"]),
        },
        {
            "id": "canonical-output-deterministic",
            "passed": bool(
                determinism["canonical_digest_all_equal"]
                and determinism["fresh_backend_raw_equal"]
                and determinism["repeated_same_backend_raw_equal"]
            ),
        },
        {
            "id": "duplicate-memory-ids-absent",
            "passed": metrics["duplicate_memory_id_count"] == 0,
        },
        {
            "id": "duplicate-content-rate",
            "passed": bool(
                metrics["duplicate_rate"] <= float(thresholds["duplicate_rate_max"])
                and metrics["source_content_deduplications"] > 0
            ),
        },
        {
            "id": "near-duplicate-collision-rate",
            "passed": bool(
                metrics["near_duplicate_collision_rate"]
                <= float(thresholds["near_duplicate_collision_rate_max"])
            ),
        },
        {
            "id": "confidence-remains-uncalibrated",
            "passed": metrics["confidence_violation_count"] == 0,
        },
        {
            "id": "stable-memory-id-tie-break",
            "passed": metrics["tie_ordering_violation_count"] == 0,
        },
        {
            "id": "score-component-signal-coverage",
            "passed": all(
                int(components.get(str(signal), 0)) > 0
                for signal in thresholds["required_positive_signals"]
            ),
        },
        {
            "id": "score-breakdown-contract-valid",
            "passed": metrics["score_contract_violation_count"] == 0,
        },
    ]
    failures = [str(check["id"]) for check in checks if not check["passed"]]
    return {
        "accepted": not failures,
        "verdict": "pass" if not failures else "fail",
        "checks": checks,
        "failure_codes": failures,
    }


def _aggregate_evidence(
    query_evidence: list[dict[str, Any]],
    *,
    baseline_run: dict[str, Any],
    fresh_run: dict[str, Any],
    shuffled_run: dict[str, Any],
    canonical_digests: dict[str, str],
    purity: dict[str, Any],
    shuffled_order_digest: str,
    random_seed: int,
) -> dict[str, Any]:
    query_count = max(1, len(query_evidence))
    totals = Counter()
    component_counts = Counter()
    all_latencies: list[float] = []
    result_bytes: list[int] = []
    result_set_bytes: list[int] = []
    for evidence in query_evidence:
        metrics = evidence["metrics"]
        totals["recall"] += float(metrics["recall_at_k"])
        totals["ndcg"] += float(metrics["ndcg_at_k"])
        totals["mrr"] += float(metrics["mrr"])
        totals["leakage"] += int(metrics["namespace_leakage_count"])
        totals["results"] += len(evidence["retrieved"])
        totals["duplicate_ids"] += int(metrics["duplicate_memory_id_count"])
        totals["duplicate_content"] += int(metrics["duplicate_content_count"])
        totals["source_deduplications"] += int(metrics["source_content_deduplications"])
        totals["near_duplicates"] += int(metrics["near_duplicate_collision_count"])
        totals["confidence"] += len(evidence["confidence_violations"])
        totals["score_contract"] += len(evidence["score_contract_violations"])
        totals["scope_provenance"] += len(evidence["scope_provenance_violations"])
        totals["tie"] += len(evidence["tie_ordering_violations"])
        result_bytes.append(int(metrics["result_bytes"]))
        result_set_bytes.append(int(metrics["result_set_bytes"]))
        for key, count in evidence["component_signals"]["positive_item_count"].items():
            component_counts[key] += int(count)
        # Latency samples remain out of per-query evidence by design; the
        # measured distributions are retained in baseline_run below.
    for samples in baseline_run["latency_ms"].values():
        all_latencies.extend(float(value) for value in samples)
    denominator = max(1, int(totals["results"]))
    metrics = {
        "macro_recall_at_k": round(totals["recall"] / query_count, 8),
        "macro_ndcg_at_k": round(totals["ndcg"] / query_count, 8),
        "macro_mrr": round(totals["mrr"] / query_count, 8),
        "namespace_leakage_count": int(totals["leakage"]),
        "namespace_leakage_rate": round(totals["leakage"] / denominator, 8),
        "duplicate_memory_id_count": int(totals["duplicate_ids"]),
        "duplicate_content_count": int(totals["duplicate_content"]),
        "source_content_deduplications": int(totals["source_deduplications"]),
        "duplicate_rate": round(totals["duplicate_content"] / denominator, 8),
        "near_duplicate_collision_count": int(totals["near_duplicates"]),
        "near_duplicate_collision_rate": round(totals["near_duplicates"] / denominator, 8),
        "confidence_violation_count": int(totals["confidence"]),
        "score_contract_violation_count": int(totals["score_contract"]),
        "scope_provenance_violation_count": int(totals["scope_provenance"]),
        "tie_ordering_violation_count": int(totals["tie"]),
        "retrieved_items": int(totals["results"]),
    }
    return {
        "metrics": metrics,
        "per_query_minimums": {
            "recall_at_k": min(float(item["metrics"]["recall_at_k"]) for item in query_evidence),
            "ndcg_at_k": min(float(item["metrics"]["ndcg_at_k"]) for item in query_evidence),
            "mrr": min(float(item["metrics"]["mrr"]) for item in query_evidence),
        },
        "component_signal_coverage": {
            key: int(component_counts[key])
            for key in ("spike_index", "surface_index", "same_context_graph")
        },
        "determinism": {
            "canonical_digest_algorithm": "sha256-canonical-json",
            "canonical_projection_excludes": [
                "latency",
                "temporary paths",
                "volatile storage timestamps",
            ],
            "baseline_digest": canonical_digests["baseline"],
            "canonical_digest": canonical_digests["baseline"],
            "fresh_backend_digest": canonical_digests["fresh_backend"],
            "randomized_insertion_digest": canonical_digests["randomized_insertion"],
            "canonical_digest_all_equal": len(set(canonical_digests.values())) == 1,
            "baseline_raw_result_digest": baseline_run["raw_digest"],
            "fresh_backend_raw_result_digest": fresh_run["raw_digest"],
            "randomized_insertion_raw_result_digest": shuffled_run["raw_digest"],
            "fresh_backend_raw_equal": baseline_run["raw_digest"] == fresh_run["raw_digest"],
            "randomized_insertion_raw_equal": baseline_run["raw_digest"] == shuffled_run["raw_digest"],
            "repeated_same_backend_raw_equal": bool(baseline_run["repeated_exact"]),
            "random_seed": random_seed,
            "randomized_document_order_sha256": shuffled_order_digest,
        },
        "purity": purity,
        "result_sizes_bytes": {
            "result": _size_summary(result_bytes),
            "result_set": _size_summary(result_set_bytes),
        },
        "latency_ms": {
            "samples": len(all_latencies),
            "p50": _nearest_rank_percentile(all_latencies, 0.5),
            "p95": _nearest_rank_percentile(all_latencies, 0.95),
            "informational_only": True,
            "excluded_from_acceptance": True,
            "excluded_from_canonical_digest": True,
            "clock": "time.perf_counter_ns",
        },
    }


def run_acceptance_benchmark(
    *,
    fixture_path: Path = FIXTURE_PATH,
    code_commit: str | None = None,
    source_snapshot: str | None = None,
    latency_samples: int = 20,
    timer: Callable[[], int] = time.perf_counter_ns,
) -> dict[str, Any]:
    """Run the full acceptance fixture in private disposable stores."""

    if type(latency_samples) is not int or not 1 <= latency_samples <= MAX_LATENCY_SAMPLES:
        raise MeasurementError(
            f"latency_samples must be an integer from 1 to {MAX_LATENCY_SAMPLES}"
        )
    commit = _bounded_identity(code_commit, field="code_commit")
    snapshot = _bounded_identity(source_snapshot, field="source_snapshot")
    fixture = load_fixture(fixture_path)
    natural_order = [str(document["document_id"]) for document in fixture["documents"]]
    shuffled_order = list(natural_order)
    random_seed = int(fixture["random_seed"])
    random.Random(random_seed).shuffle(shuffled_order)

    with tempfile.TemporaryDirectory(prefix="synapse-retrieval-v2-") as temporary:
        workspace = Path(temporary)
        baseline_root = workspace / "baseline"
        shuffled_root = workspace / "randomized"
        baseline_root.mkdir(mode=0o700)
        shuffled_root.mkdir(mode=0o700)

        baseline_backend = _make_backend(baseline_root, fixture)
        try:
            memory_ids = populate_fixture(
                baseline_backend,
                fixture,
                document_order=natural_order,
            )
            baseline_before = runtime_digest(baseline_backend)
            baseline_run = _run_query_set(
                baseline_backend,
                fixture,
                latency_samples=latency_samples,
                timer=timer,
                measure_latency=True,
            )
            baseline_after = runtime_digest(baseline_backend)
            state_path = baseline_backend.state_path
        finally:
            baseline_backend.memory_store.close()

        fresh_backend = _make_backend(baseline_root, fixture)
        try:
            fresh_before = runtime_digest(fresh_backend)
            fresh_run = _run_query_set(
                fresh_backend,
                fixture,
                latency_samples=1,
                timer=timer,
                measure_latency=False,
            )
            fresh_after = runtime_digest(fresh_backend)
            if fresh_backend.state_path != state_path:
                raise MeasurementError("fresh backend did not reopen the same isolated state")
        finally:
            fresh_backend.memory_store.close()

        shuffled_backend = _make_backend(shuffled_root, fixture)
        try:
            shuffled_memory_ids = populate_fixture(
                shuffled_backend,
                fixture,
                document_order=shuffled_order,
            )
            shuffled_before = runtime_digest(shuffled_backend)
            shuffled_run = _run_query_set(
                shuffled_backend,
                fixture,
                latency_samples=1,
                timer=timer,
                measure_latency=False,
            )
            shuffled_after = runtime_digest(shuffled_backend)
        finally:
            shuffled_backend.memory_store.close()

    if memory_ids != shuffled_memory_ids:
        raise MeasurementError("stable memory IDs changed with insertion order")
    baseline_projection = canonical_result_projection(
        fixture,
        baseline_run["results"],
        memory_ids,
    )
    fresh_projection = canonical_result_projection(
        fixture,
        fresh_run["results"],
        memory_ids,
    )
    shuffled_projection = canonical_result_projection(
        fixture,
        shuffled_run["results"],
        shuffled_memory_ids,
    )
    canonical_digests = {
        "baseline": _digest(baseline_projection),
        "fresh_backend": _digest(fresh_projection),
        "randomized_insertion": _digest(shuffled_projection),
    }
    query_evidence = [
        evaluate_query(
            query,
            baseline_run["results"][str(query["query_id"])],
            fixture,
            memory_ids,
            baseline_run["latency_ms"][str(query["query_id"])],
        )
        for query in fixture["queries"]
    ]
    purity_runs = {
        "baseline": {
            "before": baseline_before,
            "after": baseline_after,
            "unchanged": baseline_before == baseline_after,
        },
        "fresh_backend": {
            "before": fresh_before,
            "after": fresh_after,
            "unchanged": fresh_before == fresh_after,
        },
        "randomized_insertion": {
            "before": shuffled_before,
            "after": shuffled_after,
            "unchanged": shuffled_before == shuffled_after,
        },
    }
    purity = {
        "digest_algorithm": "sha256-canonical-json-and-file-bytes",
        "covers": [
            "neural arrays",
            "backend runtime fields",
            "runtime state file",
            "SQLite database",
            "canonical logical rows from every SQLite user table",
            "SQLite WAL, shared-memory, and rollback journal when present",
        ],
        "runs": purity_runs,
        "all_runs_unchanged": all(run["unchanged"] for run in purity_runs.values()),
    }
    aggregate = _aggregate_evidence(
        query_evidence,
        baseline_run=baseline_run,
        fresh_run=fresh_run,
        shuffled_run=shuffled_run,
        canonical_digests=canonical_digests,
        purity=purity,
        shuffled_order_digest=_digest(shuffled_order),
        random_seed=random_seed,
    )
    acceptance = acceptance_verdict(aggregate, fixture["thresholds"])
    aggregate["verdict"] = acceptance["verdict"]

    report = {
        "schema": REPORT_SCHEMA,
        "version": REPORT_VERSION,
        "status": acceptance["verdict"],
        "synthetic_benchmark_notice": SYNTHETIC_NOTICE,
        "run_identity": {
            "fixture_schema": FIXTURE_SCHEMA,
            "fixture_sha256": _digest(fixture),
            "code_commit": commit,
            "source_snapshot": snapshot,
            "offline": True,
            "temporary_store": True,
            "embedding_provider": str(fixture["backend"]["embedding_provider"]),
        },
        "methodology": {
            "design": "fixed graded synthetic corpus in disposable local stores",
            "population_source": "version-controlled retrieval-v2 fixture",
            "relevance_scale": "integer grades 1-3; unjudged results are nonrelevant",
            "scope_policy": "each query declares the only namespaces allowed in results",
            "rank_cutoff": "the fixture query result_limit defines k",
            "determinism": (
                "compare a canonical semantic projection across the natural corpus order, "
                "a seeded randomized insertion order, and a fresh backend instance"
            ),
            "purity": (
                "compare neural, runtime-state, physical SQLite/WAL/SHM/journal, and canonical "
                "logical database digests before and after reads; forbidden mutators are tripwired"
            ),
            "latency": "nearest-rank p50/p95 from warm serial monotonic samples; untimed warm-up excluded and informational only",
            "network_access": "none",
        },
        "population": _population(fixture),
        "metric_definitions": {
            "recall_at_k": "distinct judged-relevant documents retrieved by k divided by all judged-relevant documents",
            "ndcg_at_k": "DCG with gain 2^grade-1 and log2 rank discount, divided by ideal DCG at k",
            "mrr": "reciprocal rank of the first judged-relevant result",
            "namespace_leakage_rate": "results outside the query's allowed_contexts divided by returned results",
            "duplicate_rate": "exact normalized visible-content repeats beyond the first divided by returned results",
            "near_duplicate_collision_rate": "additional returned members of fixture near-duplicate groups divided by returned results",
            "result_bytes": "UTF-8 bytes of the canonical full Retrieval v2 JSON response",
            "result_set_bytes": "UTF-8 bytes of the canonical items array only",
            "component_signal_coverage": "returned items with each positive score_breakdown signal",
            "p50_p95_latency_ms": "nearest-rank monotonic elapsed milliseconds; excluded from acceptance",
        },
        "thresholds": fixture["thresholds"],
        "per_query": query_evidence,
        "aggregate": aggregate,
        "acceptance": acceptance,
        "limitations": [
            SYNTHETIC_NOTICE,
            "The corpus is intentionally small and does not model live namespace size, drift, language distribution, or operator behavior.",
            "The fixture exercises the deterministic semantic-hash provider, not every deployable embedding provider.",
            "Latency is measured on one local process and is not a capacity, concurrency, or service-level benchmark.",
            "Passing thresholds are regression gates for this labeled fixture and are not calibrated estimates of real-world relevance.",
        ],
    }
    canonical_json_bytes(report)
    return report


def write_report(report: dict[str, Any], output_path: Path) -> Path:
    """Atomically write canonical, private JSON evidence."""

    output = output_path.expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output.exists() and output.is_symlink():
        raise MeasurementError("output path must not be a symlink")
    payload = canonical_json_bytes(report) + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        output.chmod(0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    metadata = os.lstat(output)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise MeasurementError("output is not a regular file")
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline synthetic Retrieval v2 acceptance benchmark.",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional path for canonical versioned JSON evidence.",
    )
    parser.add_argument(
        "--code-commit",
        default="",
        help="Optional public code revision identifier to bind into the report.",
    )
    parser.add_argument(
        "--snapshot",
        default="",
        help="Optional public source snapshot identifier to bind into the report.",
    )
    parser.add_argument(
        "--latency-samples",
        type=int,
        default=20,
        help=f"Per-query informational latency samples (1-{MAX_LATENCY_SAMPLES}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = run_acceptance_benchmark(
            code_commit=args.code_commit or None,
            source_snapshot=args.snapshot or None,
            latency_samples=args.latency_samples,
        )
        if args.output:
            write_report(report, Path(args.output))
        print(canonical_json_bytes(report).decode("utf-8"))
        return 0 if report["acceptance"]["accepted"] else 1
    except Exception as exc:
        error = {
            "schema": REPORT_SCHEMA,
            "version": REPORT_VERSION,
            "status": "failed",
            "error": {
                "type": type(exc).__name__,
                "message": str(exc)[:512],
            },
        }
        print(canonical_json_bytes(error).decode("utf-8"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

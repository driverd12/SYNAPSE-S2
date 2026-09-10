#!/usr/bin/env python3
"""Explicitly invoked, content-free benchmark through the bound read-only core API.

No local backend or SQLite connection is constructed. This script only issues
health, retrieve_text_v2, and lightweight list_namespace_map requests. The fixed
query and request contract make repeat runs comparable when corpus revisions
also match. Timing fields are observations, not retrieval identities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics
import sys
import time
from datetime import datetime, timezone


QUERY = "SYNAPSE-S2 authoritative core recovery readiness"
ARGUMENTS = {
    "prompt": QUERY,
    "context_id": "default",
    "recall_scope": "local",
    "result_limit": 5,
    "candidate_limit": 128,
    "include_graph_neighbors": True,
}
READ_OPERATIONS = {"health", "retrieve_text_v2", "list_namespace_map"}
IDENTITY_FIELDS = (
    "authority_id", "neural_epoch", "build_id", "config_fingerprint",
    "store_identity", "schema_identity",
)
STAGE_FIELDS = (
    "queue_wait_ms", "embedding_ms", "index_lookup_ms",
    "graph_expansion_ms", "ranking_ms", "serialization_ms",
    "scope_lookup_ms", "revision_validation_ms", "backend_total_ms",
)


class BenchmarkError(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def number(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


def identifier(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) is None:
        raise BenchmarkError("invalid_identifier")
    return value


def project_health(client, expected_identity=None):
    health = client.health(timeout_seconds=3.0)
    identity = {key: identifier((client.authority_identity or {}).get(key)) for key in IDENTITY_FIELDS}
    if expected_identity is not None and identity != expected_identity:
        raise BenchmarkError("authority_identity_changed")
    lane = health.get("backend_lane") or {}
    capture = health.get("capture") or {}
    if (
        health.get("ready") is not True
        or health.get("deployment_mode") != "authoritative"
        or (health.get("authority") or {}).get("ready") is not True
        or capture.get("ready") is not True
        or lane.get("ready") is not True
        or lane.get("maintenance") is True
    ):
        raise BenchmarkError("production_health_not_ready")
    return {
        "observed_at": utc_now(),
        "identity": identity,
        "ready": True,
        "deployment_mode": "authoritative",
        "capture_ready": True,
        "capture_last_success_age_ms": number(capture.get("last_success_age_ms")),
        "lane": {
            "active": lane.get("active") is True,
            "owner": None if lane.get("owner") is None else identifier(lane["owner"]),
            "accepting_ordinary_operations": lane.get("accepting_ordinary_operations") is True,
            "active_age_ms": number(lane.get("active_age_ms")),
            "deadline_remaining_ms": number(lane.get("deadline_remaining_ms")),
        },
    }


def project_retrieval(payload):
    if payload.get("schema") != "synapse-retrieval.v2" or payload.get("raw_input_stored") is not False:
        raise BenchmarkError("unexpected_retrieval_contract")
    snapshot = payload.get("snapshot") or {}
    entries = snapshot.get("entries_revision") or {}
    items = payload.get("items")
    if not isinstance(items, list) or len(items) > 5:
        raise BenchmarkError("unexpected_result_count")
    # The production resolver always inherits global, even for local scope.
    # Reject any connected/all expansion instead of broadening this guard.
    context_ids = entries.get("context_ids")
    query = payload.get("query") or {}
    scope = payload.get("scope") or {}
    expected_contexts = [
        {"origin_context_id": "default", "resolved_context_id": context,
         "requested_scope": "local", "provenance": provenance,
         "context_link": None}
        for context, provenance in (("default", "local"), ("global", "global"))
    ]
    if (
        context_ids != ["default", "global"]
        or query.get("context_id") != "default"
        or query.get("recall_scope") != "local"
        or query.get("raw_input_stored") is not False
        or scope.get("origin_context_id") != "default"
        or scope.get("requested_scope") != "local"
        or scope.get("inherits_global") is not True
        or scope.get("resolved_context_count") != 2
        or scope.get("truncated") is not False
        or scope.get("active_adjacent_link_count") != 0
        or scope.get("contexts") != expected_contexts
        or any(item.get("context_id") not in context_ids for item in items)
    ):
        raise BenchmarkError("unexpected_retrieval_scope")
    work = payload.get("work") or {}
    counts = {
        key: value for key, value in work.items()
        if re.fullmatch(r"[a-z_]{1,100}", key)
        and (type(value) is bool or (type(value) is int and value >= 0))
    }
    exposed_timings = payload.get("timings_ms") or payload.get("timings") or {}
    timings = {key: number(exposed_timings.get(key)) for key in STAGE_FIELDS}
    return {
        "retrieval_id": identifier(payload.get("retrieval_id")),
        "snapshot_id": identifier(snapshot.get("snapshot_id")),
        "entries_revision": identifier(entries.get("revision")),
        "scope_entry_count": number(entries.get("entry_count")),
        "scope_context_ids": context_ids,
        "scope_inherits_global": True,
        "scope_namespace_count": len(context_ids),
        "result_ids": [identifier(item.get("memory_id")) for item in items],
        "result_count": len(items),
        "work_counts": counts,
        "stage_timings_ms": timings,
        "stage_timings_available": any(value is not None for value in timings.values()),
    }


def project_namespaces(payload):
    if payload.get("action") != "list-namespace-map" or payload.get("density_metrics_included") is not False:
        raise BenchmarkError("unexpected_namespace_map_contract")
    nodes = payload.get("nodes")
    if not isinstance(nodes, list) or len(nodes) > 2000:
        raise BenchmarkError("unexpected_namespace_count")
    counts = []
    for node in nodes:
        context = node.get("context_id")
        count = node.get("entry_count")
        if not isinstance(context, str) or type(count) is not int or count < 0:
            raise BenchmarkError("invalid_namespace_count")
        counts.append({
            "namespace_id_sha256": hashlib.sha256(context.encode()).hexdigest(),
            "is_default": context == "default",
            "is_global": context == "global",
            "entry_count": count,
        })
    return {
        "observed_namespace_count": len(counts),
        "namespace_limit": 2000,
        "may_be_truncated": len(counts) == 2000,
        "observed_total_entries": sum(item["entry_count"] for item in counts),
        "default_namespace_entry_count": next((item["entry_count"] for item in counts if item["is_default"]), None),
        "global_namespace_entry_count": next((item["entry_count"] for item in counts if item["is_global"]), None),
        "namespace_entry_counts": sorted(counts, key=lambda item: item["namespace_id_sha256"]),
        "density_metrics_included": False,
    }


def benchmark(client, report, expected_build, expected_fingerprint):
    initial = project_health(client)
    identity = initial["identity"]
    if identity["build_id"] != expected_build or identity["config_fingerprint"] != expected_fingerprint:
        raise BenchmarkError("runtime_build_or_configuration_mismatch")
    report["initial_health"] = initial
    for index in range(4):
        before = project_health(client, identity)
        started = time.perf_counter()
        payload = client.call("retrieve_text_v2", dict(ARGUMENTS), timeout_seconds=120.0)
        elapsed = time.perf_counter() - started
        sample = project_retrieval(payload)
        del payload
        sample.update({
            "sample_index": index,
            "phase": "warmup" if index == 0 else "measured",
            "elapsed_seconds": round(elapsed, 6),
            "health_before": before,
            "health_after": project_health(client, identity),
        })
        report["samples"].append(sample)
    # Collect only the lightweight count inventory after timing, avoiding a
    # full status/index scan that would change warm-up conditions.
    namespaces = client.call("list_namespace_map", {
        "context_id": "default", "limit": 2000,
        "include_suggestions": False, "include_density_metrics": False,
    }, timeout_seconds=30.0)
    report["namespace_counts_after"] = project_namespaces(namespaces)
    del namespaces
    report["final_health"] = project_health(client, identity)
    measured = report["samples"][1:]
    elapsed = [sample["elapsed_seconds"] for sample in measured]
    report["summary"] = {
        "measured_count": 3,
        "warmup_excluded": True,
        "median_seconds": statistics.median(elapsed),
        "minimum_seconds": min(elapsed),
        "maximum_seconds": max(elapsed),
        "measured_result_ids_stable": all(sample["result_ids"] == measured[0]["result_ids"] for sample in measured),
        "measured_retrieval_ids_stable": all(sample["retrieval_id"] == measured[0]["retrieval_id"] for sample in measured),
        "measured_entries_revisions_stable": all(sample["entries_revision"] == measured[0]["entries_revision"] for sample in measured),
        "any_start_lane_active": any(sample["health_before"]["lane"]["active"] for sample in measured),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--host-label", required=True)
    parser.add_argument("--execute", action="store_true", help="Run only after accepted production activation.")
    args = parser.parse_args()
    if not args.execute:
        parser.error("--execute is required; this is a postactivation operation")
    identifier(args.host_label)
    os.umask(0o077)
    repo = args.repo.resolve(strict=True)
    output = args.output.absolute()
    parent = output.parent.stat()
    if output.parent.is_symlink() or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise BenchmarkError("output_directory_must_be_private")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    report = {
        "schema": "synapse-s2.postactivation-recall-benchmark.v1",
        "host_label": args.host_label,
        "started_at": utc_now(),
        "status": "incomplete",
        "operation": "retrieve_text_v2",
        "read_only": True,
        "query_sha256": hashlib.sha256(QUERY.encode()).hexdigest(),
        "parameters": {key: value for key, value in ARGUMENTS.items() if key != "prompt"},
        "parameters_provenance": "Fixed versioned probe and explicit parameters in this script.",
        "comparison_limit": "Compare only matching query, parameters, model/configuration and corpus revisions; changed corpus or active lane confounds latency comparisons.",
        "timing_scope": "Client wall time includes socket exchange, queue wait, embedding, retrieval and response decoding; stage timings remain null when not exposed.",
        "content_included": False,
        "samples": [],
    }
    client = None
    try:
        sys.path.insert(0, str(repo))
        from core_client import CoreClient
        from core_client_binding import load_bound_core_config, load_core_client_binding
        from core_service import CORE_OPERATION_CONTRACTS, _manifest_build_id
        if any(CORE_OPERATION_CONTRACTS[name].mutation for name in READ_OPERATIONS):
            raise BenchmarkError("operation_is_not_read_only")
        binding = load_core_client_binding(Path.home() / ".config/synapse-s2/core-binding.json")
        if binding.repo_root.resolve() != repo or binding.authority_mode != "authoritative-core-v6":
            raise BenchmarkError("binding_does_not_match_repository")
        config = load_bound_core_config(binding)
        report["configuration"] = {
            "fingerprint": config.fingerprint,
            "embedding_space_identity": config.embedding_space_identity,
            "dimension": config.dimension,
            "num_neurons": config.num_neurons,
            "default_top_k": config.default_top_k,
            "recall_count": config.recall_count,
            "provider": config.embedding_provider_name,
            "model": config.embedding_neural_model_id,
            "model_revision": config.embedding_neural_revision,
            "maximum_tokens": config.embedding_neural_max_tokens,
            "mlx_device": config.mlx_device,
        }
        client = CoreClient(
            socket_path=binding.socket_path,
            state_path=binding.state_path,
            replication_inbox_root=binding.replication_inbox_root,
            expected_config_fingerprint=binding.config_fingerprint,
            caller="postactivation-recall-benchmark",
            default_timeout_seconds=120.0,
        )
        benchmark(client, report, _manifest_build_id(repo), binding.config_fingerprint)
        report["status"] = "complete"
    except Exception as exc:
        report["status"] = "failed"
        # Never serialize exception text, raw API envelopes, credentials or content.
        report["error_type"] = type(exc).__name__
        if isinstance(exc, BenchmarkError):
            report["error_code"] = str(exc)
    finally:
        if client is not None:
            client.close()
        report["finished_at"] = utc_now()
        with os.fdopen(descriptor, "w") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    print(json.dumps({"status": report["status"], "artifact": str(output), "summary": report.get("summary")}, sort_keys=True))
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())

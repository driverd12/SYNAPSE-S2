#!/usr/bin/env python3
"""Produce aggregate-only Phase 6 compact response-contract evidence.

The benchmark is intentionally coupled to a verified Phase 5 paired recovery
bundle.  It verifies that bundle with the existing recovery manager, restores
it into a private temporary directory, and performs every benchmark mutation on
that disposable database.  The live database, capture root, and export root are
never used as benchmark targets.

Durable evidence is opt-in through ``--output`` and is refused while the git
worktree is dirty.  A test-only dirty-tree bypass exists, but it additionally
requires ``SYNAPSE_S2_MEASUREMENT_TEST_MODE=1`` so it cannot be selected by
accident in an operator workflow.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator


ROOT = Path(__file__).resolve().parents[1]
while str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

import mcp_server as _mcp_server_module  # noqa: E402
import memory_store as _memory_store_module  # noqa: E402
import mlx_backend as _mlx_backend_module  # noqa: E402
import recovery_manager as _recovery_manager_module  # noqa: E402
import redaction as _redaction_module  # noqa: E402
import token_contracts as _token_contracts_module  # noqa: E402

from mcp_server import (  # noqa: E402
    MCP_COMPACT_SAFETY_SUMMARY_BYTES,
    MCP_FULL_SAFETY_SUMMARY_BYTES,
    MCP_SAFETY_SUMMARY_PREFIX,
    _contract_tool_result,
)
from memory_store import DurableMemoryStore  # noqa: E402
from mlx_backend import SpikingAttentionBackend  # noqa: E402
from recovery_manager import (  # noqa: E402
    RECOVERY_BUNDLE_RESTORE_SCHEMA,
    RECOVERY_BUNDLE_SCHEMA,
    VerifiedRecoveryManager,
)
from redaction import (  # noqa: E402
    REDACTED_SECRET,
    SecretSafeArgumentParser,
    mask_public_paths,
    safe_public_error,
    validate_public_identifier,
)
from token_contracts import (  # noqa: E402
    COMPACT_SOURCE_LIMITS,
    CONTRACT_SCHEMA,
    CONTRACT_VERSION,
    canonical_response_bytes,
    project_response,
)


EVIDENCE_SCHEMA = "synapse-s2.token-contract-acceptance.v1"
EVIDENCE_VERSION = 1
INSTALLED_COMPACT_BYTES = 12_288
FULL_DIAGNOSTIC_BYTES = 131_072
BENCHMARK_EVENT_COUNT = 20
BENCHMARK_CONTEXT_EVENT_AGENT = "phase6-measure-compact"
BENCHMARK_FULL_EVENT_AGENT = "phase6-measure-full"
BENCHMARK_SOURCE_SURFACE = "phase6-measurement"
BENCHMARK_EVENT_TYPE = "token-contract-benchmark"
BENCHMARK_SECRET_CANARY = "sk-synthetic-phase6-ABCDEFGHIJKLMNOPQRSTUVWX"
BENCHMARK_PATH_CANARY = "/Users/phase6/private/benchmark.txt"
TEST_MODE_ENV = "SYNAPSE_S2_MEASUREMENT_TEST_MODE"
_ABSOLUTE_WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\")
_RAW_IDENTIFIER_RE = re.compile(
    r"(?:ctxrcpt_|s2mem_|s2rel_|s2cap_|-----BEGIN [A-Z ]+-----)"
)
_RAW_DIGEST_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


def _capture_import_attestation() -> tuple[tuple[str, Path, str], ...]:
    records: list[tuple[str, Path, str]] = []
    modules = (
        ("mcp_server", _mcp_server_module),
        ("memory_store", _memory_store_module),
        ("mlx_backend", _mlx_backend_module),
        ("recovery_manager", _recovery_manager_module),
        ("redaction", _redaction_module),
        ("token_contracts", _token_contracts_module),
    )
    for name, module in modules:
        raw_path = getattr(module, "__file__", None)
        if not raw_path:
            raise RuntimeError("project module import has no source file")
        path = Path(str(raw_path)).resolve(strict=True)
        try:
            path.relative_to(ROOT)
        except ValueError as exc:
            raise RuntimeError("project module import escaped the repository") from exc
        records.append((name, path, hashlib.sha256(path.read_bytes()).hexdigest()))
    return tuple(records)


try:
    _IMPORTED_SOURCE_ATTESTATION = _capture_import_attestation()
    _IMPORT_ATTESTATION_ERROR = False
except Exception:
    _IMPORTED_SOURCE_ATTESTATION = ()
    _IMPORT_ATTESTATION_ERROR = True


class MeasurementError(RuntimeError):
    """The acceptance measurement cannot prove its production invariants."""


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MeasurementError("measurement value is not canonical JSON") from exc


def _legacy_wire_bytes(payload: dict[str, Any]) -> bytes:
    """Match the established one-line ``synapse_cli.py --json`` serializer."""

    source = {
        key: value
        for key, value in payload.items()
        if key != "_response_source"
    }
    try:
        return json.dumps(source, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MeasurementError("legacy producer payload is not serializable") from exc


def _private_regular_file(path: Path, *, label: str) -> Path:
    candidate = path.expanduser().absolute()
    try:
        metadata = os.lstat(candidate)
    except FileNotFoundError as exc:
        raise MeasurementError(f"{label} does not exist") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or int(metadata.st_nlink) != 1
    ):
        raise MeasurementError(
            f"{label} must be a private, user-owned, single-link regular file"
        )
    return candidate.resolve()


def resolve_live_memory_db(
    receipt_path: Path,
    memory_db: Path | None = None,
) -> Path:
    """Resolve one authoritative live DB without opening it for writes."""

    if memory_db is not None:
        resolved = _private_regular_file(memory_db, label="live memory database")
        try:
            receipt_path.relative_to(resolved.parent)
        except ValueError as exc:
            raise MeasurementError(
                "bundle receipt must be inside the selected memory-store root"
            ) from exc
        return resolved

    candidates: list[Path] = []
    for parent in receipt_path.parents:
        candidate = parent / "memory.sqlite3"
        if candidate.exists() and not candidate.is_symlink():
            candidates.append(candidate)
    unique = list(dict.fromkeys(candidate.resolve() for candidate in candidates))
    if len(unique) != 1:
        raise MeasurementError(
            "could not infer exactly one live memory database; pass --memory-db"
        )
    return _private_regular_file(unique[0], label="live memory database")


def _paths_overlap(left: Path, right: Path) -> bool:
    left_resolved = left.resolve()
    right_resolved = right.resolve()
    return (
        left_resolved == right_resolved
        or left_resolved in right_resolved.parents
        or right_resolved in left_resolved.parents
    )


def restore_verified_bundle(
    receipt_path: Path,
    live_memory_db: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Verify and restore through the Phase 5 manager without live DB init."""

    if output_root.exists() or output_root.is_symlink():
        raise MeasurementError("isolated restore output root must not already exist")
    if _paths_overlap(output_root.parent, live_memory_db.parent):
        raise MeasurementError("isolated restore must not alias the live store root")

    audit_store = DurableMemoryStore.open_existing_for_audit(live_memory_db)
    manager = VerifiedRecoveryManager(
        audit_store,
        capture_root=live_memory_db.parent,
    )
    verified = manager.verify_bundle(receipt_path)
    if (
        verified.get("verified") is not True
        or verified.get("receipt_identity_trusted") is not True
        or verified.get("cutover_ready") is not True
    ):
        raise MeasurementError(
            "Phase 5 recovery bundle is not verified, identity-trusted, and cutover-ready"
        )
    restored = manager.restore_bundle_isolated(
        receipt_path,
        output_root,
        confirm=True,
    )
    if restored.get("verified") is not True or restored.get("cutover_ready") is not True:
        raise MeasurementError("isolated recovery proof is not verified and cutover-ready")

    restored_root = Path(str(restored.get("restore_root") or "")).resolve()
    restored_db = restored_root / "memory.sqlite3"
    restored_capture = restored_root / "capture-root"
    proof_path = Path(str(restored.get("recovery_proof_path") or ""))
    if (
        restored_root != output_root.resolve()
        or not restored_db.is_file()
        or restored_db.is_symlink()
        or not restored_capture.is_dir()
        or restored_capture.is_symlink()
        or not proof_path.is_file()
        or proof_path.is_symlink()
        or _paths_overlap(restored_db, live_memory_db)
    ):
        raise MeasurementError("isolated recovery materialized an unsafe path layout")
    try:
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MeasurementError("isolated recovery proof is unreadable") from exc
    if (
        not isinstance(proof, dict)
        or proof.get("schema") != RECOVERY_BUNDLE_RESTORE_SCHEMA
        or proof.get("verified") is not True
        or proof.get("cutover_ready") is not True
    ):
        raise MeasurementError("isolated recovery proof contract is invalid")
    return {
        "bundle_schema": RECOVERY_BUNDLE_SCHEMA,
        "bundle_verified": True,
        "receipt_identity_trusted": True,
        "isolated_restore_verified": True,
        "cutover_ready": True,
        "restore_root": restored_root,
        "database_path": restored_db,
        "capture_root": restored_capture,
    }


@contextmanager
def _isolated_runtime_environment(
    *,
    workspace_root: Path,
    database_path: Path,
    capture_root: Path,
) -> Iterator[dict[str, Path]]:
    runtime_root = workspace_root / "benchmark-runtime"
    export_root = workspace_root / "benchmark-export"
    runtime_root.mkdir(mode=0o700)
    export_root.mkdir(mode=0o700)
    state_path = runtime_root / "runtime-state.json"
    replacements = {
        "SYNAPSE_S2_MEMORY_DB": str(database_path),
        "SYNAPSE_S2_STATE_PATH": str(state_path),
        "SYNAPSE_S2_EXPORT_DIR": str(export_root),
        "SYNAPSE_S2_CAPTURE_ROOT": str(capture_root),
        "SYNAPSE_S2_DEFAULT_RESPONSE_MODE": "compact",
        "SYNAPSE_S2_MAX_RESPONSE_BYTES": str(INSTALLED_COMPACT_BYTES),
    }
    prior = {key: os.environ.get(key) for key in replacements}
    os.environ.update(replacements)
    try:
        yield {
            "runtime_root": runtime_root,
            "export_root": export_root,
            "state_path": state_path,
        }
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _with_source(payload: dict[str, Any], source: dict[str, int]) -> dict[str, Any]:
    copied = copy.deepcopy(payload)
    copied["_response_source"] = dict(source)
    return copied


def _inject_projection_canary(
    surface: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Place secret/path canaries in a rendered field on every measured surface."""

    copied = copy.deepcopy(payload)
    canary = (
        f"Phase 6 {surface} password={BENCHMARK_SECRET_CANARY} "
        f"at {BENCHMARK_PATH_CANARY}"
    )
    if surface in {"memory-list", "memory-graph"}:
        entries = copied.get("entries")
        if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
            raise MeasurementError(f"{surface} has no entry for redaction canaries")
        entries[0]["source_text"] = canary
    elif surface == "cortex-state":
        goals = copied.get("goals")
        if not isinstance(goals, list):
            raise MeasurementError("cortex-state goals are not measurable")
        goals.append(
            {
                "memory_id": "phase6-canary-cortex-evidence",
                "title": canary,
                "trace_type": "goal",
                "state": "active",
                "truth_posture": "observed",
                "confidence": 0.0,
                "updated_at": 0.0,
            }
        )
        copied["goal_count"] = len(goals)
    elif surface == "agent-hydration":
        deliveries = copied.get("deliveries")
        events = copied.get("events")
        if (
            not isinstance(deliveries, list)
            or not deliveries
            or not isinstance(deliveries[0], dict)
            or not isinstance(events, list)
        ):
            raise MeasurementError("agent-hydration has no delivery for redaction canaries")
        event_id = deliveries[0].get("event_id")
        nested_event = deliveries[0].get("event")
        if isinstance(nested_event, dict):
            nested_event["summary"] = canary
        matched = False
        for event in events:
            if isinstance(event, dict) and event.get("event_id") == event_id:
                event["summary"] = canary
                matched = True
        if not matched:
            raise MeasurementError("agent-hydration canary event is not bijective")
    else:  # pragma: no cover - callers use the four fixed surfaces
        raise MeasurementError("unsupported redaction canary surface")
    return copied


def _publish_benchmark_events(
    backend: SpikingAttentionBackend,
    *,
    context_id: str,
) -> None:
    repeated = "🧠 bounded evidence " * 64
    for index in range(BENCHMARK_EVENT_COUNT):
        backend.publish_context_event(
            context_id=context_id,
            source_surface=BENCHMARK_SOURCE_SURFACE,
            event_type=BENCHMARK_EVENT_TYPE,
            summary=(
                f"Phase 6 delivery sample {index + 1}: {repeated} "
                f"token={BENCHMARK_SECRET_CANARY} at {BENCHMARK_PATH_CANARY}"
            ),
            payload={
                "ordinal": index + 1,
                "api_key": BENCHMARK_SECRET_CANARY,
                "local_path": BENCHMARK_PATH_CANARY,
            },
            agent_targets=(
                BENCHMARK_CONTEXT_EVENT_AGENT,
                BENCHMARK_FULL_EVENT_AGENT,
            ),
        )


def _source_payloads(
    backend: SpikingAttentionBackend,
    *,
    context_id: str,
) -> tuple[dict[str, dict[str, Any]], list[tuple[str, str, list[str]]]]:
    memory_requested_limit = 50
    graph_requested_limit = 100
    cortex_requested_limit = 50
    event_requested_limit = 20
    graph_hydration_requested_limit = 30

    memory_requested = backend.list_memory(
        context_id=context_id,
        limit=memory_requested_limit,
        include_vectors=False,
    )
    if int(memory_requested.get("entry_count") or 0) <= 0:
        raise MeasurementError(
            "verified snapshot context has no memory entries to measure"
        )
    memory_compact = backend.list_memory(
        context_id=context_id,
        limit=COMPACT_SOURCE_LIMITS["memory-list"],
        include_vectors=False,
    )
    memory_same = backend.list_memory(
        context_id=context_id,
        limit=5,
        include_vectors=False,
    )

    graph_requested = backend.list_memory_graph(
        context_id=context_id,
        limit=graph_requested_limit,
    )
    graph_compact = backend.list_memory_graph(
        context_id=context_id,
        limit=COMPACT_SOURCE_LIMITS["memory-graph"],
    )
    graph_same = backend.list_memory_graph(context_id=context_id, limit=5)

    cortex_requested = backend.get_cortex_state(
        context_id=context_id,
        agent_id="",
        limit=cortex_requested_limit,
    )
    cortex_compact = backend.get_cortex_state(
        context_id=context_id,
        agent_id="",
        limit=COMPACT_SOURCE_LIMITS["cortex-state"],
    )
    cortex_same = backend.get_cortex_state(
        context_id=context_id,
        agent_id="",
        limit=5,
    )

    _publish_benchmark_events(backend, context_id=context_id)
    leases_to_release: list[tuple[str, str, list[str]]] = []
    hydration_requested = backend.hydrate_agent_context(
        context_id=context_id,
        agent_id=BENCHMARK_FULL_EVENT_AGENT,
        prompt="",
        event_limit=event_requested_limit,
        graph_limit=graph_hydration_requested_limit,
        claim_events=True,
        consumer_instance_id="phase6-measurement-full",
        lease_seconds=300.0,
        recall_mode="none",
    )
    full_receipts = [
        str(item.get("receipt_id") or "")
        for item in hydration_requested.get("deliveries", [])
        if isinstance(item, dict) and str(item.get("receipt_id") or "")
    ]
    leases_to_release.append(
        (BENCHMARK_FULL_EVENT_AGENT, "phase6-measurement-full", full_receipts)
    )
    hydration_compact = backend.hydrate_agent_context(
        context_id=context_id,
        agent_id=BENCHMARK_CONTEXT_EVENT_AGENT,
        prompt="",
        event_limit=COMPACT_SOURCE_LIMITS["agent-events"],
        graph_limit=COMPACT_SOURCE_LIMITS["agent-graph"],
        claim_events=True,
        consumer_instance_id="phase6-measurement-compact",
        lease_seconds=300.0,
        recall_mode="none",
    )
    compact_receipts = [
        str(item.get("receipt_id") or "")
        for item in hydration_compact.get("deliveries", [])
        if isinstance(item, dict) and str(item.get("receipt_id") or "")
    ]
    leases_to_release.append(
        (BENCHMARK_CONTEXT_EVENT_AGENT, "phase6-measurement-compact", compact_receipts)
    )
    if len(full_receipts) != event_requested_limit:
        raise MeasurementError("full-policy benchmark did not lease every sample event")
    if len(compact_receipts) != COMPACT_SOURCE_LIMITS["agent-events"]:
        raise MeasurementError("compact-policy benchmark did not lease its bounded event page")

    return (
        {
            "memory-list": {
                "requested": _inject_projection_canary(
                    "memory-list", memory_requested
                ),
                "installed": _with_source(
                    _inject_projection_canary("memory-list", memory_compact),
                    {
                        "requested_limit": memory_requested_limit,
                        "effective_limit": COMPACT_SOURCE_LIMITS["memory-list"],
                    },
                ),
                "same": _with_source(
                    _inject_projection_canary("memory-list", memory_same),
                    {"requested_limit": 5, "effective_limit": 5},
                ),
                "requested_limit": memory_requested_limit,
                "effective_limit": COMPACT_SOURCE_LIMITS["memory-list"],
            },
            "memory-graph": {
                "requested": _inject_projection_canary(
                    "memory-graph", graph_requested
                ),
                "installed": _with_source(
                    _inject_projection_canary("memory-graph", graph_compact),
                    {
                        "requested_limit": graph_requested_limit,
                        "effective_limit": COMPACT_SOURCE_LIMITS["memory-graph"],
                    },
                ),
                "same": _with_source(
                    _inject_projection_canary("memory-graph", graph_same),
                    {"requested_limit": 5, "effective_limit": 5},
                ),
                "requested_limit": graph_requested_limit,
                "effective_limit": COMPACT_SOURCE_LIMITS["memory-graph"],
            },
            "cortex-state": {
                "requested": _inject_projection_canary(
                    "cortex-state", cortex_requested
                ),
                "installed": _with_source(
                    _inject_projection_canary("cortex-state", cortex_compact),
                    {
                        "requested_limit": cortex_requested_limit,
                        "effective_limit": COMPACT_SOURCE_LIMITS["cortex-state"],
                    },
                ),
                "same": _with_source(
                    _inject_projection_canary("cortex-state", cortex_same),
                    {"requested_limit": 5, "effective_limit": 5},
                ),
                "requested_limit": cortex_requested_limit,
                "effective_limit": COMPACT_SOURCE_LIMITS["cortex-state"],
            },
            "agent-hydration": {
                "requested": _inject_projection_canary(
                    "agent-hydration", hydration_requested
                ),
                "installed": _with_source(
                    _inject_projection_canary(
                        "agent-hydration", hydration_compact
                    ),
                    {
                        "requested_event_limit": event_requested_limit,
                        "effective_event_limit": COMPACT_SOURCE_LIMITS[
                            "agent-events"
                        ],
                        "requested_graph_limit": graph_hydration_requested_limit,
                        "effective_graph_limit": COMPACT_SOURCE_LIMITS[
                            "agent-graph"
                        ],
                    },
                ),
                "same": _with_source(
                    _inject_projection_canary(
                        "agent-hydration", hydration_compact
                    ),
                    {
                        "requested_event_limit": COMPACT_SOURCE_LIMITS[
                            "agent-events"
                        ],
                        "effective_event_limit": COMPACT_SOURCE_LIMITS[
                            "agent-events"
                        ],
                        "requested_graph_limit": COMPACT_SOURCE_LIMITS[
                            "agent-graph"
                        ],
                        "effective_graph_limit": COMPACT_SOURCE_LIMITS[
                            "agent-graph"
                        ],
                    },
                ),
                "requested_limit": event_requested_limit,
                "effective_limit": COMPACT_SOURCE_LIMITS["agent-events"],
            },
        },
        leases_to_release,
    )


def _validate_redaction_boundary(document: dict[str, Any]) -> None:
    rendered = canonical_response_bytes(document).decode("utf-8")
    if BENCHMARK_SECRET_CANARY in rendered or BENCHMARK_PATH_CANARY in rendered:
        raise MeasurementError("response contract exposed a benchmark canary")
    if mask_public_paths(rendered) != rendered:
        raise MeasurementError("response contract is not stable at the public boundary")
    if REDACTED_SECRET not in rendered or "[LOCAL_PATH]" not in rendered:
        raise MeasurementError(
            "response contract did not prove both secret and path canary projection"
        )


def _validate_contract(
    contract: dict[str, Any],
    *,
    surface: str,
    profile: str,
    budget: int,
) -> int:
    if (
        not isinstance(contract, dict)
        or contract.get("schema") != CONTRACT_SCHEMA
        or type(contract.get("version")) is not int
        or contract.get("version") != CONTRACT_VERSION
        or contract.get("operation") != surface
        or contract.get("ok") is not True
    ):
        raise MeasurementError("response contract identity is invalid")
    response_contract = contract.get("response_contract")
    if not isinstance(response_contract, dict):
        raise MeasurementError("response contract metadata is missing")
    declared = response_contract.get("serialized_bytes")
    if (
        response_contract.get("profile") != profile
        or type(response_contract.get("max_output_bytes")) is not int
        or response_contract.get("max_output_bytes") != budget
        or type(declared) is not int
    ):
        raise MeasurementError("response contract profile or byte metadata is invalid")
    measured = len(canonical_response_bytes(contract))
    if measured != declared or measured > budget:
        raise MeasurementError("response contract canonical byte accounting failed")
    if (
        not isinstance(contract.get("provenance"), dict)
        or not contract["provenance"].get("source")
        or not isinstance(contract.get("completeness"), dict)
        or "complete" not in contract["completeness"]
        or not isinstance(contract.get("continuation"), dict)
        or not contract["continuation"].get("strategy")
    ):
        raise MeasurementError("provenance, completeness, or continuation is missing")
    _validate_redaction_boundary(contract)
    return measured


def _tool_result_parts(contract: dict[str, Any]) -> tuple[dict[str, Any], str]:
    result = _contract_tool_result(contract)
    structured = getattr(result, "structured_content", None)
    content = getattr(result, "content", None)
    if not isinstance(structured, dict) or not isinstance(content, list) or len(content) != 1:
        raise MeasurementError("FastMCP result did not expose one authoritative structure")
    text = getattr(content[0], "text", None)
    if not isinstance(text, str):
        raise MeasurementError("FastMCP result did not expose one safety text item")
    if canonical_response_bytes(structured) != canonical_response_bytes(contract):
        raise MeasurementError("FastMCP structured content differs from the contract")
    return structured, text


def _validate_safety_summary(
    contract: dict[str, Any],
    *,
    surface: str,
    profile: str,
) -> int:
    _structured, text = _tool_result_parts(contract)
    if not text.startswith(MCP_SAFETY_SUMMARY_PREFIX):
        raise MeasurementError("MCP safety summary prefix is invalid")
    try:
        summary = json.loads(text[len(MCP_SAFETY_SUMMARY_PREFIX) :])
    except json.JSONDecodeError as exc:
        raise MeasurementError("MCP safety summary is invalid JSON") from exc
    ceiling = (
        MCP_FULL_SAFETY_SUMMARY_BYTES
        if profile == "full"
        else MCP_COMPACT_SAFETY_SUMMARY_BYTES
    )
    measured = len(text.encode("utf-8"))
    if (
        not isinstance(summary, dict)
        or summary.get("schema") != "synapse-s2.mcp-safety-summary.v1"
        or summary.get("operation") != surface
        or summary.get("ok") is not True
        or summary.get("structuredContent_required") is not True
        or summary.get("max_bytes") != ceiling
        or measured > ceiling
    ):
        raise MeasurementError("MCP safety summary contract or byte ceiling failed")
    if BENCHMARK_SECRET_CANARY in text or BENCHMARK_PATH_CANARY in text:
        raise MeasurementError("MCP safety summary exposed a benchmark canary")
    if mask_public_paths(text) != text:
        raise MeasurementError("MCP safety summary exposed a local path")
    if surface == "agent-hydration":
        delivery = summary.get("delivery")
        compact_delivery = contract.get("data", {}).get("delivery", {})
        if profile == "full":
            source = contract.get("data", {}).get("payload", {})
            expected_count = len(source.get("deliveries", []))
        else:
            expected_count = len(compact_delivery.get("deployments", []))
        receipts = delivery.get("receipts", []) if isinstance(delivery, dict) else []
        if (
            not isinstance(receipts, list)
            or len(receipts) != expected_count
            or any(
                not isinstance(item, dict)
                or not item.get("receipt_id")
                or not item.get("event_id")
                or not item.get("event_type")
                or not item.get("source_surface")
                or not item.get("summary")
                for item in receipts
            )
        ):
            raise MeasurementError(
                "MCP safety summary cannot support every receipt decision"
            )
    return measured


def _agent_bijection(contract: dict[str, Any]) -> dict[str, Any]:
    delivery = contract.get("data", {}).get("delivery", {})
    deployments = delivery.get("deployments", []) if isinstance(delivery, dict) else []
    receipt_values = [str(item.get("receipt_id") or "") for item in deployments]
    event_values = [int(item.get("event_id") or 0) for item in deployments]
    one_to_one = (
        bool(deployments)
        and len(receipt_values) == len(set(receipt_values))
        and len(event_values) == len(set(event_values))
        and all(receipt_values)
        and all(event_values)
        and delivery.get("ack_required") is True
    )
    if not one_to_one:
        raise MeasurementError("compact agent delivery is not receipt/event one-to-one")
    return {
        "receipt_count": len(receipt_values),
        "event_count": len(event_values),
        "unique_receipt_count": len(set(receipt_values)),
        "unique_event_count": len(set(event_values)),
        "one_to_one": True,
        "ack_required": True,
    }


def _returned_counts(surface: str, contract: dict[str, Any]) -> dict[str, int]:
    data = contract.get("data", {})
    if surface == "memory-list":
        return {"entries": int(data.get("returned") or 0)}
    if surface == "memory-graph":
        return {
            "nodes": int(data.get("returned_nodes") or 0),
            "edges": int(data.get("returned_edges") or 0),
        }
    if surface == "agent-hydration":
        delivery = data.get("delivery", {})
        return {"deployments": len(delivery.get("deployments", []))}
    pagination = contract.get("pagination", {})
    returned = pagination.get("returned", {}) if isinstance(pagination, dict) else {}
    return {
        str(key): int(value)
        for key, value in returned.items()
        if type(value) is int
    }


def _reduction(before: int, after: int) -> tuple[int, float]:
    if before <= 0 or after < 0:
        raise MeasurementError("response byte comparison is invalid")
    reduced = before - after
    return reduced, round((100.0 * reduced) / before, 3)


def _measure_surface(
    surface: str,
    source: dict[str, Any],
) -> dict[str, Any]:
    installed_payload = source["installed"]
    same_payload = source["same"]

    installed_first = project_response(
        surface,
        copy.deepcopy(installed_payload),
        mode="compact",
        max_response_bytes=INSTALLED_COMPACT_BYTES,
    )
    installed_second = project_response(
        surface,
        copy.deepcopy(installed_payload),
        mode="compact",
        max_response_bytes=INSTALLED_COMPACT_BYTES,
    )
    installed_bytes = _validate_contract(
        installed_first,
        surface=surface,
        profile="compact",
        budget=INSTALLED_COMPACT_BYTES,
    )
    if canonical_response_bytes(installed_first) != canonical_response_bytes(
        installed_second
    ):
        raise MeasurementError("installed compact projection is not deterministic")
    installed_safety_bytes = _validate_safety_summary(
        installed_first,
        surface=surface,
        profile="compact",
    )
    _structured, installed_safety_repeat = _tool_result_parts(installed_second)
    _structured, installed_safety_first = _tool_result_parts(installed_first)
    if installed_safety_first != installed_safety_repeat:
        raise MeasurementError("installed MCP safety summary is not deterministic")

    same_compact_first = project_response(
        surface,
        copy.deepcopy(same_payload),
        mode="compact",
        max_response_bytes=INSTALLED_COMPACT_BYTES,
    )
    same_compact_second = project_response(
        surface,
        copy.deepcopy(same_payload),
        mode="compact",
        max_response_bytes=INSTALLED_COMPACT_BYTES,
    )
    same_compact_bytes = _validate_contract(
        same_compact_first,
        surface=surface,
        profile="compact",
        budget=INSTALLED_COMPACT_BYTES,
    )
    if canonical_response_bytes(same_compact_first) != canonical_response_bytes(
        same_compact_second
    ):
        raise MeasurementError("same-source compact projection is not deterministic")
    same_compact_safety_bytes = _validate_safety_summary(
        same_compact_first,
        surface=surface,
        profile="compact",
    )

    same_full_first = project_response(
        surface,
        copy.deepcopy(same_payload),
        mode="full",
        max_response_bytes=FULL_DIAGNOSTIC_BYTES,
    )
    same_full_second = project_response(
        surface,
        copy.deepcopy(same_payload),
        mode="full",
        max_response_bytes=FULL_DIAGNOSTIC_BYTES,
    )
    same_full_bytes = _validate_contract(
        same_full_first,
        surface=surface,
        profile="full",
        budget=FULL_DIAGNOSTIC_BYTES,
    )
    if canonical_response_bytes(same_full_first) != canonical_response_bytes(
        same_full_second
    ):
        raise MeasurementError("same-source full projection is not deterministic")
    same_full_safety_bytes = _validate_safety_summary(
        same_full_first,
        surface=surface,
        profile="full",
    )

    legacy_bytes = len(_legacy_wire_bytes(source["requested"]))
    installed_reduced, installed_percent = _reduction(legacy_bytes, installed_bytes)
    same_legacy_bytes = len(_legacy_wire_bytes(same_payload))
    same_reduced, same_percent = _reduction(
        same_legacy_bytes,
        same_compact_bytes,
    )
    contract_metadata = installed_first["response_contract"]
    omissions = contract_metadata.get("omissions", {})
    completeness = installed_first.get("completeness", {})
    result: dict[str, Any] = {
        "surface": surface,
        "requested_limit": int(source["requested_limit"]),
        "effective_limit": int(source["effective_limit"]),
        "installed_policy": {
            "baseline": "legacy-requested-source",
            "baseline_bytes": legacy_bytes,
            "compact_structured_bytes": installed_bytes,
            "compact_safety_bytes": installed_safety_bytes,
            "reduction_bytes": installed_reduced,
            "reduction_percent": installed_percent,
        },
        "same_source": {
            "baseline": "legacy-identical-source",
            "baseline_bytes": same_legacy_bytes,
            "compact_structured_bytes": same_compact_bytes,
            "compact_safety_bytes": same_compact_safety_bytes,
            "reduction_bytes": same_reduced,
            "reduction_percent": same_percent,
        },
        "full_diagnostic": {
            "same_source_structured_bytes": same_full_bytes,
            "same_source_safety_bytes": same_full_safety_bytes,
            "within_diagnostic_budget": True,
        },
        "contract": {
            "schema": CONTRACT_SCHEMA,
            "version": CONTRACT_VERSION,
            "profile": "compact",
            "max_structured_bytes": INSTALLED_COMPACT_BYTES,
            "max_safety_bytes": MCP_COMPACT_SAFETY_SUMMARY_BYTES,
            "canonical_size_matches_declared": True,
            "within_structured_budget": True,
            "within_safety_budget": True,
            "projection_deterministic": True,
            "safety_summary_deterministic": True,
            "truncated": bool(contract_metadata.get("truncated")),
            "omission_count": sum(
                int(value)
                for value in omissions.values()
                if type(value) is int and value >= 0
            ),
            "omission_sections": sorted(str(key) for key in omissions),
            "completeness_known": type(completeness.get("complete")) is bool,
            "completeness_reason": str(completeness.get("reason") or ""),
            "provenance_present": True,
            "public_boundary_stable": True,
            "secret_canary_redacted": True,
            "path_canary_masked": True,
        },
        "returned_counts": _returned_counts(surface, installed_first),
    }
    if surface == "agent-hydration":
        result["delivery_safety"] = _agent_bijection(installed_first)
    return result


def _release_benchmark_leases(
    backend: SpikingAttentionBackend,
    *,
    context_id: str,
    leases: list[tuple[str, str, list[str]]],
) -> None:
    failures = 0
    for agent, consumer, receipts in leases:
        if not receipts:
            continue
        try:
            released = backend.release_context_events(
                context_id=context_id,
                agent_id=agent,
                consumer_instance_id=consumer,
                receipt_ids=receipts,
            )
            failures += int(released.get("released_count") or 0) != len(receipts)
        except Exception:
            failures += 1
    if failures:
        raise MeasurementError("benchmark delivery leases could not be released cleanly")


def measure_restored_database(
    *,
    database_path: Path,
    capture_root: Path,
    workspace_root: Path,
    context_id: str,
) -> list[dict[str, Any]]:
    if not database_path.is_file() or database_path.is_symlink():
        raise MeasurementError("restored database is missing or unsafe")
    if not capture_root.is_dir() or capture_root.is_symlink():
        raise MeasurementError("restored capture root is missing or unsafe")
    if not _paths_overlap(database_path, workspace_root):
        raise MeasurementError("benchmark database must stay inside the disposable workspace")
    if not _paths_overlap(capture_root, workspace_root):
        raise MeasurementError("benchmark capture root must stay inside the disposable workspace")

    with _isolated_runtime_environment(
        workspace_root=workspace_root,
        database_path=database_path,
        capture_root=capture_root,
    ) as paths:
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=64,
            default_top_k=16,
            compile_graph=False,
            state_path=paths["state_path"],
            memory_path=database_path,
            embedding_provider_name="lexical-hash",
            control_plane_only=True,
        )
        leases: list[tuple[str, str, list[str]]] = []
        primary_error: BaseException | None = None
        try:
            sources, leases = _source_payloads(backend, context_id=context_id)
            return [
                _measure_surface(surface, sources[surface])
                for surface in (
                    "memory-list",
                    "memory-graph",
                    "cortex-state",
                    "agent-hydration",
                )
            ]
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            if leases:
                try:
                    _release_benchmark_leases(
                        backend,
                        context_id=context_id,
                        leases=leases,
                    )
                except Exception:
                    if primary_error is None:
                        raise


def _aggregate_report(
    *,
    surfaces: list[dict[str, Any]],
    recovery: dict[str, Any],
) -> dict[str, Any]:
    legacy_total = sum(
        int(item["installed_policy"]["baseline_bytes"]) for item in surfaces
    )
    installed_total = sum(
        int(item["installed_policy"]["compact_structured_bytes"])
        for item in surfaces
    )
    same_legacy_total = sum(
        int(item["same_source"]["baseline_bytes"]) for item in surfaces
    )
    same_compact_total = sum(
        int(item["same_source"]["compact_structured_bytes"])
        for item in surfaces
    )
    installed_reduced, installed_percent = _reduction(legacy_total, installed_total)
    same_reduced, same_percent = _reduction(
        same_legacy_total,
        same_compact_total,
    )
    report = {
        "schema": EVIDENCE_SCHEMA,
        "version": EVIDENCE_VERSION,
        "status": "pass",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "installed_profile": "compact",
            "compact_structured_max_bytes": INSTALLED_COMPACT_BYTES,
            "compact_safety_max_bytes": MCP_COMPACT_SAFETY_SUMMARY_BYTES,
            "full_diagnostic_max_bytes": FULL_DIAGNOSTIC_BYTES,
            "full_safety_max_bytes": MCP_FULL_SAFETY_SUMMARY_BYTES,
            "transport_framing_included": False,
            "token_counts_included": False,
        },
        "recovery": {
            "verified_phase5_bundle": bool(recovery.get("bundle_verified")),
            "trusted_local_identity": bool(
                recovery.get("receipt_identity_trusted")
            ),
            "isolated_restore_verified": bool(
                recovery.get("isolated_restore_verified")
            ),
            "cutover_ready": bool(recovery.get("cutover_ready")),
            "live_alias_count": 0,
        },
        "fixture": {
            "source": "isolated-verified-recovery",
            "benchmark_event_count": BENCHMARK_EVENT_COUNT,
            "benchmark_writes_disposable_only": True,
            "raw_evidence_included": False,
        },
        "surfaces": surfaces,
        "aggregate": {
            "surface_count": len(surfaces),
            "installed_policy": {
                "baseline_bytes": legacy_total,
                "compact_structured_bytes": installed_total,
                "reduction_bytes": installed_reduced,
                "reduction_percent": installed_percent,
            },
            "same_source": {
                "baseline_bytes": same_legacy_total,
                "compact_structured_bytes": same_compact_total,
                "reduction_bytes": same_reduced,
                "reduction_percent": same_percent,
            },
        },
        "gates": {
            "bundle_and_restore_verified": True,
            "isolated_paths_verified": True,
            "canonical_sizes_verified": True,
            "structured_budgets_verified": True,
            "safety_budgets_verified": True,
            "projection_determinism_verified": True,
            "delivery_bijection_verified": True,
            "completeness_explicit": True,
            "redaction_verified": True,
            "provenance_verified": True,
            "aggregate_only": True,
        },
        "observations": {
            "installed_policy_reduction_positive": installed_reduced > 0,
            "same_source_reduction_positive": same_reduced > 0,
            "reduction_is_informational": True,
        },
    }
    if not all(report["gates"].values()):
        raise MeasurementError("one or more aggregate acceptance gates failed")
    assert_aggregate_only(report)
    return report


def assert_aggregate_only(value: Any, *, location: str = "root") -> None:
    """Reject identity-bearing or raw-content values from durable evidence."""

    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold()
            if (
                normalized.endswith("_id")
                or normalized.endswith("_path")
                or "digest" in normalized
                or "signature" in normalized
            ):
                raise MeasurementError(
                    f"aggregate evidence contains a forbidden field at {location}"
                )
            assert_aggregate_only(item, location=f"{location}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            assert_aggregate_only(item, location=f"{location}[{index}]")
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise MeasurementError("aggregate evidence contains a non-finite number")
    if isinstance(value, str):
        if (
            value.startswith("/")
            or _ABSOLUTE_WINDOWS_PATH_RE.search(value)
            or _RAW_IDENTIFIER_RE.search(value)
            or (
                _RAW_DIGEST_RE.search(value)
                and location != "root.source_control.revision"
            )
            or BENCHMARK_SECRET_CANARY in value
            or BENCHMARK_PATH_CANARY in value
        ):
            raise MeasurementError(
                f"aggregate evidence contains forbidden raw material at {location}"
            )


def run_acceptance_measurement(
    *,
    receipt_path: Path,
    live_memory_db: Path,
    context_id: str,
    restore_driver: Callable[[Path, Path, Path], dict[str, Any]] = restore_verified_bundle,
) -> dict[str, Any]:
    receipt = _private_regular_file(receipt_path, label="Phase 5 bundle receipt")
    live_db = _private_regular_file(live_memory_db, label="live memory database")
    try:
        context_id = validate_public_identifier(
            context_id,
            field="measurement context_id",
            max_chars=128,
        )
    except ValueError as exc:
        raise MeasurementError("context is not a valid public identifier") from exc

    with tempfile.TemporaryDirectory(prefix="synapse-s2-phase6-measure-") as temporary:
        workspace = Path(temporary).resolve()
        os.chmod(workspace, 0o700)
        metadata = os.lstat(workspace)
        if stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_uid != os.getuid():
            raise MeasurementError("measurement workspace is not private")
        if _paths_overlap(workspace, live_db.parent):
            raise MeasurementError("measurement workspace aliases the live store")
        restore_root = workspace / "isolated-restore"
        recovery = restore_driver(receipt, live_db, restore_root)
        restored_db = Path(str(recovery.get("database_path") or "")).resolve()
        restored_capture = Path(str(recovery.get("capture_root") or "")).resolve()
        if (
            recovery.get("bundle_verified") is not True
            or recovery.get("receipt_identity_trusted") is not True
            or recovery.get("isolated_restore_verified") is not True
            or recovery.get("cutover_ready") is not True
            or _paths_overlap(restored_db, live_db)
            or not _paths_overlap(restored_db, workspace)
            or not _paths_overlap(restored_capture, workspace)
        ):
            raise MeasurementError("recovery driver did not prove an isolated restore")
        surfaces = measure_restored_database(
            database_path=restored_db,
            capture_root=restored_capture,
            workspace_root=workspace,
            context_id=context_id,
        )
        return _aggregate_report(surfaces=surfaces, recovery=recovery)


def _git_tree_is_clean(
    repo_root: Path,
    *,
    allowed_untracked: Path | None = None,
) -> bool:
    completed = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo_root,
        capture_output=True,
        timeout=30.0,
        check=False,
    )
    if completed.returncode != 0:
        raise MeasurementError("git status failed before evidence publication")
    records = [item for item in completed.stdout.split(b"\0") if item]
    if allowed_untracked is None:
        return not records
    expected = b"?? " + os.fsencode(allowed_untracked.as_posix())
    return records == [expected]


def _git_revision(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    revision = completed.stdout.strip().casefold()
    if completed.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise MeasurementError("git revision could not be bound to evidence")
    return revision


def _verify_import_attestation(repo_root: Path) -> None:
    if repo_root.resolve(strict=True) != ROOT or _IMPORT_ATTESTATION_ERROR:
        raise MeasurementError(
            "measurement imports are not bound to the selected repository"
        )
    for _name, path, imported_digest in _IMPORTED_SOURCE_ATTESTATION:
        try:
            current_path = path.resolve(strict=True)
            current_path.relative_to(ROOT)
            current_digest = hashlib.sha256(current_path.read_bytes()).hexdigest()
        except (OSError, ValueError) as exc:
            raise MeasurementError(
                "measurement import attestation could not be reverified"
            ) from exc
        if current_digest != imported_digest:
            raise MeasurementError(
                "measurement source changed after import; start a fresh process"
            )


def _source_control_state(
    repo_root: Path,
    *,
    allow_dirty_test_only: bool,
) -> dict[str, Any]:
    if allow_dirty_test_only and os.getenv(TEST_MODE_ENV) != "1":
        raise MeasurementError("dirty-tree bypass is restricted to explicit test mode")
    clean_worktree = _git_tree_is_clean(repo_root)
    if not allow_dirty_test_only and not clean_worktree:
        raise MeasurementError(
            "refusing durable evidence from a dirty tree; commit implementation first"
        )
    return {
        "revision": _git_revision(repo_root),
        "clean_worktree": clean_worktree,
    }


def _repo_relative_output(repo_root: Path, output_path: Path) -> tuple[Path, Path]:
    resolved_repo = repo_root.expanduser().resolve(strict=True)
    if not resolved_repo.is_dir():
        raise MeasurementError("repository root is not a directory")
    requested = output_path.expanduser()
    if not requested.is_absolute():
        requested = resolved_repo / requested
    # Resolve platform aliases such as macOS ``/var`` -> ``/private/var`` and
    # reject any existing symlinked ancestor that already escapes the repo.
    normalized = Path(os.path.abspath(os.fspath(requested))).resolve(strict=False)
    try:
        relative = normalized.relative_to(resolved_repo)
    except ValueError as exc:
        raise MeasurementError(
            "durable evidence output must stay inside the repository"
        ) from exc
    if not relative.parts or relative.name in {"", ".", ".."}:
        raise MeasurementError("durable evidence output filename is invalid")
    return resolved_repo, relative


def _atomic_write_new_json_at(
    repo_root: Path,
    relative_output: Path,
    payload: dict[str, Any],
    *,
    post_publish: Callable[[], None] | None = None,
) -> None:
    """Create one evidence file without following repository-internal symlinks."""

    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    directory_fd = os.open(repo_root, directory_flags)
    try:
        for component in relative_output.parts[:-1]:
            if component in {"", ".", ".."}:
                raise MeasurementError("durable evidence parent is invalid")
            try:
                child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o755, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                    child_fd = os.open(
                        component,
                        directory_flags,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise MeasurementError(
                        "durable evidence parent could not be created safely"
                    ) from exc
            except OSError as exc:
                raise MeasurementError(
                    "durable evidence output must stay inside the repository"
                ) from exc
            os.close(directory_fd)
            directory_fd = child_fd

        target_name = relative_output.name
        if target_name in {"", ".", ".."}:
            raise MeasurementError("durable evidence output filename is invalid")
        _atomic_write_new_json_fd(
            directory_fd,
            target_name,
            payload,
            post_publish=post_publish,
        )
    finally:
        os.close(directory_fd)


def _atomic_write_new_json_fd(
    directory_fd: int,
    target_name: str,
    payload: dict[str, Any],
    *,
    post_publish: Callable[[], None] | None = None,
) -> None:
    temporary_name = f".{target_name}.{os.getpid()}.{time.time_ns()}.tmp"
    descriptor = -1
    try:
        try:
            os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MeasurementError("evidence output already exists; refusing overwrite")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name,
            flags,
            0o644,
            dir_fd=directory_fd,
        )
        encoded = _canonical_json_bytes(payload) + b"\n"
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("evidence publication made no write progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.stat(target_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MeasurementError("evidence output appeared during publication")
        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise MeasurementError(
                "evidence output already exists; refusing overwrite"
            ) from exc
        published = os.stat(
            target_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        if post_publish is not None:
            try:
                post_publish()
            except Exception:
                try:
                    current = os.stat(
                        target_name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    current = None
                if (
                    current is not None
                    and current.st_dev == published.st_dev
                    and current.st_ino == published.st_ino
                ):
                    os.unlink(target_name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def write_durable_evidence(
    *,
    report: dict[str, Any],
    output_path: Path,
    repo_root: Path,
    allow_dirty_test_only: bool = False,
    source_control_preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    assert_aggregate_only(report)
    resolved_repo, relative_output = _repo_relative_output(repo_root, output_path)
    if resolved_repo == ROOT:
        _verify_import_attestation(resolved_repo)
    preflight = (
        dict(source_control_preflight)
        if source_control_preflight is not None
        else _source_control_state(
            resolved_repo,
            allow_dirty_test_only=allow_dirty_test_only,
        )
    )
    if set(preflight) != {"revision", "clean_worktree"}:
        raise MeasurementError("source control preflight is invalid")
    current = _source_control_state(
        resolved_repo,
        allow_dirty_test_only=allow_dirty_test_only,
    )
    if current != preflight:
        raise MeasurementError(
            "source control changed during measurement; rerun measurement"
        )
    bound_report = copy.deepcopy(report)
    bound_report["source_control"] = preflight
    assert_aggregate_only(bound_report)
    if _source_control_state(
        resolved_repo,
        allow_dirty_test_only=allow_dirty_test_only,
    ) != preflight:
        raise MeasurementError(
            "source control changed during evidence publication; rerun measurement"
        )
    def post_publish_check() -> None:
        if resolved_repo == ROOT:
            _verify_import_attestation(resolved_repo)
        if _git_revision(resolved_repo) != preflight["revision"]:
            raise MeasurementError(
                "source control changed during evidence publication; rerun measurement"
            )
        if preflight["clean_worktree"] and not _git_tree_is_clean(
            resolved_repo,
            allowed_untracked=relative_output,
        ):
            raise MeasurementError(
                "worktree changed during evidence publication; rerun measurement"
            )

    _atomic_write_new_json_at(
        resolved_repo,
        relative_output,
        bound_report,
        post_publish=post_publish_check,
    )
    return bound_report


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(
        description="Measure compact token contracts from a verified isolated restore.",
    )
    parser.add_argument(
        "--receipt",
        required=True,
        help="Explicit private Phase 5 recovery bundle receipt.",
    )
    parser.add_argument(
        "--memory-db",
        default="",
        help="Authoritative live DB used only to locate local recovery trust material.",
    )
    parser.add_argument("--context", default="default")
    parser.add_argument(
        "--output",
        default="",
        help="Optional new aggregate evidence JSON path inside the repository.",
    )
    parser.add_argument("--repo-root", default=str(ROOT))
    parser.add_argument(
        "--allow-dirty-test-only",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _verify_import_attestation(ROOT)
        source_control_preflight: dict[str, Any] | None = None
        if args.output:
            resolved_repo, _relative_output = _repo_relative_output(
                Path(args.repo_root),
                Path(args.output),
            )
            _verify_import_attestation(resolved_repo)
            source_control_preflight = _source_control_state(
                resolved_repo,
                allow_dirty_test_only=bool(args.allow_dirty_test_only),
            )
        receipt = _private_regular_file(
            Path(args.receipt),
            label="Phase 5 bundle receipt",
        )
        live_db = resolve_live_memory_db(
            receipt,
            Path(args.memory_db) if args.memory_db else None,
        )
        report = run_acceptance_measurement(
            receipt_path=receipt,
            live_memory_db=live_db,
            context_id=str(args.context),
        )
        if args.output:
            report = write_durable_evidence(
                report=report,
                output_path=Path(args.output),
                repo_root=Path(args.repo_root),
                allow_dirty_test_only=bool(args.allow_dirty_test_only),
                source_control_preflight=source_control_preflight,
            )
        print(_canonical_json_bytes(report).decode("utf-8"))
        return 0
    except Exception as exc:
        error = {
            "schema": EVIDENCE_SCHEMA,
            "version": EVIDENCE_VERSION,
            "status": "failed",
            "error": safe_public_error(exc, fallback="measurement failed"),
        }
        print(_canonical_json_bytes(error).decode("utf-8"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

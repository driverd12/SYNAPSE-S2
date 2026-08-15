from __future__ import annotations

import copy
import contextvars
import functools
import json
import math
import re
import unicodedata
from typing import Any, Callable

from redaction import (
    mask_public_paths,
    redact_sensitive_value,
    reject_sensitive_identifier,
    safe_public_error,
    strip_untrusted_raw_digest_fields,
    validate_public_identifier,
)


CONTRACT_SCHEMA = "synapse-s2.token-contract.v1"
CONTRACT_VERSION = 1
CONTEXT_DELIVERY_PROTOCOL = "context-delivery.v2"
CONTEXT_DELIVERY_MODE = "leased-at-least-once"
MIN_RESPONSE_BYTES = 4 * 1024
MAX_RESPONSE_BYTES = 128 * 1024
DEFAULT_RESPONSE_BYTES = {
    "agent-hydration": 16 * 1024,
    "memory-retrieval": 24 * 1024,
    "memory-list": 32 * 1024,
    "memory-graph": 48 * 1024,
    "cortex-state": 16 * 1024,
    "media-similarity": 16 * 1024,
}
COMPACT_SOURCE_LIMITS = {
    "agent-events": 8,
    "agent-graph": 20,
    "memory-retrieval": 8,
    "memory-list": 50,
    "memory-graph": 30,
    "cortex-state": 20,
    "media-similarity": 10,
}
COMPACT_RETRIEVAL_ITEM_BYTES = {
    "memory-list": 1_024,
    "memory-graph": 2_048,
    "cortex-state": 1_024,
}
COMPACT_RETRIEVAL_FIXED_BYTES = 3_072
RETRIEVAL_PAGE_SCHEMA = "synapse-s2.retrieval-page.v2"
RETRIEVAL_CURSOR_STRATEGY = "authenticated-keyset-v2"
_RETRIEVAL_CURSOR_RE = re.compile(r"\As2rc2\.[A-Za-z0-9_-]{1,4000}\.[A-Za-z0-9_-]{43}\Z")
_RETRIEVAL_REVISION_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_RETRIEVAL_ORIGIN_RE = re.compile(r"\As2origin_[0-9a-f]{32}\Z")
SURFACE_ALIASES = {
    "agent-context-hydrate": "agent-hydration",
    "agent-hydration": "agent-hydration",
    "hydrate": "agent-hydration",
    "retrieve": "memory-retrieval",
    "retrieve-v2": "memory-retrieval",
    "memory-retrieval": "memory-retrieval",
    "list-memory": "memory-list",
    "memory-list": "memory-list",
    "graph": "memory-graph",
    "memory-graph": "memory-graph",
    "cortex": "cortex-state",
    "cortex-state": "cortex-state",
    "image-similar": "media-similarity",
    "media-similarity": "media-similarity",
}
_SAFE_CODE_RE = re.compile(r"[^a-z0-9_.:-]+")
_CONTEXT_DELIVERY_ID_RE = re.compile(r"[A-Za-z0-9_.:@-]+")
_CONTEXT_RECEIPT_ID_RE = re.compile(r"ctxrcpt_[A-Za-z0-9_-]{43}")
_PROJECTION_OMISSIONS: contextvars.ContextVar[dict[str, int] | None] = (
    contextvars.ContextVar("synapse_s2_projection_omissions", default=None)
)


TOKEN_CONTRACT_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "schema",
        "version",
        "operation",
        "ok",
        "data",
        "provenance",
        "warnings",
        "pagination",
        "completeness",
        "continuation",
        "response_contract",
    ],
    "properties": {
        "schema": {"const": CONTRACT_SCHEMA},
        "version": {"const": CONTRACT_VERSION},
        "operation": {"type": "string"},
        "ok": {"type": "boolean"},
        "data": {"type": "object"},
        "provenance": {"type": "object"},
        "warnings": {"type": "array", "items": {"type": "object"}},
        "pagination": {"type": "object"},
        "completeness": {"type": "object"},
        "continuation": {"type": "object"},
        "response_contract": {"type": "object"},
    },
    "additionalProperties": False,
}


class ResponseContractError(ValueError):
    """A response cannot be represented without violating its contract."""


class ResponseBudgetError(ResponseContractError):
    """The minimum safe response cannot fit in the requested byte budget."""


def _audited_projection(function: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    """Count every lossy allowlist projection before byte-budget compaction."""

    @functools.wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> dict[str, Any]:
        token = _PROJECTION_OMISSIONS.set({})
        try:
            return function(*args, **kwargs)
        finally:
            _PROJECTION_OMISSIONS.reset(token)

    return wrapped


def normalize_response_mode(value: Any, *, default: str = "compact") -> str:
    if value is None or value == "":
        raw = str(default or "compact")
    elif isinstance(value, str):
        try:
            reject_sensitive_identifier(value, field="response mode")
        except ValueError as exc:
            raise ResponseContractError(
                "response mode must be compact or full"
            ) from exc
        raw = value
    else:
        raise ResponseContractError("response mode must be compact or full")
    normalized = raw.strip().casefold().replace("_", "-")
    if normalized not in {"compact", "full"}:
        raise ResponseContractError("response mode must be compact or full")
    return normalized


def normalize_response_budget(
    value: Any,
    *,
    default_bytes: int,
) -> int:
    if value is None or value == "":
        budget = int(default_bytes)
    elif isinstance(value, bool):
        raise ResponseBudgetError("max output bytes must be an integer")
    elif isinstance(value, int):
        budget = value
    elif isinstance(value, str):
        try:
            reject_sensitive_identifier(value, field="max output bytes")
        except ValueError as exc:
            raise ResponseBudgetError(
                "max output bytes must be an integer"
            ) from exc
        text = value.strip()
        if not text.isascii() or not text.isdecimal():
            raise ResponseBudgetError("max output bytes must be an integer")
        budget = int(text)
    else:
        raise ResponseBudgetError("max output bytes must be an integer")
    if budget < MIN_RESPONSE_BYTES:
        raise ResponseBudgetError(
            f"max output bytes must be at least {MIN_RESPONSE_BYTES}"
        )
    if budget > MAX_RESPONSE_BYTES:
        raise ResponseBudgetError(
            f"max output bytes must not exceed {MAX_RESPONSE_BYTES}"
        )
    return budget


def normalize_surface(surface: Any) -> str:
    if not isinstance(surface, str):
        raise ResponseContractError("response surface is unsupported")
    normalized = SURFACE_ALIASES.get(surface.strip().casefold().replace("_", "-"))
    if normalized is None:
        raise ResponseContractError("response surface is unsupported")
    return normalized


def compact_agent_event_limit(*, requested_limit: int, max_output_bytes: int) -> int:
    """Cap leases before delivery so every receipt can fit the selected budget."""

    requested = max(1, int(requested_limit))
    budget = normalize_response_budget(
        max_output_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["agent-hydration"],
    )
    # Reserve the fixed delivery, Cortex, graph-summary, and namespace-safety
    # capsules before leasing receipts. Every leased receipt must remain
    # renderable even at the minimum 4 KiB contract.
    budget_bound = max(1, (budget - 3_072) // 768)
    return min(requested, COMPACT_SOURCE_LIMITS["agent-events"], budget_bound)


def compact_retrieval_page_limit(
    surface: Any,
    *,
    requested_limit: int,
    max_output_bytes: Any,
) -> int:
    """Choose a source page that can preserve every cursor-addressed item.

    Retrieval v2 must never fetch an item, drop it during compact projection,
    and then issue a cursor beyond it.  The conservative per-surface envelope
    keeps whole page identities while excerpt text remains shrinkable.
    """

    normalized_surface = normalize_surface(surface)
    if normalized_surface not in COMPACT_RETRIEVAL_ITEM_BYTES:
        raise ResponseContractError("response surface does not support retrieval pages")
    requested = max(1, int(requested_limit))
    budget = normalize_response_budget(
        max_output_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES[normalized_surface],
    )
    available = max(1, budget - COMPACT_RETRIEVAL_FIXED_BYTES)
    budget_bound = max(
        1,
        available // COMPACT_RETRIEVAL_ITEM_BYTES[normalized_surface],
    )
    return min(
        requested,
        COMPACT_SOURCE_LIMITS[normalized_surface],
        budget_bound,
    )


def compact_retrieval_result_limit(
    *,
    requested_limit: int,
    max_output_bytes: Any,
) -> int:
    """Bound structured recall before ranking so compact output drops no hits."""

    requested = max(1, int(requested_limit))
    budget = normalize_response_budget(
        max_output_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["memory-retrieval"],
    )
    budget_bound = max(1, (budget - 4_096) // 2_304)
    return min(
        requested,
        COMPACT_SOURCE_LIMITS["memory-retrieval"],
        budget_bound,
    )


def _validate_json_mapping_keys(
    value: Any,
    *,
    _seen: set[int] | None = None,
) -> None:
    seen = _seen if _seen is not None else set()
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            raise ResponseContractError("response contains unsupported recursive values")
        seen.add(identity)
        try:
            if any(not isinstance(key, str) for key in value):
                raise ResponseContractError("response contains unsupported mapping keys")
            for item in value.values():
                _validate_json_mapping_keys(item, _seen=seen)
        finally:
            seen.discard(identity)
    elif isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in seen:
            raise ResponseContractError("response contains unsupported recursive values")
        seen.add(identity)
        try:
            for item in value:
                _validate_json_mapping_keys(item, _seen=seen)
        finally:
            seen.discard(identity)


def canonical_response_bytes(payload: dict[str, Any]) -> bytes:
    try:
        _validate_json_mapping_keys(payload)
        rendered = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ResponseContractError("response contains unsupported values") from exc
    return rendered.encode("utf-8")


def _mask_full_response_paths(value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        masked = mask_public_paths(value)
        return masked, int(masked != value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            safe_key = mask_public_paths(key)
            if safe_key != key:
                count += 1
            candidate = safe_key
            ordinal = 2
            while candidate in result:
                candidate = f"{safe_key}#{ordinal}"
                ordinal += 1
            safe_item, item_count = _mask_full_response_paths(item)
            result[candidate] = safe_item
            count += item_count
        return result, count
    if isinstance(value, list):
        result_list: list[Any] = []
        count = 0
        for item in value:
            safe_item, item_count = _mask_full_response_paths(item)
            result_list.append(safe_item)
            count += item_count
        return result_list, count
    if isinstance(value, tuple):
        result_tuple: list[Any] = []
        count = 0
        for item in value:
            safe_item, item_count = _mask_full_response_paths(item)
            result_tuple.append(safe_item)
            count += item_count
        return tuple(result_tuple), count
    return value, 0


def serialize_response(payload: dict[str, Any]) -> str:
    return canonical_response_bytes(payload).decode("utf-8")


def response_error(
    *,
    operation: str,
    error: BaseException | str,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    surface = normalize_surface(operation)
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES[surface],
    )
    envelope = _base_envelope(
        surface=surface,
        mode="compact",
        budget=budget,
        data={
            "error": {
                "code": _error_code(error),
                "message": safe_public_error(error, fallback="request failed", max_chars=240),
                "retryable": False,
            }
        },
        provenance={"source": "response-boundary"},
        pagination=_unknown_pagination(),
        completeness={"complete": False, "reason": "request-failed"},
        continuation={"strategy": "correct-request-and-retry", "cursor": None},
        warnings=[
            _warning(
                "request-failed",
                "high",
                "The request was not completed; correct the error before relying on this response.",
                action_required=True,
            )
        ],
        ok=False,
    )
    return _finalize(envelope, budget=budget, shrinkers=[])


def project_response(
    surface: Any,
    payload: dict[str, Any],
    *,
    mode: Any = "compact",
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    normalized_surface = normalize_surface(surface)
    normalized_mode = normalize_response_mode(mode)
    if not isinstance(payload, dict):
        raise ResponseContractError("response payload must be an object")
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES[normalized_surface],
    )
    if normalized_mode == "full":
        return full_response(
            normalized_surface,
            payload,
            max_response_bytes=budget,
        )
    projector = {
        "agent-hydration": project_agent_hydration,
        "memory-retrieval": project_memory_retrieval,
        "memory-list": project_memory_list,
        "memory-graph": project_memory_graph,
        "cortex-state": project_cortex_state,
        "media-similarity": project_media_similarity,
    }[normalized_surface]
    return projector(payload, max_response_bytes=budget)


def full_response(
    surface: Any,
    payload: dict[str, Any],
    *,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    normalized_surface = normalize_surface(surface)
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=MAX_RESPONSE_BYTES,
    )
    _validate_surface_identities(normalized_surface, payload)
    try:
        copied = copy.deepcopy(
            {
                key: value
                for key, value in payload.items()
                if key not in {"_response_source", "_retrieval_page"}
            }
        )
        canonical_response_bytes(copied)
    except Exception as exc:
        raise ResponseContractError("full response contains unsupported values") from exc
    redacted, secret_redactions = redact_sensitive_value(copied)
    redacted, raw_digest_removals = strip_untrusted_raw_digest_fields(redacted)
    redacted, path_redactions = _mask_full_response_paths(redacted)
    if not isinstance(redacted, dict):  # pragma: no cover - copied is a dict
        raise ResponseContractError("full response redaction produced an invalid payload")
    copied = redacted
    if normalized_surface == "memory-graph":
        source_summary = payload.get("relationship_summary")
        copied_summary = copied.get("relationship_summary")
        if isinstance(source_summary, dict) and isinstance(copied_summary, dict):
            source_by_type = source_summary.get("by_type")
            if isinstance(source_by_type, dict):
                copied_summary["by_type"] = _safe_count_map(
                    source_by_type,
                    max_entries=None,
                    max_key_chars=None,
                )
    elif normalized_surface == "agent-hydration":
        source_graph_summary = payload.get("graph_summary")
        copied_graph_summary = copied.get("graph_summary")
        if isinstance(source_graph_summary, dict) and isinstance(
            copied_graph_summary, dict
        ):
            source_modes = source_graph_summary.get("relationship_modes")
            copied_modes = copied_graph_summary.get("relationship_modes")
            if isinstance(source_modes, dict) and isinstance(copied_modes, dict):
                source_by_type = source_modes.get("by_type")
                if isinstance(source_by_type, dict):
                    copied_modes["by_type"] = _safe_count_map(
                        source_by_type,
                        max_entries=None,
                        max_key_chars=None,
                    )
    transport_redactions = 0
    if normalized_surface == "agent-hydration":
        blocking = copied.get("blocking_delivery")
        if isinstance(blocking, dict) and "lease_owner" in blocking:
            blocking.pop("lease_owner", None)
            transport_redactions += 1
    total_redactions = (
        int(secret_redactions)
        + int(raw_digest_removals)
        + int(path_redactions)
        + transport_redactions
    )
    canonical_response_bytes(copied)
    warnings = _trusted_warnings(payload.get("warnings"))
    if total_redactions:
        warnings.append(
            _warning(
                "redacted",
                "warning",
                "Sensitive values, local paths, or untrusted raw-content digests were redacted.",
            )
        )
    agent_invariant_warnings: list[dict[str, Any]] = []
    if normalized_surface == "agent-hydration":
        warnings.extend(_cortex_session_warnings(payload.get("cortex_state")))
        agent_invariant_warnings = _agent_delivery_invariant_warnings(payload)
        warnings.extend(agent_invariant_warnings)
    elif normalized_surface == "cortex-state":
        warnings.extend(_cortex_session_warnings(payload))
    pagination = _unknown_pagination()
    completeness = {
        "complete": None,
        "reason": "authoritative-producer-did-not-provide-total",
    }
    continuation = {"strategy": "none", "cursor": None}
    retrieval_page = _retrieval_page_metadata(
        payload,
        surface=normalized_surface,
        mode="full",
    )
    if normalized_surface == "agent-hydration":
        source = _source_metadata(payload)
        deployments = _strict_object_list(payload.get("deliveries"), field="deliveries")
        delivery_observed = bool(payload.get("claim_events"))
        pagination = {
            "supported": True,
            "strategy": (
                "receipt-fenced-fifo" if delivery_observed else "not-observed"
            ),
            "requested_limit": source.get("requested_event_limit"),
            "effective_limit": source.get("effective_event_limit"),
            "returned": len(deployments),
            "has_more": (
                bool(payload.get("has_more_events"))
                if delivery_observed
                else None
            ),
            "next_cursor": None,
        }
        completeness = {
            "complete": None,
            "event_delivery_complete": (
                not bool(payload.get("has_more_events"))
                if delivery_observed
                else None
            ),
            "event_delivery_exact": True if delivery_observed else None,
            "reason": "graph-and-cortex-producers-do-not-expose-authoritative-totals",
        }
        continuation = _agent_delivery_continuation(payload)
    elif normalized_surface == "memory-retrieval":
        raw_completeness = payload.get("completeness")
        if not isinstance(raw_completeness, dict):
            raise ResponseContractError("retrieval completeness must be an object")
        source = _source_metadata(payload)
        returned = len(copied.get("items", []))
        has_more = _strict_boolean(
            raw_completeness.get("has_more"),
            field="completeness.has_more",
        )
        pagination = {
            "supported": False,
            "strategy": "deterministic-bounded-top-k",
            "requested_limit": source.get("requested_limit"),
            "effective_limit": source.get("effective_limit"),
            "returned": returned,
            "has_more": has_more,
            "next_cursor": None,
        }
        completeness = {
            "complete": _strict_boolean(
                raw_completeness.get("complete"),
                field="completeness.complete",
            ),
            "scope_complete": _strict_boolean(
                raw_completeness.get("scope_complete"),
                field="completeness.scope_complete",
            ),
            "query_terms_truncated": _strict_boolean(
                raw_completeness.get("query_terms_truncated"),
                field="completeness.query_terms_truncated",
            ),
            "candidate_scan_truncated": _strict_boolean(
                raw_completeness.get("candidate_scan_truncated"),
                field="completeness.candidate_scan_truncated",
            ),
            "result_set_truncated": _strict_boolean(
                raw_completeness.get("result_set_truncated"),
                field="completeness.result_set_truncated",
            ),
            "reason": (
                "bounded-result-set-has-more"
                if has_more
                else "bounded-result-set-complete"
            ),
        }
        continuation = {
            "strategy": (
                "refine-query-or-increase-result-limit" if has_more else "none"
            ),
            "cursor": None,
        }
        warnings.extend(_trusted_warnings(raw_completeness.get("warnings")))
    elif retrieval_page is not None:
        returned: Any
        if normalized_surface == "memory-list":
            returned = len(copied.get("entries", []))
        elif normalized_surface == "memory-graph":
            returned = {
                "nodes": len(copied.get("entries", [])),
                "relationships": len(copied.get("relationships", [])),
            }
        else:
            returned = {
                "working_memory": len(copied.get("working_memory", [])),
                "sessions": len(copied.get("active_sessions", [])),
                "goals": len(copied.get("goals", [])),
            }
        pagination, completeness, continuation = _retrieval_contract_fields(
            retrieval_page,
            returned=(
                retrieval_page["returned"]["entries"]
                if normalized_surface == "memory-list"
                else {
                    "nodes": retrieval_page["returned"]["nodes"],
                    "relationships": retrieval_page["returned"]["relationships"],
                }
                if normalized_surface == "memory-graph"
                else {
                    **returned,
                    "working_memory": retrieval_page["returned"]["working_memory"],
                }
            ),
        )
    envelope = _base_envelope(
        surface=normalized_surface,
        mode="full",
        budget=budget,
        data={"payload": copied},
        provenance={
            "source": "authoritative-backend",
            "payload_trust": "mixed-control-and-untrusted-evidence",
            "context_id": _atomic_identifier(
                (
                    payload.get("query", {}).get("context_id")
                    if normalized_surface == "memory-retrieval"
                    and isinstance(payload.get("query"), dict)
                    else payload.get("context_id")
                ),
                field="context_id",
                max_chars=128,
            ),
            "redaction_applied": total_redactions > 0,
            "redaction_count": total_redactions,
            "raw_digest_removal_count": int(raw_digest_removals),
            "origin_node": (
                retrieval_page["origin_node"]
                if retrieval_page is not None
                else None
            ),
        },
        pagination=pagination,
        completeness=completeness,
        continuation=continuation,
        warnings=_dedupe_warnings(warnings),
        ok="error" not in payload,
    )
    for warning in agent_invariant_warnings:
        _ensure_warning(envelope, warning)
    size = len(canonical_response_bytes(envelope))
    if size > budget:
        raise ResponseBudgetError(
            "full response exceeds max output bytes; request compact mode or a larger budget"
        )
    return _finalize(envelope, budget=budget, shrinkers=[])


@_audited_projection
def project_agent_hydration(
    payload: dict[str, Any],
    *,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["agent-hydration"],
    )
    _validate_surface_identities("agent-hydration", payload)
    event_rows = _strict_object_list(payload.get("events"), field="events")
    events: dict[int, dict[str, Any]] = {}
    for event in event_rows:
        event_id = _integer_identifier(event.get("event_id"), field="event_id")
        if event_id <= 0 or event_id in events:
            raise ResponseContractError("visible delivery events must have unique positive ids")
        events[event_id] = event
    deployments: list[dict[str, Any]] = []
    seen_receipts: set[str] = set()
    seen_delivery_events: set[int] = set()
    for delivery in _strict_object_list(payload.get("deliveries"), field="deliveries"):
        receipt_id = _context_receipt_identifier(delivery.get("receipt_id"))
        event_id = _integer_identifier(delivery.get("event_id"), field="event_id")
        if not receipt_id or receipt_id in seen_receipts:
            raise ResponseContractError("leased delivery receipts must be unique and non-empty")
        if event_id in seen_delivery_events:
            raise ResponseContractError("each visible event may have only one leased receipt")
        event = events.get(event_id)
        if event is None:
            raise ResponseContractError("every leased receipt must map to a visible event")
        seen_receipts.add(receipt_id)
        seen_delivery_events.add(event_id)
        state = _clean_text(delivery.get("state"), 32)
        if state != "leased":
            raise ResponseContractError("delivery state must be leased")
        deployment = {
            "receipt_id": receipt_id,
            "delivery_id": _context_delivery_identifier(
                delivery.get("delivery_id")
            ),
            "event_id": event_id,
            "state": state,
            "attempt_count": _safe_int(delivery.get("attempt_count")),
            "redelivered": bool(delivery.get("redelivered", False)),
            "lease_expires_at": _safe_number(delivery.get("lease_expires_at")),
            "event": {
                "event_type": _clean_text(event.get("event_type"), 80),
                "source_surface": _clean_text(event.get("source_surface"), 80),
                "summary": _clean_text(event.get("summary"), 360),
                "created_at": _safe_number(event.get("created_at")),
                "evidence": _project_event_evidence(event.get("payload_summary")),
                "trust": "untrusted-event-evidence",
            },
        }
        deployments.append(deployment)
    if set(events) != seen_delivery_events:
        raise ResponseContractError(
            "leased delivery events and visible events must form a one-to-one batch"
        )
    if bool(payload.get("ack_required")) != bool(deployments):
        raise ResponseContractError(
            "ack_required must be true exactly when leased receipts are returned"
        )

    recall_items = [
        {"excerpt": _clean_text(item, 480), "trust": "untrusted-memory-evidence"}
        for item in _strict_string_list(
            payload.get("recall_items"),
            field="recall_items",
            allow_missing=True,
        )
    ]
    graph_entries = [
        _project_graph_node(item)
        for item in _strict_object_list(
            payload.get("graph_entries"),
            field="graph_entries",
            allow_missing=True,
        )
    ]
    graph_relationships = [
        _project_graph_edge(item)
        for item in _strict_object_list(
            payload.get("graph_relationships"),
            field="graph_relationships",
            allow_missing=True,
        )
    ]
    graph_node_ids = {
        str(item.get("memory_id") or "") for item in graph_entries
    }
    resolved_graph_relationships = [
        item
        for item in graph_relationships
        if str(item.get("source_memory_id") or "") in graph_node_ids
        and str(item.get("target_memory_id") or "") in graph_node_ids
    ]
    unresolved_graph_relationship_count = (
        len(graph_relationships) - len(resolved_graph_relationships)
    )
    if unresolved_graph_relationship_count:
        _record_projection_omission(
            "graph_unresolved_relationships",
            unresolved_graph_relationship_count,
        )
    graph_relationships = resolved_graph_relationships
    source = _source_metadata(payload)
    cortex_warnings = _cortex_session_warnings(payload.get("cortex_state"))
    warnings = [
        *_trusted_warnings(payload.get("warnings")),
        *cortex_warnings,
    ]
    agent_invariant_warnings = _agent_delivery_invariant_warnings(payload)
    warnings.extend(agent_invariant_warnings)
    if bool(payload.get("has_more_events")):
        warnings.append(_warning("more-available", "info", "More eligible events remain."))
    blocking_reason = _blocking_reason(payload)
    if _safe_int(payload.get("input_redaction_count")):
        warnings.append(_warning("redacted", "warning", "Sensitive input shapes were redacted."))
    graph_source_reduced = _source_limit_reduced(
        source,
        requested_key="requested_graph_limit",
        effective_key="effective_graph_limit",
    )
    event_source_reduced = _source_limit_reduced(
        source,
        requested_key="requested_event_limit",
        effective_key="effective_event_limit",
    )
    if graph_source_reduced:
        warnings.append(
            _warning(
                "source-limit-reduced",
                "info",
                "The compact profile reduced the graph source limit before projection.",
            )
        )
    data = {
        "context_id": _atomic_identifier(
            payload.get("context_id"), field="context_id", max_chars=128
        ),
        "agent_id": _atomic_identifier(
            payload.get("agent_id"), field="agent_id", max_chars=128
        ),
        "delivery": {
            "protocol_version": CONTEXT_DELIVERY_PROTOCOL,
            "mode": CONTEXT_DELIVERY_MODE,
            "observed": bool(payload.get("claim_events")),
            "ack_required": bool(payload.get("ack_required")),
            "has_more": bool(payload.get("has_more_events")),
            "remaining_pending_count": _optional_int(payload.get("remaining_pending_count")),
            "max_delivery_attempts": _safe_int(payload.get("max_delivery_attempts")),
            "blocking": _project_blocking_delivery(payload.get("blocking_delivery")),
            "retry_exhausted": _blocking_reason(payload) == "retry-exhausted",
            "dead_letter_required": bool(
                blocking_reason == "retry-exhausted"
            ),
            "deployments": deployments,
        },
        "event_window": {
            "since_event_id": _optional_integer_identifier(
                payload.get("since_event_id"), field="since_event_id"
            ),
            "latest_event_id": _optional_integer_identifier(
                payload.get("latest_event_id"), field="latest_event_id"
            ),
            "returned": len(deployments),
        },
        "recall": {
            "mode": _clean_text(payload.get("recall_mode"), 32),
            "provenance": _clean_text(payload.get("recall_provenance"), 96),
            "returned": len(recall_items),
            "items": recall_items,
            "raw_input_stored": False,
            "input_redaction_count": _safe_int(payload.get("input_redaction_count")),
        },
        "graph": {
            "summary": _project_graph_summary(payload.get("graph_summary")),
            "relationship_text_trust": "untrusted-memory-evidence",
            "returned_entries": len(graph_entries),
            "returned_relationships": len(graph_relationships),
            "unresolved_relationship_count": 0,
            "unresolved_relationships_omitted": unresolved_graph_relationship_count,
            "entries": graph_entries,
            "relationships": graph_relationships,
        },
        "namespace_connectivity": _project_namespace_connectivity(
            payload.get("namespace_connectivity")
        ),
        "cortex": _project_cortex_summary(
            payload.get("cortex_state"),
            cortex_warnings=cortex_warnings,
        ),
    }
    delivery_observed = bool(payload.get("claim_events"))
    pagination = {
        "supported": True,
        "strategy": "receipt-fenced-fifo" if delivery_observed else "not-observed",
        "requested_limit": source.get("requested_event_limit"),
        "effective_limit": source.get("effective_event_limit"),
        "returned": len(deployments),
        "has_more": (
            bool(payload.get("has_more_events")) if delivery_observed else None
        ),
        "next_cursor": None,
    }
    envelope = _base_envelope(
        surface="agent-hydration",
        mode="compact",
        budget=budget,
        data=data,
        provenance={
            "source": "sqlite-context-bus",
            "context_id": data["context_id"],
            "agent_id": data["agent_id"],
            "recall_method": data["recall"]["provenance"],
            "delivery_protocol": data["delivery"]["protocol_version"],
        },
        pagination=pagination,
        completeness={
            "complete": None,
            "event_delivery_complete": (
                not bool(payload.get("has_more_events"))
                if delivery_observed
                else None
            ),
            "event_delivery_exact": True if delivery_observed else None,
            "all_returned_graph_edge_endpoints_resolved": True,
            "event_source_limit_reduced": event_source_reduced,
            "graph_complete": None,
            "cortex_complete": None,
            "graph_source_limit_reduced": graph_source_reduced,
            "reason": "graph-and-cortex-producers-do-not-expose-authoritative-totals",
        },
        continuation=_agent_delivery_continuation(payload),
        warnings=warnings,
    )
    for warning in agent_invariant_warnings:
        _ensure_warning(envelope, warning)
    shrinkers: list[Callable[[], bool]] = [
        lambda: _shrink_namespace_connectivity_diagnostics(
            data["namespace_connectivity"], envelope
        ),
        lambda: _shrink_namespace_connectivity_ids(
            data["namespace_connectivity"], envelope
        ),
        lambda: _drop_last(graph_relationships, envelope, "graph_relationships"),
        lambda: _drop_last(graph_entries, envelope, "graph_entries"),
        lambda: _drop_last(recall_items, envelope, "recall_items"),
        lambda: _shrink_deployment_text(deployments, envelope),
        lambda: _drop_noncritical_warning(envelope),
    ]
    return _finalize(envelope, budget=budget, shrinkers=shrinkers)


@_audited_projection
def project_memory_retrieval(
    payload: dict[str, Any],
    *,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["memory-retrieval"],
    )
    _validate_surface_identities("memory-retrieval", payload)
    items = [
        _project_retrieval_item(item)
        for item in _strict_object_list(payload.get("items"), field="items")
    ]
    source = _source_metadata(payload)
    query = payload.get("query") if isinstance(payload.get("query"), dict) else {}
    ranker = payload.get("ranker") if isinstance(payload.get("ranker"), dict) else {}
    snapshot = (
        payload.get("snapshot") if isinstance(payload.get("snapshot"), dict) else {}
    )
    scope = payload.get("scope") if isinstance(payload.get("scope"), dict) else {}
    resolved_scope = []
    for record in _strict_object_list(
        scope.get("contexts"), field="scope contexts"
    ):
        link = _project_retrieval_context_link(record.get("context_link"))
        resolved_scope.append(
            {
                "context_id": _atomic_identifier(
                    record.get("resolved_context_id"),
                    field="resolved_context_id",
                    max_chars=128,
                ),
                "provenance": _clean_text(record.get("provenance"), 32),
                "via_context_link_id": (
                    link["context_link_id"] if link is not None else None
                ),
                "via_relation_type": (
                    link["relation_type"] if link is not None else ""
                ),
                "via_direction": link["direction"] if link is not None else "",
            }
        )
    raw_completeness = (
        payload.get("completeness")
        if isinstance(payload.get("completeness"), dict)
        else {}
    )
    warnings = _trusted_warnings(raw_completeness.get("warnings"))
    has_more = _strict_boolean(
        raw_completeness.get("has_more"),
        field="completeness.has_more",
    )
    complete = _strict_boolean(
        raw_completeness.get("complete"),
        field="completeness.complete",
    )
    data = {
        "retrieval_id": _atomic_identifier(
            payload.get("retrieval_id"), field="retrieval_id", max_chars=80
        ),
        "query": {
            "fingerprint_sha256": _digest_identifier(
                query.get("fingerprint_sha256"), field="query fingerprint"
            ),
            "context_id": _atomic_identifier(
                query.get("context_id"), field="context_id", max_chars=128
            ),
            "recall_scope": _clean_text(query.get("recall_scope"), 16),
            "raw_input_stored": _strict_boolean(
                query.get("raw_input_stored"), field="query.raw_input_stored"
            ),
            "input_redaction_count": _safe_int(
                query.get("input_redaction_count")
            ),
        },
        "ranker": {
            "id": _atomic_identifier(
                ranker.get("id"), field="ranker_id", max_chars=96
            ),
            "version": _atomic_identifier(
                ranker.get("version"), field="ranker_version", max_chars=48
            ),
            "fusion": _clean_text(ranker.get("fusion"), 48),
            "confidence_calibrated": False,
            "score_semantics": "uncalibrated-ranking-signal",
        },
        "snapshot": {
            "snapshot_id": _atomic_identifier(
                snapshot.get("snapshot_id"), field="snapshot_id", max_chars=80
            ),
            "consistency": _clean_text(snapshot.get("consistency"), 80),
            "entries_revision": _retrieval_revision_summary(
                snapshot.get("entries_revision")
            ),
            "scope_revision": _digest_identifier(
                snapshot.get("scope_revision"), field="scope_revision"
            ),
            "graph_revision": _digest_identifier(
                snapshot.get("graph_revision"), field="graph_revision"
            ),
        },
        "scope": {
            "origin_context_id": _atomic_identifier(
                scope.get("origin_context_id"),
                field="origin_context_id",
                max_chars=128,
            ),
            "requested_scope": _clean_text(scope.get("requested_scope"), 16),
            "one_hop_only": _strict_boolean(
                scope.get("one_hop_only"), field="scope.one_hop_only"
            ),
            "inherits_global": _strict_boolean(
                scope.get("inherits_global"), field="scope.inherits_global"
            ),
            "resolved_context_count": _safe_int(
                scope.get("resolved_context_count")
            ),
            "active_adjacent_link_count": _safe_int(
                scope.get("active_adjacent_link_count")
            ),
            "link_provenance_complete": _strict_boolean(
                scope.get("link_provenance_complete"),
                field="scope.link_provenance_complete",
            ),
            "truncated": _strict_boolean(
                scope.get("truncated"), field="scope.truncated"
            ),
            "contexts": resolved_scope,
        },
        "result_count": len(items),
        "items": items,
        "raw_input_stored": False,
    }
    envelope = _base_envelope(
        surface="memory-retrieval",
        mode="compact",
        budget=budget,
        data=data,
        provenance={
            "source": "authoritative-retrieval-v2",
            "context_id": data["query"]["context_id"],
            "recall_scope": data["query"]["recall_scope"],
            "snapshot_id": data["snapshot"]["snapshot_id"],
            "ranker_id": data["ranker"]["id"],
            "ranker_version": data["ranker"]["version"],
            "raw_input_stored": False,
        },
        pagination={
            "supported": False,
            "strategy": "deterministic-bounded-top-k",
            "requested_limit": source.get("requested_limit"),
            "effective_limit": source.get("effective_limit"),
            "returned": len(items),
            "has_more": has_more,
            "next_cursor": None,
        },
        completeness={
            "complete": complete,
            "scope_complete": _strict_boolean(
                raw_completeness.get("scope_complete"),
                field="completeness.scope_complete",
            ),
            "query_terms_truncated": _strict_boolean(
                raw_completeness.get("query_terms_truncated"),
                field="completeness.query_terms_truncated",
            ),
            "candidate_scan_truncated": _strict_boolean(
                raw_completeness.get("candidate_scan_truncated"),
                field="completeness.candidate_scan_truncated",
            ),
            "result_set_truncated": _strict_boolean(
                raw_completeness.get("result_set_truncated"),
                field="completeness.result_set_truncated",
            ),
            "reason": (
                "bounded-result-set-has-more" if has_more else "bounded-result-set-complete"
            ),
        },
        continuation={
            "strategy": (
                "refine-query-or-increase-result-limit" if has_more else "none"
            ),
            "cursor": None,
        },
        warnings=warnings,
    )
    return _finalize(
        envelope,
        budget=budget,
        shrinkers=[
            lambda: _shrink_item_excerpts(
                items,
                envelope,
                "retrieval_excerpts",
            ),
            lambda: _drop_retrieval_optional_reason(items, envelope),
            lambda: _drop_noncritical_warning(envelope),
        ],
    )


@_audited_projection
def project_memory_list(
    payload: dict[str, Any],
    *,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["memory-list"],
    )
    _validate_surface_identities("memory-list", payload)
    if bool(payload.get("include_vectors")):
        raise ResponseContractError("compact memory responses do not support vectors; use full mode")
    source_entries = _strict_object_list(
        payload.get("entries"),
        field="entries",
        allow_missing=True,
    )
    entries = [_project_memory_entry(item) for item in source_entries]
    source = _source_metadata(payload)
    source_reduced = _source_limit_reduced(source)
    retrieval_page = _retrieval_page_metadata(
        payload,
        surface="memory-list",
        mode="compact",
    )
    warnings = [*_trusted_warnings(payload.get("warnings"))]
    if retrieval_page is None:
        warnings.append(
            _warning(
                "pagination-unsupported",
                "info",
                "This producer has no authoritative cursor yet.",
            )
        )
    if source_reduced:
        warnings.append(
            _warning(
                "source-limit-reduced",
                "info",
                "The compact profile reduced the memory source limit before projection.",
            )
        )
    if retrieval_page is None:
        pagination = {
            "supported": False,
            "strategy": "retrieval-v2-required",
            "requested_limit": source.get("requested_limit"),
            "effective_limit": source.get("effective_limit"),
            "returned": len(entries),
            "has_more": None,
            "next_cursor": None,
        }
        completeness = {
            "complete": None,
            "source_limit_reduced": source_reduced,
            "reason": "authoritative-total-and-cursor-unavailable",
        }
        continuation = {
            "strategy": "request-full-or-wait-for-retrieval-v2",
            "cursor": None,
        }
    else:
        pagination, completeness, continuation = _retrieval_contract_fields(
            retrieval_page,
            returned=retrieval_page["returned"]["entries"],
        )
        pagination["requested_limit"] = source.get("requested_limit")
        pagination["effective_limit"] = source.get("effective_limit")
        completeness["source_limit_reduced"] = source_reduced
    envelope = _base_envelope(
        surface="memory-list",
        mode="compact",
        budget=budget,
        data={
            "context_id": _atomic_identifier(
                payload.get("context_id"), field="context_id", max_chars=128
            ),
            "recall_scope": _clean_text(payload.get("recall_scope"), 32),
            "one_hop_only": bool(payload.get("one_hop_only", False)),
            "returned": len(entries),
            "entries": entries,
        },
        provenance={
            "source": "sqlite-memory-store",
            "context_id": _atomic_identifier(
                payload.get("context_id"), field="context_id", max_chars=128
            ),
            "recall_scope": _clean_text(payload.get("recall_scope"), 32),
            "origin_node": (
                retrieval_page["origin_node"]
                if retrieval_page is not None
                else None
            ),
        },
        pagination=pagination,
        completeness=completeness,
        continuation=continuation,
        warnings=warnings,
    )
    shrinkers = [lambda: _shrink_item_excerpts(entries, envelope, "memory_excerpts")]
    if retrieval_page is None:
        shrinkers.insert(0, lambda: _drop_last(entries, envelope, "memory_entries"))
    shrinkers.append(lambda: _drop_noncritical_warning(envelope))
    return _finalize(envelope, budget=budget, shrinkers=shrinkers)


@_audited_projection
def project_memory_graph(
    payload: dict[str, Any],
    *,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["memory-graph"],
    )
    _validate_surface_identities("memory-graph", payload)
    nodes = [
        _project_graph_node(item)
        for item in _strict_object_list(
            payload.get("entries"),
            field="entries",
            allow_missing=True,
        )
    ]
    for node in nodes:
        node.pop("trust", None)
    node_ids = {str(item.get("memory_id") or "") for item in nodes}
    edges = []
    unresolved = 0
    for relationship in _strict_object_list(
        payload.get("relationships"),
        field="relationships",
        allow_missing=True,
    ):
        edge = _project_graph_edge(relationship)
        unresolved_endpoints = [
            endpoint
            for endpoint, memory_id in (
                ("source", edge["source_memory_id"]),
                ("target", edge["target_memory_id"]),
            )
            if memory_id not in node_ids
        ]
        if unresolved_endpoints:
            edge["unresolved_endpoints"] = unresolved_endpoints
            unresolved += 1
        edges.append(edge)
    source = _source_metadata(payload)
    source_reduced = _source_limit_reduced(source)
    retrieval_page = _retrieval_page_metadata(
        payload,
        surface="memory-graph",
        mode="compact",
    )
    warnings = [*_trusted_warnings(payload.get("warnings"))]
    if retrieval_page is None:
        warnings.append(
            _warning(
                "pagination-unsupported",
                "info",
                "This producer has no authoritative cursor yet.",
            )
        )
    if source_reduced:
        warnings.append(
            _warning(
                "source-limit-reduced",
                "info",
                "The compact profile reduced the graph source limit before projection.",
            )
        )
    returned = {"nodes": len(nodes), "relationships": len(edges)}
    if retrieval_page is None:
        pagination = {
            "supported": False,
            "strategy": "retrieval-v2-required",
            "requested_limit": source.get("requested_limit"),
            "effective_limit": source.get("effective_limit"),
            "returned": {"nodes": len(nodes), "edges": len(edges)},
            "has_more": None,
            "next_cursor": None,
        }
        completeness = {
            "complete": None,
            "all_returned_edge_endpoints_resolved": unresolved == 0,
            "source_limit_reduced": source_reduced,
            "reason": "authoritative-total-and-cursor-unavailable",
        }
        continuation = {
            "strategy": "request-full-or-wait-for-retrieval-v2",
            "cursor": None,
        }
    else:
        pagination, completeness, continuation = _retrieval_contract_fields(
            retrieval_page,
            returned={
                "nodes": retrieval_page["returned"]["nodes"],
                "relationships": retrieval_page["returned"]["relationships"],
            },
        )
        pagination["requested_limit"] = source.get("requested_limit")
        pagination["effective_limit"] = source.get("effective_limit")
        completeness["all_returned_edge_endpoints_resolved"] = unresolved == 0
        completeness["source_limit_reduced"] = source_reduced
    envelope = _base_envelope(
        surface="memory-graph",
        mode="compact",
        budget=budget,
        data={
            "context_id": _atomic_identifier(
                payload.get("context_id"), field="context_id", max_chars=128
            ),
            "summary": _project_graph_summary(
                {
                    "entry_count": payload.get("entry_count"),
                    "relationship_count": payload.get("relationship_count"),
                    "relationship_modes": payload.get("relationship_summary"),
                }
            ),
            "returned_nodes": len(nodes),
            "returned_edges": len(edges),
            "unresolved_edge_count": unresolved,
            "node_text_trust": "untrusted-memory-evidence",
            "edge_text_trust": "untrusted-memory-evidence",
            "nodes": nodes,
            "edges": edges,
        },
        provenance={
            "source": "sqlite-memory-graph",
            "context_id": _atomic_identifier(
                payload.get("context_id"), field="context_id", max_chars=128
            ),
            "entry_strategy": _clean_text(payload.get("graph_entry_strategy"), 80),
            "origin_node": (
                retrieval_page["origin_node"]
                if retrieval_page is not None
                else None
            ),
        },
        pagination=pagination,
        completeness=completeness,
        continuation=continuation,
        warnings=warnings,
    )
    shrinkers = [lambda: _shrink_item_excerpts(nodes, envelope, "graph_excerpts")]
    if retrieval_page is None:
        shrinkers.extend(
            [
                lambda: _drop_unreferenced_node(nodes, edges, envelope),
                lambda: _drop_edge_with_orphan_cleanup(edges, nodes, envelope),
            ]
        )
    shrinkers.append(lambda: _drop_noncritical_warning(envelope))
    return _finalize(envelope, budget=budget, shrinkers=shrinkers)


@_audited_projection
def project_cortex_state(
    payload: dict[str, Any],
    *,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["cortex-state"],
    )
    _validate_surface_identities("cortex-state", payload)
    session_rows = _strict_object_list(
        payload.get("active_sessions"),
        field="active_sessions",
        allow_missing=True,
    )
    sessions = [_project_session(item) for item in session_rows]
    goals = [
        _project_cortex_item(item)
        for item in _strict_object_list(
            payload.get("goals"), field="goals", allow_missing=True
        )
    ]
    constraints = [
        _project_cortex_item(item)
        for item in _strict_object_list(
            payload.get("constraints"), field="constraints", allow_missing=True
        )
    ]
    risks = [
        _project_cortex_item(item)
        for item in _strict_object_list(
            payload.get("risks"), field="risks", allow_missing=True
        )
    ]
    contradictions = [
        _project_cortex_item(item)
        for item in _strict_object_list(
            payload.get("contradictions"),
            field="contradictions",
            allow_missing=True,
        )
    ]
    retrieval_page = _retrieval_page_metadata(
        payload,
        surface="cortex-state",
        mode="compact",
    )
    working_memory = (
        [
            _project_cortex_item(item)
            for item in _strict_object_list(
                payload.get("working_memory"),
                field="working_memory",
                allow_missing=True,
            )
        ]
        if retrieval_page is not None
        else []
    )
    source = _source_metadata(payload)
    source_reduced = _source_limit_reduced(source)
    cortex_warnings = _cortex_session_warnings(payload)
    warnings = [*_trusted_warnings(payload.get("warnings")), *cortex_warnings]
    if retrieval_page is None:
        warnings.append(
            _warning(
                "pagination-unsupported",
                "info",
                "Working-memory totals are not cursor-addressable yet.",
            )
        )
    if source_reduced:
        warnings.append(
            _warning(
                "source-limit-reduced",
                "info",
                "The compact profile reduced the Cortex source limit before projection.",
            )
        )
    data = {
        "context_id": _atomic_identifier(
            payload.get("context_id"), field="context_id", max_chars=128
        ),
        "agent_id": _optional_atomic_identifier(
            payload.get("agent_id"), field="agent_id", max_chars=128
        ),
        "active_goal": _clean_text(payload.get("active_goal"), 320),
        "active_goal_trust": (
            "untrusted-session-input"
            if session_rows
            else "untrusted-memory-evidence"
        ),
        "active_session_count": _safe_int(payload.get("active_session_count")),
        "active_sessions": sessions,
        "goal_count": _safe_int(payload.get("goal_count")),
        "goals": goals,
        "typed_memory_counts": _safe_count_map(payload.get("typed_memory_counts")),
        "constraints": constraints,
        "risks": risks,
        "contradictions": contradictions,
        "suggested_next_move": _clean_text(payload.get("suggested_next_move"), 360),
        "suggested_next_move_trust": "trusted-governor-synthesis",
        "policy": _project_policy(payload.get("policy")),
        "governance": _project_cortex_governance(
            payload,
            cortex_warnings=cortex_warnings,
        ),
    }
    if retrieval_page is not None:
        data["working_memory"] = working_memory
        data["working_memory_trust"] = "untrusted-memory-evidence"
    if retrieval_page is None:
        pagination = {
            "supported": False,
            "strategy": "retrieval-v2-required",
            "requested_limit": source.get("requested_limit"),
            "effective_limit": source.get("effective_limit"),
            "returned": {
                "sessions": len(sessions),
                "goals": len(goals),
                "constraints": len(constraints),
                "risks": len(risks),
                "contradictions": len(contradictions),
            },
            "has_more": None,
            "next_cursor": None,
        }
        completeness = {
            "complete": None,
            "source_limit_reduced": source_reduced,
            "reason": "authoritative-total-and-cursor-unavailable",
        }
        continuation = {
            "strategy": "request-full-or-wait-for-retrieval-v2",
            "cursor": None,
        }
    else:
        returned = {
            "working_memory": len(working_memory),
            "sessions": len(sessions),
            "goals": len(goals),
            "constraints": len(constraints),
            "risks": len(risks),
            "contradictions": len(contradictions),
        }
        pagination, completeness, continuation = _retrieval_contract_fields(
            retrieval_page,
            returned={
                **returned,
                "working_memory": retrieval_page["returned"]["working_memory"],
            },
        )
        pagination["requested_limit"] = source.get("requested_limit")
        pagination["effective_limit"] = source.get("effective_limit")
        completeness["source_limit_reduced"] = source_reduced
    envelope = _base_envelope(
        surface="cortex-state",
        mode="compact",
        budget=budget,
        data=data,
        provenance={
            "source": "cortex-governor",
            "context_id": data["context_id"],
            "agent_id": data["agent_id"],
            "origin_node": (
                retrieval_page["origin_node"]
                if retrieval_page is not None
                else None
            ),
        },
        pagination=pagination,
        completeness=completeness,
        continuation=continuation,
        warnings=warnings,
    )
    shrinkers = [
        lambda: _drop_last(contradictions, envelope, "cortex_contradictions"),
        lambda: _drop_last(risks, envelope, "cortex_risks"),
        lambda: _drop_last(constraints, envelope, "cortex_constraints"),
        lambda: _drop_last(goals, envelope, "cortex_goals"),
        lambda: _drop_last(sessions, envelope, "cortex_sessions"),
        lambda: _drop_noncritical_warning(envelope),
    ]
    if retrieval_page is not None:
        shrinkers.insert(
            0,
            lambda: _shrink_item_excerpts(
                working_memory,
                envelope,
                "cortex_working_memory_excerpts",
            ),
        )
    return _finalize(envelope, budget=budget, shrinkers=shrinkers)


@_audited_projection
def project_media_similarity(
    payload: dict[str, Any],
    *,
    max_response_bytes: Any = None,
) -> dict[str, Any]:
    """Project bounded image-to-image recall without any feature-byte leakage."""

    budget = normalize_response_budget(
        max_response_bytes,
        default_bytes=DEFAULT_RESPONSE_BYTES["media-similarity"],
    )
    _validate_surface_identities("media-similarity", payload)
    query = payload.get("query")
    candidate = payload.get("candidate")
    confidence = payload.get("confidence")
    if (
        not isinstance(query, dict)
        or not isinstance(candidate, dict)
        or not isinstance(confidence, dict)
    ):
        raise ResponseContractError("media similarity control metadata is invalid")
    media_id = _atomic_identifier(
        query.get("media_id"), field="media_id", max_chars=64
    )
    feature_fields = (
        "provider",
        "schema",
        "request_revision",
        "element_type",
        "element_count",
        "input_derivative",
    )
    clean_query = {
        "media_id": media_id,
        **{field: query.get(field) for field in feature_fields},
    }
    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        raise ResponseContractError("media similarity results are invalid")
    results: list[dict[str, Any]] = []
    for item in raw_results[: COMPACT_SOURCE_LIMITS["media-similarity"]]:
        if not isinstance(item, dict):
            raise ResponseContractError("media similarity result item is invalid")
        feature = item.get("feature_print")
        if not isinstance(feature, dict) or "data" in feature or "data" in item:
            raise ResponseContractError(
                "media similarity result must not carry feature bytes"
            )
        results.append(
            {
                "rank": _safe_int(item.get("rank")),
                "media_id": _atomic_identifier(
                    item.get("media_id"), field="media_id", max_chars=64
                ),
                "distance": _safe_number(item.get("distance")),
                "score": _unit_number(item.get("score"), field="score"),
                "artifact_schema": _clean_text(str(item.get("artifact_schema") or ""), 64),
                "mime_type": _clean_text(str(item.get("mime_type") or ""), 32),
                "source_dimensions": {
                    "width": _safe_int((item.get("source_dimensions") or {}).get("width")),
                    "height": _safe_int((item.get("source_dimensions") or {}).get("height")),
                },
                "thumbnail_dimensions": {
                    "width": _safe_int((item.get("thumbnail_dimensions") or {}).get("width")),
                    "height": _safe_int((item.get("thumbnail_dimensions") or {}).get("height")),
                },
                "thumbnail_available": bool(item.get("thumbnail_available")),
                "feature_print": {
                    field: feature.get(field) for field in feature_fields
                },
            }
        )
    projection_truncated = len(raw_results) > len(results)
    if projection_truncated:
        _record_projection_omission("media_similarity_results", len(raw_results) - len(results))
    candidate_fields = (
        "scope_reference_count",
        "scanned_count",
        "compatible_count",
        "incompatible_count",
        "missing_feature_count",
        "candidate_limit",
    )
    clean_candidate = {
        field: _safe_int(candidate.get(field)) for field in candidate_fields
    }
    clean_candidate["truncated"] = bool(candidate.get("truncated"))
    result_truncated = bool(payload.get("result_truncated")) or projection_truncated
    data = {
        "context_id": _atomic_identifier(
            payload.get("context_id") or "default",
            field="context_id",
            max_chars=128,
        ),
        "recall_scope": str(payload.get("recall_scope") or "local"),
        "resolved_context_count": _safe_int(payload.get("resolved_context_count")),
        "distance_metric": str(payload.get("distance_metric")),
        "query": clean_query,
        "result_count": len(results),
        "results": results,
        "result_limit": _safe_int(payload.get("result_limit")),
        "result_truncated": result_truncated,
        "candidate": clean_candidate,
        "confidence": {
            "calibrated": False,
            "signal": _clean_text(str(confidence.get("signal") or ""), 64),
            "warning": _clean_text(str(confidence.get("warning") or ""), 240),
        },
        "deterministic_tie_break": _clean_text(
            str(payload.get("deterministic_tie_break") or ""), 64
        ),
        "feature_print_bytes_returned": False,
        "raw_original_stored": False,
    }
    envelope = _base_envelope(
        surface="media-similarity",
        mode="compact",
        budget=budget,
        data=data,
        provenance={
            "source": "node-local-media-cache",
            "context_id": data["context_id"],
            "recall_scope": data["recall_scope"],
            "distance_metric": data["distance_metric"],
        },
        pagination={
            "supported": False,
            "strategy": "deterministic-bounded-top-k",
            "requested_limit": data["result_limit"],
            "effective_limit": (
                min(
                    data["result_limit"],
                    COMPACT_SOURCE_LIMITS["media-similarity"],
                )
                if data["result_limit"]
                else data["result_limit"]
            ),
            "returned": len(results),
            "has_more": result_truncated,
            "next_cursor": None,
        },
        completeness={
            "complete": not (result_truncated or clean_candidate["truncated"]),
            "candidate_scan_truncated": clean_candidate["truncated"],
            "result_set_truncated": result_truncated,
            "reason": (
                "bounded-result-set-has-more"
                if result_truncated or clean_candidate["truncated"]
                else "bounded-scan-complete"
            ),
        },
        continuation={
            "strategy": "refine-query-or-increase-result-limit",
            "cursor": None,
        },
        warnings=[
            _warning(
                "uncalibrated-similarity",
                "info",
                "Feature-print distance is a deterministic node-local ranking "
                "signal, not a truth probability.",
            )
        ],
    )
    return _finalize(
        envelope,
        budget=budget,
        shrinkers=[
            lambda: _drop_last(
                envelope["data"]["results"], envelope, "media_similarity_results"
            ),
        ],
    )


def _base_envelope(
    *,
    surface: str,
    mode: str,
    budget: int,
    data: dict[str, Any],
    provenance: dict[str, Any],
    pagination: dict[str, Any],
    completeness: dict[str, Any],
    continuation: dict[str, Any],
    warnings: list[dict[str, Any]],
    ok: bool = True,
) -> dict[str, Any]:
    envelope = {
        "schema": CONTRACT_SCHEMA,
        "version": CONTRACT_VERSION,
        "operation": surface,
        "ok": bool(ok),
        "data": data,
        "provenance": provenance,
        "warnings": _dedupe_warnings(warnings),
        "pagination": pagination,
        "completeness": completeness,
        "continuation": continuation,
        "response_contract": {
            "profile": mode,
            "max_output_bytes": budget,
            "serialized_bytes": 0,
            "estimated_tokens": 0,
            "truncated": False,
            "omissions": {},
        },
    }
    pending_omissions = dict(_PROJECTION_OMISSIONS.get() or {})
    if pending_omissions:
        for section, count in pending_omissions.items():
            _record_omission(envelope, section, count)
        envelope["response_contract"]["truncated"] = True
        _ensure_warning(
            envelope,
            _warning(
                "output-truncated",
                "warning",
                "Optional response evidence was omitted to honor the byte ceiling or field bounds.",
            ),
        )
    return envelope


def _finalize(
    envelope: dict[str, Any],
    *,
    budget: int,
    shrinkers: list[Callable[[], bool]],
) -> dict[str, Any]:
    contract = envelope["response_contract"]
    while True:
        if contract.get("profile") == "compact" and bool(envelope.get("ok")):
            _refresh_dynamic_counts(envelope)
        _stabilize_metrics(envelope)
        size = len(canonical_response_bytes(envelope))
        if size <= budget:
            return envelope
        changed = False
        for shrink in shrinkers:
            if shrink():
                changed = True
                contract["truncated"] = True
                _ensure_warning(
                    envelope,
                    _warning("output-truncated", "warning", "Optional response evidence was omitted to honor the byte ceiling."),
                )
                break
        if not changed:
            raise ResponseBudgetError("minimum safe response exceeds max output bytes")


def _refresh_dynamic_counts(envelope: dict[str, Any]) -> None:
    operation = str(envelope.get("operation") or "")
    data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
    pagination = (
        envelope.get("pagination")
        if isinstance(envelope.get("pagination"), dict)
        else {}
    )
    if operation == "media-similarity":
        results = data.get("results") if isinstance(data.get("results"), list) else []
        data["result_count"] = len(results)
        pagination["returned"] = len(results)
        return
    if operation == "agent-hydration":
        recall = data.get("recall") if isinstance(data.get("recall"), dict) else {}
        graph = data.get("graph") if isinstance(data.get("graph"), dict) else {}
        connectivity = (
            data.get("namespace_connectivity")
            if isinstance(data.get("namespace_connectivity"), dict)
            else {}
        )
        recall["returned"] = (
            len(recall.get("items", [])) if isinstance(recall.get("items"), list) else 0
        )
        graph["returned_entries"] = (
            len(graph.get("entries", [])) if isinstance(graph.get("entries"), list) else 0
        )
        graph["returned_relationships"] = (
            len(graph.get("relationships", []))
            if isinstance(graph.get("relationships"), list)
            else 0
        )
        for prefix in ("connected", "pending"):
            ids = connectivity.get(f"{prefix}_context_ids")
            returned = len(ids) if isinstance(ids, list) else 0
            total = _safe_int(
                connectivity.get(f"{prefix}_context_count_lower_bound")
            )
            upstream_truncated = bool(
                connectivity.get(
                    "bridge_records_truncated"
                    if prefix == "connected"
                    else "pending_proposal_records_truncated"
                )
            )
            connectivity[f"{prefix}_context_ids_returned"] = returned
            connectivity[f"{prefix}_context_ids_truncated"] = (
                bool(connectivity.get(f"{prefix}_context_ids_truncated"))
                or upstream_truncated
                or total > returned
            )
        graph_node_ids = {
            str(item.get("memory_id") or "")
            for item in graph.get("entries", [])
            if isinstance(item, dict)
        }
        unresolved = sum(
            1
            for item in graph.get("relationships", [])
            if isinstance(item, dict)
            and (
                str(item.get("source_memory_id") or "") not in graph_node_ids
                or str(item.get("target_memory_id") or "") not in graph_node_ids
            )
        )
        graph["unresolved_relationship_count"] = unresolved
        completeness = envelope.get("completeness")
        if isinstance(completeness, dict):
            completeness["all_returned_graph_edge_endpoints_resolved"] = (
                unresolved == 0
            )
    elif operation == "memory-retrieval":
        items = data.get("items", []) if isinstance(data.get("items"), list) else []
        data["result_count"] = len(items)
        pagination["returned"] = len(items)
    elif operation == "memory-list":
        count = len(data.get("entries", [])) if isinstance(data.get("entries"), list) else 0
        data["returned"] = count
        if pagination.get("strategy") != RETRIEVAL_CURSOR_STRATEGY:
            pagination["returned"] = count
    elif operation == "memory-graph":
        nodes = data.get("nodes", []) if isinstance(data.get("nodes"), list) else []
        edges = data.get("edges", []) if isinstance(data.get("edges"), list) else []
        node_ids = {str(node.get("memory_id") or "") for node in nodes if isinstance(node, dict)}
        unresolved = sum(
            1
            for edge in edges
            if isinstance(edge, dict)
            and (
                str(edge.get("source_memory_id") or "") not in node_ids
                or str(edge.get("target_memory_id") or "") not in node_ids
            )
        )
        data["returned_nodes"] = len(nodes)
        data["returned_edges"] = len(edges)
        data["unresolved_edge_count"] = unresolved
        if pagination.get("strategy") != RETRIEVAL_CURSOR_STRATEGY:
            pagination["returned"] = {"nodes": len(nodes), "edges": len(edges)}
        completeness = envelope.get("completeness")
        if isinstance(completeness, dict):
            completeness["all_returned_edge_endpoints_resolved"] = unresolved == 0
    elif operation == "cortex-state":
        keys = {
            "sessions": "active_sessions",
            "goals": "goals",
            "constraints": "constraints",
            "risks": "risks",
            "contradictions": "contradictions",
        }
        if "working_memory" in data:
            keys = {"working_memory": "working_memory", **keys}
        dynamic_returned = {
            label: len(data.get(key, [])) if isinstance(data.get(key), list) else 0
            for label, key in keys.items()
        }
        if pagination.get("strategy") == RETRIEVAL_CURSOR_STRATEGY:
            authoritative = pagination.get("returned")
            if isinstance(authoritative, dict) and "working_memory" in authoritative:
                dynamic_returned["working_memory"] = _safe_int(
                    authoritative["working_memory"]
                )
        pagination["returned"] = dynamic_returned


def _stabilize_metrics(envelope: dict[str, Any]) -> None:
    contract = envelope["response_contract"]
    for _ in range(12):
        size = len(canonical_response_bytes(envelope))
        estimated = int(math.ceil(size / 4.0))
        if contract.get("serialized_bytes") == size and contract.get("estimated_tokens") == estimated:
            return
        contract["serialized_bytes"] = size
        contract["estimated_tokens"] = estimated
    contract["serialized_bytes"] = len(canonical_response_bytes(envelope))
    contract["estimated_tokens"] = int(math.ceil(contract["serialized_bytes"] / 4.0))


def _record_omission(envelope: dict[str, Any], section: str, count: int = 1) -> None:
    omissions = envelope["response_contract"]["omissions"]
    omissions[section] = _safe_int(omissions.get(section)) + max(0, int(count))


def _record_projection_omission(section: str, count: int = 1) -> None:
    audit = _PROJECTION_OMISSIONS.get()
    if audit is None:
        return
    audit[section] = int(audit.get(section, 0)) + max(0, int(count))


def _drop_last(items: list[Any], envelope: dict[str, Any], section: str) -> bool:
    if not items:
        return False
    items.pop()
    _record_omission(envelope, section)
    return True


def _drop_noncritical_warning(envelope: dict[str, Any]) -> bool:
    warnings = envelope.get("warnings", [])
    protected_codes = {
        "ack-required",
        "delivery-retry-exhausted",
        "output-truncated",
        "request-failed",
    }
    for index in range(len(warnings) - 1, -1, -1):
        if (
            str(warnings[index].get("severity")) not in {"critical", "high"}
            and str(warnings[index].get("code")) not in protected_codes
        ):
            warnings.pop(index)
            _record_omission(envelope, "noncritical_warnings")
            return True
    return False


def _shrink_namespace_connectivity_ids(
    connectivity: dict[str, Any],
    envelope: dict[str, Any],
) -> bool:
    """Yield compact byte budget to recall and graph evidence first."""

    candidates = ("pending_context_ids", "connected_context_ids")
    populated = [
        field
        for field in candidates
        if isinstance(connectivity.get(field), list) and connectivity[field]
    ]
    if not populated:
        return False
    field = max(populated, key=lambda item: len(connectivity[item]))
    connectivity[field].pop()
    _record_omission(envelope, f"namespace_connectivity.{field}")
    return True


def _shrink_namespace_connectivity_diagnostics(
    connectivity: dict[str, Any],
    envelope: dict[str, Any],
) -> bool:
    """Keep routing and safety facts when the minimum hydration budget is tight.

    The exact connected/pending namespace identities, lower bounds, truncation
    flags, and the two fail-closed behavior flags remain present.  Aggregate
    scan diagnostics are useful for larger envelopes but are not required to
    safely consume and acknowledge a leased event.
    """

    optional_fields = (
        "bridge_record_limit",
        "active_bridge_records_returned",
        "incident_bridge_records_returned",
        "inbound_only_bridge_records_returned",
        "pending_proposals_returned",
        "suggestion_evaluation",
    )
    removed = 0
    for field in optional_fields:
        if field in connectivity:
            connectivity.pop(field, None)
            removed += 1
    if not removed:
        return False
    _record_omission(envelope, "namespace_connectivity.diagnostics", removed)
    return True


def _shrink_deployment_text(deployments: list[dict[str, Any]], envelope: dict[str, Any]) -> bool:
    caps = (160, 80, 48, 32, 16, 8, 4, 2, 1)
    for deployment in reversed(deployments):
        event = deployment.get("event", {})
        for field in ("summary", "event_type", "source_surface"):
            text = str(event.get(field) or "")
            next_cap = next((cap for cap in caps if len(text) > cap), None)
            if next_cap is not None:
                shortened = "~" if next_cap == 1 else text[: next_cap - 1] + "…"
                event[field] = shortened
                _record_omission(
                    envelope,
                    f"event_{field}_characters",
                    len(text) - len(shortened),
                )
                return True
        evidence = event.get("evidence")
        if evidence:
            event["evidence"] = {}
            _record_omission(envelope, "event_evidence")
            return True
    return False


def _shrink_item_excerpts(items: list[dict[str, Any]], envelope: dict[str, Any], section: str) -> bool:
    for item in reversed(items):
        for key in ("excerpt", "summary", "title"):
            text = str(item.get(key) or "")
            if len(text) > 80:
                item[key] = text[:79].rstrip() + "…"
                _record_omission(envelope, section, len(text) - 79)
                return True
    return False


def _drop_retrieval_optional_reason(
    items: list[dict[str, Any]],
    envelope: dict[str, Any],
) -> bool:
    for item in reversed(items):
        reasons = item.get("match_reasons")
        if isinstance(reasons, list) and reasons:
            reasons.pop()
            _record_omission(envelope, "retrieval_match_reasons")
            return True
        facets = item.get("facets")
        if isinstance(facets, list) and facets:
            facets.pop()
            _record_omission(envelope, "retrieval_facets")
            return True
    return False


def _drop_edge_with_orphan_cleanup(
    edges: list[dict[str, Any]],
    nodes: list[dict[str, Any]],
    envelope: dict[str, Any],
) -> bool:
    if not edges:
        return False
    removed = edges.pop()
    _record_omission(envelope, "graph_edges")
    referenced = {
        str(edge.get(key) or "")
        for edge in edges
        for key in ("source_memory_id", "target_memory_id")
    }
    removed_ids = {
        str(removed.get("source_memory_id") or ""),
        str(removed.get("target_memory_id") or ""),
    }
    before = len(nodes)
    nodes[:] = [
        node
        for node in nodes
        if str(node.get("memory_id") or "") not in removed_ids
        or str(node.get("memory_id") or "") in referenced
    ]
    if len(nodes) < before:
        _record_omission(envelope, "graph_nodes", before - len(nodes))
    return True


def _drop_unreferenced_node(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    envelope: dict[str, Any],
) -> bool:
    referenced = {
        str(edge.get(key) or "")
        for edge in edges
        for key in ("source_memory_id", "target_memory_id")
    }
    for index in range(len(nodes) - 1, -1, -1):
        if str(nodes[index].get("memory_id") or "") not in referenced:
            nodes.pop(index)
            _record_omission(envelope, "graph_nodes")
            return True
    return False


def _warning(
    code: str,
    severity: str,
    message: str,
    *,
    action_required: bool = False,
) -> dict[str, Any]:
    clean_code = _SAFE_CODE_RE.sub("-", str(code or "warning").casefold()).strip("-._:") or "warning"
    clean_severity = str(severity or "warning").casefold()
    if clean_severity not in {"critical", "high", "warning", "info"}:
        clean_severity = "warning"
    raw_message = str(message or "")
    clean_message = safe_public_error(raw_message, fallback=clean_code, max_chars=240)
    _record_projection_text_edit(raw_message, clean_message, max_chars=240)
    return {
        "code": clean_code[:80],
        "severity": clean_severity,
        "message": clean_message,
        "action_required": bool(action_required),
    }


def _trusted_warnings(value: Any) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    if value is None:
        return warnings
    for item in _strict_object_list(value, field="warnings"):
        warnings.append(
            _warning(
                _clean_text(item.get("code"), 80) or "producer-warning",
                _clean_text(item.get("severity"), 16) or "warning",
                _clean_text(item.get("message"), 240) or "Producer reported a warning.",
                action_required=bool(item.get("action_required", False)),
            )
        )
    warnings.sort(key=lambda item: ({"critical": 0, "high": 1, "warning": 2, "info": 3}[item["severity"]], item["code"]))
    return _dedupe_warnings(warnings)


def _dedupe_warnings(warnings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    positions: dict[str, int] = {}
    for warning in warnings:
        code = str(warning.get("code"))
        if code not in positions:
            positions[code] = len(result)
            result.append(dict(warning))
            continue
        index = positions[code]
        existing = result[index]
        existing_severity = str(existing.get("severity") or "warning")
        incoming_severity = str(warning.get("severity") or "warning")
        severity_order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
        if severity_order.get(incoming_severity, 2) < severity_order.get(existing_severity, 2):
            existing["severity"] = incoming_severity
            existing["message"] = warning.get("message", existing.get("message", ""))
        existing["action_required"] = bool(
            existing.get("action_required") or warning.get("action_required")
        )
    return result


def _ensure_warning(envelope: dict[str, Any], warning: dict[str, Any]) -> None:
    warnings = envelope.setdefault("warnings", [])
    severity_order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    for index, existing in enumerate(warnings):
        if existing.get("code") != warning.get("code"):
            continue
        existing_severity = str(existing.get("severity") or "warning")
        incoming_severity = str(warning.get("severity") or "warning")
        merged = dict(existing)
        if severity_order.get(incoming_severity, 2) < severity_order.get(existing_severity, 2):
            merged["severity"] = incoming_severity
        merged["action_required"] = bool(
            existing.get("action_required") or warning.get("action_required")
        )
        # Callers use this helper for contract-authored invariants. Their bounded
        # message must win over a producer warning with the same code.
        merged["message"] = warning.get("message", merged.get("message", ""))
        warnings[index] = merged
        return
    warnings.append(dict(warning))


def _project_memory_entry(entry: dict[str, Any]) -> dict[str, Any]:
    metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
    result = {
        "memory_id": _atomic_identifier(entry.get("memory_id"), field="memory_id"),
        "tag": _clean_text(entry.get("tag"), 160),
        "context_id": _atomic_identifier(
            entry.get("context_id"), field="context_id", max_chars=128
        ),
        "excerpt": _clean_text(entry.get("source_text"), 360),
        "trust": "untrusted-memory-evidence",
        "embedding_dimensions": _safe_int(entry.get("embedding_dimensions")),
        "spike_count": _safe_int(entry.get("spike_count")),
        "neuron_count": _safe_int(entry.get("neuron_count")),
        "created_at": _safe_number(entry.get("created_at")),
        "updated_at": _safe_number(entry.get("updated_at")),
        "provenance": {
            "recall_scope": _clean_text(entry.get("recall_scope"), 32),
            "recall_provenance": _clean_text(entry.get("recall_provenance"), 96),
            "via_context_link_id": _optional_atomic_identifier(
                entry.get("via_context_link_id"), field="context_link_id"
            ),
            "via_relation_type": _clean_text(entry.get("via_relation_type"), 80),
            "via_direction": _clean_text(entry.get("via_direction"), 32),
            "source_surface": _clean_text(metadata.get("source_surface"), 80),
            "speaker": _clean_text(metadata.get("speaker"), 80),
        },
    }
    result["provenance"] = {key: val for key, val in result["provenance"].items() if val not in {"", None}}
    return result


def _digest_identifier(value: Any, *, field: str) -> str:
    digest = _atomic_identifier(value, field=field, max_chars=64)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ResponseContractError(f"{field} must be a lowercase sha256 digest")
    return digest


def _retrieval_revision_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResponseContractError("entries_revision must be an object")
    revision = _atomic_identifier(
        value.get("revision"), field="entries_revision", max_chars=64
    )
    if re.fullmatch(r"[0-9a-f]{16,64}", revision) is None:
        raise ResponseContractError("entries_revision is invalid")
    return {
        "revision": revision,
        "entry_count": _safe_int(value.get("entry_count")),
        "semantic_index_generation": _safe_int(
            value.get("semantic_index_generation")
        ),
    }


def _unit_number(value: Any, *, field: str) -> int | float:
    number = _safe_number(value)
    if float(number) < 0.0 or float(number) > 1.0:
        raise ResponseContractError(f"{field} must be between zero and one")
    return number


def _project_retrieval_context_link(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ResponseContractError("retrieval context_link must be an object")
    return {
        "context_link_id": _atomic_identifier(
            value.get("context_link_id"), field="context_link_id", max_chars=160
        ),
        "source_context_id": _atomic_identifier(
            value.get("source_context_id"),
            field="source_context_id",
            max_chars=128,
        ),
        "target_context_id": _atomic_identifier(
            value.get("target_context_id"),
            field="target_context_id",
            max_chars=128,
        ),
        "relation_type": _clean_text(value.get("relation_type"), 80),
        "direction": _clean_text(value.get("direction"), 32),
        "confidence": _unit_number(
            value.get("confidence"), field="context_link.confidence"
        ),
        "enabled": _strict_boolean(
            value.get("enabled"), field="context_link.enabled"
        ),
        "approved": _strict_boolean(
            value.get("approved"), field="context_link.approved"
        ),
        "approved_by": _clean_text(value.get("approved_by"), 96),
        "approved_at": _safe_number(value.get("approved_at")),
        "updated_at": _safe_number(value.get("updated_at")),
    }


def _validate_retrieval_link_reachability(
    link: dict[str, Any],
    *,
    origin_context_id: str,
    resolved_context_id: str,
) -> None:
    source = str(link.get("source_context_id") or "")
    target = str(link.get("target_context_id") or "")
    direction = str(link.get("direction") or "")
    reachable = ""
    if source == origin_context_id:
        reachable = target
    elif target == origin_context_id and direction == "bidirectional":
        reachable = source
    if reachable != resolved_context_id:
        raise ResponseContractError(
            "retrieval context link does not authorize the resolved namespace"
        )


def _project_retrieval_relationship(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResponseContractError("retrieval relationship must be an object")
    return {
        "relationship_id": _atomic_identifier(
            value.get("relationship_id"), field="relationship_id", max_chars=200
        ),
        "anchor_memory_id": _atomic_identifier(
            value.get("anchor_memory_id"), field="anchor_memory_id"
        ),
        "neighbor_memory_id": _atomic_identifier(
            value.get("neighbor_memory_id"), field="neighbor_memory_id"
        ),
        "relation_type": _clean_text(value.get("relation_type"), 80),
        "signal": _unit_number(value.get("signal"), field="graph signal"),
    }


def _project_retrieval_reason(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResponseContractError("retrieval match reason must be an object")
    reason_type = _atomic_identifier(
        value.get("type"), field="match reason type", max_chars=64
    )
    if reason_type == "spike-index-overlap":
        return {
            "type": reason_type,
            "overlap_count": _safe_int(value.get("overlap_count")),
            "query_spike_count": _safe_int(value.get("query_spike_count")),
            "candidate_spike_count": _safe_int(
                value.get("candidate_spike_count")
            ),
            "jaccard": _unit_number(value.get("jaccard"), field="spike jaccard"),
            "source_rank": _safe_int(value.get("source_rank")),
        }
    if reason_type == "surface-index-overlap":
        return {
            "type": reason_type,
            "indexed_overlap_count": _safe_int(
                value.get("indexed_overlap_count")
            ),
            "query_term_count": _safe_int(value.get("query_term_count")),
            "matched_terms": [
                _clean_text(term, 64)
                for term in _strict_string_list(
                    value.get("matched_terms"),
                    field="matched_terms",
                    allow_missing=True,
                )[:8]
            ],
            "indexed_coverage": _unit_number(
                value.get("indexed_coverage"), field="indexed coverage"
            ),
            "rendered_coverage": _unit_number(
                value.get("rendered_coverage"), field="rendered coverage"
            ),
            "source_rank": _safe_int(value.get("source_rank")),
        }
    if reason_type == "same-context-graph-neighbor":
        relationships = [
            _project_retrieval_relationship(item)
            for item in _strict_object_list(
                value.get("relationships"),
                field="reason relationships",
                allow_missing=True,
            )[:4]
        ]
        return {
            "type": reason_type,
            "relationship_count": _safe_int(value.get("relationship_count")),
            "relationships": relationships,
        }
    raise ResponseContractError("retrieval match reason type is unsupported")


def _project_retrieval_item(item: dict[str, Any]) -> dict[str, Any]:
    score = _unit_number(item.get("score"), field="retrieval score")
    score_breakdown = (
        item.get("score_breakdown")
        if isinstance(item.get("score_breakdown"), dict)
        else {}
    )
    signals = (
        score_breakdown.get("signals")
        if isinstance(score_breakdown.get("signals"), dict)
        else {}
    )
    contributions = (
        score_breakdown.get("contributions")
        if isinstance(score_breakdown.get("contributions"), dict)
        else {}
    )
    diversity = (
        score_breakdown.get("diversity")
        if isinstance(score_breakdown.get("diversity"), dict)
        else {}
    )
    confidence = (
        item.get("confidence") if isinstance(item.get("confidence"), dict) else {}
    )
    if (
        confidence.get("calibrated") is not False
        or confidence.get("probability") is not None
        or confidence.get("signal") != "uncalibrated-ranking-score"
    ):
        raise ResponseContractError("retrieval confidence semantics are invalid")
    scope = (
        item.get("scope_provenance")
        if isinstance(item.get("scope_provenance"), dict)
        else {}
    )
    source = (
        item.get("source_provenance")
        if isinstance(item.get("source_provenance"), dict)
        else {}
    )
    result = {
        "rank": _integer_identifier(item.get("rank"), field="retrieval rank"),
        "memory_id": _atomic_identifier(item.get("memory_id"), field="memory_id"),
        "context_id": _atomic_identifier(
            item.get("context_id"), field="context_id", max_chars=128
        ),
        "tag": _clean_text(item.get("tag"), 96),
        "label": _clean_text(item.get("label"), 96),
        "summary": _clean_text(item.get("summary"), 180),
        "excerpt": _clean_text(item.get("excerpt"), 320),
        "facets": [
            _clean_text(facet, 48)
            for facet in _strict_string_list(
                item.get("facets"), field="facets", allow_missing=True
            )[:6]
        ],
        "score": score,
        "score_breakdown": {
            "signals": {
                key: _unit_number(signals.get(key), field=f"signal {key}")
                for key in ("spike_index", "surface_index", "same_context_graph")
            },
            "contributions": {
                key: _unit_number(
                    contributions.get(key), field=f"contribution {key}"
                )
                for key in ("spike_index", "surface_index", "same_context_graph")
            },
            "relevance_score": _unit_number(
                score_breakdown.get("relevance_score"),
                field="relevance_score",
            ),
            "diversity": {
                "lambda": _unit_number(diversity.get("lambda"), field="MMR lambda"),
                "maximum_selected_similarity": _unit_number(
                    diversity.get("maximum_selected_similarity"),
                    field="MMR similarity",
                ),
                "diversity_penalty": _unit_number(
                    diversity.get("diversity_penalty"),
                    field="MMR penalty",
                ),
                "selection_score": _safe_number(
                    diversity.get("selection_score")
                ),
            },
        },
        "confidence": {
            "calibrated": False,
            "probability": None,
            "signal": "uncalibrated-ranking-score",
            "score": _unit_number(
                confidence.get("score"), field="confidence score"
            ),
            "warning": "Do not interpret this ranking signal as a truth probability.",
        },
        "match_reasons": [
            _project_retrieval_reason(reason)
            for reason in _strict_object_list(
                item.get("match_reasons"),
                field="match_reasons",
                allow_missing=True,
            )[:3]
        ],
        "scope_provenance": {
            "origin_context_id": _atomic_identifier(
                scope.get("origin_context_id"),
                field="origin_context_id",
                max_chars=128,
            ),
            "resolved_context_id": _atomic_identifier(
                scope.get("resolved_context_id"),
                field="resolved_context_id",
                max_chars=128,
            ),
            "requested_scope": _clean_text(scope.get("requested_scope"), 16),
            "provenance": _clean_text(scope.get("provenance"), 32),
            "context_link": _project_retrieval_context_link(
                scope.get("context_link")
            ),
        },
        "source_provenance": {
            "created_at": _safe_number(source.get("created_at")),
            "updated_at": _safe_number(source.get("updated_at")),
            "source": _clean_text(source.get("source"), 128),
            "source_tag": _clean_text(source.get("source_tag"), 128),
            "speaker": _clean_text(source.get("speaker"), 96),
            "trace_type": _clean_text(source.get("trace_type"), 64),
            "truth_posture": _clean_text(source.get("truth_posture"), 64),
            "stored_confidence": (
                None
                if source.get("stored_confidence") is None
                else _unit_number(
                    source.get("stored_confidence"),
                    field="stored confidence",
                )
            ),
        },
        "ranker_id": _atomic_identifier(
            item.get("ranker_id"), field="ranker_id", max_chars=96
        ),
        "ranker_version": _atomic_identifier(
            item.get("ranker_version"), field="ranker_version", max_chars=48
        ),
        "content_duplicate_count": _safe_int(
            item.get("content_duplicate_count")
        ),
        "raw_source_included": _strict_boolean(
            item.get("raw_source_included"), field="raw_source_included"
        ),
        "trust": "untrusted-memory-evidence",
    }
    result["source_provenance"] = {
        key: value
        for key, value in result["source_provenance"].items()
        if value not in {"", None}
    }
    return result


def _project_graph_node(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "memory_id": _atomic_identifier(entry.get("memory_id"), field="memory_id"),
        "tag": _clean_text(entry.get("tag"), 160),
        "context_id": _atomic_identifier(
            entry.get("context_id"), field="context_id", max_chars=128
        ),
        "excerpt": _clean_text(entry.get("excerpt", entry.get("source_text")), 280),
        "updated_at": _safe_number(entry.get("updated_at")),
        "trust": "untrusted-memory-evidence",
    }


def _project_graph_edge(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "relationship_id": _atomic_identifier(
            edge.get("relationship_id"), field="relationship_id"
        ),
        "source_memory_id": _atomic_identifier(
            edge.get("source_memory_id"), field="source_memory_id"
        ),
        "target_memory_id": _atomic_identifier(
            edge.get("target_memory_id"), field="target_memory_id"
        ),
        "relation_type": _clean_text(edge.get("relation_type"), 80),
        "weight": _safe_number(edge.get("weight")),
        "updated_at": _safe_number(edge.get("updated_at")),
    }


def _project_event_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed_strings = ("tag", "memory_id", "source_tag", "speaker", "target_type", "reason")
    allowed_counts = ("event_count", "relationship_count", "spike_count", "neuron_count", "source_text_bytes", "text_bytes")
    result: dict[str, Any] = {}
    for key in allowed_strings:
        if key in value:
            result[key] = _clean_text(value.get(key), 180)
    for key in allowed_counts:
        if key in value:
            result[key] = _safe_int(value.get(key))
    return result


def _project_blocking_delivery(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    reason = _clean_text(value.get("reason"), 64)
    result = {
        "delivery_id": _context_delivery_identifier(value.get("delivery_id")),
        "event_id": _integer_identifier(value.get("event_id"), field="event_id"),
        "reason": reason,
    }
    if reason == "retry-exhausted":
        result.update(
            {
                "attempt_count": _safe_int(value.get("attempt_count")),
                "max_delivery_attempts": _safe_int(
                    value.get("max_delivery_attempts")
                ),
                "requires_governed_dead_letter": True,
            }
        )
    elif reason == "active-lease":
        result["lease_expires_at"] = _safe_number(
            value.get("lease_expires_at")
        )
    return result


def _blocking_reason(payload: dict[str, Any]) -> str:
    value = payload.get("blocking_delivery")
    if not isinstance(value, dict):
        return ""
    return _clean_text(value.get("reason"), 64)


def _agent_delivery_continuation(payload: dict[str, Any]) -> dict[str, Any]:
    deployments = _strict_object_list(payload.get("deliveries"), field="deliveries")
    if not bool(payload.get("claim_events")):
        return {
            "strategy": "claim-events-to-observe-delivery",
            "cursor": None,
            "instruction": (
                "Hydrate again with delivery claiming enabled before concluding that "
                "the event queue is complete."
            ),
        }
    reason = _blocking_reason(payload)
    if reason == "retry-exhausted":
        strategy = (
            "ack-receipts-then-governed-dead-letter"
            if deployments
            else "governed-dead-letter-required"
        )
        blocker_instruction = (
            "Then complete governed dead-letter review for the blocking delivery before hydrating again."
        )
    elif reason == "active-lease":
        strategy = (
            "ack-receipts-then-wait-for-active-lease-expiry"
            if deployments
            else "wait-for-active-lease-expiry"
        )
        blocker_instruction = (
            "Then wait until blocking.lease_expires_at before hydrating again; "
            "do not acknowledge another consumer's receipt."
        )
    elif deployments:
        strategy = "ack-all-receipts-then-hydrate-again"
        blocker_instruction = "Then hydrate again when has_more is true."
    else:
        strategy = "hydrate-when-context-expected"
        blocker_instruction = "Hydrate again when new context is expected."

    if deployments:
        instruction = (
            "Consume every returned event and acknowledge each receipt_id only after "
            "successful use; release any unconsumed receipt. " + blocker_instruction
        )
    else:
        instruction = blocker_instruction
    return {
        "strategy": strategy,
        "cursor": None,
        "instruction": instruction,
    }


def _agent_delivery_invariant_warnings(
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    if not bool(payload.get("claim_events")):
        warnings.append(
            _warning(
                "delivery-not-observed",
                "info",
                "This hydration did not inspect or claim the delivery queue.",
            )
        )
    if bool(payload.get("ack_required")):
        warnings.append(
            _warning(
                "ack-required",
                "high",
                "Acknowledge every returned receipt only after successful consumption.",
                action_required=True,
            )
        )
    reason = _blocking_reason(payload)
    if reason == "retry-exhausted":
        warnings.append(
            _warning(
                "delivery-retry-exhausted",
                "critical",
                "A blocking delivery requires governed dead-letter review.",
                action_required=True,
            )
        )
    elif reason == "active-lease":
        warnings.append(
            _warning(
                "delivery-active-lease",
                "warning",
                "Another consumer holds the next delivery lease; retry after lease expiry.",
            )
        )
    return warnings


def _project_graph_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"entry_count": 0, "relationship_count": 0, "relationship_modes": {}}
    modes = value.get("relationship_modes")
    projected_modes: dict[str, Any] = {}
    if isinstance(modes, dict):
        for key in ("total", "temporal", "associative", "other"):
            if key in modes:
                projected_modes[key] = _safe_int(modes.get(key))
        projected_modes["by_type"] = _safe_count_map(modes.get("by_type"))
    return {
        "entry_count": _safe_int(value.get("entry_count")),
        "relationship_count": _safe_int(value.get("relationship_count")),
        "relationship_modes": projected_modes,
    }


def _project_namespace_connectivity(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResponseContractError("namespace_connectivity must be an object")

    for field in ("automatic_cross_namespace_write", "multi_mac_live_sync"):
        if value.get(field) is not False:
            raise ResponseContractError(f"namespace_connectivity.{field} must be false")

    def context_ids(
        field: str,
        *,
        count_field: str,
        truncated_field: str,
    ) -> tuple[list[str], int, bool]:
        raw = value.get(field)
        if not isinstance(raw, list):
            raw = []
        projected: list[str] = []
        for item in raw[:8]:
            projected.append(
                _atomic_identifier(item, field=field, max_chars=128)
            )
        if len(raw) > len(projected):
            _record_projection_omission(field, len(raw) - len(projected))
        total = max(_safe_int(value.get(count_field)), len(raw))
        expected_truncated = total > len(projected)
        producer_truncated = value.get(truncated_field)
        if (
            not isinstance(producer_truncated, bool)
            or (expected_truncated and not producer_truncated)
        ):
            raise ResponseContractError(
                f"namespace_connectivity.{truncated_field} does not match its count"
            )
        return projected, total, producer_truncated

    connected_ids, connected_count, connected_truncated = context_ids(
        "connected_context_ids",
        count_field="connected_context_count_lower_bound",
        truncated_field="connected_context_ids_truncated",
    )
    pending_ids, pending_count, pending_truncated = context_ids(
        "pending_context_ids",
        count_field="pending_context_count_lower_bound",
        truncated_field="pending_context_ids_truncated",
    )

    return {
        "scope": _clean_text(
            value.get("scope") or "local-authoritative-store",
            64,
        ),
        "local_namespace_count": _safe_int(value.get("local_namespace_count")),
        "bridge_record_limit": _safe_int(value.get("bridge_record_limit")),
        "active_bridge_records_returned": _safe_int(
            value.get("active_bridge_records_returned")
        ),
        "incident_bridge_records_returned": _safe_int(
            value.get("incident_bridge_records_returned")
        ),
        "inbound_only_bridge_records_returned": _safe_int(
            value.get("inbound_only_bridge_records_returned")
        ),
        "bridge_records_truncated": _strict_boolean(
            value.get("bridge_records_truncated"),
            field="namespace_connectivity.bridge_records_truncated",
        ),
        "connected_context_count_lower_bound": connected_count,
        "connected_context_ids_returned": len(connected_ids),
        "connected_context_ids": connected_ids,
        "connected_context_ids_truncated": connected_truncated,
        "pending_proposals_returned": _safe_int(
            value.get("pending_proposals_returned")
        ),
        "pending_proposal_records_truncated": _strict_boolean(
            value.get("pending_proposal_records_truncated"),
            field="namespace_connectivity.pending_proposal_records_truncated",
        ),
        "pending_context_count_lower_bound": pending_count,
        "pending_context_ids_returned": len(pending_ids),
        "pending_context_ids": pending_ids,
        "pending_context_ids_truncated": pending_truncated,
        "suggestion_evaluation": _clean_text(
            value.get("suggestion_evaluation") or "on-demand-namespace-map",
            64,
        ),
        "automatic_cross_namespace_write": False,
        "multi_mac_live_sync": False,
    }


def _project_cortex_summary(
    value: Any,
    *,
    cortex_warnings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "active_goal": "",
            "active_goal_trust": "untrusted-memory-evidence",
            "active_session_count": 0,
            "goal_count": 0,
            "typed_memory_counts": {},
            "risk_count": 0,
            "constraint_count": 0,
            "contradiction_count": 0,
            "suggested_next_move": "",
            "suggested_next_move_trust": "trusted-governor-synthesis",
            "governance": {},
        }
    sessions = _strict_object_list(
        value.get("active_sessions"),
        field="cortex active_sessions",
        allow_missing=True,
    )
    risks = _strict_object_list(
        value.get("risks"), field="cortex risks", allow_missing=True
    )
    constraints = _strict_object_list(
        value.get("constraints"), field="cortex constraints", allow_missing=True
    )
    contradictions = _strict_object_list(
        value.get("contradictions"),
        field="cortex contradictions",
        allow_missing=True,
    )
    return {
        "active_goal": _clean_text(value.get("active_goal"), 320),
        "active_goal_trust": (
            "untrusted-session-input"
            if sessions
            else "untrusted-memory-evidence"
        ),
        "active_session_count": _safe_int(value.get("active_session_count")),
        "goal_count": _safe_int(value.get("goal_count")),
        "typed_memory_counts": _safe_count_map(value.get("typed_memory_counts")),
        "risk_count": len(risks),
        "constraint_count": len(constraints),
        "contradiction_count": len(contradictions),
        "suggested_next_move": _clean_text(value.get("suggested_next_move"), 360),
        "suggested_next_move_trust": "trusted-governor-synthesis",
        "governance": _project_cortex_governance(
            value,
            cortex_warnings=cortex_warnings,
        ),
    }


def _project_session(item: dict[str, Any]) -> dict[str, Any]:
    last_warnings = _strict_object_list(
        item.get("last_warnings"),
        field="cortex last_warnings",
        allow_missing=True,
    )
    return {
        "session_id": _atomic_identifier(item.get("session_id"), field="session_id"),
        "agent_id": _atomic_identifier(
            item.get("agent_id"), field="agent_id", max_chars=128
        ),
        "mode": _clean_text(item.get("mode"), 32),
        "status": _clean_text(item.get("status"), 32),
        "task": _clean_text(item.get("task"), 320),
        "task_trust": "untrusted-session-input",
        "last_decision": _clean_text(item.get("last_decision"), 80),
        "last_warning_count": len(last_warnings),
        "updated_at": _safe_number(item.get("updated_at")),
    }


def _cortex_session_warnings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    warnings: list[dict[str, Any]] = []
    for session in _strict_object_list(
        value.get("active_sessions"),
        field="cortex active_sessions",
        allow_missing=True,
    ):
        raw_warnings = session.get("last_warnings")
        if raw_warnings is None:
            continue
        for item in _strict_object_list(raw_warnings, field="cortex last_warnings"):
            severity = _clean_text(item.get("severity"), 16) or "warning"
            normalized_severity = (
                severity if severity in {"critical", "high", "warning", "info"} else "warning"
            )
            warnings.append(
                _warning(
                    _clean_text(item.get("code"), 80) or "cortex-governor-warning",
                    normalized_severity,
                    _clean_text(item.get("message"), 240)
                    or "Cortex Governor reported a warning.",
                    action_required=bool(item.get("action_required", False))
                    or normalized_severity in {"critical", "high"},
                )
            )
    return _dedupe_warnings(warnings)


def _project_cortex_governance(
    value: Any,
    *,
    cortex_warnings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    sessions = _strict_object_list(
        value.get("active_sessions"),
        field="cortex active_sessions",
        allow_missing=True,
    )
    warnings = (
        list(cortex_warnings)
        if cortex_warnings is not None
        else _cortex_session_warnings(value)
    )
    actionable_warnings = [
        item
        for item in warnings
        if bool(item.get("action_required"))
        or str(item.get("severity")) in {"critical", "high"}
    ]
    latest = sessions[0] if sessions else {}
    return {
        "latest_decision": _clean_text(latest.get("last_decision"), 80),
        "action_required": any(
            bool(item.get("action_required"))
            or str(item.get("severity")) in {"critical", "high"}
            for item in actionable_warnings
        ),
        "warning_codes": [
            str(item.get("code") or "") for item in actionable_warnings
        ],
    }


def _project_cortex_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "memory_id": _optional_atomic_identifier(
            item.get("memory_id", item.get("goal_id")), field="memory_id"
        ),
        "title": _clean_text(item.get("title", item.get("excerpt")), 320),
        "trace_type": _clean_text(item.get("trace_type"), 48),
        "state": _clean_text(item.get("state", item.get("goal_state")), 32),
        "truth_posture": _clean_text(item.get("truth_posture"), 48),
        "confidence": _safe_number(item.get("confidence")),
        "updated_at": _safe_number(item.get("updated_at")),
        "trust": "untrusted-memory-evidence",
    }


def _project_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed = ("policy_id", "mode", "require_evidence", "require_validation", "capture_recommendation")
    result: dict[str, Any] = {}
    for key in allowed:
        item = value.get(key)
        if key == "policy_id" and item not in (None, ""):
            result[key] = _atomic_identifier(
                item, field="policy_id", max_chars=160
            )
        elif isinstance(item, bool):
            result[key] = item
        elif isinstance(item, (str, int, float)) and not isinstance(item, bool):
            result[key] = _clean_text(item, 160) if isinstance(item, str) else _safe_number(item)
    return result


def _source_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("_response_source")
    if not isinstance(value, dict):
        return {}
    allowed = (
        "requested_limit",
        "effective_limit",
        "requested_event_limit",
        "effective_event_limit",
        "requested_graph_limit",
        "effective_graph_limit",
    )
    return {key: _safe_int(value.get(key)) for key in allowed if key in value}


def _retrieval_page_metadata(
    payload: dict[str, Any],
    *,
    surface: str,
    mode: str,
) -> dict[str, Any] | None:
    raw = payload.get("_retrieval_page")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ResponseContractError("retrieval page metadata must be an object")
    required = {
        "schema",
        "surface",
        "response_mode",
        "snapshot_revision",
        "filters_sha256",
        "ordering",
        "total",
        "returned",
        "has_more",
        "next_cursor",
        "expires_at",
        "origin_node",
    }
    if set(raw) != required:
        raise ResponseContractError("retrieval page metadata fields are invalid")
    if raw.get("schema") != RETRIEVAL_PAGE_SCHEMA:
        raise ResponseContractError("retrieval page schema is invalid")
    if raw.get("surface") != surface or raw.get("response_mode") != mode:
        raise ResponseContractError("retrieval page binding is invalid")
    snapshot_revision = raw.get("snapshot_revision")
    filters_sha256 = raw.get("filters_sha256")
    origin_node = raw.get("origin_node")
    if (
        not isinstance(snapshot_revision, str)
        or _RETRIEVAL_REVISION_RE.fullmatch(snapshot_revision) is None
        or not isinstance(filters_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", filters_sha256) is None
        or not isinstance(origin_node, str)
        or _RETRIEVAL_ORIGIN_RE.fullmatch(origin_node) is None
    ):
        raise ResponseContractError("retrieval page identity is invalid")
    expected_ordering = {
        "memory-list": "updated_at-desc,memory_id-desc",
        "memory-graph": (
            "entries:updated_at-desc,memory_id-desc;"
            "relationships:updated_at-desc,relationship_id-desc"
        ),
        "cortex-state": "updated_at-desc,memory_id-desc",
    }[surface]
    if raw.get("ordering") != expected_ordering:
        raise ResponseContractError("retrieval page ordering is invalid")
    expected_total_keys = {
        "memory-list": {"entries"},
        "memory-graph": {"nodes", "relationships"},
        "cortex-state": {"working_memory"},
    }[surface]
    total = raw.get("total")
    if not isinstance(total, dict) or set(total) != expected_total_keys:
        raise ResponseContractError("retrieval page total is invalid")
    clean_total = {key: _safe_int(value) for key, value in total.items()}
    returned = raw.get("returned")
    if not isinstance(returned, dict) or set(returned) != expected_total_keys:
        raise ResponseContractError("retrieval page returned counts are invalid")
    clean_returned = {key: _safe_int(value) for key, value in returned.items()}
    if any(clean_returned[key] > clean_total[key] for key in expected_total_keys):
        raise ResponseContractError("retrieval page returned counts exceed totals")
    has_more = raw.get("has_more")
    if not isinstance(has_more, bool):
        raise ResponseContractError("retrieval page has_more is invalid")
    next_cursor = raw.get("next_cursor")
    if has_more:
        try:
            cursor_bytes = (
                next_cursor.encode("ascii", "strict")
                if isinstance(next_cursor, str)
                else b""
            )
        except UnicodeError:
            cursor_bytes = b""
        if (
            not isinstance(next_cursor, str)
            or not cursor_bytes
            or len(cursor_bytes) > 4_096
            or _RETRIEVAL_CURSOR_RE.fullmatch(next_cursor) is None
        ):
            raise ResponseContractError("retrieval continuation is invalid")
    elif next_cursor is not None:
        raise ResponseContractError("complete retrieval page must not have a cursor")
    expires_at = _safe_int(raw.get("expires_at"))
    if has_more and expires_at <= 0:
        raise ResponseContractError("retrieval continuation expiry is invalid")
    return {
        "schema": RETRIEVAL_PAGE_SCHEMA,
        "snapshot_revision": snapshot_revision,
        "filters_sha256": filters_sha256,
        "ordering": expected_ordering,
        "total": clean_total,
        "returned": clean_returned,
        "has_more": has_more,
        "next_cursor": next_cursor,
        "expires_at": expires_at,
        "origin_node": origin_node,
    }


def _retrieval_contract_fields(
    page: dict[str, Any],
    *,
    returned: Any | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    has_more = bool(page["has_more"])
    authoritative_returned: Any = (
        dict(page["returned"]) if returned is None else returned
    )
    pagination = {
        "supported": True,
        "strategy": RETRIEVAL_CURSOR_STRATEGY,
        "returned": authoritative_returned,
        "total": dict(page["total"]),
        "has_more": has_more,
        "next_cursor": page["next_cursor"],
        "snapshot_revision": page["snapshot_revision"],
        "expires_at": page["expires_at"] if has_more else None,
    }
    completeness = {
        "complete": not has_more,
        "snapshot_bound": True,
        "authoritative_total": True,
        "reason": "more-pages-available" if has_more else "snapshot-page-complete",
    }
    continuation = {
        "strategy": "use-authenticated-keyset-cursor" if has_more else "none",
        "cursor": page["next_cursor"],
        "expires_at": page["expires_at"] if has_more else None,
    }
    return pagination, completeness, continuation


def _source_limit_reduced(
    source: dict[str, Any],
    *,
    requested_key: str = "requested_limit",
    effective_key: str = "effective_limit",
) -> bool:
    requested = source.get(requested_key)
    effective = source.get(effective_key)
    return (
        isinstance(requested, int)
        and isinstance(effective, int)
        and requested > effective
    )


def _unknown_pagination() -> dict[str, Any]:
    return {
        "supported": False,
        "strategy": "unavailable",
        "returned": None,
        "has_more": None,
        "next_cursor": None,
    }


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _strict_object_list(
    value: Any,
    *,
    field: str,
    allow_missing: bool = False,
) -> list[dict[str, Any]]:
    if value is None and allow_missing:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ResponseContractError(f"{field} must be a list of objects")
    return list(value)


def _strict_string_list(
    value: Any,
    *,
    field: str,
    allow_missing: bool = False,
) -> list[str]:
    if value is None and allow_missing:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ResponseContractError(f"{field} must be a list of strings")
    return list(value)


def _atomic_identifier(value: Any, *, field: str, max_chars: int = 512) -> str:
    try:
        return validate_public_identifier(
            value,
            field=field,
            max_chars=max_chars,
        )
    except ValueError as exc:
        raise ResponseContractError(str(exc)) from exc


def _has_renderable_evidence_text(value: str) -> bool:
    return any(
        not char.isspace() and not unicodedata.category(char).startswith("C")
        for char in value
    )


def _context_delivery_identifier(value: Any, *, field: str = "delivery_id") -> str:
    raw = _atomic_identifier(value, field=field, max_chars=160)
    if _CONTEXT_DELIVERY_ID_RE.fullmatch(raw) is None:
        raise ResponseContractError(f"{field} is invalid")
    return raw


def _context_receipt_identifier(value: Any, *, field: str = "receipt_id") -> str:
    raw = _atomic_identifier(value, field=field, max_chars=51)
    if _CONTEXT_RECEIPT_ID_RE.fullmatch(raw) is None:
        raise ResponseContractError(f"{field} is invalid")
    return raw


def _context_delivery_consumer_identifier(
    value: Any,
    *,
    field: str = "consumer_instance_id",
) -> str:
    raw = _atomic_identifier(value, field=field, max_chars=256)
    if not raw.isascii() or any(not (0x20 <= ord(char) <= 0x7E) for char in raw):
        raise ResponseContractError(f"{field} is invalid")
    return raw


def _optional_atomic_identifier(
    value: Any,
    *,
    field: str,
    max_chars: int = 512,
) -> str:
    if value in (None, ""):
        return ""
    return _atomic_identifier(value, field=field, max_chars=max_chars)


def _integer_identifier(
    value: Any,
    *,
    field: str,
    minimum: int = 1,
) -> int:
    if isinstance(value, bool):
        raise ResponseContractError(f"{field} must be an exact integer identifier")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        if value != value.strip() or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
            raise ResponseContractError(f"{field} must be an exact integer identifier")
        result = int(value)
    else:
        raise ResponseContractError(f"{field} must be an exact integer identifier")
    if result < minimum:
        raise ResponseContractError(f"{field} must be at least {minimum}")
    return result


def _optional_integer_identifier(value: Any, *, field: str) -> int:
    if value in (None, ""):
        return 0
    return _integer_identifier(value, field=field, minimum=0)


def _strict_boolean(
    value: Any,
    *,
    field: str,
    allow_missing: bool = False,
) -> bool:
    if value is None and allow_missing:
        return False
    if not isinstance(value, bool):
        raise ResponseContractError(f"{field} must be a boolean")
    return value


def _strict_positive_number(value: Any, *, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResponseContractError(f"{field} must be a positive finite number")
    if not math.isfinite(float(value)) or float(value) <= 0:
        raise ResponseContractError(f"{field} must be a positive finite number")
    return value


def _validate_agent_delivery_batch(
    payload: dict[str, Any],
    *,
    context_id: str,
    agent_id: str,
) -> None:
    events: dict[int, dict[str, Any]] = {}
    for event in _strict_object_list(payload.get("events"), field="events"):
        event_id = _integer_identifier(event.get("event_id"), field="event_id")
        if event_id in events:
            raise ResponseContractError("visible delivery events must have unique positive ids")
        _atomic_identifier(
            event.get("event_type"), field="event_type", max_chars=128
        )
        _atomic_identifier(
            event.get("source_surface"), field="source_surface", max_chars=128
        )
        event_context_id = _atomic_identifier(
            event.get("context_id"), field="event_context_id", max_chars=128
        )
        if event_context_id != context_id:
            raise ResponseContractError(
                "visible delivery event context_id must match hydration context_id"
            )
        summary = event.get("summary")
        if (
            not isinstance(summary, str)
            or not summary.strip()
            or not _has_renderable_evidence_text(summary)
        ):
            raise ResponseContractError("every visible event must have a non-empty summary")
        if not safe_public_error(summary, fallback="", max_chars=360).strip():
            raise ResponseContractError("every visible event must have renderable summary evidence")
        payload_summary = event.get("payload_summary")
        if payload_summary is not None:
            if not isinstance(payload_summary, dict):
                raise ResponseContractError("event payload_summary must be an object")
            _validate_nonnegative_count_fields(
                payload_summary,
                (
                    "event_count",
                    "relationship_count",
                    "spike_count",
                    "neuron_count",
                    "source_text_bytes",
                    "text_bytes",
                ),
                prefix="event payload_summary",
            )
        events[event_id] = event

    receipt_ids: set[str] = set()
    delivery_ids: set[str] = set()
    delivery_event_ids: set[int] = set()
    attempt_counts: list[int] = []
    deliveries = _strict_object_list(payload.get("deliveries"), field="deliveries")
    for delivery in deliveries:
        receipt_id = _context_receipt_identifier(delivery.get("receipt_id"))
        delivery_id = _context_delivery_identifier(delivery.get("delivery_id"))
        event_id = _integer_identifier(delivery.get("event_id"), field="event_id")
        delivery_context_id = _atomic_identifier(
            delivery.get("context_id"),
            field="delivery_context_id",
            max_chars=128,
        )
        delivery_agent_id = _atomic_identifier(
            delivery.get("agent_id"), field="delivery_agent_id", max_chars=128
        )
        if delivery_context_id != context_id or delivery_agent_id != agent_id:
            raise ResponseContractError(
                "leased delivery context and agent must match hydration scope"
            )
        _context_delivery_consumer_identifier(
            delivery.get("consumer_instance_id")
        )
        if _strict_boolean(
            delivery.get("ack_required"), field="delivery_ack_required"
        ) is not True:
            raise ResponseContractError(
                "every visible leased delivery must require acknowledgement"
            )
        if receipt_id in receipt_ids:
            raise ResponseContractError("leased delivery receipts must be unique")
        if delivery_id in delivery_ids:
            raise ResponseContractError("leased delivery ids must be unique")
        if event_id in delivery_event_ids:
            raise ResponseContractError("each visible event may have only one leased receipt")
        if event_id not in events:
            raise ResponseContractError("every leased receipt must map to a visible event")
        if delivery.get("state") != "leased":
            raise ResponseContractError("delivery state must be leased")
        attempt_count = _integer_identifier(
            delivery.get("attempt_count"), field="attempt_count", minimum=1
        )
        attempt_counts.append(attempt_count)
        _strict_boolean(delivery.get("redelivered"), field="redelivered")
        _strict_positive_number(
            delivery.get("lease_expires_at"), field="lease_expires_at"
        )
        receipt_ids.add(receipt_id)
        delivery_ids.add(delivery_id)
        delivery_event_ids.add(event_id)

    if set(events) != delivery_event_ids:
        raise ResponseContractError(
            "leased delivery events and visible events must form a one-to-one batch"
        )
    claim_events = _strict_boolean(payload.get("claim_events"), field="claim_events")
    ack_required = _strict_boolean(payload.get("ack_required"), field="ack_required")
    if ack_required != bool(deliveries):
        raise ResponseContractError(
            "ack_required must be a boolean true exactly when leased receipts are returned"
        )
    has_more_events = _strict_boolean(
        payload.get("has_more_events"), field="has_more_events"
    )
    remaining_pending_count = _optional_integer_identifier(
        payload.get("remaining_pending_count"), field="remaining_pending_count"
    )
    max_delivery_attempts = _optional_integer_identifier(
        payload.get("max_delivery_attempts"), field="max_delivery_attempts"
    )
    if deliveries and max_delivery_attempts < 1:
        raise ResponseContractError(
            "max_delivery_attempts must be positive when receipts are leased"
        )
    if any(attempt > max_delivery_attempts for attempt in attempt_counts):
        raise ResponseContractError(
            "delivery attempt_count must not exceed max_delivery_attempts"
        )
    blocking = payload.get("blocking_delivery")
    if blocking is not None:
        if not isinstance(blocking, dict):
            raise ResponseContractError("blocking_delivery must be an object or null")
        blocking_delivery_id = _context_delivery_identifier(
            blocking.get("delivery_id")
        )
        blocking_event_id = _integer_identifier(
            blocking.get("event_id"), field="event_id"
        )
        if (
            blocking_delivery_id in delivery_ids
            or blocking_event_id in delivery_event_ids
        ):
            raise ResponseContractError(
                "blocking delivery must be distinct from visible leased receipts"
            )
        reason = _atomic_identifier(
            blocking.get("reason"), field="blocking_reason", max_chars=64
        )
        if reason == "retry-exhausted":
            blocking_attempt_count = _integer_identifier(
                blocking.get("attempt_count"), field="attempt_count", minimum=1
            )
            blocking_max_attempts = _integer_identifier(
                blocking.get("max_delivery_attempts"),
                field="max_delivery_attempts",
                minimum=1,
            )
            if blocking_max_attempts != max_delivery_attempts:
                raise ResponseContractError(
                    "blocking max_delivery_attempts must match hydration delivery policy"
                )
            if blocking_attempt_count < blocking_max_attempts:
                raise ResponseContractError(
                    "retry-exhausted attempt_count must reach max_delivery_attempts"
                )
            if _strict_boolean(
                blocking.get("requires_governed_dead_letter"),
                field="requires_governed_dead_letter",
            ) is not True:
                raise ResponseContractError(
                    "retry-exhausted delivery must require governed dead-letter review"
                )
        elif reason == "active-lease":
            if any(
                key in blocking
                for key in (
                    "attempt_count",
                    "max_delivery_attempts",
                    "requires_governed_dead_letter",
                )
            ):
                raise ResponseContractError(
                    "active-lease blocker contains incompatible retry-exhaustion fields"
                )
            _strict_positive_number(
                blocking.get("lease_expires_at"), field="lease_expires_at"
            )
        else:
            raise ResponseContractError("blocking_delivery reason is unsupported")
        if not payload.get("has_more_events"):
            raise ResponseContractError(
                "has_more_events must be true while a delivery is blocked"
            )
    if not claim_events and (
        events
        or deliveries
        or ack_required
        or has_more_events
        or blocking is not None
    ):
        raise ResponseContractError(
            "observation-only hydration cannot claim delivery state"
        )
    if claim_events and has_more_events and not deliveries and blocking is None:
        raise ResponseContractError(
            "has_more_events requires visible receipts or an explicit blocking delivery"
        )
    if claim_events:
        if remaining_pending_count < len(deliveries):
            raise ResponseContractError(
                "remaining_pending_count cannot be smaller than the leased batch"
            )
        if has_more_events != (remaining_pending_count > len(deliveries)):
            raise ResponseContractError(
                "has_more_events must exactly reflect pending work beyond the leased batch"
            )
    elif remaining_pending_count != 0:
        raise ResponseContractError(
            "observation-only hydration cannot assert a pending delivery count"
        )


def _validate_nonnegative_count_fields(
    value: dict[str, Any],
    fields: tuple[str, ...],
    *,
    prefix: str,
) -> None:
    for field in fields:
        if field in value:
            _safe_int(value.get(field))


def _validate_nonnegative_count_map(value: Any, *, field: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ResponseContractError(f"{field} must be an object")
    for key, count in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ResponseContractError(f"{field} contains an invalid count key")
        _safe_int(count)


def _validate_graph_count_summary(
    value: Any,
    *,
    field: str,
    modes_key: str = "relationship_modes",
) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ResponseContractError(f"{field} must be an object")
    _validate_nonnegative_count_fields(
        value,
        ("entry_count", "relationship_count"),
        prefix=field,
    )
    relationship_count = (
        _safe_int(value.get("relationship_count"))
        if "relationship_count" in value
        else None
    )
    modes = value.get(modes_key)
    if modes is None:
        return
    if not isinstance(modes, dict):
        raise ResponseContractError(f"{field}.{modes_key} must be an object")
    _validate_nonnegative_count_fields(
        modes,
        ("total", "temporal", "associative", "other"),
        prefix=f"{field}.{modes_key}",
    )
    _validate_nonnegative_count_map(
        modes.get("by_type"), field=f"{field}.{modes_key}.by_type"
    )
    total = _safe_int(modes.get("total")) if "total" in modes else None
    if (
        relationship_count is not None
        and total is not None
        and total != relationship_count
    ):
        raise ResponseContractError(
            f"{field} relationship total must match relationship_count"
        )
    by_type = modes.get("by_type")
    if isinstance(by_type, dict) and total is not None:
        if sum(_safe_int(count) for count in by_type.values()) != total:
            raise ResponseContractError(
                f"{field} by_type counts must sum to relationship total"
            )
    mode_fields = ("temporal", "associative", "other")
    if total is not None and all(key in modes for key in mode_fields):
        if sum(_safe_int(modes.get(key)) for key in mode_fields) != total:
            raise ResponseContractError(
                f"{field} relationship mode counts must sum to total"
            )


def _validate_memory_entry_counts(entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        _validate_nonnegative_count_fields(
            entry,
            ("embedding_dimensions", "spike_count", "neuron_count"),
            prefix="memory entry",
        )


def _validate_cortex_counts(payload: dict[str, Any]) -> None:
    _validate_nonnegative_count_fields(
        payload,
        ("active_session_count", "goal_count"),
        prefix="cortex state",
    )
    _validate_nonnegative_count_map(
        payload.get("typed_memory_counts"), field="typed_memory_counts"
    )


def _validate_surface_identities(surface: str, payload: dict[str, Any]) -> None:
    if surface == "media-similarity":
        if payload.get("schema") != "synapse-s2.media-similarity.v1":
            raise ResponseContractError("media similarity schema is unsupported")
        if payload.get("distance_metric") != "s2-feature-vector-l2-v1":
            raise ResponseContractError("media similarity metric is unsupported")
        if payload.get("feature_print_bytes_returned") is not False:
            raise ResponseContractError(
                "media similarity must never return feature bytes"
            )
        if payload.get("raw_original_stored") is not False:
            raise ResponseContractError(
                "media similarity must never store raw originals"
            )
        confidence = payload.get("confidence")
        if (
            not isinstance(confidence, dict)
            or confidence.get("calibrated") is not False
        ):
            raise ResponseContractError(
                "media similarity confidence is not uncalibrated"
            )
        return
    if surface == "memory-retrieval":
        if payload.get("schema") != "synapse-retrieval.v2":
            raise ResponseContractError("retrieval schema is unsupported")
        if payload.get("schema_version") != 2:
            raise ResponseContractError("retrieval schema_version is unsupported")
        if payload.get("raw_input_stored") is not False:
            raise ResponseContractError("retrieval must not store raw query input")
        query = payload.get("query")
        ranker = payload.get("ranker")
        scope = payload.get("scope")
        completeness = payload.get("completeness")
        if not all(
            isinstance(value, dict)
            for value in (query, ranker, scope, completeness)
        ):
            raise ResponseContractError("retrieval control metadata is invalid")
        assert isinstance(query, dict)
        assert isinstance(ranker, dict)
        assert isinstance(scope, dict)
        assert isinstance(completeness, dict)
        context_id = _atomic_identifier(
            query.get("context_id"), field="context_id", max_chars=128
        )
        if query.get("raw_input_stored") is not False:
            raise ResponseContractError("retrieval query must not store raw input")
        if str(query.get("recall_scope") or "") not in {
            "local",
            "connected",
            "all",
        }:
            raise ResponseContractError("retrieval recall_scope is invalid")
        recall_scope = str(query.get("recall_scope"))
        confidence_semantics = ranker.get("confidence_semantics")
        if (
            not isinstance(confidence_semantics, dict)
            or confidence_semantics.get("calibrated") is not False
            or confidence_semantics.get("probability") is not False
        ):
            raise ResponseContractError("retrieval ranker confidence is not uncalibrated")
        if scope.get("origin_context_id") != context_id:
            raise ResponseContractError("retrieval scope origin does not match query")
        if scope.get("requested_scope") != recall_scope:
            raise ResponseContractError("retrieval scope does not match query")
        scope_contexts = _strict_object_list(
            scope.get("contexts"), field="scope contexts"
        )
        resolved_context_ids: set[str] = set()
        for record in scope_contexts:
            record_origin = _atomic_identifier(
                record.get("origin_context_id"),
                field="origin_context_id",
                max_chars=128,
            )
            resolved_context_id = _atomic_identifier(
                record.get("resolved_context_id"),
                field="resolved_context_id",
                max_chars=128,
            )
            record_scope = str(record.get("requested_scope") or "")
            provenance = str(record.get("provenance") or "")
            if record_origin != context_id or record_scope != recall_scope:
                raise ResponseContractError(
                    "retrieval scope provenance does not match query"
                )
            context_link = _project_retrieval_context_link(
                record.get("context_link")
            )
            if provenance == "connected":
                if (
                    recall_scope != "connected"
                    or context_link is None
                    or context_link.get("enabled") is not True
                    or context_link.get("approved") is not True
                ):
                    raise ResponseContractError(
                        "connected retrieval scope requires approved link provenance"
                    )
                _validate_retrieval_link_reachability(
                    context_link,
                    origin_context_id=context_id,
                    resolved_context_id=resolved_context_id,
                )
            elif provenance not in {"local", "global", "all"}:
                raise ResponseContractError("retrieval scope provenance is invalid")
            elif context_link is not None:
                raise ResponseContractError(
                    "non-connected retrieval scope must not claim link provenance"
                )
            resolved_context_ids.add(resolved_context_id)
        if len(resolved_context_ids) != len(scope_contexts):
            raise ResponseContractError("retrieval scope contexts must be unique")
        if context_id not in resolved_context_ids:
            raise ResponseContractError("retrieval scope omitted its origin context")
        if _safe_int(scope.get("resolved_context_count")) != len(scope_contexts):
            raise ResponseContractError(
                "retrieval resolved_context_count must match scope contexts"
            )
        items = _strict_object_list(payload.get("items"), field="items")
        if _safe_int(payload.get("result_count")) != len(items):
            raise ResponseContractError("retrieval result_count must match items")
        memory_ids: set[str] = set()
        for expected_rank, item in enumerate(items, start=1):
            projected = _project_retrieval_item(item)
            if projected["rank"] != expected_rank:
                raise ResponseContractError("retrieval ranks must be contiguous")
            memory_id = projected["memory_id"]
            if memory_id in memory_ids:
                raise ResponseContractError("retrieval memory ids must be unique")
            memory_ids.add(memory_id)
            item_context = projected["context_id"]
            item_scope = projected["scope_provenance"]
            if (
                item_context not in resolved_context_ids
                or item_scope["origin_context_id"] != context_id
                or item_scope["resolved_context_id"] != item_context
                or item_scope["requested_scope"] != query.get("recall_scope")
            ):
                raise ResponseContractError("retrieval item escaped its resolved scope")
            provenance = item_scope["provenance"]
            context_link = item_scope["context_link"]
            if provenance == "connected":
                if (
                    not isinstance(context_link, dict)
                    or context_link.get("enabled") is not True
                    or context_link.get("approved") is not True
                ):
                    raise ResponseContractError(
                        "connected retrieval requires approved link provenance"
                    )
                _validate_retrieval_link_reachability(
                    context_link,
                    origin_context_id=context_id,
                    resolved_context_id=item_context,
                )
            elif context_link is not None:
                raise ResponseContractError(
                    "non-connected retrieval must not claim link provenance"
                )
            if projected["raw_source_included"] is not False:
                raise ResponseContractError("retrieval item exposed raw source")
            if (
                projected["ranker_id"] != ranker.get("id")
                or projected["ranker_version"] != ranker.get("version")
            ):
                raise ResponseContractError(
                    "retrieval item ranker identity does not match response"
                )
        if completeness.get("pagination_supported") is not False:
            raise ResponseContractError("ranked retrieval pagination is unsupported")
        if completeness.get("next_cursor") is not None:
            raise ResponseContractError("ranked retrieval must not invent a cursor")
        scope_complete = _strict_boolean(
            completeness.get("scope_complete"),
            field="completeness.scope_complete",
        )
        query_terms_truncated = _strict_boolean(
            completeness.get("query_terms_truncated"),
            field="completeness.query_terms_truncated",
        )
        candidate_scan_truncated = _strict_boolean(
            completeness.get("candidate_scan_truncated"),
            field="completeness.candidate_scan_truncated",
        )
        result_set_truncated = _strict_boolean(
            completeness.get("result_set_truncated"),
            field="completeness.result_set_truncated",
        )
        expected_has_more = candidate_scan_truncated or result_set_truncated
        if _strict_boolean(
            completeness.get("has_more"), field="completeness.has_more"
        ) != expected_has_more:
            raise ResponseContractError("retrieval has_more is inconsistent")
        expected_complete = bool(
            scope_complete
            and not query_terms_truncated
            and not candidate_scan_truncated
            and not result_set_truncated
        )
        if _strict_boolean(
            completeness.get("complete"), field="completeness.complete"
        ) != expected_complete:
            raise ResponseContractError("retrieval completeness is inconsistent")
        return

    context_id = _atomic_identifier(
        payload.get("context_id"), field="context_id", max_chars=128
    )
    if surface == "agent-hydration":
        connectivity = payload.get("namespace_connectivity")
        if not isinstance(connectivity, dict):
            raise ResponseContractError("namespace_connectivity must be an object")
        for field in (
            "automatic_cross_namespace_write",
            "multi_mac_live_sync",
        ):
            if connectivity.get(field) is not False:
                raise ResponseContractError(
                    f"namespace_connectivity.{field} must be false"
                )
        protocol_version = _atomic_identifier(
            payload.get("protocol_version"),
            field="protocol_version",
            max_chars=64,
        )
        delivery_mode = _atomic_identifier(
            payload.get("delivery_mode"), field="delivery_mode", max_chars=64
        )
        if protocol_version != CONTEXT_DELIVERY_PROTOCOL:
            raise ResponseContractError("agent hydration protocol_version is unsupported")
        if delivery_mode != CONTEXT_DELIVERY_MODE:
            raise ResponseContractError("agent hydration delivery_mode is unsupported")
        agent_id = _atomic_identifier(
            payload.get("agent_id"), field="agent_id", max_chars=128
        )
        since_event_id = _optional_integer_identifier(
            payload.get("since_event_id"), field="since_event_id"
        )
        latest_event_id = _optional_integer_identifier(
            payload.get("latest_event_id"), field="latest_event_id"
        )
        if latest_event_id < since_event_id:
            raise ResponseContractError(
                "latest_event_id must not precede since_event_id"
            )
        _validate_agent_delivery_batch(
            payload,
            context_id=context_id,
            agent_id=agent_id,
        )
        visible_event_ids = [
            _integer_identifier(event.get("event_id"), field="event_id")
            for event in _strict_object_list(payload.get("events"), field="events")
        ]
        if any(event_id <= since_event_id for event_id in visible_event_ids):
            raise ResponseContractError(
                "visible delivery event ids must be newer than since_event_id"
            )
        if visible_event_ids and latest_event_id < max(visible_event_ids):
            raise ResponseContractError(
                "latest_event_id must cover every visible delivery event"
            )
        if "new_event_count" in payload:
            new_event_count = _optional_integer_identifier(
                payload.get("new_event_count"), field="new_event_count"
            )
            if new_event_count != len(visible_event_ids):
                raise ResponseContractError(
                    "new_event_count must match the visible delivery event batch"
                )
        blocking = payload.get("blocking_delivery")
        if isinstance(blocking, dict):
            blocking_event_id = _integer_identifier(
                blocking.get("event_id"), field="event_id"
            )
            if blocking_event_id <= since_event_id:
                raise ResponseContractError(
                    "blocking delivery event_id must be newer than since_event_id"
                )
        memory_rows = _strict_object_list(
            payload.get("graph_entries"), field="graph_entries", allow_missing=True
        )
        relationship_rows = _strict_object_list(
            payload.get("graph_relationships"),
            field="graph_relationships",
            allow_missing=True,
        )
        _validate_nonnegative_count_fields(
            payload,
            ("input_redaction_count",),
            prefix="agent hydration",
        )
        _validate_graph_count_summary(
            payload.get("graph_summary"), field="graph_summary"
        )
        graph_summary = payload.get("graph_summary")
        if isinstance(graph_summary, dict):
            if (
                "entry_count" in graph_summary
                and _safe_int(graph_summary.get("entry_count")) < len(memory_rows)
            ):
                raise ResponseContractError(
                    "graph_summary entry_count cannot be smaller than returned graph entries"
                )
            if (
                "relationship_count" in graph_summary
                and _safe_int(graph_summary.get("relationship_count"))
                < len(relationship_rows)
            ):
                raise ResponseContractError(
                    "graph_summary relationship_count cannot be smaller than returned graph relationships"
                )
        cortex_state = payload.get("cortex_state")
        if cortex_state is not None:
            if not isinstance(cortex_state, dict):
                raise ResponseContractError("cortex_state must be an object")
            _validate_surface_identities("cortex-state", cortex_state)
            if cortex_state.get("context_id") != context_id:
                raise ResponseContractError(
                    "nested Cortex context_id must match hydration context_id"
                )
            nested_agent_id = cortex_state.get("agent_id")
            if nested_agent_id not in (None, "") and nested_agent_id != agent_id:
                raise ResponseContractError(
                    "nested Cortex agent_id must match hydration agent_id"
                )
    elif surface == "memory-list":
        if "one_hop_only" in payload:
            _strict_boolean(payload.get("one_hop_only"), field="one_hop_only")
        if "include_vectors" in payload:
            _strict_boolean(payload.get("include_vectors"), field="include_vectors")
        memory_rows = _strict_object_list(
            payload.get("entries"), field="entries", allow_missing=True
        )
        relationship_rows = []
        if "entry_count" in payload and _safe_int(payload.get("entry_count")) != len(
            memory_rows
        ):
            raise ResponseContractError(
                "memory list entry_count must match returned entries"
            )
    elif surface == "memory-graph":
        memory_rows = _strict_object_list(
            payload.get("entries"), field="entries", allow_missing=True
        )
        relationship_rows = _strict_object_list(
            payload.get("relationships"), field="relationships", allow_missing=True
        )
        _validate_graph_count_summary(
            {
                "entry_count": payload.get("entry_count"),
                "relationship_count": payload.get("relationship_count"),
                "relationship_modes": payload.get("relationship_summary"),
            },
            field="memory graph summary",
        )
        if "entry_count" in payload and _safe_int(payload.get("entry_count")) != len(
            memory_rows
        ):
            raise ResponseContractError(
                "memory graph entry_count must match returned entries"
            )
        if (
            "relationship_count" in payload
            and _safe_int(payload.get("relationship_count")) != len(relationship_rows)
        ):
            raise ResponseContractError(
                "memory graph relationship_count must match returned relationships"
            )
        relationship_summary = payload.get("relationship_summary")
        if isinstance(relationship_summary, dict) and isinstance(
            relationship_summary.get("by_type"), dict
        ):
            actual_by_type: dict[str, int] = {}
            for relationship in relationship_rows:
                relation_type = str(relationship.get("relation_type") or "unknown")
                actual_by_type[relation_type] = actual_by_type.get(relation_type, 0) + 1
            declared_by_type = {
                str(key): _safe_int(value)
                for key, value in relationship_summary["by_type"].items()
            }
            if declared_by_type != actual_by_type:
                raise ResponseContractError(
                    "memory graph by_type counts must match returned relationships"
                )
    else:
        root_agent_id = _optional_atomic_identifier(
            payload.get("agent_id"), field="agent_id", max_chars=128
        )
        for session in _strict_object_list(
            payload.get("active_sessions"),
            field="active_sessions",
            allow_missing=True,
        ):
            _atomic_identifier(session.get("session_id"), field="session_id")
            session_context_id = _optional_atomic_identifier(
                session.get("context_id"),
                field="session_context_id",
                max_chars=128,
            )
            session_agent_id = _atomic_identifier(
                session.get("agent_id"), field="agent_id", max_chars=128
            )
            if session_context_id and session_context_id != context_id:
                raise ResponseContractError(
                    "Cortex session context_id must match Cortex context_id"
                )
            if root_agent_id and session_agent_id != root_agent_id:
                raise ResponseContractError(
                    "Cortex session agent_id must match Cortex agent_id"
                )
        for collection in (
            "goals",
            "constraints",
            "risks",
            "contradictions",
        ):
            for item in _strict_object_list(
                payload.get(collection), field=collection, allow_missing=True
            ):
                _optional_atomic_identifier(
                    item.get("memory_id", item.get("goal_id")), field="memory_id"
                )
        if payload.get("_retrieval_page") is not None:
            for item in _strict_object_list(
                payload.get("working_memory"),
                field="working_memory",
                allow_missing=True,
            ):
                _optional_atomic_identifier(
                    item.get("memory_id", item.get("goal_id")),
                    field="memory_id",
                )
        policy = payload.get("policy")
        if isinstance(policy, dict) and policy.get("policy_id") not in (None, ""):
            _atomic_identifier(policy.get("policy_id"), field="policy_id", max_chars=160)
        _validate_cortex_counts(payload)
        sessions = _strict_object_list(
            payload.get("active_sessions"),
            field="active_sessions",
            allow_missing=True,
        )
        goals = _strict_object_list(
            payload.get("goals"), field="goals", allow_missing=True
        )
        if (
            "active_session_count" in payload
            and _safe_int(payload.get("active_session_count")) < len(sessions)
        ):
            raise ResponseContractError(
                "active_session_count cannot be smaller than returned sessions"
            )
        if "goal_count" in payload and _safe_int(payload.get("goal_count")) != len(
            goals
        ):
            raise ResponseContractError("goal_count must match returned goals")
        return

    _validate_memory_entry_counts(memory_rows)
    for entry in memory_rows:
        _atomic_identifier(entry.get("memory_id"), field="memory_id")
        _atomic_identifier(entry.get("context_id"), field="context_id", max_chars=128)
        _optional_atomic_identifier(
            entry.get("via_context_link_id"), field="context_link_id"
        )
    for relationship in relationship_rows:
        _atomic_identifier(
            relationship.get("relationship_id"), field="relationship_id"
        )
        _atomic_identifier(
            relationship.get("source_memory_id"), field="source_memory_id"
        )
        _atomic_identifier(
            relationship.get("target_memory_id"), field="target_memory_id"
        )


def _record_projection_text_edit(
    raw: str,
    projected: str,
    *,
    max_chars: int,
) -> None:
    audit = _PROJECTION_OMISSIONS.get()
    if audit is None or projected == raw:
        return
    if len(raw) > max_chars:
        omitted = len(raw) - max(0, max_chars - 1)
    else:
        omitted = 1
    audit["projected_text_characters"] = (
        int(audit.get("projected_text_characters", 0)) + max(1, omitted)
    )


def _clean_text(value: Any, max_chars: int) -> str:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    raw = str(value)
    if not raw.strip():
        return ""
    projected = safe_public_error(raw, fallback="redacted", max_chars=max_chars)
    _record_projection_text_edit(raw, projected, max_chars=max_chars)
    return projected


def _safe_int(value: Any) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        raise ResponseContractError("response contains an unsupported numeric value")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        if value != value.strip() or not re.fullmatch(r"[+-]?[0-9]+", value):
            raise ResponseContractError("response contains an unsupported numeric value")
        result = int(value)
    elif not isinstance(value, float):
        raise ResponseContractError("response contains an unsupported numeric value")
    else:
        if not math.isfinite(value) or not value.is_integer():
            raise ResponseContractError(
                "response contains an unsupported nonintegral numeric value"
            )
        result = int(value)
    if result < 0:
        raise ResponseContractError(
            "response contains an unsupported negative numeric value"
        )
    return result


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return _safe_int(value)


def _safe_number(value: Any) -> int | float:
    if value in (None, "") or isinstance(value, bool):
        return 0
    if not isinstance(value, (int, float, str)):
        raise ResponseContractError("response contains an unsupported numeric value")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ResponseContractError("response contains an unsupported numeric value") from exc
    if not math.isfinite(number):
        raise ResponseContractError(
            "response contains an unsupported nonfinite numeric value"
        )
    if number.is_integer():
        return int(number)
    return round(number, 9)


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _safe_count_map(
    value: Any,
    *,
    max_entries: int | None = 64,
    max_key_chars: int | None = 80,
) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, int] = {}
    all_keys = sorted(key for key in value if isinstance(key, str))
    keys = (
        all_keys
        if max_entries is None
        else all_keys[: max(0, int(max_entries))]
    )
    audit = _PROJECTION_OMISSIONS.get()
    if audit is not None and len(all_keys) > len(keys):
        audit["projected_map_entries"] = (
            int(audit.get("projected_map_entries", 0)) + len(all_keys) - len(keys)
        )
    for key in keys:
        if max_key_chars is None:
            clean_key_value, _ = redact_sensitive_value(key)
            clean_key_value, _ = strip_untrusted_raw_digest_fields(clean_key_value)
            clean_key_value, _ = _mask_full_response_paths(clean_key_value)
            clean_key = (
                clean_key_value if isinstance(clean_key_value, str) else ""
            )
        else:
            clean_key = _clean_text(key, max(1, int(max_key_chars)))
        if clean_key:
            count = _safe_int(value.get(key))
            if clean_key in result:
                if audit is not None:
                    audit["projected_count_key_collisions"] = (
                        int(audit.get("projected_count_key_collisions", 0)) + 1
                    )
                result[clean_key] += count
            else:
                result[clean_key] = count
    return result


def _error_code(error: BaseException | str) -> str:
    if isinstance(error, ResponseBudgetError):
        return "response-budget-invalid"
    if isinstance(error, ResponseContractError):
        return "response-contract-invalid"
    return "request-failed"

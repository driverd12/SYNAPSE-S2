#!/usr/bin/env python3
"""Preview and perform a guarded purge of whole SYNAPSE-S2 namespaces.

This operator tool deliberately composes supported authoritative-core reads
and the existing governed ``prune_memory`` operation. Mutations always pass
through the core. A separate owner-bound, read-only metadata probe refuses
cataloged namespaces because this release has no catalog archive primitive.
The tool never permits cwd-based backend selection.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core_client import CoreClient, CoreOutcomeUnknown, outcome_unknown_projection
from core_client_binding import (
    BINDING_ENV,
    CoreClientBinding,
    apply_binding_environment,
    default_binding_path,
)
from redaction import (
    SecretSafeArgumentParser,
    redact_capture_text,
    validate_public_identifier,
)
from memory_store import NAMESPACE_CATALOG_METADATA_PREFIX


PLAN_SCHEMA = "synapse-s2.namespace-purge-plan.v1"
RESULT_SCHEMA = "synapse-s2.namespace-purge-result.v1"
SOURCE_SURFACE = "namespace-purge-script"
PROTECTED_CONTEXTS = frozenset({"default", "global"})
MAX_CONTEXTS = 32
MAX_CONTEXT_CHARS = 128
MAX_REASON_BYTES = 2_048
PAGE_LIMIT = 500
MAP_LIMIT = 10_000
PROPOSAL_LIMIT = 2_000
REVISION_RE = re.compile(r"^[0-9a-f]{64}$")
CONTEXT_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")


class NamespacePurgeError(RuntimeError):
    """A stable, content-free refusal suitable for a public CLI boundary."""

    def __init__(self, code: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(code)
        self.code = str(code)
        self.details = dict(details or {})


@dataclass(frozen=True)
class NamespaceInventory:
    context_id: str
    memory_ids: tuple[str, ...]
    relationship_ids: tuple[str, ...]
    context_event_ids: tuple[int, ...]
    memory_snapshot_revision: str
    graph_snapshot_revision: str
    status: Mapping[str, Any]
    delivery: Mapping[str, Any]
    pending_proposals: tuple[Mapping[str, Any], ...]
    cataloged: bool


@dataclass(frozen=True)
class PurgePlan:
    contexts: tuple[str, ...]
    inventories: Mapping[str, NamespaceInventory]
    nodes: Mapping[str, Mapping[str, Any]]
    active_links: tuple[Mapping[str, Any], ...]
    blockers: tuple[Mapping[str, Any], ...]
    revision: str

    @property
    def ready(self) -> bool:
        return not self.blockers

    def public_preview(self) -> dict[str, Any]:
        namespaces: list[dict[str, Any]] = []
        blockers_by_context: dict[str, list[str]] = {item: [] for item in self.contexts}
        for blocker in self.blockers:
            context = str(blocker.get("context_id") or "")
            if context in blockers_by_context:
                blockers_by_context[context].append(str(blocker["code"]))

        for context in self.contexts:
            inventory = self.inventories[context]
            node = self.nodes.get(context)
            relevant_links = _links_for_context(self.active_links, context)
            namespaces.append(
                {
                    "context_id": context,
                    "namespace_visible": node is not None,
                    "cataloged": inventory.cataloged,
                    "catalog_only_visible": _catalog_only_node(node),
                    "counts": {
                        "memory_nodes": len(inventory.memory_ids),
                        "memory_relationships": len(inventory.relationship_ids),
                        "context_events": len(inventory.context_event_ids),
                        "active_namespace_links": len(relevant_links),
                        "pending_link_proposals": len(inventory.pending_proposals),
                        "deliveries": _integer(inventory.delivery, "delivery_count"),
                        "delivery_receipts": _integer(inventory.delivery, "receipt_count"),
                        "existing_ack_tombstones": _integer(
                            inventory.delivery, "ack_tombstone_count"
                        ),
                        "active_delivery_leases": _integer(
                            inventory.status, "context_bus_active_lease_count"
                        ),
                        "surface_terms": _node_integer(node, "surface_term_count"),
                        "spike_indexes": _node_integer(node, "spike_index_count"),
                    },
                    "blockers": sorted(blockers_by_context[context]),
                }
            )
        return {
            "schema": PLAN_SCHEMA,
            "action": "preview-namespace-purge",
            "read_only": True,
            "ready": self.ready,
            "revision": self.revision,
            "namespace_count": len(self.contexts),
            "namespaces": namespaces,
            "blockers": [dict(item) for item in self.blockers],
            "commit_requirements": {
                "confirm": True,
                "nonempty_reason": True,
                "expected_revision": self.revision,
            },
            "whole_batch_atomic": False,
            "mutation_surface": "authoritative-core-prune-memory",
            "automatic_cross_namespace_write": False,
        }


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise NamespacePurgeError("inventory_projection_invalid") from exc


def _revision(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mapping(value: Any, *, code: str = "authoritative_response_invalid") -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NamespacePurgeError(code)
    return value


def _sequence(value: Any, *, code: str = "authoritative_response_invalid") -> list[Any]:
    if not isinstance(value, list):
        raise NamespacePurgeError(code)
    return value


def _integer(value: Mapping[str, Any] | None, key: str) -> int:
    raw = 0 if value is None else value.get(key, 0)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise NamespacePurgeError("authoritative_response_invalid")
    return raw


def _node_integer(node: Mapping[str, Any] | None, key: str) -> int:
    return 0 if node is None else _integer(node, key)


def _identifier(value: Any, *, field: str) -> str:
    try:
        return validate_public_identifier(value, field=field, max_chars=256)
    except ValueError as exc:
        raise NamespacePurgeError("authoritative_response_invalid") from exc


def normalize_contexts(values: Sequence[str]) -> tuple[str, ...]:
    if not values:
        raise NamespacePurgeError("context_required")
    if len(values) > MAX_CONTEXTS:
        raise NamespacePurgeError("too_many_contexts")
    contexts: list[str] = []
    seen: set[str] = set()
    for value in values:
        try:
            context = validate_public_identifier(
                value,
                field="context",
                max_chars=MAX_CONTEXT_CHARS,
            )
        except ValueError as exc:
            raise NamespacePurgeError("context_invalid") from exc
        if CONTEXT_RE.fullmatch(context) is None:
            raise NamespacePurgeError("context_invalid")
        if context.casefold() in PROTECTED_CONTEXTS:
            raise NamespacePurgeError(
                "protected_context",
                details={"context_id": context},
            )
        if context in seen:
            raise NamespacePurgeError(
                "duplicate_context",
                details={"context_id": context},
            )
        seen.add(context)
        contexts.append(context)
    return tuple(sorted(contexts))


def sanitize_reason(value: str) -> tuple[str, int]:
    raw = str(value or "")
    if not raw.strip() or len(raw.encode("utf-8")) > MAX_REASON_BYTES:
        raise NamespacePurgeError("reason_invalid")
    safe, redaction_count = redact_capture_text(raw.strip())
    safe = " ".join(safe.split())
    if not safe or len(safe.encode("utf-8")) > MAX_REASON_BYTES:
        raise NamespacePurgeError("reason_invalid")
    return safe, int(redaction_count)


def validate_expected_revision(value: str) -> str:
    revision = str(value or "")
    if REVISION_RE.fullmatch(revision) is None:
        raise NamespacePurgeError("expected_revision_invalid")
    return revision


def _assert_memory_path(response: Mapping[str, Any], expected: Path | None) -> None:
    if expected is None:
        return
    observed = response.get("memory_db_path")
    if not isinstance(observed, str) or Path(observed) != expected:
        raise NamespacePurgeError("authoritative_store_mismatch")


def _list_memory_ids(
    client: Any,
    context: str,
    *,
    expected_memory_path: Path | None,
) -> tuple[tuple[str, ...], str]:
    cursor = ""
    snapshot_revision = ""
    memory_ids: set[str] = set()
    while True:
        response = _mapping(
            client.list_memory(
                context_id=context,
                limit=PAGE_LIMIT,
                include_global=False,
                include_vectors=False,
                recall_scope="local",
                cursor=cursor,
                response_mode="full",
            )
        )
        _assert_memory_path(response, expected_memory_path)
        if response.get("context_id") != context:
            raise NamespacePurgeError("authoritative_response_invalid")
        for entry in _sequence(response.get("entries")):
            item = _mapping(entry)
            if item.get("context_id") != context:
                raise NamespacePurgeError("cross_context_inventory")
            memory_id = _identifier(item.get("memory_id"), field="memory_id")
            if memory_id in memory_ids:
                raise NamespacePurgeError("duplicate_inventory_identifier")
            memory_ids.add(memory_id)
        page = _mapping(response.get("_retrieval_page"))
        revision = str(page.get("snapshot_revision") or "")
        if REVISION_RE.fullmatch(revision) is None:
            raise NamespacePurgeError("authoritative_response_invalid")
        if snapshot_revision and revision != snapshot_revision:
            raise NamespacePurgeError("inventory_snapshot_changed")
        snapshot_revision = revision
        total = _integer(_mapping(page.get("total")), "entries")
        has_more = page.get("has_more")
        if type(has_more) is not bool:
            raise NamespacePurgeError("authoritative_response_invalid")
        if not has_more:
            if len(memory_ids) != total:
                raise NamespacePurgeError("inventory_count_mismatch")
            break
        next_cursor = page.get("next_cursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            raise NamespacePurgeError("authoritative_response_invalid")
        cursor = next_cursor
    return tuple(sorted(memory_ids)), snapshot_revision


def _list_relationship_ids(
    client: Any,
    context: str,
    *,
    expected_memory_path: Path | None,
) -> tuple[tuple[str, ...], str]:
    cursor = ""
    snapshot_revision = ""
    relationship_ids: set[str] = set()
    while True:
        response = _mapping(
            client.list_memory_graph(
                context_id=context,
                limit=PAGE_LIMIT,
                cursor=cursor,
                response_mode="full",
                include_global=False,
            )
        )
        _assert_memory_path(response, expected_memory_path)
        if response.get("context_id") != context:
            raise NamespacePurgeError("authoritative_response_invalid")
        for relationship in _sequence(response.get("relationships")):
            item = _mapping(relationship)
            if item.get("context_id") != context:
                raise NamespacePurgeError("cross_context_inventory")
            relationship_id = _identifier(
                item.get("relationship_id"), field="relationship_id"
            )
            if relationship_id in relationship_ids:
                raise NamespacePurgeError("duplicate_inventory_identifier")
            relationship_ids.add(relationship_id)
        page = _mapping(response.get("_retrieval_page"))
        revision = str(page.get("snapshot_revision") or "")
        if REVISION_RE.fullmatch(revision) is None:
            raise NamespacePurgeError("authoritative_response_invalid")
        if snapshot_revision and revision != snapshot_revision:
            raise NamespacePurgeError("inventory_snapshot_changed")
        snapshot_revision = revision
        total = _integer(_mapping(page.get("total")), "relationships")
        has_more = page.get("has_more")
        if type(has_more) is not bool:
            raise NamespacePurgeError("authoritative_response_invalid")
        if not has_more:
            if len(relationship_ids) != total:
                raise NamespacePurgeError("inventory_count_mismatch")
            break
        next_cursor = page.get("next_cursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
            raise NamespacePurgeError("authoritative_response_invalid")
        cursor = next_cursor
    return tuple(sorted(relationship_ids)), snapshot_revision


def _list_context_event_ids(client: Any, context: str) -> tuple[int, ...]:
    since_event_id = 0
    event_ids: set[int] = set()
    while True:
        response = _mapping(
            client.list_context_events(
                context_id=context,
                since_event_id=since_event_id,
                order="asc",
                limit=PAGE_LIMIT,
            )
        )
        if response.get("context_id") != context:
            raise NamespacePurgeError("authoritative_response_invalid")
        events = _sequence(response.get("events"))
        for event in events:
            item = _mapping(event)
            if item.get("context_id") != context:
                raise NamespacePurgeError("cross_context_inventory")
            event_id = item.get("event_id")
            if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id <= 0:
                raise NamespacePurgeError("authoritative_response_invalid")
            if event_id in event_ids:
                raise NamespacePurgeError("duplicate_inventory_identifier")
            event_ids.add(event_id)
        has_more = response.get("has_more")
        if type(has_more) is not bool:
            raise NamespacePurgeError("authoritative_response_invalid")
        if not has_more:
            break
        next_event_id = response.get("next_event_id")
        if (
            isinstance(next_event_id, bool)
            or not isinstance(next_event_id, int)
            or next_event_id <= since_event_id
        ):
            raise NamespacePurgeError("authoritative_response_invalid")
        since_event_id = next_event_id
    return tuple(sorted(event_ids))


def _stable_link(link: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "context_link_id": _identifier(link.get("context_link_id"), field="context_link_id"),
        "source_context_id": str(link.get("source_context_id") or ""),
        "target_context_id": str(link.get("target_context_id") or ""),
        "revision": str(link.get("revision") or ""),
        "enabled": bool(link.get("enabled")),
        "effective_state": str(link.get("effective_state") or ""),
    }


def _stable_proposal(proposal: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "proposal_id": _identifier(proposal.get("proposal_id"), field="proposal_id"),
        "source_context_id": str(proposal.get("source_context_id") or ""),
        "target_context_id": str(proposal.get("target_context_id") or ""),
        "revision": str(proposal.get("revision") or ""),
        "effective_state": str(proposal.get("effective_state") or ""),
    }


def _links_for_context(
    links: Iterable[Mapping[str, Any]], context: str
) -> tuple[Mapping[str, Any], ...]:
    return tuple(
        item
        for item in links
        if context in {
            str(item.get("source_context_id") or ""),
            str(item.get("target_context_id") or ""),
        }
    )


def _catalog_only_node(node: Mapping[str, Any] | None) -> bool:
    if node is None:
        return False
    return all(
        _node_integer(node, key) == 0
        for key in (
            "entry_count",
            "relationship_count",
            "context_event_count",
            "context_link_count",
            "surface_term_count",
            "spike_index_count",
        )
    )


def _cataloged_contexts(
    client: Any,
    contexts: Sequence[str],
    *,
    expected_memory_path: Path | None,
) -> frozenset[str]:
    fake_probe = getattr(client, "namespace_catalog_contexts", None)
    if expected_memory_path is None:
        if callable(fake_probe):
            return frozenset(str(item) for item in fake_probe(contexts))
        return frozenset()
    path = expected_memory_path.expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise NamespacePurgeError("authoritative_store_mismatch")
    keys = [f"{NAMESPACE_CATALOG_METADATA_PREFIX}{context}" for context in contexts]
    placeholders = ",".join("?" for _ in keys)
    try:
        uri = f"{path.resolve().as_uri()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=2.0)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT key FROM store_metadata WHERE key IN ({placeholders})",
                keys,
            ).fetchall()
    except (OSError, sqlite3.Error) as exc:
        raise NamespacePurgeError("namespace_catalog_probe_failed") from exc
    observed: set[str] = set()
    expected_keys = set(keys)
    for row in rows:
        key = str(row["key"] or "")
        if key not in expected_keys:
            raise NamespacePurgeError("namespace_catalog_probe_failed")
        observed.add(key[len(NAMESPACE_CATALOG_METADATA_PREFIX) :])
    return frozenset(observed)


def _status_projection(status: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "memory_context_entry_count",
        "memory_context_relationship_count",
        "memory_selected_context_link_count",
        "context_bus_context_event_count",
        "context_bus_delivery_count",
        "context_bus_active_lease_count",
        "context_bus_ack_receipt_count",
        "context_bus_ack_tombstone_count",
        "active_cortex_session_count",
    )
    return {key: _integer(status, key) for key in keys}


def _delivery_projection(delivery: Mapping[str, Any]) -> dict[str, Any]:
    keys = (
        "structural_error_count",
        "expired_active_lease_count",
        "retry_exhausted_count",
        "dead_letter_count",
        "delivery_count",
        "receipt_count",
        "ack_tombstone_count",
    )
    projection = {key: _integer(delivery, key) for key in keys}
    projection["status"] = str(delivery.get("status") or "")
    return projection


def _node_projection(node: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if node is None:
        return None
    return {
        "context_id": str(node.get("context_id") or ""),
        "entry_count": _node_integer(node, "entry_count"),
        "relationship_count": _node_integer(node, "relationship_count"),
        "spike_index_count": _node_integer(node, "spike_index_count"),
        "surface_term_count": _node_integer(node, "surface_term_count"),
        "context_event_count": _node_integer(node, "context_event_count"),
        "context_link_count": _node_integer(node, "context_link_count"),
        "last_activity_at": node.get("last_activity_at", 0.0),
    }


def build_plan(
    client: Any,
    contexts: Sequence[str],
    *,
    expected_memory_path: Path | None = None,
) -> PurgePlan:
    normalized = normalize_contexts(contexts)
    cataloged_contexts = _cataloged_contexts(
        client,
        normalized,
        expected_memory_path=expected_memory_path,
    )
    inventories: dict[str, NamespaceInventory] = {}
    for context in normalized:
        memory_ids, memory_revision = _list_memory_ids(
            client, context, expected_memory_path=expected_memory_path
        )
        relationship_ids, graph_revision = _list_relationship_ids(
            client, context, expected_memory_path=expected_memory_path
        )
        event_ids = _list_context_event_ids(client, context)
        status = _mapping(client.status(context_id=context))
        _assert_memory_path(status, expected_memory_path)
        delivery = _mapping(client.context_delivery_health(context_id=context))
        proposals_response = _mapping(
            client.list_namespace_link_proposals(
                context_id=context,
                state="pending",
                limit=PROPOSAL_LIMIT,
            )
        )
        raw_proposals = _sequence(proposals_response.get("proposals"))
        proposals = tuple(
            sorted(
                (_stable_proposal(_mapping(item)) for item in raw_proposals),
                key=lambda item: item["proposal_id"],
            )
        )
        inventories[context] = NamespaceInventory(
            context_id=context,
            memory_ids=memory_ids,
            relationship_ids=relationship_ids,
            context_event_ids=event_ids,
            memory_snapshot_revision=memory_revision,
            graph_snapshot_revision=graph_revision,
            status=_status_projection(status),
            delivery=_delivery_projection(delivery),
            pending_proposals=proposals,
            cataloged=context in cataloged_contexts,
        )

    map_response = _mapping(
        client.list_namespace_map(
            context_id="",
            limit=MAP_LIMIT,
            include_suggestions=False,
            include_density_metrics=True,
            suggestion_limit=1,
            min_suggestion_score=1.0,
            max_visual_phase_delay_ticks=4,
        )
    )
    _assert_memory_path(map_response, expected_memory_path)
    raw_nodes = _sequence(map_response.get("nodes"))
    nodes: dict[str, Mapping[str, Any]] = {}
    for item in raw_nodes:
        node = _mapping(item)
        context_id = str(node.get("context_id") or "")
        if context_id in nodes:
            raise NamespacePurgeError("duplicate_namespace_map_node")
        nodes[context_id] = _node_projection(node) or {}
    active_links = tuple(
        sorted(
            (_stable_link(_mapping(item)) for item in _sequence(map_response.get("links"))),
            key=lambda item: item["context_link_id"],
        )
    )

    blockers: list[dict[str, Any]] = []
    map_truncated = len(raw_nodes) >= MAP_LIMIT
    for context in normalized:
        inventory = inventories[context]
        node = nodes.get(context)
        relevant_links = _links_for_context(active_links, context)
        if node is None:
            if map_truncated or inventory.memory_ids or inventory.context_event_ids:
                blockers.append({"code": "namespace-map-incomplete", "context_id": context})
            else:
                blockers.append({"code": "namespace-not-found", "context_id": context})
        else:
            count_pairs = (
                ("memory-nodes", len(inventory.memory_ids), _node_integer(node, "entry_count")),
                (
                    "memory-relationships",
                    len(inventory.relationship_ids),
                    _node_integer(node, "relationship_count"),
                ),
                (
                    "context-events",
                    len(inventory.context_event_ids),
                    _node_integer(node, "context_event_count"),
                ),
                (
                    "active-namespace-links",
                    len(relevant_links),
                    _node_integer(node, "context_link_count"),
                ),
            )
            for surface, enumerated, mapped in count_pairs:
                if enumerated != mapped:
                    blockers.append(
                        {
                            "code": "inventory-count-mismatch",
                            "context_id": context,
                            "surface": surface,
                            "enumerated": enumerated,
                            "mapped": mapped,
                        }
                    )
            if _integer(inventory.status, "memory_context_entry_count") != len(
                inventory.memory_ids
            ) or _integer(
                inventory.status, "memory_context_relationship_count"
            ) != len(
                inventory.relationship_ids
            ) or _integer(
                inventory.status, "context_bus_context_event_count"
            ) != len(
                inventory.context_event_ids
            ):
                blockers.append({"code": "status-count-mismatch", "context_id": context})
            if inventory.cataloged:
                blockers.append(
                    {"code": "cataloged-namespace-unsupported", "context_id": context}
                )
            if (
                _node_integer(node, "surface_term_count") > 0
                or _node_integer(node, "spike_index_count") > 0
            ) and not inventory.memory_ids:
                blockers.append(
                    {"code": "derived-index-without-memory", "context_id": context}
                )
        if relevant_links:
            blockers.append(
                {
                    "code": "active-namespace-links",
                    "context_id": context,
                    "count": len(relevant_links),
                }
            )
        if inventory.pending_proposals:
            blockers.append(
                {
                    "code": "pending-namespace-link-proposals",
                    "context_id": context,
                    "count": len(inventory.pending_proposals),
                }
            )
        if len(inventory.pending_proposals) >= PROPOSAL_LIMIT:
            blockers.append(
                {"code": "pending-proposal-inventory-truncated", "context_id": context}
            )
        active_leases = _integer(inventory.status, "context_bus_active_lease_count")
        if active_leases:
            blockers.append(
                {
                    "code": "active-delivery-leases",
                    "context_id": context,
                    "count": active_leases,
                }
            )
        if (
            str(inventory.delivery.get("status") or "") != "ready"
            or _integer(inventory.delivery, "structural_error_count") > 0
            or _integer(inventory.delivery, "retry_exhausted_count") > 0
        ):
            blockers.append({"code": "delivery-ledger-degraded", "context_id": context})

    blockers.sort(
        key=lambda item: (
            str(item.get("context_id") or ""),
            str(item.get("code") or ""),
            str(item.get("surface") or ""),
        )
    )
    revision_basis = {
        "schema": PLAN_SCHEMA,
        "contexts": [
            {
                "context_id": context,
                "memory_ids": list(inventories[context].memory_ids),
                "relationship_ids": list(inventories[context].relationship_ids),
                "context_event_ids": list(inventories[context].context_event_ids),
                "memory_snapshot_revision": inventories[
                    context
                ].memory_snapshot_revision,
                "graph_snapshot_revision": inventories[context].graph_snapshot_revision,
                "node": nodes.get(context),
                "active_links": list(_links_for_context(active_links, context)),
                "pending_proposals": list(inventories[context].pending_proposals),
                "cataloged": inventories[context].cataloged,
                "status": dict(inventories[context].status),
                "delivery": dict(inventories[context].delivery),
            }
            for context in normalized
        ],
        "blockers": blockers,
    }
    return PurgePlan(
        contexts=normalized,
        inventories=inventories,
        nodes={context: nodes[context] for context in normalized if context in nodes},
        active_links=active_links,
        blockers=tuple(blockers),
        revision=_revision(revision_basis),
    )


def _prune(
    client: Any,
    *,
    context: str,
    target_type: str,
    reason: str,
    memory_id: str = "",
    event_id: int = 0,
) -> None:
    response = _mapping(
        client.prune_memory(
            context_id=context,
            target_type=target_type,
            memory_id=memory_id,
            tag="",
            relationship_id="",
            event_id=event_id,
            reason=reason,
            source_surface=SOURCE_SURFACE,
            publish_audit=False,
            confirm=True,
        )
    )
    result = _mapping(response.get("result"))
    if result.get("deleted") is not True:
        raise NamespacePurgeError(
            "prune-target-changed",
            details={"context_id": context, "target_type": target_type},
        )
    if response.get("agent_deployment") is not None:
        raise NamespacePurgeError("per-target-audit-not-disabled")


def _verify_absent(plan: PurgePlan) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for context in plan.contexts:
        inventory = plan.inventories[context]
        if plan.nodes.get(context) is not None:
            failures.append({"context_id": context, "code": "namespace-still-visible"})
        if inventory.memory_ids:
            failures.append({"context_id": context, "code": "memory-still-visible"})
        if inventory.relationship_ids:
            failures.append({"context_id": context, "code": "relationships-still-visible"})
        if inventory.context_event_ids:
            failures.append({"context_id": context, "code": "context-events-still-visible"})
        if _links_for_context(plan.active_links, context):
            failures.append({"context_id": context, "code": "links-still-visible"})
        if inventory.pending_proposals:
            failures.append({"context_id": context, "code": "proposals-still-visible"})
        if _integer(inventory.delivery, "delivery_count"):
            failures.append({"context_id": context, "code": "deliveries-still-visible"})
        if _integer(inventory.status, "context_bus_active_lease_count"):
            failures.append({"context_id": context, "code": "leases-still-visible"})
    return sorted(failures, key=lambda item: (item["context_id"], item["code"]))


def commit_purge(
    client: Any,
    contexts: Sequence[str],
    *,
    expected_revision: str,
    reason: str,
    confirm: bool,
    expected_memory_path: Path | None = None,
) -> dict[str, Any]:
    if confirm is not True:
        raise NamespacePurgeError("confirm_required")
    expected = validate_expected_revision(expected_revision)
    safe_reason, reason_redaction_count = sanitize_reason(reason)
    plan = build_plan(client, contexts, expected_memory_path=expected_memory_path)
    if plan.revision != expected:
        raise NamespacePurgeError(
            "revision_mismatch",
            details={"actual_revision": plan.revision},
        )
    if not plan.ready:
        raise NamespacePurgeError(
            "purge_blocked",
            details={"revision": plan.revision, "blockers": list(plan.blockers)},
        )

    removed_counts: dict[str, dict[str, int]] = {
        context: {
            "memory_nodes": len(plan.inventories[context].memory_ids),
            "memory_relationships": len(
                plan.inventories[context].relationship_ids
            ),
            "context_events": len(plan.inventories[context].context_event_ids),
            "deliveries": _integer(
                plan.inventories[context].delivery, "delivery_count"
            ),
            "ack_tombstones_preserved_before": _integer(
                plan.inventories[context].delivery, "ack_tombstone_count"
            ),
        }
        for context in plan.contexts
    }
    started_audit = _mapping(
        client.publish_context_event(
            context_id="default",
            source_surface=SOURCE_SURFACE,
            event_type="namespace-purge-started",
            summary=(
                f"Governed namespace purge started for {len(plan.contexts)} "
                "namespace(s)."
            ),
            payload={
                "schema": RESULT_SCHEMA,
                "purge_state": "started",
                "target_context_ids": list(plan.contexts),
                "plan_revision": plan.revision,
                "reason": safe_reason,
                "reason_redaction_count": reason_redaction_count,
                "planned_counts": removed_counts,
                "whole_batch_atomic": False,
                "per_target_audit_published": False,
                "automatic_cross_namespace_write": False,
            },
        )
    )
    started_audit_event_id = started_audit.get("event_id")
    if (
        isinstance(started_audit_event_id, bool)
        or not isinstance(started_audit_event_id, int)
    ):
        raise NamespacePurgeError("audit_projection_invalid")

    for context in plan.contexts:
        inventory = plan.inventories[context]
        for memory_id in inventory.memory_ids:
            _prune(
                client,
                context=context,
                target_type="memory",
                memory_id=memory_id,
                reason=safe_reason,
            )
        for event_id in sorted(inventory.context_event_ids, reverse=True):
            _prune(
                client,
                context=context,
                target_type="context_event",
                event_id=event_id,
                reason=safe_reason,
            )

    verification = build_plan(
        client,
        plan.contexts,
        expected_memory_path=expected_memory_path,
    )
    verification_failures = _verify_absent(verification)
    if verification_failures:
        raise NamespacePurgeError(
            "post_purge_verification_failed",
            details={"failures": verification_failures},
        )

    audit = _mapping(
        client.publish_context_event(
            context_id="default",
            source_surface=SOURCE_SURFACE,
            event_type="namespace-purge",
            summary=f"Governed namespace purge removed {len(plan.contexts)} namespace(s).",
            payload={
                "schema": RESULT_SCHEMA,
                "purge_state": "completed",
                "purged_context_ids": list(plan.contexts),
                "plan_revision": plan.revision,
                "started_audit_event_id": started_audit_event_id,
                "reason": safe_reason,
                "reason_redaction_count": reason_redaction_count,
                "removed_counts": removed_counts,
                "post_purge_verified": True,
                "per_target_audit_published": False,
                "automatic_cross_namespace_write": False,
            },
        )
    )
    completed_audit_event_id = audit.get("event_id")
    if (
        isinstance(completed_audit_event_id, bool)
        or not isinstance(completed_audit_event_id, int)
    ):
        raise NamespacePurgeError("audit_projection_invalid")
    return {
        "schema": RESULT_SCHEMA,
        "action": "commit-namespace-purge",
        "status": "purged",
        "plan_revision": plan.revision,
        "purged_context_ids": list(plan.contexts),
        "removed_counts": removed_counts,
        "post_purge_verified": True,
        "audit_context_id": "default",
        "started_audit_event_id": started_audit_event_id,
        "completed_audit_event_id": completed_audit_event_id,
        "per_target_audit_published": False,
        "automatic_cross_namespace_write": False,
    }


def authoritative_client() -> tuple[CoreClient, CoreClientBinding]:
    if BINDING_ENV not in os.environ:
        installed = default_binding_path()
        if installed.exists() or installed.is_symlink():
            os.environ[BINDING_ENV] = str(installed)
    binding = apply_binding_environment()
    if binding is None or binding.authority_mode != "authoritative-core-v6":
        raise NamespacePurgeError("authoritative_binding_required")
    # Memory-node pruning refreshes the registered neural trace projection and
    # can legitimately approach the ordinary core deadline on a large store.
    # Use the protocol's full control-plane window so a committed delete is not
    # reported as outcome-unknown merely because the generic 15-second client
    # default elapsed first.
    return CoreClient(caller=SOURCE_SURFACE, default_timeout_seconds=30.0), binding


def build_parser() -> SecretSafeArgumentParser:
    parser = SecretSafeArgumentParser(
        description="Preview or commit a governed whole-namespace purge."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    preview = subparsers.add_parser("preview", help="read-only exact inventory")
    preview.add_argument(
        "--context",
        action="append",
        required=True,
        help="namespace id; repeat for a bounded batch",
    )
    commit = subparsers.add_parser("commit", help="commit a previously previewed plan")
    commit.add_argument("--context", action="append", required=True)
    commit.add_argument("--reason", required=True)
    commit.add_argument("--expected-revision", required=True)
    commit.add_argument("--confirm", action="store_true")
    return parser


def _emit(payload: Mapping[str, Any], *, stream: Any = sys.stdout) -> None:
    stream.write(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        client, binding = authoritative_client()
        if args.command == "preview":
            plan = build_plan(
                client,
                args.context,
                expected_memory_path=binding.memory_path,
            )
            _emit(plan.public_preview())
            return 0
        result = commit_purge(
            client,
            args.context,
            expected_revision=args.expected_revision,
            reason=args.reason,
            confirm=args.confirm,
            expected_memory_path=binding.memory_path,
        )
        _emit(result)
        return 0
    except CoreOutcomeUnknown as exc:
        _emit(
            {
                "schema": RESULT_SCHEMA,
                "status": "outcome_unknown",
                "reconciliation": outcome_unknown_projection(exc),
            },
            stream=sys.stderr,
        )
        return 3
    except NamespacePurgeError as exc:
        _emit(
            {
                "schema": RESULT_SCHEMA,
                "status": "refused",
                "code": exc.code,
                **exc.details,
            },
            stream=sys.stderr,
        )
        return 2
    except Exception:
        _emit(
            {
                "schema": RESULT_SCHEMA,
                "status": "failed",
                "code": "namespace_purge_failed",
            },
            stream=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

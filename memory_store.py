from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import secrets
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import unicodedata
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core_authority import (
    CORE_AUTHORITY_INSTANCE_RE,
    CORE_AUTHORITY_LOCK_GENERATION_RE,
    CORE_AUTHORITY_METADATA_KEY,
    CORE_AUTHORITY_SCHEMA_VERSION,
    CoreAuthorityError,
    CoreAuthorityLease,
)
from core_request_journal import JOURNAL_BINDING_SCHEMA, JOURNAL_SCHEMA_VERSION
from redaction import (
    SECRET_SAFE_LOG_FORMAT,
    SecretRedactingFormatter,
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    strip_untrusted_raw_digest_fields,
    strip_untrusted_raw_digest_text,
    validate_public_identifier,
)


LOGGER = logging.getLogger("synapse_s2.memory_store")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(SecretRedactingFormatter(SECRET_SAFE_LOG_FORMAT))
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False


class ContextDeliveryRejected(ValueError):
    """A deterministic delivery request rejection with no committed effects."""


class RetrievalSnapshotStaleError(ValueError):
    """Raised when a Retrieval v2 page no longer matches its reviewed snapshot."""

    def __init__(self, *, expected_revision: str, actual_revision: str) -> None:
        self.expected_revision = str(expected_revision)
        self.actual_revision = str(actual_revision)
        super().__init__("retrieval snapshot revision is stale")


_RETRIEVAL_PAGE_MAX_LIMIT = 500
_RETRIEVAL_MAX_CONTEXTS = 64
_RETRIEVAL_SNAPSHOT_REVISION_RE = re.compile(r"^[0-9a-f]{64}$")
_RETRIEVAL_GENERATION_KEY_PREFIX = "retrieval_snapshot_generation.v1"
_RETRIEVAL_GENERATION_MAX = 9_223_372_036_854_775_807
NAMESPACE_CATALOG_SCHEMA = "synapse-s2.namespace-catalog.v1"
NAMESPACE_CATALOG_METADATA_PREFIX = "namespace_catalog.v1:"
_NAMESPACE_GRAPH_CLUSTER_METADATA_KEYS = frozenset(
    {
        "context_memory_type",
        "event_segment",
        "cortex_trace_type",
        "context_namespace",
        "context_namespace_title",
        "display_label",
        "context_label",
        "semantic_facets",
    }
)
_NAMESPACE_GRAPH_NODE_METADATA_KEYS = (
    _NAMESPACE_GRAPH_CLUSTER_METADATA_KEYS
    | frozenset(
        {
            "display_summary",
            "detail_badges",
            "source",
            "source_tag",
            "speaker",
            "sequence_id",
            "context_namespace_source",
            "truth_posture",
            "trace_type",
        }
    )
)
_NAMESPACE_GRAPH_EMBEDDING_PROVIDER_KEYS = frozenset(
    {
        "provider",
        "provider_type",
        "model_id",
        "local_only",
        "semantic",
    }
)


BACKUP_RECEIPT_SCHEMA = "synapse-s2.memory-backup.v3"
LEGACY_BACKUP_RECEIPT_SCHEMA = "synapse-s2.memory-backup.v2"
BACKUP_RESTORE_RECEIPT_SCHEMA = "synapse-s2.memory-restore.v2"
BACKUP_RESTORE_PLAN_SCHEMA = "synapse-s2.memory-restore-plan.v1"
RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA = (
    "synapse-s2.recovery-request-journal-binding.v1"
)
LOGICAL_SNAPSHOT_DIGEST_SCHEMA = "synapse-s2.logical-snapshot.v1"
CORE_ADOPTION_ATTESTATION_METADATA_KEY = "core_adoption_attestation"
CORE_ADOPTION_ATTESTATION_SCHEMA = "synapse-s2.core-adoption-attestation.v1"
CORE_RUNTIME_PUBLICATION_METADATA_KEY = "core_runtime_state_publication"
CORE_RUNTIME_PUBLICATION_SCHEMA = "synapse-s2.core-runtime-publication.v1"
CORE_STORE_IDENTITY_RE = re.compile(r"^store-[0-9a-f]{24}$")
CORE_REQUEST_JOURNAL_ID_RE = re.compile(r"^journal-[0-9a-f]{24}$")
CORE_ROOT_GENERATION_ID_RE = re.compile(r"^generation-[0-9a-f]{24}$")
BACKUP_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA = (
    "synapse-s2.runtime-authority-binding.v1"
)
CORE_AUTHORITY_MARKER_FIELDS = (
    "schema_version",
    "service_required",
    "epoch",
    "instance_id",
    "config_fingerprint",
    "build_id",
    "protocol_version",
    "lock_generation_id",
    "store_identity",
    "request_journal_id",
    "request_journal_binding_schema",
    "request_journal_schema_version",
    "root_generation_id",
    "embedding_space_identity",
    "restored_target_binding_receipt_digest",
    "claimed_at",
    "updated_at",
)
SQLITE_APPLICATION_ID = 0x53324442  # ASCII "S2DB"
SQLITE_USER_VERSION = 6
BACKUP_SCHEMA_CONTRACT_VERSION = "s2-schema-v6"
BACKUP_RECOVERY_RUNTIME_ID = "synapse-s2/0.1.0+schema-v6"
BACKUP_SCHEMA_COMPATIBILITY_REGISTRY: dict[str, dict[str, Any]] = {
    "s2-schema-v5": {
        "schema_sha256": "861746736fae070d4ccd2765cedb0d049892385158846b1ea8272aa890c59685",
        "table_count": 19,
        "index_count": 28,
        "migration_set_sha256": "ff16d292fa470cd97a9a6cb2e88dd2f801824ce6c3ee640d7546e08b3191c228",
        "migration_count": 12,
        "application_id": SQLITE_APPLICATION_ID,
        "user_version": 5,
    },
    "s2-schema-v5-dans-mbp-20260723": {
        "schema_sha256": "338c97e56aaab242f0d23143288d2825d3e12c22389612d7fda97cde90b225f8",
        "table_count": 19,
        "index_count": 28,
        "migration_set_sha256": "ff16d292fa470cd97a9a6cb2e88dd2f801824ce6c3ee640d7546e08b3191c228",
        "migration_count": 12,
        "application_id": SQLITE_APPLICATION_ID,
        "user_version": 5,
    },
    BACKUP_SCHEMA_CONTRACT_VERSION: {
        "schema_sha256": "861746736fae070d4ccd2765cedb0d049892385158846b1ea8272aa890c59685",
        "table_count": 19,
        "index_count": 28,
        "migration_set_sha256": "ae7a7d3cd572233c5090f1bb6bb0ce209dd19925e5b03a3f86a00f6e2bc5f995",
        "migration_count": 13,
        "application_id": SQLITE_APPLICATION_ID,
        "user_version": SQLITE_USER_VERSION,
    },
    # The reviewed Dans-MBP legacy database differs from the canonical DDL
    # only in stored SQLite whitespace for three schema objects. Authority
    # adoption adds the v6 migration/marker and changes user_version, but does
    # not rewrite sqlite_schema text. Register that exact continuing shape
    # instead of normalizing or rebuilding any table.
    "s2-schema-v6-dans-mbp-20260724": {
        "schema_sha256": "338c97e56aaab242f0d23143288d2825d3e12c22389612d7fda97cde90b225f8",
        "table_count": 19,
        "index_count": 28,
        "migration_set_sha256": "ae7a7d3cd572233c5090f1bb6bb0ce209dd19925e5b03a3f86a00f6e2bc5f995",
        "migration_count": 13,
        "application_id": SQLITE_APPLICATION_ID,
        "user_version": SQLITE_USER_VERSION,
    },
}
_CANONICAL_BACKUP_CONTRACT: dict[str, Any] | None = None


def _matching_backup_schema_contract_versions(
    schema_contract: dict[str, Any],
) -> list[str]:
    return sorted(
        version
        for version, registered in BACKUP_SCHEMA_COMPATIBILITY_REGISTRY.items()
        if all(
            schema_contract.get(key) == expected_value
            for key, expected_value in registered.items()
        )
    )
BACKUP_CRITICAL_TABLES = frozenset(
    {
        "memory_entries",
        "memory_events",
        "memory_relationships",
        "memory_spikes",
        "memory_surface_terms",
        "agent_context_events",
        "agent_context_event_targets",
        "capture_operations",
        "agent_context_deliveries",
        "agent_context_delivery_receipts",
        "agent_context_delivery_ack_tombstones",
        "agent_context_delivery_cursors",
        "store_migrations",
        "store_metadata",
        "store_maintenance_receipts",
    }
)


CONTEXT_EVENT_TARGET_GROUPS = frozenset(
    {"mcp-clients", "local-ide-adapters"}
)
CAPTURE_PROTOCOL_VERSION = "capture.v2"
CAPTURE_ID_RE = re.compile(r"s2cap_[0-9a-f]{32}")
CAPTURE_REQUEST_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
CAPTURE_OPERATION_RESULT_JSON_MAX_BYTES = 2048
CAPTURE_OPERATION_COUNTER_MAX = 10_000_000
CAPTURE_OPERATION_ENVELOPE_KEYS = frozenset(
    {
        "capture_id",
        "protocol",
        "request_fingerprint",
        "context_id",
        "source_tag",
        "speaker",
        "result",
        "deployment_event",
        "entry_count",
        "relationship_count",
        "committed_at",
    }
)
CAPTURE_OPERATION_DEPLOYMENT_HEADER_KEYS = frozenset(
    {
        "event_id",
        "context_id",
        "event_type",
        "source_surface",
        "published_at",
    }
)
CAPTURE_OPERATION_LEGACY_DEPLOYMENT_KEYS = frozenset(
    {
        "event_id",
        "context_id",
        "source_surface",
        "event_type",
        "summary",
        "payload",
        "agent_targets",
        "created_at",
    }
)
CAPTURE_OPERATION_RESULT_KEYS = frozenset(
    {
        "status",
        "event_count",
        "entry_count",
        "relationship_count",
    }
)

# Every durable TEXT column is intentionally classified as either content that
# can be redacted/deleted or an identifier/structural value that must fail the
# secret-shape audit. A schema-coverage regression keeps this inventory exact.
LEGACY_SECRET_CONTENT_COLUMNS = frozenset(
    {
        ("agent_context_events", "summary"),
        ("agent_context_events", "payload_json"),
        ("capture_operations", "result_json"),
        ("context_relationships", "evidence_json"),
        ("memory_entries", "tag"),
        ("memory_entries", "source_text"),
        ("memory_entries", "metadata_json"),
        ("memory_events", "payload_json"),
        ("memory_relationships", "evidence_json"),
        ("store_maintenance_receipts", "payload_json"),
        ("store_metadata", "value_json"),
    }
)
LEGACY_SECRET_IDENTIFIER_COLUMNS = frozenset(
    {
        ("agent_context_consumer_groups", "agent_id"),
        ("agent_context_consumer_groups", "group_id"),
        ("agent_context_consumers", "agent_id"),
        ("agent_context_consumers", "consumer_kind"),
        ("agent_context_cursors", "context_id"),
        ("agent_context_cursors", "agent_id"),
        ("agent_context_deliveries", "delivery_id"),
        ("agent_context_deliveries", "context_id"),
        ("agent_context_deliveries", "agent_id"),
        ("agent_context_deliveries", "state"),
        ("agent_context_deliveries", "current_receipt_id"),
        ("agent_context_deliveries", "lease_owner"),
        ("agent_context_delivery_ack_tombstones", "receipt_digest"),
        ("agent_context_delivery_ack_tombstones", "delivery_id"),
        ("agent_context_delivery_ack_tombstones", "context_id"),
        ("agent_context_delivery_ack_tombstones", "agent_id"),
        ("agent_context_delivery_cursors", "context_id"),
        ("agent_context_delivery_cursors", "agent_id"),
        ("agent_context_delivery_receipts", "receipt_id"),
        ("agent_context_delivery_receipts", "delivery_id"),
        ("agent_context_delivery_receipts", "consumer_instance_id"),
        ("agent_context_delivery_receipts", "state"),
        ("agent_context_event_targets", "target_kind"),
        ("agent_context_event_targets", "target_id"),
        ("agent_context_events", "context_id"),
        ("agent_context_events", "source_surface"),
        ("agent_context_events", "event_type"),
        ("agent_context_events", "agent_targets_json"),
        ("capture_operations", "capture_id"),
        ("capture_operations", "protocol"),
        ("capture_operations", "request_fingerprint"),
        ("capture_operations", "context_id"),
        ("capture_operations", "source_tag"),
        ("capture_operations", "speaker"),
        ("context_relationships", "context_link_id"),
        ("context_relationships", "source_context_id"),
        ("context_relationships", "target_context_id"),
        ("context_relationships", "relation_type"),
        ("context_relationships", "direction"),
        ("context_relationships", "approved_by"),
        ("memory_entries", "memory_id"),
        ("memory_entries", "context_id"),
        ("memory_entries", "spike_indices_json"),
        ("memory_entries", "neuron_indices_json"),
        ("memory_events", "memory_id"),
        ("memory_events", "event_type"),
        ("memory_relationships", "relationship_id"),
        ("memory_relationships", "context_id"),
        ("memory_relationships", "source_memory_id"),
        ("memory_relationships", "target_memory_id"),
        ("memory_relationships", "relation_type"),
        ("memory_spikes", "memory_id"),
        ("memory_spikes", "context_id"),
        ("memory_surface_terms", "memory_id"),
        ("memory_surface_terms", "context_id"),
        ("memory_surface_terms", "term"),
        ("store_maintenance_receipts", "operation_id"),
        ("store_maintenance_receipts", "operation_type"),
        ("store_maintenance_receipts", "context_id"),
        ("store_maintenance_receipts", "before_revision"),
        ("store_maintenance_receipts", "after_revision"),
        ("store_metadata", "key"),
        ("store_migrations", "key"),
    }
)
LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS = frozenset(
    {
        ("agent_context_ack_receipts", "ack_id"),
        ("agent_context_ack_receipts", "delivery_id"),
        ("agent_context_ack_receipts", "context_id"),
        ("agent_context_ack_receipts", "agent_id"),
        ("agent_context_ack_receipts", "lease_token_sha256"),
    }
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS memory_entries (
    memory_id TEXT PRIMARY KEY,
    tag TEXT NOT NULL,
    context_id TEXT NOT NULL,
    source_text TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    embedding_dimensions INTEGER NOT NULL,
    spike_indices_json TEXT NOT NULL DEFAULT '[]',
    neuron_indices_json TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_memory_entries_context_tag
ON memory_entries(context_id, tag);

CREATE INDEX IF NOT EXISTS ix_memory_entries_context_updated
ON memory_entries(context_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS memory_spikes (
    memory_id TEXT NOT NULL,
    context_id TEXT NOT NULL,
    spike_index INTEGER NOT NULL,
    PRIMARY KEY(memory_id, spike_index),
    FOREIGN KEY(memory_id)
        REFERENCES memory_entries(memory_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_memory_spikes_context_spike
ON memory_spikes(context_id, spike_index, memory_id);

CREATE INDEX IF NOT EXISTS ix_memory_spikes_context_memory
ON memory_spikes(context_id, memory_id);

CREATE TABLE IF NOT EXISTS memory_surface_terms (
    memory_id TEXT NOT NULL,
    context_id TEXT NOT NULL,
    term TEXT NOT NULL,
    weight REAL NOT NULL DEFAULT 1.0,
    PRIMARY KEY(memory_id, term),
    FOREIGN KEY(memory_id)
        REFERENCES memory_entries(memory_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_memory_surface_terms_context_term
ON memory_surface_terms(context_id, term, memory_id);

CREATE INDEX IF NOT EXISTS ix_memory_surface_terms_context_memory
ON memory_surface_terms(context_id, memory_id);

CREATE TABLE IF NOT EXISTS memory_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    memory_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    FOREIGN KEY(memory_id)
        REFERENCES memory_entries(memory_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_memory_events_memory_created
ON memory_events(memory_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_context_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    context_id TEXT NOT NULL,
    source_surface TEXT NOT NULL,
    event_type TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    agent_targets_json TEXT NOT NULL DEFAULT '[]',
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_agent_context_events_context_event
ON agent_context_events(context_id, event_id);

CREATE UNIQUE INDEX IF NOT EXISTS ux_agent_context_events_context_event
ON agent_context_events(context_id, event_id);

CREATE TABLE IF NOT EXISTS agent_context_cursors (
    context_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    last_event_id INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL,
    PRIMARY KEY (context_id, agent_id)
);

CREATE INDEX IF NOT EXISTS ix_agent_context_cursors_context
ON agent_context_cursors(context_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS agent_context_consumers (
    agent_id TEXT PRIMARY KEY,
    consumer_kind TEXT NOT NULL DEFAULT 'local-mcp',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    CHECK(enabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS agent_context_consumer_groups (
    agent_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY(agent_id, group_id),
    FOREIGN KEY(agent_id)
        REFERENCES agent_context_consumers(agent_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_agent_context_consumer_groups_group_agent
ON agent_context_consumer_groups(group_id, agent_id);

CREATE TABLE IF NOT EXISTS agent_context_event_targets (
    event_id INTEGER NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY(event_id, target_kind, target_id),
    CHECK(target_kind IN ('agent', 'group', 'broadcast')),
    FOREIGN KEY(event_id)
        REFERENCES agent_context_events(event_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_agent_context_event_targets_route
ON agent_context_event_targets(target_kind, target_id, event_id);

CREATE TABLE IF NOT EXISTS capture_operations (
    capture_id TEXT PRIMARY KEY NOT NULL,
    protocol TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    context_id TEXT NOT NULL,
    source_tag TEXT NOT NULL,
    speaker TEXT NOT NULL,
    result_json TEXT NOT NULL,
    deployment_event_id INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    relationship_count INTEGER NOT NULL,
    committed_at REAL NOT NULL,
    CHECK(protocol = 'capture.v2'),
    CHECK(length(capture_id) = 38),
    CHECK(substr(capture_id, 1, 6) = 's2cap_'),
    CHECK(substr(capture_id, 7) NOT GLOB '*[^0-9a-f]*'),
    CHECK(length(request_fingerprint) = 64),
    CHECK(request_fingerprint NOT GLOB '*[^0-9a-f]*'),
    CHECK(length(context_id) BETWEEN 1 AND 128),
    CHECK(context_id = trim(context_id)),
    CHECK(length(source_tag) BETWEEN 1 AND 200),
    CHECK(source_tag = trim(source_tag)),
    CHECK(length(speaker) BETWEEN 1 AND 128),
    CHECK(speaker = trim(speaker)),
    CHECK(deployment_event_id > 0),
    CHECK(entry_count >= 0),
    CHECK(relationship_count >= 0),
    CHECK(typeof(committed_at) IN ('integer', 'real')),
    CHECK(abs(committed_at) < 1.0e308)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_capture_operations_deployment_event
ON capture_operations(deployment_event_id);

CREATE INDEX IF NOT EXISTS ix_capture_operations_context_committed
ON capture_operations(context_id, committed_at DESC, capture_id);

CREATE TABLE IF NOT EXISTS agent_context_delivery_cursors (
    context_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    last_contiguous_event_id INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL,
    PRIMARY KEY(context_id, agent_id),
    FOREIGN KEY(agent_id)
        REFERENCES agent_context_consumers(agent_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_agent_context_delivery_cursors_context
ON agent_context_delivery_cursors(context_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS memory_relationships (
    relationship_id TEXT PRIMARY KEY,
    context_id TEXT NOT NULL,
    source_memory_id TEXT NOT NULL,
    target_memory_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    weight REAL NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY(source_memory_id)
        REFERENCES memory_entries(memory_id)
        ON DELETE CASCADE,
    FOREIGN KEY(target_memory_id)
        REFERENCES memory_entries(memory_id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_memory_relationships_edge
ON memory_relationships(
    context_id,
    source_memory_id,
    target_memory_id,
    relation_type
);

CREATE INDEX IF NOT EXISTS ix_memory_relationships_context_weight
ON memory_relationships(context_id, weight DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS ix_memory_relationships_context_source_weight
ON memory_relationships(context_id, source_memory_id, weight DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS ix_memory_relationships_context_target_weight
ON memory_relationships(context_id, target_memory_id, weight DESC, updated_at DESC);

CREATE TABLE IF NOT EXISTS context_relationships (
    context_link_id TEXT PRIMARY KEY,
    source_context_id TEXT NOT NULL,
    target_context_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    direction TEXT NOT NULL DEFAULT 'bidirectional',
    confidence REAL NOT NULL DEFAULT 1.0,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    approved_by TEXT NOT NULL,
    approved_at REAL NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    CHECK(source_context_id <> target_context_id),
    CHECK(direction IN ('directed', 'bidirectional')),
    CHECK(enabled IN (0, 1))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_context_relationships_edge
ON context_relationships(
    source_context_id,
    target_context_id,
    relation_type,
    direction
);

CREATE INDEX IF NOT EXISTS ix_context_relationships_source_enabled
ON context_relationships(source_context_id, enabled, confidence DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS ix_context_relationships_target_enabled
ON context_relationships(target_context_id, enabled, confidence DESC, updated_at DESC);

CREATE TABLE IF NOT EXISTS store_migrations (
    key TEXT PRIMARY KEY,
    applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS store_metadata (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL DEFAULT '{}',
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS store_maintenance_receipts (
    operation_id TEXT PRIMARY KEY,
    operation_type TEXT NOT NULL,
    context_id TEXT,
    before_revision TEXT NOT NULL DEFAULT '',
    after_revision TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_store_maintenance_receipts_type_created
ON store_maintenance_receipts(operation_type, created_at DESC);
"""

CAPTURE_OPERATION_COLUMN_SIGNATURE = (
    ("capture_id", "TEXT", 1, None, 1),
    ("protocol", "TEXT", 1, None, 0),
    ("request_fingerprint", "TEXT", 1, None, 0),
    ("context_id", "TEXT", 1, None, 0),
    ("source_tag", "TEXT", 1, None, 0),
    ("speaker", "TEXT", 1, None, 0),
    ("result_json", "TEXT", 1, None, 0),
    ("deployment_event_id", "INTEGER", 1, None, 0),
    ("entry_count", "INTEGER", 1, None, 0),
    ("relationship_count", "INTEGER", 1, None, 0),
    ("committed_at", "REAL", 1, None, 0),
)
CAPTURE_OPERATION_INDEX_COLUMNS = {
    "ux_capture_operations_deployment_event": (
        True,
        ("deployment_event_id",),
    ),
    "ix_capture_operations_context_committed": (
        False,
        ("context_id", "committed_at", "capture_id"),
    ),
}
CAPTURE_OPERATION_INDEX_SQL = {
    "ux_capture_operations_deployment_event": (
        "CREATE UNIQUE INDEX ux_capture_operations_deployment_event "
        "ON capture_operations(deployment_event_id)"
    ),
    "ix_capture_operations_context_committed": (
        "CREATE INDEX ix_capture_operations_context_committed "
        "ON capture_operations(context_id, committed_at DESC, capture_id)"
    ),
}
CAPTURE_OPERATION_CHECK_FRAGMENTS = (
    "check(protocol = 'capture.v2')",
    "check(length(capture_id) = 38)",
    "check(substr(capture_id, 1, 6) = 's2cap_')",
    "check(substr(capture_id, 7) not glob '*[^0-9a-f]*')",
    "check(length(request_fingerprint) = 64)",
    "check(request_fingerprint not glob '*[^0-9a-f]*')",
    "check(length(context_id) between 1 and 128)",
    "check(context_id = trim(context_id))",
    "check(length(source_tag) between 1 and 200)",
    "check(source_tag = trim(source_tag))",
    "check(length(speaker) between 1 and 128)",
    "check(speaker = trim(speaker))",
    "check(deployment_event_id > 0)",
    "check(entry_count >= 0)",
    "check(relationship_count >= 0)",
    "check(typeof(committed_at) in ('integer', 'real'))",
    "check(abs(committed_at) < 1.0e308)",
)

# Context delivery is intentionally installed by a versioned migration rather
# than the general ``CREATE TABLE IF NOT EXISTS`` bootstrap above.  An early v2
# prototype used ``status``/``lease_token`` columns under the final table name;
# creating final indexes before rebuilding that table made existing stores
# impossible to open.  Keeping these statements separate lets the migration
# inspect, validate, and atomically replace the prototype schema first.
CONTEXT_DELIVERY_V2_TABLE_STATEMENTS = (
    """
    CREATE TABLE agent_context_deliveries (
        delivery_id TEXT PRIMARY KEY NOT NULL,
        context_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        state TEXT NOT NULL DEFAULT 'leased',
        attempt_count INTEGER NOT NULL DEFAULT 1,
        current_receipt_id TEXT NOT NULL,
        lease_owner TEXT NOT NULL,
        first_delivered_at REAL NOT NULL,
        last_delivered_at REAL NOT NULL,
        lease_expires_at REAL NOT NULL,
        acknowledged_at REAL,
        cancelled_at REAL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        UNIQUE(context_id, agent_id, event_id),
        CHECK(state IN ('leased', 'acknowledged', 'dead_letter')),
        CHECK(attempt_count >= 1),
        CHECK(length(delivery_id) BETWEEN 1 AND 160),
        CHECK(delivery_id = trim(delivery_id)),
        CHECK(delivery_id NOT GLOB '*[^A-Za-z0-9_.:@-]*'),
        CHECK(length(context_id) BETWEEN 1 AND 128),
        CHECK(context_id = trim(context_id)),
        CHECK(length(agent_id) BETWEEN 1 AND 128),
        CHECK(agent_id = trim(agent_id)),
        CHECK(agent_id = lower(agent_id)),
        CHECK(agent_id NOT GLOB '*[^a-z0-9_.:@-]*'),
        CHECK(length(current_receipt_id) = 51),
        CHECK(substr(current_receipt_id, 1, 8) = 'ctxrcpt_'),
        CHECK(substr(current_receipt_id, 9) NOT GLOB '*[^A-Za-z0-9_-]*'),
        CHECK(length(lease_owner) BETWEEN 1 AND 256),
        CHECK(lease_owner = trim(lease_owner)),
        CHECK(lease_owner NOT GLOB '*[^ -~]*'),
        CHECK(typeof(first_delivered_at) IN ('integer', 'real')),
        CHECK(typeof(last_delivered_at) IN ('integer', 'real')),
        CHECK(typeof(lease_expires_at) IN ('integer', 'real')),
        CHECK(typeof(created_at) IN ('integer', 'real')),
        CHECK(typeof(updated_at) IN ('integer', 'real')),
        CHECK(abs(first_delivered_at) < 1.0e308),
        CHECK(abs(last_delivered_at) < 1.0e308),
        CHECK(abs(lease_expires_at) < 1.0e308),
        CHECK(abs(created_at) < 1.0e308),
        CHECK(abs(updated_at) < 1.0e308),
        CHECK(created_at <= first_delivered_at),
        CHECK(first_delivered_at <= last_delivered_at),
        CHECK(last_delivered_at <= updated_at),
        CHECK(last_delivered_at <= lease_expires_at),
        CHECK(
            (
                state = 'leased'
                AND acknowledged_at IS NULL
                AND cancelled_at IS NULL
            )
            OR (
                state = 'acknowledged'
                AND typeof(acknowledged_at) IN ('integer', 'real')
                AND abs(acknowledged_at) < 1.0e308
                AND acknowledged_at >= last_delivered_at
                AND acknowledged_at <= lease_expires_at
                AND acknowledged_at <= updated_at
                AND cancelled_at IS NULL
            )
            OR (
                state = 'dead_letter'
                AND acknowledged_at IS NULL
                AND typeof(cancelled_at) IN ('integer', 'real')
                AND abs(cancelled_at) < 1.0e308
                AND cancelled_at >= last_delivered_at
                AND cancelled_at <= updated_at
            )
        ),
        FOREIGN KEY(agent_id)
            REFERENCES agent_context_consumers(agent_id)
            ON DELETE CASCADE,
        FOREIGN KEY(context_id, event_id)
            REFERENCES agent_context_events(context_id, event_id)
            ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE agent_context_delivery_receipts (
        receipt_id TEXT PRIMARY KEY NOT NULL,
        delivery_id TEXT NOT NULL,
        attempt_number INTEGER NOT NULL,
        consumer_instance_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'leased',
        leased_at REAL NOT NULL,
        lease_expires_at REAL NOT NULL,
        acknowledged_at REAL,
        released_at REAL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        UNIQUE(delivery_id, attempt_number),
        CHECK(state IN ('leased', 'acknowledged', 'expired', 'released', 'cancelled')),
        CHECK(attempt_number >= 1),
        CHECK(length(receipt_id) = 51),
        CHECK(substr(receipt_id, 1, 8) = 'ctxrcpt_'),
        CHECK(substr(receipt_id, 9) NOT GLOB '*[^A-Za-z0-9_-]*'),
        CHECK(length(delivery_id) BETWEEN 1 AND 160),
        CHECK(delivery_id = trim(delivery_id)),
        CHECK(delivery_id NOT GLOB '*[^A-Za-z0-9_.:@-]*'),
        CHECK(length(consumer_instance_id) BETWEEN 1 AND 256),
        CHECK(consumer_instance_id = trim(consumer_instance_id)),
        CHECK(consumer_instance_id NOT GLOB '*[^ -~]*'),
        CHECK(typeof(leased_at) IN ('integer', 'real')),
        CHECK(typeof(lease_expires_at) IN ('integer', 'real')),
        CHECK(typeof(created_at) IN ('integer', 'real')),
        CHECK(typeof(updated_at) IN ('integer', 'real')),
        CHECK(abs(leased_at) < 1.0e308),
        CHECK(abs(lease_expires_at) < 1.0e308),
        CHECK(abs(created_at) < 1.0e308),
        CHECK(abs(updated_at) < 1.0e308),
        CHECK(created_at <= leased_at),
        CHECK(leased_at <= lease_expires_at),
        CHECK(created_at <= updated_at),
        CHECK(
            (
                state = 'leased'
                AND acknowledged_at IS NULL
                AND released_at IS NULL
            )
            OR (
                state = 'expired'
                AND acknowledged_at IS NULL
                AND released_at IS NULL
                AND lease_expires_at <= updated_at
            )
            OR (
                state = 'acknowledged'
                AND typeof(acknowledged_at) IN ('integer', 'real')
                AND abs(acknowledged_at) < 1.0e308
                AND acknowledged_at >= leased_at
                AND acknowledged_at <= lease_expires_at
                AND acknowledged_at <= updated_at
                AND released_at IS NULL
            )
            OR (
                state = 'released'
                AND acknowledged_at IS NULL
                AND typeof(released_at) IN ('integer', 'real')
                AND abs(released_at) < 1.0e308
                AND released_at >= leased_at
                AND released_at <= lease_expires_at
                AND released_at <= updated_at
            )
            OR (
                state = 'cancelled'
                AND acknowledged_at IS NULL
                AND (
                    released_at IS NULL
                    OR (
                        typeof(released_at) IN ('integer', 'real')
                        AND abs(released_at) < 1.0e308
                        AND released_at >= leased_at
                        AND released_at <= lease_expires_at
                        AND released_at <= updated_at
                    )
                )
            )
        ),
        FOREIGN KEY(delivery_id)
            REFERENCES agent_context_deliveries(delivery_id)
            ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agent_context_delivery_ack_tombstones (
        receipt_digest TEXT PRIMARY KEY NOT NULL,
        delivery_id TEXT NOT NULL,
        context_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        attempt_number INTEGER NOT NULL,
        acknowledged_at REAL NOT NULL,
        deleted_at REAL NOT NULL,
        UNIQUE(delivery_id, attempt_number),
        CHECK(length(receipt_digest) = 64),
        CHECK(receipt_digest NOT GLOB '*[^0-9a-f]*'),
        CHECK(length(delivery_id) BETWEEN 1 AND 160),
        CHECK(delivery_id = trim(delivery_id)),
        CHECK(delivery_id NOT GLOB '*[^A-Za-z0-9_.:@-]*'),
        CHECK(length(context_id) BETWEEN 1 AND 128),
        CHECK(context_id = trim(context_id)),
        CHECK(trim(agent_id) <> ''),
        CHECK(agent_id = lower(agent_id)),
        CHECK(event_id >= 1),
        CHECK(attempt_number >= 1),
        CHECK(abs(acknowledged_at) < 1.0e308),
        CHECK(abs(deleted_at) < 1.0e308),
        CHECK(deleted_at >= acknowledged_at)
    )
    """,
)
CONTEXT_DELIVERY_V2_INDEX_STATEMENTS = (
    """
    CREATE INDEX IF NOT EXISTS ix_agent_context_deliveries_agent_state_event
    ON agent_context_deliveries(context_id, agent_id, state, event_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_agent_context_deliveries_lease_expiry
    ON agent_context_deliveries(state, lease_expires_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_agent_context_delivery_receipts_delivery_attempt
    ON agent_context_delivery_receipts(delivery_id, attempt_number)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_agent_context_delivery_receipts_state_expiry
    ON agent_context_delivery_receipts(state, lease_expires_at)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_agent_context_delivery_ack_tombstones_owner
    ON agent_context_delivery_ack_tombstones(context_id, agent_id, deleted_at DESC)
    """,
)
CONTEXT_DELIVERY_V2_DELIVERY_COLUMNS = (
    "delivery_id",
    "context_id",
    "agent_id",
    "event_id",
    "state",
    "attempt_count",
    "current_receipt_id",
    "lease_owner",
    "first_delivered_at",
    "last_delivered_at",
    "lease_expires_at",
    "acknowledged_at",
    "cancelled_at",
    "created_at",
    "updated_at",
)
CONTEXT_DELIVERY_V2_RECEIPT_COLUMNS = (
    "receipt_id",
    "delivery_id",
    "attempt_number",
    "consumer_instance_id",
    "state",
    "leased_at",
    "lease_expires_at",
    "acknowledged_at",
    "released_at",
    "created_at",
    "updated_at",
)
CONTEXT_DELIVERY_V2_TOMBSTONE_COLUMNS = (
    "receipt_digest",
    "delivery_id",
    "context_id",
    "agent_id",
    "event_id",
    "attempt_number",
    "acknowledged_at",
    "deleted_at",
)
CONTEXT_DELIVERY_V1_DELIVERY_COLUMNS = (
    "delivery_id",
    "context_id",
    "agent_id",
    "event_id",
    "status",
    "lease_token",
    "attempt_count",
    "first_delivered_at",
    "last_delivered_at",
    "lease_expires_at",
    "acknowledged_at",
    "created_at",
    "updated_at",
)
CONTEXT_DELIVERY_V2_COLUMN_SIGNATURES = {
    "agent_context_deliveries": (
        ("delivery_id", "TEXT", 1, None, 1),
        ("context_id", "TEXT", 1, None, 0),
        ("agent_id", "TEXT", 1, None, 0),
        ("event_id", "INTEGER", 1, None, 0),
        ("state", "TEXT", 1, "'leased'", 0),
        ("attempt_count", "INTEGER", 1, "1", 0),
        ("current_receipt_id", "TEXT", 1, None, 0),
        ("lease_owner", "TEXT", 1, None, 0),
        ("first_delivered_at", "REAL", 1, None, 0),
        ("last_delivered_at", "REAL", 1, None, 0),
        ("lease_expires_at", "REAL", 1, None, 0),
        ("acknowledged_at", "REAL", 0, None, 0),
        ("cancelled_at", "REAL", 0, None, 0),
        ("created_at", "REAL", 1, None, 0),
        ("updated_at", "REAL", 1, None, 0),
    ),
    "agent_context_delivery_receipts": (
        ("receipt_id", "TEXT", 1, None, 1),
        ("delivery_id", "TEXT", 1, None, 0),
        ("attempt_number", "INTEGER", 1, None, 0),
        ("consumer_instance_id", "TEXT", 1, None, 0),
        ("state", "TEXT", 1, "'leased'", 0),
        ("leased_at", "REAL", 1, None, 0),
        ("lease_expires_at", "REAL", 1, None, 0),
        ("acknowledged_at", "REAL", 0, None, 0),
        ("released_at", "REAL", 0, None, 0),
        ("created_at", "REAL", 1, None, 0),
        ("updated_at", "REAL", 1, None, 0),
    ),
    "agent_context_delivery_ack_tombstones": (
        ("receipt_digest", "TEXT", 1, None, 1),
        ("delivery_id", "TEXT", 1, None, 0),
        ("context_id", "TEXT", 1, None, 0),
        ("agent_id", "TEXT", 1, None, 0),
        ("event_id", "INTEGER", 1, None, 0),
        ("attempt_number", "INTEGER", 1, None, 0),
        ("acknowledged_at", "REAL", 1, None, 0),
        ("deleted_at", "REAL", 1, None, 0),
    ),
}
CONTEXT_DELIVERY_V2_FOREIGN_KEYS = {
    "agent_context_deliveries": {
        ("agent_context_consumers", "agent_id", "agent_id", "CASCADE"),
        ("agent_context_events", "context_id", "context_id", "CASCADE"),
        ("agent_context_events", "event_id", "event_id", "CASCADE"),
    },
    "agent_context_delivery_receipts": {
        ("agent_context_deliveries", "delivery_id", "delivery_id", "CASCADE"),
    },
    "agent_context_delivery_ack_tombstones": set(),
}
CONTEXT_DELIVERY_V2_UNIQUE_KEYS = {
    "agent_context_deliveries": {
        ("delivery_id",),
        ("context_id", "agent_id", "event_id"),
    },
    "agent_context_delivery_receipts": {
        ("receipt_id",),
        ("delivery_id", "attempt_number"),
    },
    "agent_context_delivery_ack_tombstones": {
        ("receipt_digest",),
        ("delivery_id", "attempt_number"),
    },
}
CONTEXT_DELIVERY_V2_CHECK_FRAGMENTS = {
    "agent_context_deliveries": (
        "check(state in ('leased', 'acknowledged', 'dead_letter'))",
        "check(attempt_count >= 1)",
        "check(length(delivery_id) between 1 and 160)",
        "check(delivery_id = trim(delivery_id))",
        "check(delivery_id not glob '*[^a-za-z0-9_.:@-]*')",
        "check(length(context_id) between 1 and 128)",
        "check(context_id = trim(context_id))",
        "check(length(agent_id) between 1 and 128)",
        "check(agent_id = trim(agent_id))",
        "check(agent_id = lower(agent_id))",
        "check(agent_id not glob '*[^a-z0-9_.:@-]*')",
        "check(length(current_receipt_id) = 51)",
        "check(substr(current_receipt_id, 1, 8) = 'ctxrcpt_')",
        "check(substr(current_receipt_id, 9) not glob '*[^a-za-z0-9_-]*')",
        "check(length(lease_owner) between 1 and 256)",
        "check(lease_owner = trim(lease_owner))",
        "check(lease_owner not glob '*[^ -~]*')",
        "check(typeof(first_delivered_at) in ('integer', 'real'))",
        "check(typeof(last_delivered_at) in ('integer', 'real'))",
        "check(typeof(lease_expires_at) in ('integer', 'real'))",
        "check(typeof(created_at) in ('integer', 'real'))",
        "check(typeof(updated_at) in ('integer', 'real'))",
        "check(abs(first_delivered_at) < 1.0e308)",
        "check(abs(last_delivered_at) < 1.0e308)",
        "check(abs(lease_expires_at) < 1.0e308)",
        "check(abs(created_at) < 1.0e308)",
        "check(abs(updated_at) < 1.0e308)",
        "check(created_at <= first_delivered_at)",
        "check(first_delivered_at <= last_delivered_at)",
        "check(last_delivered_at <= updated_at)",
        "check(last_delivered_at <= lease_expires_at)",
        "state = 'leased' and acknowledged_at is null and cancelled_at is null",
        "state = 'acknowledged' and typeof(acknowledged_at) in ('integer', 'real')",
        "and abs(acknowledged_at) < 1.0e308 and acknowledged_at >= last_delivered_at",
        "state = 'dead_letter' and acknowledged_at is null",
        "and abs(cancelled_at) < 1.0e308 and cancelled_at >= last_delivered_at",
        "foreign key(context_id, event_id) references agent_context_events(context_id, event_id)",
    ),
    "agent_context_delivery_receipts": (
        "check(state in ('leased', 'acknowledged', 'expired', 'released', 'cancelled'))",
        "check(attempt_number >= 1)",
        "check(length(receipt_id) = 51)",
        "check(substr(receipt_id, 1, 8) = 'ctxrcpt_')",
        "check(substr(receipt_id, 9) not glob '*[^a-za-z0-9_-]*')",
        "check(length(delivery_id) between 1 and 160)",
        "check(delivery_id = trim(delivery_id))",
        "check(delivery_id not glob '*[^a-za-z0-9_.:@-]*')",
        "check(length(consumer_instance_id) between 1 and 256)",
        "check(consumer_instance_id = trim(consumer_instance_id))",
        "check(consumer_instance_id not glob '*[^ -~]*')",
        "check(typeof(leased_at) in ('integer', 'real'))",
        "check(typeof(lease_expires_at) in ('integer', 'real'))",
        "check(typeof(created_at) in ('integer', 'real'))",
        "check(typeof(updated_at) in ('integer', 'real'))",
        "check(abs(leased_at) < 1.0e308)",
        "check(abs(lease_expires_at) < 1.0e308)",
        "check(abs(created_at) < 1.0e308)",
        "check(abs(updated_at) < 1.0e308)",
        "check(created_at <= leased_at)",
        "check(leased_at <= lease_expires_at)",
        "check(created_at <= updated_at)",
        "state = 'leased' and acknowledged_at is null and released_at is null",
        "state = 'expired' and acknowledged_at is null and released_at is null",
        "and lease_expires_at <= updated_at",
        "state = 'acknowledged' and typeof(acknowledged_at) in ('integer', 'real')",
        "and abs(acknowledged_at) < 1.0e308 and acknowledged_at >= leased_at",
        "state = 'released' and acknowledged_at is null",
        "and abs(released_at) < 1.0e308 and released_at >= leased_at",
        "state = 'cancelled' and acknowledged_at is null",
        "foreign key(delivery_id) references agent_context_deliveries(delivery_id)",
    ),
    "agent_context_delivery_ack_tombstones": (
        "check(length(receipt_digest) = 64)",
        "check(receipt_digest not glob '*[^0-9a-f]*')",
        "check(length(delivery_id) between 1 and 160)",
        "check(delivery_id = trim(delivery_id))",
        "check(delivery_id not glob '*[^a-za-z0-9_.:@-]*')",
        "check(length(context_id) between 1 and 128)",
        "check(context_id = trim(context_id))",
        "check(trim(agent_id) <> '')",
        "check(agent_id = lower(agent_id))",
        "check(event_id >= 1)",
        "check(attempt_number >= 1)",
        "check(abs(acknowledged_at) < 1.0e308)",
        "check(abs(deleted_at) < 1.0e308)",
        "check(deleted_at >= acknowledged_at)",
    ),
}
CONTEXT_DELIVERY_V2_INDEX_COLUMNS = {
    "ix_agent_context_deliveries_agent_state_event": (
        "agent_context_deliveries",
        ("context_id", "agent_id", "state", "event_id"),
    ),
    "ix_agent_context_deliveries_lease_expiry": (
        "agent_context_deliveries",
        ("state", "lease_expires_at"),
    ),
    "ix_agent_context_delivery_receipts_delivery_attempt": (
        "agent_context_delivery_receipts",
        ("delivery_id", "attempt_number"),
    ),
    "ix_agent_context_delivery_receipts_state_expiry": (
        "agent_context_delivery_receipts",
        ("state", "lease_expires_at"),
    ),
    "ix_agent_context_delivery_ack_tombstones_owner": (
        "agent_context_delivery_ack_tombstones",
        ("context_id", "agent_id", "deleted_at"),
    ),
}
CONTEXT_DELIVERY_V2_PARENT_INDEX = (
    "ux_agent_context_events_context_event",
    "agent_context_events",
    ("context_id", "event_id"),
)

SEMANTIC_INDEX_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS memory_spikes (
        memory_id TEXT NOT NULL,
        context_id TEXT NOT NULL,
        spike_index INTEGER NOT NULL,
        PRIMARY KEY(memory_id, spike_index),
        FOREIGN KEY(memory_id) REFERENCES memory_entries(memory_id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_memory_spikes_context_spike
    ON memory_spikes(context_id, spike_index, memory_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_memory_spikes_context_memory
    ON memory_spikes(context_id, memory_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS memory_surface_terms (
        memory_id TEXT NOT NULL,
        context_id TEXT NOT NULL,
        term TEXT NOT NULL,
        weight REAL NOT NULL DEFAULT 1.0,
        PRIMARY KEY(memory_id, term),
        FOREIGN KEY(memory_id) REFERENCES memory_entries(memory_id) ON DELETE CASCADE
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_memory_surface_terms_context_term
    ON memory_surface_terms(context_id, term, memory_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_memory_surface_terms_context_memory
    ON memory_surface_terms(context_id, memory_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS store_metadata (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL DEFAULT '{}',
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS store_maintenance_receipts (
        operation_id TEXT PRIMARY KEY,
        operation_type TEXT NOT NULL,
        context_id TEXT,
        before_revision TEXT NOT NULL DEFAULT '',
        after_revision TEXT NOT NULL DEFAULT '',
        payload_json TEXT NOT NULL DEFAULT '{}',
        created_at REAL NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_store_maintenance_receipts_type_created
    ON store_maintenance_receipts(operation_type, created_at DESC)
    """,
)
SEMANTIC_INDEX_REQUIRED_SCHEMA_OBJECTS = {
    "memory_entries",
    "memory_spikes",
    "memory_surface_terms",
    "store_metadata",
    "store_maintenance_receipts",
    "ix_memory_spikes_context_spike",
    "ix_memory_spikes_context_memory",
    "ix_memory_surface_terms_context_term",
    "ix_memory_surface_terms_context_memory",
    "ix_store_maintenance_receipts_type_created",
}
SEMANTIC_INDEX_REQUIRED_ENTRY_COLUMNS = {
    "memory_id",
    "context_id",
    "tag",
    "source_text",
    "metadata_json",
    "embedding_dimensions",
    "created_at",
    "updated_at",
    "spike_indices_json",
    "neuron_indices_json",
}
SEMANTIC_INDEX_EXPECTED_TABLE_COLUMNS = {
    "memory_entries": (
        ("memory_id", "TEXT", 0, 1),
        ("tag", "TEXT", 1, 0),
        ("context_id", "TEXT", 1, 0),
        ("source_text", "TEXT", 1, 0),
        ("metadata_json", "TEXT", 1, 0),
        ("embedding_dimensions", "INTEGER", 1, 0),
        ("spike_indices_json", "TEXT", 1, 0),
        ("neuron_indices_json", "TEXT", 1, 0),
        ("created_at", "REAL", 1, 0),
        ("updated_at", "REAL", 1, 0),
    ),
    "memory_spikes": (
        ("memory_id", "TEXT", 1, 1),
        ("context_id", "TEXT", 1, 0),
        ("spike_index", "INTEGER", 1, 2),
    ),
    "memory_surface_terms": (
        ("memory_id", "TEXT", 1, 1),
        ("context_id", "TEXT", 1, 0),
        ("term", "TEXT", 1, 2),
        ("weight", "REAL", 1, 0),
    ),
    "store_metadata": (
        ("key", "TEXT", 0, 1),
        ("value_json", "TEXT", 1, 0),
        ("updated_at", "REAL", 1, 0),
    ),
    "store_maintenance_receipts": (
        ("operation_id", "TEXT", 0, 1),
        ("operation_type", "TEXT", 1, 0),
        ("context_id", "TEXT", 0, 0),
        ("before_revision", "TEXT", 1, 0),
        ("after_revision", "TEXT", 1, 0),
        ("payload_json", "TEXT", 1, 0),
        ("created_at", "REAL", 1, 0),
    ),
}
SEMANTIC_INDEX_EXPECTED_INDEX_COLUMNS = {
    "ix_memory_spikes_context_spike": (
        "context_id",
        "spike_index",
        "memory_id",
    ),
    "ix_memory_spikes_context_memory": ("context_id", "memory_id"),
    "ix_memory_surface_terms_context_term": (
        "context_id",
        "term",
        "memory_id",
    ),
    "ix_memory_surface_terms_context_memory": ("context_id", "memory_id"),
    "ix_store_maintenance_receipts_type_created": (
        "operation_type",
        "created_at",
    ),
}
SEMANTIC_INDEX_EXPECTED_INDEX_PARENTS = {
    "ix_memory_spikes_context_spike": "memory_spikes",
    "ix_memory_spikes_context_memory": "memory_spikes",
    "ix_memory_surface_terms_context_term": "memory_surface_terms",
    "ix_memory_surface_terms_context_memory": "memory_surface_terms",
    "ix_store_maintenance_receipts_type_created": "store_maintenance_receipts",
}

SURFACE_TERM_RE = re.compile(r"[a-z0-9][a-z0-9_./:-]{1,63}")
MAX_SURFACE_INDEX_SOURCE_CHARS = 4096
SEMANTIC_INDEX_ALGORITHM_VERSION = "spike-json-v1+surface-terms-v1"
SEMANTIC_INDEX_ALGORITHM_FINGERPRINT = hashlib.sha256(
    (
        f"{SEMANTIC_INDEX_ALGORITHM_VERSION}|"
        f"{MAX_SURFACE_INDEX_SOURCE_CHARS}|{SURFACE_TERM_RE.pattern}"
    ).encode("utf-8")
).hexdigest()[:16]
CONTEXT_SUGGESTION_STOP_TERMS = {
    "and",
    "are",
    "for",
    "from",
    "has",
    "have",
    "into",
    "not",
    "that",
    "the",
    "this",
    "was",
    "were",
    "with",
}


def _json_safe(value: Any, fallback: Any) -> Any:
    safe_value, _ = redact_sensitive_value(value)
    safe_value, _ = strip_untrusted_raw_digest_fields(safe_value)
    try:
        return json.loads(json.dumps(safe_value, allow_nan=False))
    except (TypeError, ValueError):
        return fallback


def _json_dumps(value: Any) -> str:
    return json.dumps(_json_safe(value, {}), sort_keys=True, separators=(",", ":"))


def _capture_json_dumps(value: Any, *, field: str) -> str:
    """Serialize capture-plan values without coercion or non-finite numbers."""

    safe_value, _ = redact_sensitive_value(value)
    safe_value, _ = strip_untrusted_raw_digest_fields(safe_value)
    try:
        return json.dumps(
            safe_value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be finite, JSON-safe data") from exc


def capture_request_fingerprint(
    *,
    text: str,
    context_id: str,
    source_tag: str,
    speaker: str,
    surprise_threshold: float,
    min_segment_sentences: int,
    metadata: dict[str, Any],
) -> str:
    """Return the durable capture.v2 request identity used by the ledger.

    The capture ID deliberately is not part of this digest: it is the
    idempotency key stored beside the digest.  Keeping this function in the
    persistence module gives normal capture and governed historical repair one
    authoritative byte contract instead of two similar implementations.
    """

    request = {
        "protocol": CAPTURE_PROTOCOL_VERSION,
        "text": str(text),
        "context_id": str(context_id),
        "source_tag": str(source_tag),
        "speaker": str(speaker),
        "surprise_threshold": float(surprise_threshold),
        "min_segment_sentences": int(min_segment_sentences),
        "metadata": metadata,
    }
    canonical = _capture_json_dumps(
        request,
        field="capture request fingerprint input",
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _json_list(values: Iterable[int]) -> str:
    safe_values = [int(value) for value in values]
    return json.dumps(safe_values, separators=(",", ":"))


def _decode_json(raw: str, fallback: Any) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return fallback


class DurableMemoryStore:
    """SQLite-backed memory substrate shared by CLI and MCP launches."""

    def __init__(
        self,
        db_path: str | os.PathLike[str] | None = None,
        *,
        authority_lease: CoreAuthorityLease | None = None,
    ) -> None:
        self.db_path = self._resolve_db_path(db_path)
        self._target_integrity_verified = False
        self._capture_integrity_verified = False
        self._initializing_authority_store = True
        self._database_created_for_initialization = False
        self._claimed_core_authority_marker_sha256: str | None = None
        self._ensure_directory(self.db_path.parent, owned=False)
        self._owns_authority_lease = authority_lease is None
        self._authority_lease = authority_lease or CoreAuthorityLease.acquire_local(
            self.db_path
        )
        if authority_lease is not None:
            authority_lease.assert_core_for(self.db_path)
        try:
            self._initialize()
        except BaseException:
            if self._owns_authority_lease:
                self._authority_lease.close()
            raise
        finally:
            self._initializing_authority_store = False

    @classmethod
    def open_existing_for_audit(
        cls,
        db_path: str | os.PathLike[str] | None = None,
    ) -> "DurableMemoryStore":
        """Open an existing store without schema creation, migration, or chmod writes."""

        store = cls.__new__(cls)
        store.db_path = store._resolve_db_path(db_path)
        store._target_integrity_verified = False
        store._capture_integrity_verified = False
        store._initializing_authority_store = False
        store._database_created_for_initialization = False
        store._claimed_core_authority_marker_sha256 = None
        store._authority_lease = None
        store._owns_authority_lease = False
        if not store.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {store.db_path}"
            )
        return store

    @classmethod
    def open_existing_for_core_maintenance(
        cls,
        db_path: str | os.PathLike[str],
        *,
        authority_lease: CoreAuthorityLease,
    ) -> "DurableMemoryStore":
        """Bind an existing exact v5/v6 store to an unclaimed exclusive lease.

        This is the narrow recovery-certification lane.  It deliberately skips
        ``__init__`` so opening an unexpected target can never create a database,
        configure WAL, run a migration, or repair permissions.  The supplied
        authority remains caller-owned and is used only to fence the live path;
        an unclaimed core lease makes every normal store connection read-only.
        Recovery code may still publish new, signed artifacts outside the live
        SQLite database while that fence is held.
        """

        if not isinstance(authority_lease, CoreAuthorityLease):
            raise TypeError("core maintenance requires a CoreAuthorityLease")
        store = cls.__new__(cls)
        store.db_path = store._resolve_db_path(db_path)
        authority_lease.assert_core_for(store.db_path)
        if authority_lease.durable_epoch is not None:
            raise CoreAuthorityError(
                "core maintenance requires an unclaimed authoritative core lease"
            )
        store._target_integrity_verified = False
        store._capture_integrity_verified = False
        store._initializing_authority_store = False
        store._database_created_for_initialization = False
        store._claimed_core_authority_marker_sha256 = None
        store._authority_lease = authority_lease
        store._owns_authority_lease = False
        if not store.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {store.db_path}"
            )
        store._assert_private_database_identity()
        with closing(store._connect_read_only()) as conn:
            store._validate_existing_schema_compatibility_markers(conn)
            user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if user_version not in {5, SQLITE_USER_VERSION}:
                raise CoreAuthorityError(
                    "core maintenance requires an authoritative v5 or v6 store"
                )
        try:
            store.inspect_core_authority_preclaim()
        except CoreAuthorityError:
            raise
        except (sqlite3.DatabaseError, RuntimeError, ValueError) as exc:
            raise CoreAuthorityError(
                "core maintenance store contract is invalid"
            ) from exc
        authority_lease.assert_core_for(store.db_path)
        return store

    def close(self) -> None:
        if self._owns_authority_lease and self._authority_lease is not None:
            self._authority_lease.close()

    def __del__(self) -> None:  # pragma: no cover - process teardown fallback
        try:
            self.close()
        except Exception:
            pass

    def _resolve_db_path(self, db_path: str | os.PathLike[str] | None) -> Path:
        if db_path is not None:
            reject_sensitive_identifier(str(db_path), field="memory_db_path")
            return Path(db_path).expanduser()
        configured = os.getenv("SYNAPSE_S2_MEMORY_DB")
        if configured:
            reject_sensitive_identifier(configured, field="memory_db_path")
            return Path(configured).expanduser()
        return Path.cwd() / ".synapse_s2" / "memory.sqlite3"

    def _assert_filesystem_authority(self) -> CoreAuthorityLease:
        lease = self._authority_lease
        if lease is None:
            raise CoreAuthorityError(
                "writable memory-store access requires an active authority lease"
            )
        lease.assert_active_for(self.db_path)
        return lease

    def assert_active_authority(self) -> None:
        """Fence a non-SQLite publication against this store's live authority.

        SQLite mutations revalidate inside their transaction immediately before
        commit.  Runtime-state files share the same authority but commit through
        atomic rename, so callers use this method as their pre-publication
        callback.  A governed v6 store additionally proves the durable epoch.
        """

        lease = self._assert_filesystem_authority()
        if lease.role == "core" and lease.durable_epoch is None:
            return
        with closing(self._connect_read_only()) as conn:
            self._assert_durable_authority(conn)

    @staticmethod
    def _core_authority_marker(
        conn: sqlite3.Connection,
    ) -> dict[str, Any] | None:
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            ("store_metadata",),
        ).fetchone()
        if table_exists is None:
            return None
        row = conn.execute(
            "SELECT value_json, updated_at FROM store_metadata WHERE key = ?",
            (CORE_AUTHORITY_METADATA_KEY,),
        ).fetchone()
        if row is None:
            return None
        try:
            marker = json.loads(str(row["value_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CoreAuthorityError(
                "durable core authority marker is invalid"
            ) from exc
        if not isinstance(marker, dict):
            raise CoreAuthorityError("durable core authority marker is invalid")
        if set(marker) != set(CORE_AUTHORITY_MARKER_FIELDS):
            raise CoreAuthorityError("durable core authority marker is invalid")
        schema_version = marker.get("schema_version")
        service_required = marker.get("service_required")
        epoch = marker.get("epoch")
        instance_id = marker.get("instance_id")
        claimed_at = marker.get("claimed_at")
        updated_at = marker.get("updated_at")
        config_fingerprint = marker.get("config_fingerprint")
        build_id = marker.get("build_id")
        protocol_version = marker.get("protocol_version")
        lock_generation_id = marker.get("lock_generation_id")
        store_identity = marker.get("store_identity")
        request_journal_id = marker.get("request_journal_id")
        request_journal_binding_schema = marker.get(
            "request_journal_binding_schema"
        )
        request_journal_schema_version = marker.get(
            "request_journal_schema_version"
        )
        root_generation_id = marker.get("root_generation_id")
        embedding_space_identity = marker.get("embedding_space_identity")
        restored_target_binding_receipt_digest = marker.get(
            "restored_target_binding_receipt_digest"
        )
        timestamps_valid = all(
            type(value) in {int, float}
            and math.isfinite(float(value))
            and float(value) > 0.0
            for value in (claimed_at, updated_at)
        )
        if (
            type(schema_version) is not int
            or schema_version != CORE_AUTHORITY_SCHEMA_VERSION
            or service_required is not True
            or type(epoch) is not int
            or epoch <= 0
            or epoch > (2**63 - 1)
            or not isinstance(instance_id, str)
            or CORE_AUTHORITY_INSTANCE_RE.fullmatch(instance_id) is None
            or not isinstance(config_fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", config_fingerprint) is None
            or not isinstance(build_id, str)
            or CORE_AUTHORITY_INSTANCE_RE.fullmatch(build_id) is None
            or not isinstance(protocol_version, str)
            or CORE_AUTHORITY_INSTANCE_RE.fullmatch(protocol_version) is None
            or not isinstance(lock_generation_id, str)
            or CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(lock_generation_id)
            is None
            or not isinstance(store_identity, str)
            or CORE_STORE_IDENTITY_RE.fullmatch(store_identity) is None
            or not isinstance(request_journal_id, str)
            or CORE_REQUEST_JOURNAL_ID_RE.fullmatch(request_journal_id) is None
            or request_journal_binding_schema != JOURNAL_BINDING_SCHEMA
            or type(request_journal_schema_version) is not int
            or request_journal_schema_version != JOURNAL_SCHEMA_VERSION
            or not isinstance(root_generation_id, str)
            or CORE_ROOT_GENERATION_ID_RE.fullmatch(root_generation_id) is None
            or not isinstance(embedding_space_identity, str)
            or BACKUP_DIGEST_RE.fullmatch(embedding_space_identity) is None
            or (
                restored_target_binding_receipt_digest is not None
                and (
                    not isinstance(
                        restored_target_binding_receipt_digest,
                        str,
                    )
                    or BACKUP_DIGEST_RE.fullmatch(
                        restored_target_binding_receipt_digest
                    )
                    is None
                )
            )
            or not timestamps_valid
            or float(claimed_at) > float(updated_at)
            or float(row["updated_at"]) != float(updated_at)
        ):
            raise CoreAuthorityError("durable core authority marker is invalid")
        return {
            "schema_version": schema_version,
            "service_required": service_required,
            "epoch": epoch,
            "instance_id": instance_id,
            "config_fingerprint": config_fingerprint,
            "build_id": build_id,
            "protocol_version": protocol_version,
            "lock_generation_id": lock_generation_id,
            "store_identity": store_identity,
            "request_journal_id": request_journal_id,
            "request_journal_binding_schema": request_journal_binding_schema,
            "request_journal_schema_version": request_journal_schema_version,
            "root_generation_id": root_generation_id,
            "embedding_space_identity": embedding_space_identity,
            "restored_target_binding_receipt_digest": (
                restored_target_binding_receipt_digest
            ),
            "claimed_at": float(claimed_at),
            "updated_at": float(updated_at),
        }

    @staticmethod
    def _core_authority_marker_sha256(marker: dict[str, Any]) -> str:
        """Digest the closed immutable marker contract without coercion."""

        if set(marker) != set(CORE_AUTHORITY_MARKER_FIELDS):
            raise CoreAuthorityError("durable core authority marker is invalid")
        try:
            encoded = json.dumps(
                marker,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise CoreAuthorityError(
                "durable core authority marker is invalid"
            ) from exc
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def runtime_state_authority_binding_for_marker(
        cls,
        marker: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the closed epoch binding embedded in governed runtime state."""

        marker_sha256 = cls._core_authority_marker_sha256(marker)
        epoch = marker.get("epoch")
        lock_generation_id = marker.get("lock_generation_id")
        if (
            type(epoch) is not int
            or epoch <= 0
            or not isinstance(lock_generation_id, str)
            or CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(lock_generation_id)
            is None
        ):
            raise CoreAuthorityError("durable core authority marker is invalid")
        return {
            "schema": RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA,
            "marker_sha256": marker_sha256,
            "authority_epoch_number": epoch,
            "lock_generation_id": lock_generation_id,
        }

    def runtime_state_authority_binding(self) -> dict[str, Any] | None:
        """Return this live core epoch's exact runtime-state binding."""

        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is None:
            return None
        with closing(self._connect_read_only()) as conn:
            marker = self._core_authority_marker(conn)
            self._assert_core_marker_matches(marker)
        assert marker is not None
        return self.runtime_state_authority_binding_for_marker(marker)

    @staticmethod
    def runtime_state_path_sha256(path: str | os.PathLike[str]) -> str:
        """Return the closed identity of one canonical runtime-state pathname."""

        candidate = Path(path).expanduser().resolve(strict=False)
        return hashlib.sha256(str(candidate).encode("utf-8")).hexdigest()

    @classmethod
    def _core_runtime_publication(
        cls,
        conn: sqlite3.Connection,
        marker: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Read and strictly validate the claim-to-runtime publication receipt."""

        row = conn.execute(
            "SELECT value_json, updated_at FROM store_metadata WHERE key = ?",
            (CORE_RUNTIME_PUBLICATION_METADATA_KEY,),
        ).fetchone()
        if row is None:
            # v6 stores created before this receipt contract remain readable,
            # but they are never eligible for automatic publication repair.
            return None
        try:
            payload = json.loads(str(row["value_json"]))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CoreAuthorityError(
                "core runtime publication receipt is invalid"
            ) from exc
        expected_fields = {
            "schema",
            "status",
            "marker_sha256",
            "authority_epoch_number",
            "lock_generation_id",
            "instance_id",
            "config_fingerprint",
            "build_id",
            "protocol_version",
            "runtime_state_path_sha256",
            "started_at",
            "completed_at",
            "updated_at",
        }
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise CoreAuthorityError("core runtime publication receipt is invalid")
        started_at = payload.get("started_at")
        completed_at = payload.get("completed_at")
        updated_at = payload.get("updated_at")
        status_value = payload.get("status")
        timestamps_valid = (
            type(started_at) in {int, float}
            and math.isfinite(float(started_at))
            and float(started_at) > 0.0
            and type(updated_at) in {int, float}
            and math.isfinite(float(updated_at))
            and float(updated_at) >= float(started_at)
            and float(row["updated_at"]) == float(updated_at)
        )
        completion_valid = (
            status_value == "pending" and completed_at is None
        ) or (
            status_value == "complete"
            and type(completed_at) in {int, float}
            and math.isfinite(float(completed_at))
            and float(completed_at) >= float(started_at)
            and float(completed_at) == float(updated_at)
        )
        if (
            marker is None
            or payload.get("schema") != CORE_RUNTIME_PUBLICATION_SCHEMA
            or status_value not in {"pending", "complete"}
            or re.fullmatch(
                r"[0-9a-f]{64}", str(payload.get("marker_sha256") or "")
            )
            is None
            or type(payload.get("authority_epoch_number")) is not int
            or CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(
                str(payload.get("lock_generation_id") or "")
            )
            is None
            or CORE_AUTHORITY_INSTANCE_RE.fullmatch(
                str(payload.get("instance_id") or "")
            )
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}", str(payload.get("config_fingerprint") or "")
            )
            is None
            or CORE_AUTHORITY_INSTANCE_RE.fullmatch(
                str(payload.get("build_id") or "")
            )
            is None
            or CORE_AUTHORITY_INSTANCE_RE.fullmatch(
                str(payload.get("protocol_version") or "")
            )
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(payload.get("runtime_state_path_sha256") or ""),
            )
            is None
            or not timestamps_valid
            or not completion_valid
            or payload["marker_sha256"] != cls._core_authority_marker_sha256(marker)
            or payload["authority_epoch_number"] != marker["epoch"]
            or payload["lock_generation_id"] != marker["lock_generation_id"]
            or payload["instance_id"] != marker["instance_id"]
            or payload["config_fingerprint"] != marker["config_fingerprint"]
            or payload["build_id"] != marker["build_id"]
            or payload["protocol_version"] != marker["protocol_version"]
        ):
            raise CoreAuthorityError("core runtime publication receipt is invalid")
        return dict(payload)

    def interrupted_runtime_publication_binding(
        self,
        *,
        marker: dict[str, Any],
        publication: dict[str, Any],
        runtime_state_path: str | os.PathLike[str],
        expected_config_fingerprint: str,
        expected_build_id: str,
        expected_protocol_version: str,
        expected_root_generation_id: str,
        expected_embedding_space_identity: str,
    ) -> dict[str, Any]:
        """Authorize a same-lock repair of one interrupted runtime publication.

        This is deliberately not a general runtime-state repair surface.  It is
        available only while an unbound core holds the exact lock inode named
        by a durable ``pending`` receipt committed atomically with the marker.
        """

        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is not None:
            raise CoreAuthorityError(
                "interrupted runtime publication requires an unbound core lease"
            )
        with closing(self._connect_read_only()) as conn:
            live_marker = self._core_authority_marker(conn)
            self._validate_core_authority_version_pair(conn, live_marker)
            live_publication = self._core_runtime_publication(conn, live_marker)
        if (
            live_marker != marker
            or live_publication != publication
            or live_publication is None
        ):
            raise CoreAuthorityError(
                "interrupted runtime publication is not recoverable by this core"
            )
        binding = self.validate_interrupted_runtime_publication_binding(
            marker=live_marker,
            publication=live_publication,
            runtime_state_path=runtime_state_path,
            expected_lock_generation_id=lease.lock_generation_id,
            expected_config_fingerprint=expected_config_fingerprint,
            expected_build_id=expected_build_id,
            expected_protocol_version=expected_protocol_version,
            expected_root_generation_id=expected_root_generation_id,
            expected_embedding_space_identity=expected_embedding_space_identity,
        )
        self._assert_filesystem_authority()
        return binding

    def complete_interrupted_runtime_state_authority_publication(
        self,
        *,
        marker: dict[str, Any],
        publication: dict[str, Any],
        runtime_state_path: str | os.PathLike[str],
        expected_config_fingerprint: str,
        expected_build_id: str,
        expected_protocol_version: str,
        expected_root_generation_id: str,
        expected_embedding_space_identity: str,
    ) -> dict[str, Any]:
        """Complete only an exact recovered pending publication.

        The durable marker already committed in another process, so this lane
        deliberately keeps the current lease unbound.  It revalidates the live
        marker, pending receipt, runtime path, and every closed identity under
        the exclusive filesystem lease, then updates only that receipt.  It
        cannot advance an epoch or authorize a new authority claim.
        """

        self.interrupted_runtime_publication_binding(
            marker=marker,
            publication=publication,
            runtime_state_path=runtime_state_path,
            expected_config_fingerprint=expected_config_fingerprint,
            expected_build_id=expected_build_id,
            expected_protocol_version=expected_protocol_version,
            expected_root_generation_id=expected_root_generation_id,
            expected_embedding_space_identity=expected_embedding_space_identity,
        )
        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is not None:
            raise CoreAuthorityError(
                "interrupted runtime publication completion requires an "
                "unbound core lease"
            )
        uri = self.db_path.resolve().as_uri() + "?mode=rw"
        conn = sqlite3.connect(uri, timeout=10.0, isolation_level=None, uri=True)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("BEGIN IMMEDIATE")
            try:
                live_marker = self._core_authority_marker(conn)
                self._validate_core_authority_version_pair(conn, live_marker)
                live_publication = self._core_runtime_publication(
                    conn,
                    live_marker,
                )
                if (
                    live_marker != marker
                    or live_publication != publication
                    or live_publication is None
                    or live_publication.get("status") != "pending"
                ):
                    raise CoreAuthorityError(
                        "interrupted runtime publication changed before completion"
                    )
                self.validate_interrupted_runtime_publication_binding(
                    marker=live_marker,
                    publication=live_publication,
                    runtime_state_path=runtime_state_path,
                    expected_lock_generation_id=lease.lock_generation_id,
                    expected_config_fingerprint=expected_config_fingerprint,
                    expected_build_id=expected_build_id,
                    expected_protocol_version=expected_protocol_version,
                    expected_root_generation_id=expected_root_generation_id,
                    expected_embedding_space_identity=(
                        expected_embedding_space_identity
                    ),
                )
                now = max(
                    time.time(),
                    float(live_publication["started_at"]),
                    float(live_publication["updated_at"]),
                )
                completed = {
                    **live_publication,
                    "status": "complete",
                    "completed_at": now,
                    "updated_at": now,
                }
                conn.execute(
                    """
                    UPDATE store_metadata
                    SET value_json = ?, updated_at = ?
                    WHERE key = ?
                    """,
                    (
                        _json_dumps(completed),
                        now,
                        CORE_RUNTIME_PUBLICATION_METADATA_KEY,
                    ),
                )
                persisted = self._core_runtime_publication(
                    conn,
                    live_marker,
                )
                if persisted != completed:
                    raise CoreAuthorityError(
                        "interrupted runtime publication completion did not "
                        "persist exactly"
                    )
                self._assert_filesystem_authority()
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        finally:
            conn.close()
        self._assert_filesystem_authority()
        return completed

    @classmethod
    def validate_interrupted_runtime_publication_binding(
        cls,
        *,
        marker: dict[str, Any],
        publication: dict[str, Any],
        runtime_state_path: str | os.PathLike[str],
        expected_lock_generation_id: str,
        expected_config_fingerprint: str,
        expected_build_id: str,
        expected_protocol_version: str,
        expected_root_generation_id: str,
        expected_embedding_space_identity: str,
    ) -> dict[str, Any]:
        """Purely validate one same-generation interrupted publication."""

        if (
            publication.get("status") != "pending"
            or publication.get("marker_sha256")
            != cls._core_authority_marker_sha256(marker)
            or publication.get("authority_epoch_number") != marker.get("epoch")
            or publication.get("lock_generation_id")
            != marker.get("lock_generation_id")
            or publication.get("instance_id") != marker.get("instance_id")
            or publication.get("config_fingerprint")
            != marker.get("config_fingerprint")
            or publication.get("build_id") != marker.get("build_id")
            or publication.get("protocol_version")
            != marker.get("protocol_version")
            or publication.get("runtime_state_path_sha256")
            != cls.runtime_state_path_sha256(runtime_state_path)
            or marker.get("lock_generation_id") != expected_lock_generation_id
            or marker.get("config_fingerprint") != expected_config_fingerprint
            or marker.get("build_id") != expected_build_id
            or marker.get("protocol_version") != expected_protocol_version
            or marker.get("root_generation_id") != expected_root_generation_id
            or marker.get("embedding_space_identity")
            != expected_embedding_space_identity
        ):
            raise CoreAuthorityError(
                "interrupted runtime publication is not recoverable by this core"
            )
        return cls.runtime_state_authority_binding_for_marker(marker)

    def complete_runtime_state_authority_publication(
        self,
        *,
        runtime_state_path: str | os.PathLike[str],
    ) -> dict[str, Any]:
        """Commit the completion receipt after exact runtime-state publication."""

        expected_path_digest = self.runtime_state_path_sha256(runtime_state_path)
        self.assert_active_authority()
        uri = self.db_path.resolve().as_uri() + "?mode=rw"
        conn = sqlite3.connect(uri, timeout=10.0, isolation_level=None, uri=True)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._assert_durable_authority(conn)
                marker = self._core_authority_marker(conn)
                publication = self._core_runtime_publication(conn, marker)
                if (
                    marker is None
                    or publication is None
                    or publication["status"] != "pending"
                    or publication["runtime_state_path_sha256"]
                    != expected_path_digest
                ):
                    raise CoreAuthorityError(
                        "core runtime publication is not pending"
                    )
                now = max(
                    time.time(),
                    float(publication["started_at"]),
                    float(publication["updated_at"]),
                )
                completed = {
                    **publication,
                    "status": "complete",
                    "completed_at": now,
                    "updated_at": now,
                }
                conn.execute(
                    """
                    UPDATE store_metadata
                    SET value_json = ?, updated_at = ?
                    WHERE key = ?
                    """,
                    (
                        _json_dumps(completed),
                        now,
                        CORE_RUNTIME_PUBLICATION_METADATA_KEY,
                    ),
                )
                persisted = self._core_runtime_publication(conn, marker)
                if persisted != completed:
                    raise CoreAuthorityError(
                        "core runtime publication completion did not persist exactly"
                    )
                self._assert_durable_authority(conn)
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        finally:
            conn.close()
        self.assert_active_authority()
        return completed

    @staticmethod
    def _core_authority_migration_present(conn: sqlite3.Connection) -> bool:
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            ("store_migrations",),
        ).fetchone()
        if table_exists is None:
            return False
        return (
            conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ? LIMIT 1",
                ("authoritative_core_v1",),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _base_authority_migrations() -> frozenset[str]:
        return frozenset(
            {
                "capture_operations_v1",
                "capture_operations_private_receipts_v1",
                "secret_content_scrub_v1",
                "secret_content_scrub_v2",
                "secret_content_scrub_v3",
                "raw_digest_oracle_scrub_v1",
                "secret_identifier_audit_v1",
                "legacy_ack_receipts_retirement_v1",
                "memory_spikes_v1",
                "memory_surface_terms_v1",
                "context_event_targets_v2",
                "context_deliveries_v2",
            }
        )

    def _assert_core_marker_matches(
        self,
        marker: dict[str, Any] | None,
    ) -> None:
        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is None:
            raise CoreAuthorityError("authoritative core has not claimed the memory store")
        if (
            marker is None
            or marker["service_required"] is not True
            or marker["schema_version"] != lease.durable_schema_version
            or marker["epoch"] != lease.durable_epoch
            or marker["instance_id"] != lease.instance_id
            or marker["config_fingerprint"] != lease.config_fingerprint
            or marker["build_id"] != lease.build_id
            or marker["protocol_version"] != lease.protocol_version
        ):
            raise CoreAuthorityError("durable core authority epoch does not match this process")
        claimed_marker_sha256 = self._claimed_core_authority_marker_sha256
        if (
            claimed_marker_sha256 is None
            or not secrets.compare_digest(
                self._core_authority_marker_sha256(marker),
                claimed_marker_sha256,
            )
        ):
            raise CoreAuthorityError(
                "durable core authority marker changed after this process claimed it"
            )

    def _assert_durable_authority(self, conn: sqlite3.Connection) -> None:
        lease = self._assert_filesystem_authority()
        marker = self._core_authority_marker(conn)
        self._validate_core_authority_version_pair(conn, marker)
        if lease.role == "core":
            self._assert_core_marker_matches(marker)
            return
        if marker is not None and marker["service_required"] is True:
            raise CoreAuthorityError(
                "memory store requires the authoritative core service; "
                "route through the core client"
            )

    def _preflight_durable_authority(self, conn: sqlite3.Connection) -> None:
        lease = self._assert_filesystem_authority()
        marker = self._core_authority_marker(conn)
        self._validate_core_authority_version_pair(conn, marker)
        if lease.role == "core":
            if lease.durable_epoch is not None:
                self._assert_core_marker_matches(marker)
            return
        if marker is not None and marker["service_required"] is True:
            raise CoreAuthorityError(
                "memory store requires the authoritative core service; "
                "route through the core client"
            )

    @staticmethod
    def _validate_core_authority_version_pair(
        conn: sqlite3.Connection,
        marker: dict[str, Any] | None,
    ) -> None:
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        marker_present = marker is not None
        migration_present = DurableMemoryStore._core_authority_migration_present(conn)
        adopted_version = user_version >= 6
        if not (
            (not adopted_version and not marker_present and not migration_present)
            or (adopted_version and marker_present and migration_present)
        ):
            raise CoreAuthorityError(
                "SQLite version, durable core authority marker, and adoption migration "
                "are inconsistent"
            )

    def _inspect_core_authority_preclaim_transaction(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, Any]:
        self._validate_existing_schema_compatibility_markers(conn)
        marker = self._core_authority_marker(conn)
        self._validate_core_authority_version_pair(conn, marker)
        runtime_publication = self._core_runtime_publication(conn, marker)
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if user_version not in {5, SQLITE_USER_VERSION}:
            raise CoreAuthorityError(
                "core preclaim inspection requires an authoritative v5 or v6 store"
            )
        self._assert_exact_schema_contract(conn, user_version=user_version)
        logical_snapshot = self._canonical_logical_snapshot_digest(
            conn,
            install_progress_handler=False,
        )
        previous_epoch = int(marker["epoch"]) if marker is not None else 0
        if previous_epoch >= (2**63 - 1):
            raise CoreAuthorityError("authoritative core epoch is exhausted")
        return {
            "governance_mode": (
                "authoritative-v6" if marker is not None else "pre-governed-v5"
            ),
            "schema_identity": f"sqlite-{SQLITE_APPLICATION_ID:x}-v{user_version}",
            "previous_epoch": previous_epoch,
            "next_epoch": previous_epoch + 1,
            "logical_snapshot": logical_snapshot,
            "marker": None if marker is None else dict(marker),
            "runtime_publication": (
                None if runtime_publication is None else dict(runtime_publication)
            ),
            "store_identity": (
                str(marker["store_identity"])
                if marker is not None
                else self.store_identity_for_path(self.db_path)
            ),
            "new_empty_bootstrap": bool(
                marker is None and self._database_created_for_initialization
            ),
        }

    def inspect_core_authority_preclaim(self) -> dict[str, Any]:
        """Return one coherent, WAL-aware read-only authority snapshot.

        The returned logical digest and epoch are inputs to
        :meth:`claim_core_authority`; that method recomputes both inside its
        ``BEGIN IMMEDIATE`` transaction before publishing any v6 state.
        """

        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is not None:
            raise CoreAuthorityError(
                "preclaim inspection requires one unbound authoritative core lease"
            )
        with closing(self._connect_read_only()) as conn:
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("BEGIN")
            try:
                result = self._inspect_core_authority_preclaim_transaction(conn)
            finally:
                conn.execute("ROLLBACK")
        self._assert_filesystem_authority()
        return result

    def inspect_core_authority_preclaim_immutable(self) -> dict[str, Any]:
        """Inspect a quiescent standalone main database without side effects.

        This narrow audit lane accepts either no sidecars or the normal sealed
        clean-close pair of a zero-byte WAL and a bounded 32-KiB-aligned SHM. It never opens
        the live path in ordinary WAL-aware read-only mode.
        """

        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is not None:
            raise CoreAuthorityError(
                "preclaim inspection requires one unbound authoritative core lease"
            )
        observed = self._assert_private_database_identity()

        def clean_close_sidecars() -> tuple[tuple[Any, ...], ...]:
            rollback = Path(f"{self.db_path}-journal")
            wal = Path(f"{self.db_path}-wal")
            shm = Path(f"{self.db_path}-shm")
            if rollback.exists() or rollback.is_symlink():
                raise CoreAuthorityError(
                    "immutable core inspection found rollback state"
                )
            wal_present = wal.exists() or wal.is_symlink()
            shm_present = shm.exists() or shm.is_symlink()
            if wal_present != shm_present:
                raise CoreAuthorityError(
                    "immutable core inspection found incomplete sidecar state"
                )
            if not wal_present:
                return ()

            snapshots: list[tuple[Any, ...]] = []
            for path in (wal, shm):
                before = os.lstat(path)
                observed_size = int(before.st_size)
                size_valid = (
                    observed_size == 0
                    if path == wal
                    else (
                        32_768 <= observed_size <= 8 * 1024 * 1024
                        and observed_size % 32_768 == 0
                    )
                )
                if (
                    stat.S_ISLNK(before.st_mode)
                    or not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or int(before.st_nlink) != 1
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or not size_valid
                ):
                    raise CoreAuthorityError(
                        "immutable core inspection found unsafe sidecar state"
                    )
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags)
                digest = hashlib.sha256()
                try:
                    opened = os.fstat(descriptor)
                    while True:
                        chunk = os.read(descriptor, 65_536)
                        if not chunk:
                            break
                        digest.update(chunk)
                    finished = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                visible = os.lstat(path)

                def identity(value: os.stat_result) -> tuple[int, ...]:
                    return (
                        int(value.st_dev),
                        int(value.st_ino),
                        int(value.st_size),
                        int(value.st_mtime_ns),
                        int(value.st_ctime_ns),
                        int(value.st_uid),
                        int(value.st_nlink),
                        stat.S_IMODE(value.st_mode),
                    )

                identities = {
                    identity(value) for value in (before, opened, finished, visible)
                }
                if len(identities) != 1:
                    raise CoreAuthorityError(
                        "immutable core sidecar changed while being sealed"
                    )
                snapshots.append((*identity(before), digest.hexdigest()))
            return tuple(snapshots)

        sidecars_before = clean_close_sidecars()
        uri = self.db_path.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("BEGIN")
            try:
                quick = conn.execute("PRAGMA quick_check(1)").fetchone()
                integrity = conn.execute("PRAGMA integrity_check(1)").fetchone()
                foreign_key_violation = conn.execute(
                    "PRAGMA foreign_key_check"
                ).fetchone()
                if (
                    quick is None
                    or str(quick[0]) != "ok"
                    or integrity is None
                    or str(integrity[0]) != "ok"
                    or foreign_key_violation is not None
                ):
                    raise CoreAuthorityError(
                        "memory database failed immutable integrity verification"
                    )
                result = self._inspect_core_authority_preclaim_transaction(conn)
            finally:
                conn.execute("ROLLBACK")
        self._assert_filesystem_authority()
        visible = self._assert_private_database_identity()
        if (
            self._regular_file_identity(visible)
            != self._regular_file_identity(observed)
            or visible.st_uid != observed.st_uid
            or int(visible.st_nlink) != int(observed.st_nlink)
            or stat.S_IMODE(visible.st_mode) != stat.S_IMODE(observed.st_mode)
        ):
            raise CoreAuthorityError(
                "memory database changed during immutable core inspection"
            )
        if clean_close_sidecars() != sidecars_before:
            raise CoreAuthorityError(
                "memory database sidecar changed during immutable core inspection"
            )
        return result

    def claim_core_authority(
        self,
        *,
        instance_id: str,
        config_fingerprint: str,
        build_id: str,
        protocol_version: str,
        expected_store_identity: str,
        request_journal_id: str,
        request_journal_binding_schema: str,
        request_journal_schema_version: int,
        expected_preclaim_logical_snapshot_sha256: str,
        expected_previous_epoch: int,
        expected_next_epoch: int,
        root_generation_id: str,
        embedding_space_identity: str,
        attestation_receipt_digest: str | None = None,
        restored_target_binding_receipt_digest: str | None = None,
        attestation_expires_at_unix_ms: int | None = None,
        allow_legacy_lock_generation_transition: bool = False,
    ) -> dict[str, Any]:
        """Permanently adopt the store after the core backend is fully ready.

        The v6 marker, migration row, and monotonic epoch are committed in one
        ``BEGIN IMMEDIATE`` transaction.  Before this explicit call an unbound
        core lease is read-only, so a failed backend bootstrap leaves a v5 store
        unclaimed and legacy-compatible.
        """

        lease = self._assert_filesystem_authority()
        if lease.role != "core":
            raise CoreAuthorityError("only the authoritative core may claim the store")
        clean_instance_id = str(instance_id).strip()
        clean_config_fingerprint = str(config_fingerprint).strip()
        clean_build_id = str(build_id).strip()
        clean_protocol_version = str(protocol_version).strip()
        clean_store_identity = str(expected_store_identity).strip()
        clean_request_journal_id = str(request_journal_id).strip()
        clean_journal_binding_schema = str(request_journal_binding_schema).strip()
        clean_preclaim_digest = str(
            expected_preclaim_logical_snapshot_sha256
        ).strip()
        clean_root_generation_id = str(root_generation_id).strip()
        clean_embedding_space_identity = str(embedding_space_identity).strip()
        clean_attestation_digest = (
            None
            if attestation_receipt_digest is None
            else str(attestation_receipt_digest).strip()
        )
        clean_restored_binding_digest = (
            None
            if restored_target_binding_receipt_digest is None
            else str(restored_target_binding_receipt_digest).strip()
        )
        if clean_instance_id != lease.instance_id:
            raise CoreAuthorityError(
                "core service identity does not match its authority lease"
            )
        if re.fullmatch(r"[0-9a-f]{64}", clean_config_fingerprint) is None:
            raise CoreAuthorityError("core configuration fingerprint is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", clean_preclaim_digest) is None:
            raise CoreAuthorityError("core preclaim logical snapshot digest is invalid")
        if CORE_ROOT_GENERATION_ID_RE.fullmatch(clean_root_generation_id) is None:
            raise CoreAuthorityError("core root generation is invalid")
        if BACKUP_DIGEST_RE.fullmatch(clean_embedding_space_identity) is None:
            raise CoreAuthorityError("core embedding-space identity is invalid")
        if (
            type(expected_previous_epoch) is not int
            or expected_previous_epoch < 0
            or expected_previous_epoch >= (2**63 - 1)
            or type(expected_next_epoch) is not int
            or expected_next_epoch != expected_previous_epoch + 1
        ):
            raise CoreAuthorityError("core authority epoch expectation is invalid")
        if clean_attestation_digest is not None and re.fullmatch(
            r"[0-9a-f]{64}", clean_attestation_digest
        ) is None:
            raise CoreAuthorityError("core cutover attestation digest is invalid")
        if clean_attestation_digest is None:
            if attestation_expires_at_unix_ms is not None:
                raise CoreAuthorityError("core cutover attestation expiry is invalid")
        elif (
            type(attestation_expires_at_unix_ms) is not int
            or int(attestation_expires_at_unix_ms) <= 0
        ):
            raise CoreAuthorityError("core cutover attestation expiry is invalid")
        if clean_restored_binding_digest is not None and BACKUP_DIGEST_RE.fullmatch(
            clean_restored_binding_digest
        ) is None:
            raise CoreAuthorityError("restored-target binding digest is invalid")
        if type(allow_legacy_lock_generation_transition) is not bool:
            raise CoreAuthorityError(
                "legacy authority-lock generation transition request is invalid"
            )
        if CORE_STORE_IDENTITY_RE.fullmatch(clean_store_identity) is None:
            raise CoreAuthorityError("core store identity is invalid")
        if CORE_REQUEST_JOURNAL_ID_RE.fullmatch(clean_request_journal_id) is None:
            raise CoreAuthorityError("core request-journal identity is invalid")
        if (
            clean_journal_binding_schema != JOURNAL_BINDING_SCHEMA
            or type(request_journal_schema_version) is not int
            or request_journal_schema_version != JOURNAL_SCHEMA_VERSION
        ):
            raise CoreAuthorityError("core request-journal binding is unsupported")
        for field, value in (
            ("build_id", clean_build_id),
            ("protocol_version", clean_protocol_version),
        ):
            if CORE_AUTHORITY_INSTANCE_RE.fullmatch(value) is None:
                raise CoreAuthorityError(f"core {field} is invalid")
            try:
                reject_sensitive_identifier(value, field=f"core_{field}")
            except ValueError as exc:
                raise CoreAuthorityError(f"core {field} is invalid") from exc
        if lease.durable_epoch is not None:
            with closing(self._connect_read_only()) as existing:
                marker = self._core_authority_marker(existing)
            self._assert_core_marker_matches(marker)
            assert marker is not None
            if (
                clean_config_fingerprint != lease.config_fingerprint
                or clean_build_id != lease.build_id
                or clean_protocol_version != lease.protocol_version
            ):
                raise CoreAuthorityError(
                    "core service diagnostics do not match the durable claim"
                )
            if (
                marker["store_identity"] != clean_store_identity
                or marker["request_journal_id"] != clean_request_journal_id
                or marker["request_journal_binding_schema"]
                != clean_journal_binding_schema
                or marker["request_journal_schema_version"]
                != request_journal_schema_version
                or marker["root_generation_id"] != clean_root_generation_id
                or marker["embedding_space_identity"]
                != clean_embedding_space_identity
                or marker["lock_generation_id"] != lease.lock_generation_id
            ):
                raise CoreAuthorityError(
                    "core request journal does not match the durable claim"
                )
            existing_restored_digest = marker[
                "restored_target_binding_receipt_digest"
            ]
            if (
                clean_restored_binding_digest is not None
                and clean_restored_binding_digest != existing_restored_digest
            ):
                raise CoreAuthorityError(
                    "restored-target binding does not match the durable claim"
                )
            if int(marker["epoch"]) != expected_previous_epoch:
                raise CoreAuthorityError("core authority epoch expectation changed")
            return self._core_authority_claim_response(marker)
        if not self.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {self.db_path}"
            )
        self._assert_private_database_identity()
        uri = self.db_path.resolve().as_uri() + "?mode=rw"
        conn = sqlite3.connect(uri, timeout=10.0, isolation_level=None, uri=True)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            self._assert_filesystem_authority()
            self._validate_existing_schema_compatibility_markers(conn)
            initial_marker = self._core_authority_marker(conn)
            self._validate_core_authority_version_pair(conn, initial_marker)
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._assert_filesystem_authority()
                marker = self._core_authority_marker(conn)
                self._validate_core_authority_version_pair(conn, marker)
                self._run_migrations(conn, allow_mutation=False)
                claim_user_version = int(
                    conn.execute("PRAGMA user_version").fetchone()[0]
                )
                if claim_user_version not in {5, SQLITE_USER_VERSION}:
                    raise CoreAuthorityError(
                        "core authority claim requires an authoritative v5 or v6 store"
                    )
                self._assert_exact_schema_contract(
                    conn,
                    user_version=claim_user_version,
                )
                applied = {
                    str(row[0])
                    for row in conn.execute(
                        "SELECT key FROM store_migrations"
                    ).fetchall()
                }
                missing = self._base_authority_migrations() - applied
                if missing:
                    raise CoreAuthorityError(
                        "core authority claim requires a fully migrated v5 store "
                        f"(missing_migrations={len(missing)})"
                    )
                previous_epoch = int(marker["epoch"]) if marker is not None else 0
                if previous_epoch >= (2**63 - 1):
                    raise CoreAuthorityError("authoritative core epoch is exhausted")
                epoch = previous_epoch + 1
                if (
                    previous_epoch != expected_previous_epoch
                    or epoch != expected_next_epoch
                ):
                    raise CoreAuthorityError(
                        "core authority epoch changed after preflight"
                    )
                preclaim_snapshot = self._canonical_logical_snapshot_digest(
                    conn,
                    install_progress_handler=False,
                )
                if not secrets.compare_digest(
                    str(preclaim_snapshot["sha256"]),
                    clean_preclaim_digest,
                ):
                    raise CoreAuthorityError(
                        "memory store changed after core cutover preflight"
                    )
                identity_changed = marker is not None and (
                    marker["config_fingerprint"] != clean_config_fingerprint
                    or marker["build_id"] != clean_build_id
                    or marker["protocol_version"] != clean_protocol_version
                )
                if marker is not None and (
                    marker["store_identity"] != clean_store_identity
                    or marker["request_journal_id"] != clean_request_journal_id
                    or marker["request_journal_binding_schema"]
                    != clean_journal_binding_schema
                    or marker["request_journal_schema_version"]
                    != request_journal_schema_version
                ):
                    raise CoreAuthorityError(
                        "core request journal changed after durable adoption"
                    )
                if marker is not None and (
                    marker["embedding_space_identity"]
                    != clean_embedding_space_identity
                ):
                    raise CoreAuthorityError(
                        "core embedding-space identity requires a verified reindex migration"
                    )
                root_generation_changed = marker is not None and (
                    marker["root_generation_id"] != clean_root_generation_id
                )
                lock_generation_changed = marker is not None and (
                    marker["lock_generation_id"] != lease.lock_generation_id
                )
                legacy_lock_generation_transition = False
                if allow_legacy_lock_generation_transition:
                    if (
                        marker is None
                        or not lock_generation_changed
                        or root_generation_changed
                        or clean_attestation_digest is None
                        or clean_restored_binding_digest is not None
                    ):
                        raise CoreAuthorityError(
                            "legacy authority-lock generation transition is not "
                            "narrowly authorized"
                        )
                    lease.validate_legacy_lock_generation_transition(
                        legacy_generation_id=str(
                            marker["lock_generation_id"]
                        ),
                        durable_claimed_at=float(marker["claimed_at"]),
                    )
                    legacy_lock_generation_transition = True
                if root_generation_changed and not (
                    clean_attestation_digest is not None
                    and clean_restored_binding_digest is not None
                ):
                    raise CoreAuthorityError(
                        "core root generation changed without restored-target adoption"
                    )
                if lock_generation_changed and not (
                    (
                        clean_attestation_digest is not None
                        and clean_restored_binding_digest is not None
                    )
                    or legacy_lock_generation_transition
                ):
                    raise CoreAuthorityError(
                        "core authority lock generation changed without "
                        "restored-target adoption"
                    )
                if (
                    (marker is None and not self._database_created_for_initialization)
                    or identity_changed
                    or root_generation_changed
                    or lock_generation_changed
                ) and clean_attestation_digest is None:
                    raise CoreAuthorityError(
                        "signed cutover attestation is required for this authority claim"
                    )
                now = time.time()
                claimed = {
                    "schema_version": CORE_AUTHORITY_SCHEMA_VERSION,
                    "service_required": True,
                    "epoch": epoch,
                    "instance_id": clean_instance_id,
                    "config_fingerprint": clean_config_fingerprint,
                    "build_id": clean_build_id,
                    "protocol_version": clean_protocol_version,
                    "lock_generation_id": lease.lock_generation_id,
                    "store_identity": clean_store_identity,
                    "request_journal_id": clean_request_journal_id,
                    "request_journal_binding_schema": clean_journal_binding_schema,
                    "request_journal_schema_version": request_journal_schema_version,
                    "root_generation_id": clean_root_generation_id,
                    "embedding_space_identity": clean_embedding_space_identity,
                    "restored_target_binding_receipt_digest": (
                        clean_restored_binding_digest
                        if clean_restored_binding_digest is not None
                        else (
                            None
                            if marker is None
                            else marker[
                                "restored_target_binding_receipt_digest"
                            ]
                        )
                    ),
                    "claimed_at": now,
                    "updated_at": now,
                }
                conn.execute(
                    """
                    INSERT INTO store_metadata (key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (CORE_AUTHORITY_METADATA_KEY, _json_dumps(claimed), now),
                )
                runtime_publication = {
                    "schema": CORE_RUNTIME_PUBLICATION_SCHEMA,
                    "status": "pending",
                    "marker_sha256": self._core_authority_marker_sha256(claimed),
                    "authority_epoch_number": epoch,
                    "lock_generation_id": lease.lock_generation_id,
                    "instance_id": clean_instance_id,
                    "config_fingerprint": clean_config_fingerprint,
                    "build_id": clean_build_id,
                    "protocol_version": clean_protocol_version,
                    "runtime_state_path_sha256": self.runtime_state_path_sha256(
                        self.db_path.parent / "runtime_state.json"
                    ),
                    "started_at": now,
                    "completed_at": None,
                    "updated_at": now,
                }
                conn.execute(
                    """
                    INSERT INTO store_metadata (key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        CORE_RUNTIME_PUBLICATION_METADATA_KEY,
                        _json_dumps(runtime_publication),
                        now,
                    ),
                )
                if marker is None:
                    existing_adoption = conn.execute(
                        "SELECT 1 FROM store_metadata WHERE key = ?",
                        (CORE_ADOPTION_ATTESTATION_METADATA_KEY,),
                    ).fetchone()
                    if existing_adoption is not None:
                        raise CoreAuthorityError(
                            "core adoption attestation record already exists"
                        )
                    adoption = {
                        "schema": CORE_ADOPTION_ATTESTATION_SCHEMA,
                        "mode": (
                            "signed-cutover"
                            if clean_attestation_digest is not None
                            else "new-empty-bootstrap"
                        ),
                        "preclaim_logical_snapshot_sha256": clean_preclaim_digest,
                        "attestation_receipt_digest": clean_attestation_digest,
                        "config_fingerprint": clean_config_fingerprint,
                        "build_id": clean_build_id,
                        "protocol_version": clean_protocol_version,
                        "lock_generation_id": lease.lock_generation_id,
                        "store_identity": clean_store_identity,
                        "request_journal_id": clean_request_journal_id,
                        "request_journal_binding_schema": clean_journal_binding_schema,
                        "request_journal_schema_version": request_journal_schema_version,
                        "root_generation_id": clean_root_generation_id,
                        "embedding_space_identity": clean_embedding_space_identity,
                        "restored_target_binding_receipt_digest": (
                            clean_restored_binding_digest
                        ),
                        "authority_epoch_number": epoch,
                        "claimed_at": now,
                    }
                    conn.execute(
                        """
                        INSERT INTO store_metadata (key, value_json, updated_at)
                        VALUES (?, ?, ?)
                        """,
                        (
                            CORE_ADOPTION_ATTESTATION_METADATA_KEY,
                            _json_dumps(adoption),
                            now,
                        ),
                    )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("authoritative_core_v1", now),
                )
                conn.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
                conn.execute(f"PRAGMA user_version = {SQLITE_USER_VERSION}")
                persisted = self._core_authority_marker(conn)
                if persisted != claimed:
                    raise CoreAuthorityError(
                        "authoritative core marker did not persist exactly"
                    )
                persisted_publication = self._core_runtime_publication(
                    conn,
                    persisted,
                )
                if persisted_publication != runtime_publication:
                    raise CoreAuthorityError(
                        "core runtime publication intent did not persist exactly"
                    )
                self._validate_core_authority_version_pair(conn, persisted)
                self._assert_exact_schema_contract(
                    conn,
                    user_version=SQLITE_USER_VERSION,
                )
                # Claim publication is itself the first v6 write, so it
                # cannot use the already-bound durable fence yet. Reassert
                # the exact filesystem lock identity at the last possible
                # point before COMMIT to prevent a replaced lock inode from
                # publishing a stale authority epoch.
                self._assert_filesystem_authority()
                if (
                    clean_attestation_digest is not None
                    and (
                        type(attestation_expires_at_unix_ms) is not int
                        or int(time.time() * 1000) + 1_000
                        >= int(attestation_expires_at_unix_ms)
                    )
                ):
                    raise CoreAuthorityError(
                        "core cutover attestation expired before durable claim"
                    )
                # Bind the in-process fence before the irreversible commit.
                # The binding is process-local and disappears when startup
                # closes the lease, whereas any failure after COMMIT could
                # otherwise strand a durable v6 marker without a service.
                lease.bind_durable_authority(
                    epoch=epoch,
                    config_fingerprint=clean_config_fingerprint,
                    build_id=clean_build_id,
                    protocol_version=clean_protocol_version,
                )
                conn.commit()
                self._claimed_core_authority_marker_sha256 = (
                    self._core_authority_marker_sha256(claimed)
                )
            except BaseException:
                conn.rollback()
                raise
        finally:
            conn.close()
        return self._core_authority_claim_response(claimed)

    def _core_authority_claim_response(
        self,
        marker: dict[str, Any],
    ) -> dict[str, Any]:
        epoch = int(marker["epoch"])
        return {
            **marker,
            "authority_epoch": f"epoch-{epoch}",
            "neural_epoch": f"epoch-{epoch}",
            "authority_epoch_number": epoch,
            "store_identity": str(marker["store_identity"]),
            "schema_identity": f"sqlite-{SQLITE_APPLICATION_ID:x}-v{SQLITE_USER_VERSION}",
        }

    @staticmethod
    def store_identity_for_path(path: str | os.PathLike[str]) -> str:
        return "store-" + hashlib.sha256(
            str(Path(path).expanduser().resolve()).encode("utf-8")
        ).hexdigest()[:24]

    def _prepare_database_identity(self, lease: CoreAuthorityLease) -> None:
        """Create only a genuinely missing store, then bind its exact inode."""

        lease.assert_active_for(self.db_path)
        if lease.database_device is None and lease.database_inode is None:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = -1
            try:
                descriptor = os.open(lease.db_path, flags, 0o600)
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.getuid()
                    or opened.st_nlink != 1
                ):
                    raise CoreAuthorityError(
                        "new memory database is not one owner-controlled regular file"
                    )
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                self._fsync_directory(lease.db_path.parent)
                self._database_created_for_initialization = True
            except FileExistsError as exc:
                raise CoreAuthorityError(
                    "memory database appeared during secure creation"
                ) from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            lease.bind_database_identity(self.db_path)
        lease.assert_active_for(self.db_path)

        self._assert_private_database_identity()

    def _assert_private_database_identity(self) -> os.stat_result:
        try:
            observed = os.lstat(self.db_path)
        except FileNotFoundError as exc:
            raise CoreAuthorityError("memory database does not exist") from exc
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or int(observed.st_nlink) != 1
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise CoreAuthorityError(
                "memory database must already be one private owner-controlled file"
            )
        return observed

    @staticmethod
    def _schema_statements() -> tuple[str, ...]:
        statements: list[str] = []
        pending = ""
        for line in SCHEMA_SQL.splitlines(keepends=True):
            pending += line
            if sqlite3.complete_statement(pending):
                statement = pending.strip()
                pending = ""
                if statement:
                    statements.append(statement)
        if pending.strip():
            raise RuntimeError("SYNAPSE-S2 schema script is incomplete")
        return tuple(statements)

    def _ensure_schema_transactionally(self, conn: sqlite3.Connection) -> None:
        # sqlite3.executescript() commits an open transaction implicitly. Execute
        # each statement ourselves so the authority checks in _transaction cover
        # the complete schema publication and its single COMMIT.
        with self._transaction(conn, immediate=True):
            for statement in self._schema_statements():
                conn.execute(statement)

    @staticmethod
    def _schema_contract_key(user_version: int) -> str:
        return BACKUP_SCHEMA_CONTRACT_VERSION if user_version >= 6 else "s2-schema-v5"

    def _assert_exact_schema_contract(
        self,
        conn: sqlite3.Connection,
        *,
        user_version: int,
    ) -> None:
        schema = self._sqlite_schema_fingerprint(conn)
        migrations = sorted(
            str(row[0])
            for row in conn.execute(
                "SELECT key FROM store_migrations ORDER BY key"
            ).fetchall()
        )
        migration_digest = hashlib.sha256(
            _json_dumps(migrations).encode("utf-8")
        ).hexdigest()
        schema_contract = {
            "schema_sha256": str(schema["sha256"]),
            "table_count": int(schema["table_count"]),
            "index_count": int(schema["index_count"]),
            "migration_set_sha256": migration_digest,
            "migration_count": len(migrations),
            "application_id": int(conn.execute("PRAGMA application_id").fetchone()[0]),
            "user_version": int(user_version),
        }
        if not _matching_backup_schema_contract_versions(schema_contract):
            raise CoreAuthorityError(
                "memory database schema or migration contract is not authoritative"
            )

    def _assert_mutation_authority(self, conn: sqlite3.Connection) -> None:
        lease = self._assert_filesystem_authority()
        if not (
            lease.role == "core"
            and lease.durable_epoch is None
            and self._initializing_authority_store
        ):
            self._assert_durable_authority(conn)

    @staticmethod
    def _install_retrieval_revision_triggers(conn: sqlite3.Connection) -> None:
        """Track content generations without adding durable schema objects.

        Every authoritative writer connection gets TEMP triggers over each
        available retrieval table. The counters themselves live in
        ``store_metadata`` and therefore advance in the exact same transaction
        as the content mutation. TEMP triggers keep the versioned backup schema
        stable while still covering direct SQL issued through governed store
        connections, including maintenance and repair operations.

        Existing-write repair connections may deliberately open a store whose
        derived index tables are missing or quarantined. Install coverage for
        every valid table that exists, then let the repair path call this helper
        again immediately after it restores the derived schema.
        """

        now_sql = "CAST(strftime('%s', 'now') AS REAL)"

        def bump(channel: str, context_expression: str) -> str:
            key_expression = (
                f"'{_RETRIEVAL_GENERATION_KEY_PREFIX}.{channel}.' || "
                f"{context_expression}"
            )
            return f"""
                INSERT INTO store_metadata (key, value_json, updated_at)
                VALUES ({key_expression}, '1', {now_sql})
                ON CONFLICT(key) DO UPDATE SET
                    value_json =
                        CASE
                            WHEN json_valid(store_metadata.value_json)
                                AND json_type(store_metadata.value_json) = 'integer'
                                AND CAST(store_metadata.value_json AS INTEGER)
                                BETWEEN 0 AND {_RETRIEVAL_GENERATION_MAX - 1}
                            THEN CAST(
                                CAST(store_metadata.value_json AS INTEGER) + 1
                                AS TEXT
                            )
                            ELSE 'null'
                        END,
                    updated_at = excluded.updated_at;
            """

        memory_new = bump("memory", "NEW.context_id")
        memory_old = bump("memory", "OLD.context_id")
        cortex_new = bump("cortex", "NEW.context_id")
        cortex_old = bump("cortex", "OLD.context_id")
        relationship_new = bump("relationship", "NEW.context_id")
        relationship_old = bump("relationship", "OLD.context_id")
        spike_new = bump("memory", "NEW.context_id")
        spike_old = bump("memory", "OLD.context_id")
        surface_new = bump("memory", "NEW.context_id")
        surface_old = bump("memory", "OLD.context_id")
        new_is_cortex = (
            "json_valid(NEW.metadata_json) "
            "AND json_type(NEW.metadata_json, '$.cortex_governor') = 'true'"
        )
        old_is_cortex = (
            "json_valid(OLD.metadata_json) "
            "AND json_type(OLD.metadata_json, '$.cortex_governor') = 'true'"
        )
        rows = conn.execute(
            """
            SELECT name
            FROM main.sqlite_master
            WHERE type = 'table'
              AND name IN (
                  'memory_entries',
                  'memory_relationships',
                  'memory_spikes',
                  'memory_surface_terms'
              )
            """
        ).fetchall()
        available_tables = {str(row[0]) for row in rows}
        statements: list[str] = []
        if "memory_entries" in available_tables:
            statements.extend(
                (
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_memory_ai
                    AFTER INSERT ON main.memory_entries
                    BEGIN {memory_new} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_memory_ad
                    AFTER DELETE ON main.memory_entries
                    BEGIN {memory_old} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_memory_au
                    AFTER UPDATE ON main.memory_entries
                    BEGIN {memory_new} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_memory_au_old_context
                    AFTER UPDATE OF context_id ON main.memory_entries
                    WHEN OLD.context_id <> NEW.context_id
                    BEGIN {memory_old} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_cortex_ai
                    AFTER INSERT ON main.memory_entries
                    WHEN {new_is_cortex}
                    BEGIN {cortex_new} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_cortex_ad
                    AFTER DELETE ON main.memory_entries
                    WHEN {old_is_cortex}
                    BEGIN {cortex_old} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_cortex_au
                    AFTER UPDATE ON main.memory_entries
                    WHEN ({old_is_cortex}) OR ({new_is_cortex})
                    BEGIN {cortex_new} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_cortex_au_old_context
                    AFTER UPDATE OF context_id ON main.memory_entries
                    WHEN OLD.context_id <> NEW.context_id AND ({old_is_cortex})
                    BEGIN {cortex_old} END
                    """,
                )
            )
        if "memory_relationships" in available_tables:
            statements.extend(
                (
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_relationship_ai
                    AFTER INSERT ON main.memory_relationships
                    BEGIN {relationship_new} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_relationship_ad
                    AFTER DELETE ON main.memory_relationships
                    BEGIN {relationship_old} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_relationship_au
                    AFTER UPDATE ON main.memory_relationships
                    BEGIN {relationship_new} END
                    """,
                    f"""
                    CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_relationship_au_old_context
                    AFTER UPDATE OF context_id ON main.memory_relationships
                    WHEN OLD.context_id <> NEW.context_id
                    BEGIN {relationship_old} END
                    """,
                )
            )
        if "memory_spikes" in available_tables:
            statements.extend((
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_spike_ai
                AFTER INSERT ON main.memory_spikes
                BEGIN {spike_new} END
                """,
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_spike_ad
                AFTER DELETE ON main.memory_spikes
                BEGIN {spike_old} END
                """,
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_spike_au
                AFTER UPDATE ON main.memory_spikes
                BEGIN {spike_new} END
                """,
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_spike_au_old_context
                AFTER UPDATE OF context_id ON main.memory_spikes
                WHEN OLD.context_id <> NEW.context_id
                BEGIN {spike_old} END
                """,
            ))
        if "memory_surface_terms" in available_tables:
            statements.extend((
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_surface_ai
                AFTER INSERT ON main.memory_surface_terms
                BEGIN {surface_new} END
                """,
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_surface_ad
                AFTER DELETE ON main.memory_surface_terms
                BEGIN {surface_old} END
                """,
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_surface_au
                AFTER UPDATE ON main.memory_surface_terms
                BEGIN {surface_new} END
                """,
                f"""
                CREATE TEMP TRIGGER IF NOT EXISTS s2_retrieval_surface_au_old_context
                AFTER UPDATE OF context_id ON main.memory_surface_terms
                WHEN OLD.context_id <> NEW.context_id
                BEGIN {surface_old} END
                """,
            ))
        for statement in statements:
            conn.execute(statement)

    def _connect(self) -> sqlite3.Connection:
        lease = self._assert_filesystem_authority()
        if (
            lease.role == "core"
            and lease.durable_epoch is None
            and not self._initializing_authority_store
        ):
            return self._connect_read_only()
        self._ensure_directory(self.db_path.parent, owned=False)
        self._prepare_database_identity(lease)
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            self._assert_filesystem_authority()
            self._validate_existing_schema_compatibility_markers(conn)
            self._preflight_durable_authority(conn)
            current_user_version = int(
                conn.execute("PRAGMA user_version").fetchone()[0]
            )
            if (
                lease.role == "core"
                and lease.durable_epoch is None
                and self.db_path.is_file()
                and current_user_version >= 5
            ):
                conn.close()
                return self._connect_read_only()
            durability = str(
                os.getenv("SYNAPSE_S2_SQLITE_DURABILITY", "full")
            ).strip().lower()
            if durability not in {"full", "balanced"}:
                raise ValueError(
                    "SYNAPSE_S2_SQLITE_DURABILITY must be full or balanced"
                )
            conn.execute(
                "PRAGMA synchronous = FULL"
                if durability == "full"
                else "PRAGMA synchronous = NORMAL"
            )
            if current_user_version >= 6:
                journal_mode = str(
                    conn.execute("PRAGMA journal_mode").fetchone()[0]
                ).strip().lower()
                if journal_mode != "wal":
                    raise CoreAuthorityError(
                        "authoritative memory database journal mode is not WAL"
                    )
                self._assert_exact_schema_contract(
                    conn,
                    user_version=current_user_version,
                )
                self._run_migrations(conn, allow_mutation=False)
                self._assert_durable_authority(conn)
                self._install_retrieval_revision_triggers(conn)
                return conn

            journal_mode = str(
                conn.execute("PRAGMA journal_mode").fetchone()[0]
            ).strip().lower()
            if journal_mode != "wal":
                writer_gate_fd = self._acquire_writer_gate()
                try:
                    # Re-read after taking the maintenance-coordination gate;
                    # another initializer may have completed while we waited.
                    journal_mode = str(
                        conn.execute("PRAGMA journal_mode").fetchone()[0]
                    ).strip().lower()
                    if journal_mode != "wal":
                        self._assert_mutation_authority(conn)
                        configured_journal_mode = str(
                            conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
                        ).strip().lower()
                        self._assert_mutation_authority(conn)
                        if configured_journal_mode != "wal":
                            raise RuntimeError(
                                "failed to configure SQLite WAL journal mode"
                            )
                finally:
                    self._release_file_lock(writer_gate_fd)
            self._ensure_schema_transactionally(conn)
            self._assert_filesystem_authority()
            self._run_migrations(conn, allow_mutation=True)
            self._publish_schema_compatibility_markers(conn, user_version=5)
            self._install_retrieval_revision_triggers(conn)
            return conn
        except BaseException:
            conn.close()
            raise

    @staticmethod
    def _schema_compatibility_markers(
        conn: sqlite3.Connection,
    ) -> tuple[int, int]:
        return (
            int(conn.execute("PRAGMA application_id").fetchone()[0]),
            int(conn.execute("PRAGMA user_version").fetchone()[0]),
        )

    def _validate_existing_schema_compatibility_markers(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        """Reject foreign or newer stores before any schema claim is written."""

        application_id, user_version = self._schema_compatibility_markers(conn)
        if application_id not in {0, SQLITE_APPLICATION_ID}:
            raise RuntimeError(
                "SQLite application_id does not identify a SYNAPSE-S2 store"
            )
        if user_version < 0 or user_version > SQLITE_USER_VERSION:
            raise RuntimeError(
                "SQLite user_version is newer than this SYNAPSE-S2 runtime"
            )

    def _publish_schema_compatibility_markers(
        self,
        conn: sqlite3.Connection,
        *,
        user_version: int = SQLITE_USER_VERSION,
    ) -> None:
        """Publish the schema identity only after every migration gate succeeds."""

        if self._schema_compatibility_markers(conn) == (
            SQLITE_APPLICATION_ID,
            user_version,
        ):
            return
        with self._transaction(conn, immediate=True):
            self._validate_existing_schema_compatibility_markers(conn)
            conn.execute(f"PRAGMA application_id = {SQLITE_APPLICATION_ID}")
            conn.execute(f"PRAGMA user_version = {user_version}")
            if self._schema_compatibility_markers(conn) != (
                SQLITE_APPLICATION_ID,
                user_version,
            ):
                raise RuntimeError(
                    "failed to publish SYNAPSE-S2 schema compatibility markers"
                )

    def _connect_read_only(self) -> sqlite3.Connection:
        lease = self._authority_lease
        if lease is not None:
            lease.assert_active_for(self.db_path)
        if not self.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {self.db_path}"
            )
        self._assert_private_database_identity()
        uri = self.db_path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(
            uri,
            timeout=10.0,
            isolation_level=None,
            uri=True,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA query_only = ON")
            if lease is not None:
                lease.assert_active_for(self.db_path)
            return conn
        except BaseException:
            conn.close()
            raise

    def _connect_existing_write(self) -> sqlite3.Connection:
        """Open an existing store read/write without implicit schema migration."""

        acquired_for_governed_write = False
        if self._authority_lease is None:
            self._authority_lease = CoreAuthorityLease.acquire_local(self.db_path)
            self._owns_authority_lease = True
            acquired_for_governed_write = True
        self._assert_filesystem_authority()
        if not self.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {self.db_path}"
            )
        self._assert_private_database_identity()
        uri = self.db_path.resolve().as_uri() + "?mode=rw"
        conn = sqlite3.connect(
            uri,
            timeout=10.0,
            isolation_level=None,
            uri=True,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            self._assert_filesystem_authority()
            self._validate_existing_schema_compatibility_markers(conn)
            self._preflight_durable_authority(conn)
            durability = str(
                os.getenv("SYNAPSE_S2_SQLITE_DURABILITY", "full")
            ).strip().lower()
            if durability not in {"full", "balanced"}:
                raise ValueError(
                    "SYNAPSE_S2_SQLITE_DURABILITY must be full or balanced"
                )
            conn.execute(
                "PRAGMA synchronous = FULL"
                if durability == "full"
                else "PRAGMA synchronous = NORMAL"
            )
            self._install_retrieval_revision_triggers(conn)
            return conn
        except BaseException:
            conn.close()
            if acquired_for_governed_write and self._authority_lease is not None:
                self._authority_lease.close()
                self._authority_lease = None
                self._owns_authority_lease = False
            raise

    @contextmanager
    def _read_connection_scope(
        self,
        existing: sqlite3.Connection | None = None,
    ) -> Iterator[sqlite3.Connection]:
        """Borrow a snapshot connection or open the normal migrated reader."""

        if existing is not None:
            yield existing
            return
        with closing(self._connect()) as conn:
            yield conn

    @contextmanager
    def _transaction(
        self,
        conn: sqlite3.Connection,
        *,
        immediate: bool = False,
        cooperate_with_maintenance: bool = True,
    ) -> Iterator[None]:
        """Run a real SQLite transaction while connections remain autocommit by default.

        The store deliberately keeps ``isolation_level=None`` so single-statement
        operations commit immediately.  Python's ``with conn`` is a no-op in that
        mode, however, so every compound durability boundary must enter here.
        ``BEGIN IMMEDIATE`` is used for read-modify-write maintenance to obtain one
        consistent writer snapshot before any index rows are replaced.
        """
        if conn.in_transaction:
            raise RuntimeError("nested DurableMemoryStore transactions are not supported")
        writer_gate_fd: int | None = None
        if immediate and cooperate_with_maintenance:
            writer_gate_fd = self._acquire_writer_gate()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                query_only = bool(int(conn.execute("PRAGMA query_only").fetchone()[0]))
                if not query_only:
                    self._assert_mutation_authority(conn)
                yield
            except BaseException:
                conn.rollback()
                raise
            else:
                # The lease and durable epoch may have been replaced while a
                # long-running mutation held its SQLite transaction.  Recheck
                # immediately before COMMIT so that work begun by a stale core
                # is rolled back instead of crossing an authority handoff.
                query_only = bool(int(conn.execute("PRAGMA query_only").fetchone()[0]))
                if not query_only:
                    self._assert_mutation_authority(conn)
                conn.commit()
        finally:
            if writer_gate_fd is not None:
                self._release_file_lock(writer_gate_fd)

    @staticmethod
    def _schema_column_names(
        conn: sqlite3.Connection,
        table_name: str,
    ) -> tuple[str, ...]:
        allowed_tables = {
            "agent_context_deliveries",
            "agent_context_delivery_receipts",
            "agent_context_deliveries_v1_legacy",
            "agent_context_delivery_receipts_v1_legacy",
            "agent_context_deliveries_v2_legacy",
            "agent_context_delivery_receipts_v2_legacy",
            "agent_context_delivery_ack_tombstones",
            "agent_context_delivery_ack_tombstones_v2_legacy",
        }
        if table_name not in allowed_tables:
            raise ValueError(f"unsupported schema inspection table: {table_name}")
        return tuple(
            str(row["name"])
            for row in conn.execute(f'PRAGMA table_info("{table_name}")').fetchall()
        )

    @staticmethod
    def _normalized_schema_sql(raw_sql: str) -> str:
        normalized = re.sub(r"\s+", " ", str(raw_sql or "").strip().casefold())
        return normalized.replace(" if not exists ", " ")

    def _capture_operation_schema_errors(
        self,
        conn: sqlite3.Connection,
    ) -> list[str]:
        errors: list[str] = []
        table_row = conn.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = ?",
            ("capture_operations",),
        ).fetchone()
        if table_row is None or str(table_row["type"]) != "table":
            return ["capture_operations:missing-table"]

        actual_columns = tuple(
            (
                str(row["name"]),
                str(row["type"]).upper(),
                int(row["notnull"]),
                None if row["dflt_value"] is None else str(row["dflt_value"]),
                int(row["pk"]),
            )
            for row in conn.execute(
                'PRAGMA table_info("capture_operations")'
            ).fetchall()
        )
        if actual_columns != CAPTURE_OPERATION_COLUMN_SIGNATURE:
            errors.append("capture_operations:column-signature")
        if conn.execute(
            'PRAGMA foreign_key_list("capture_operations")'
        ).fetchall():
            # Capture receipts intentionally survive graph/deployment pruning.
            errors.append("capture_operations:unexpected-foreign-key")

        normalized_table_sql = self._normalized_schema_sql(str(table_row["sql"] or ""))
        for fragment in CAPTURE_OPERATION_CHECK_FRAGMENTS:
            if self._normalized_schema_sql(fragment) not in normalized_table_sql:
                errors.append("capture_operations:constraint-sql")
                break

        listed_indexes = {
            str(row["name"]): row
            for row in conn.execute(
                'PRAGMA index_list("capture_operations")'
            ).fetchall()
        }
        for index_name, (expected_unique, expected_columns) in (
            CAPTURE_OPERATION_INDEX_COLUMNS.items()
        ):
            index_row = listed_indexes.get(index_name)
            schema_row = conn.execute(
                "SELECT type, tbl_name, sql FROM sqlite_master WHERE name = ?",
                (index_name,),
            ).fetchone()
            actual_columns = tuple(
                str(row["name"])
                for row in conn.execute(
                    f'PRAGMA index_info("{index_name}")'
                ).fetchall()
            )
            if (
                index_row is None
                or schema_row is None
                or str(schema_row["type"]) != "index"
                or str(schema_row["tbl_name"]) != "capture_operations"
                or bool(index_row["unique"]) is not bool(expected_unique)
                or int(index_row["partial"]) != 0
                or actual_columns != expected_columns
                or self._normalized_schema_sql(str(schema_row["sql"] or ""))
                != self._normalized_schema_sql(CAPTURE_OPERATION_INDEX_SQL[index_name])
            ):
                errors.append(f"{index_name}:index-signature")
        return errors

    @staticmethod
    def _capture_operation_live_event(row: sqlite3.Row) -> dict[str, Any] | None:
        if "live_event_context_id" not in row.keys():
            return None
        if row["live_event_context_id"] is None:
            return None
        return {
            "context_id": str(row["live_event_context_id"]),
            "event_type": str(row["live_event_type"]),
            "source_surface": str(row["live_event_source_surface"]),
            "published_at": float(row["live_event_published_at"]),
        }

    @staticmethod
    def _capture_operation_bounded_count(
        value: Any,
        *,
        field: str,
        maximum: int = CAPTURE_OPERATION_COUNTER_MAX,
    ) -> int:
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError(
                f"{field} must be an exact integer between 0 and {maximum}"
            )
        return value

    def _build_private_capture_operation_receipt(
        self,
        *,
        capture_id: str,
        request_fingerprint: str,
        context_id: str,
        source_tag: str,
        speaker: str,
        deployment_event_id: int,
        deployment_event_type: str,
        deployment_source_surface: str,
        deployment_published_at: float,
        event_count: int,
        entry_count: int,
        relationship_count: int,
        committed_at: float,
    ) -> tuple[dict[str, Any], str]:
        clean_capture_id = self._validate_capture_id(capture_id)
        clean_fingerprint = self._validate_capture_fingerprint(request_fingerprint)
        clean_context = self._validate_capture_identity_text(
            context_id,
            field="context_id",
            max_length=128,
        )
        clean_source_tag = self._validate_capture_identity_text(
            source_tag,
            field="source_tag",
            max_length=200,
        )
        clean_speaker = self._validate_capture_identity_text(
            speaker,
            field="speaker",
            max_length=128,
        )
        clean_event_type = self._validate_capture_identity_text(
            deployment_event_type,
            field="deployment_event.event_type",
            max_length=200,
        )
        clean_source_surface = self._validate_capture_identity_text(
            deployment_source_surface,
            field="deployment_event.source_surface",
            max_length=200,
        )
        if type(deployment_event_id) is not int or deployment_event_id <= 0:
            raise ValueError("deployment_event.event_id must be a positive exact integer")
        clean_event_count = self._capture_operation_bounded_count(
            event_count,
            field="result.event_count",
        )
        clean_entry_count = self._capture_operation_bounded_count(
            entry_count,
            field="entry_count",
        )
        clean_relationship_count = self._capture_operation_bounded_count(
            relationship_count,
            field="relationship_count",
        )
        if clean_event_count > clean_entry_count:
            raise ValueError("result.event_count must not exceed entry_count")
        clean_published_at = self._validate_capture_timestamp(
            deployment_published_at,
            field="deployment_event.published_at",
        )
        clean_committed_at = self._validate_capture_timestamp(
            committed_at,
            field="committed_at",
        )
        envelope = {
            "capture_id": clean_capture_id,
            "protocol": CAPTURE_PROTOCOL_VERSION,
            "request_fingerprint": clean_fingerprint,
            "context_id": clean_context,
            "source_tag": clean_source_tag,
            "speaker": clean_speaker,
            "result": {
                "status": "committed",
                "event_count": clean_event_count,
                "entry_count": clean_entry_count,
                "relationship_count": clean_relationship_count,
            },
            "deployment_event": {
                "event_id": deployment_event_id,
                "context_id": clean_context,
                "event_type": clean_event_type,
                "source_surface": clean_source_surface,
                "published_at": clean_published_at,
            },
            "entry_count": clean_entry_count,
            "relationship_count": clean_relationship_count,
            "committed_at": clean_committed_at,
        }
        envelope_json = _capture_json_dumps(envelope, field="result_json")
        if len(envelope_json.encode("utf-8")) > CAPTURE_OPERATION_RESULT_JSON_MAX_BYTES:
            raise ValueError(
                "content-free capture receipt exceeds the bounded storage envelope"
            )
        return envelope, envelope_json

    def _capture_operation_receipt_reasons(
        self,
        row: sqlite3.Row,
        envelope: Any,
        raw_result: str,
        *,
        live_event: dict[str, Any] | None = None,
    ) -> list[str]:
        reasons: list[str] = []
        capture_id = str(row["capture_id"])
        fingerprint = str(row["request_fingerprint"])
        row_context = str(row["context_id"])
        source_tag = str(row["source_tag"])
        speaker = str(row["speaker"])
        deployment_event_id = int(row["deployment_event_id"])
        entry_count = int(row["entry_count"])
        relationship_count = int(row["relationship_count"])
        committed_at = float(row["committed_at"])
        if CAPTURE_ID_RE.fullmatch(capture_id) is None:
            reasons.append("capture-id")
        if str(row["protocol"]) != CAPTURE_PROTOCOL_VERSION:
            reasons.append("protocol")
        if CAPTURE_REQUEST_FINGERPRINT_RE.fullmatch(fingerprint) is None:
            reasons.append("request-fingerprint")
        if not (1 <= len(row_context) <= 128 and row_context == row_context.strip()):
            reasons.append("context-id")
        if not (1 <= len(source_tag) <= 200 and source_tag == source_tag.strip()):
            reasons.append("source-tag")
        if not (1 <= len(speaker) <= 128 and speaker == speaker.strip()):
            reasons.append("speaker")
        if (
            deployment_event_id <= 0
            or not 0 <= entry_count <= CAPTURE_OPERATION_COUNTER_MAX
            or not 0 <= relationship_count <= CAPTURE_OPERATION_COUNTER_MAX
            or not math.isfinite(committed_at)
        ):
            reasons.append("numeric-envelope")
        if len(raw_result.encode("utf-8")) > CAPTURE_OPERATION_RESULT_JSON_MAX_BYTES:
            reasons.append("result-json-size")
        if not isinstance(envelope, dict):
            reasons.append("result-json")
            return reasons
        if set(envelope) != CAPTURE_OPERATION_ENVELOPE_KEYS:
            reasons.append("result-envelope-keys")
        if (
            type(envelope.get("capture_id")) is not str
            or type(envelope.get("protocol")) is not str
            or type(envelope.get("request_fingerprint")) is not str
            or type(envelope.get("context_id")) is not str
            or type(envelope.get("source_tag")) is not str
            or type(envelope.get("speaker")) is not str
            or type(envelope.get("entry_count")) is not int
            or type(envelope.get("relationship_count")) is not int
            or not isinstance(envelope.get("committed_at"), (int, float))
            or isinstance(envelope.get("committed_at"), bool)
            or not math.isfinite(float(envelope.get("committed_at")))
            or abs(float(envelope.get("committed_at"))) >= 1.0e308
            or envelope.get("capture_id") != capture_id
            or envelope.get("protocol") != CAPTURE_PROTOCOL_VERSION
            or envelope.get("request_fingerprint") != fingerprint
            or envelope.get("context_id") != row_context
            or envelope.get("source_tag") != source_tag
            or envelope.get("speaker") != speaker
            or envelope.get("entry_count") != entry_count
            or envelope.get("relationship_count") != relationship_count
            or envelope.get("committed_at") != committed_at
        ):
            reasons.append("result-envelope-values")

        result = envelope.get("result")
        if not isinstance(result, dict) or set(result) != CAPTURE_OPERATION_RESULT_KEYS:
            reasons.append("result-counter-keys")
        elif (
            result.get("status") != "committed"
            or type(result.get("event_count")) is not int
            or not 0 <= result["event_count"] <= min(
                entry_count,
                CAPTURE_OPERATION_COUNTER_MAX,
            )
            or type(result.get("entry_count")) is not int
            or type(result.get("relationship_count")) is not int
            or result.get("entry_count") != entry_count
            or result.get("relationship_count") != relationship_count
        ):
            reasons.append("result-counter-values")

        deployment = envelope.get("deployment_event")
        if (
            not isinstance(deployment, dict)
            or set(deployment) != CAPTURE_OPERATION_DEPLOYMENT_HEADER_KEYS
        ):
            reasons.append("result-deployment-keys")
        else:
            event_type = deployment.get("event_type")
            source_surface = deployment.get("source_surface")
            published_at = deployment.get("published_at")
            if (
                type(deployment.get("event_id")) is not int
                or deployment.get("event_id") != deployment_event_id
                or type(deployment.get("context_id")) is not str
                or deployment.get("context_id") != row_context
                or type(event_type) is not str
                or not 1 <= len(event_type) <= 200
                or event_type != event_type.strip()
                or type(source_surface) is not str
                or not 1 <= len(source_surface) <= 200
                or source_surface != source_surface.strip()
                or not isinstance(published_at, (int, float))
                or isinstance(published_at, bool)
                or not math.isfinite(float(published_at))
                or abs(float(published_at)) >= 1.0e308
            ):
                reasons.append("result-deployment-values")
            if live_event is not None and (
                live_event.get("context_id") != row_context
                or event_type != live_event.get("event_type")
                or source_surface != live_event.get("source_surface")
                or published_at != live_event.get("published_at")
            ):
                reasons.append("deployment-live-parity")
        try:
            if _capture_json_dumps(envelope, field="result_json") != raw_result:
                reasons.append("result-json-not-canonical")
        except ValueError:
            reasons.append("result-json-not-canonical")
        return reasons

    def _capture_operation_is_legacy_full_receipt(
        self,
        row: sqlite3.Row,
        envelope: Any,
        raw_result: str,
    ) -> bool:
        """Recognize the exact pre-privacy v2 envelope without blessing tampering."""

        if not isinstance(envelope, dict) or set(envelope) != CAPTURE_OPERATION_ENVELOPE_KEYS:
            return False
        try:
            canonical = _capture_json_dumps(envelope, field="result_json")
        except ValueError:
            return False
        if canonical != raw_result:
            return False
        if (
            envelope.get("capture_id") != str(row["capture_id"])
            or envelope.get("protocol") != CAPTURE_PROTOCOL_VERSION
            or envelope.get("request_fingerprint") != str(row["request_fingerprint"])
            or envelope.get("context_id") != str(row["context_id"])
            or envelope.get("source_tag") != str(row["source_tag"])
            or envelope.get("speaker") != str(row["speaker"])
            or envelope.get("entry_count") != int(row["entry_count"])
            or envelope.get("relationship_count") != int(row["relationship_count"])
            or envelope.get("committed_at") != float(row["committed_at"])
            or not isinstance(envelope.get("result"), dict)
        ):
            return False
        deployment = envelope.get("deployment_event")
        return bool(
            isinstance(deployment, dict)
            and set(deployment) == CAPTURE_OPERATION_LEGACY_DEPLOYMENT_KEYS
            and deployment.get("event_id") == int(row["deployment_event_id"])
            and deployment.get("context_id") == str(row["context_id"])
        )

    def _scrub_legacy_capture_operation_receipts(
        self,
        conn: sqlite3.Connection,
    ) -> int:
        rows = conn.execute(
            """
            SELECT
                operation.*,
                event.context_id AS live_event_context_id,
                event.event_type AS live_event_type,
                event.source_surface AS live_event_source_surface,
                event.created_at AS live_event_published_at
            FROM capture_operations AS operation
            LEFT JOIN agent_context_events AS event
              ON event.event_id = operation.deployment_event_id
            ORDER BY operation.committed_at, operation.capture_id
            """
        ).fetchall()
        scrubbed = 0
        for row in rows:
            raw_result = str(row["result_json"])
            try:
                envelope = json.loads(raw_result)
            except (TypeError, json.JSONDecodeError):
                continue
            if not self._capture_operation_receipt_reasons(
                row,
                envelope,
                raw_result,
            ):
                continue
            if not self._capture_operation_is_legacy_full_receipt(
                row,
                envelope,
                raw_result,
            ):
                continue
            live_event = self._capture_operation_live_event(row)
            legacy_deployment = envelope["deployment_event"]
            legacy_result = envelope["result"]
            event_type = (
                str(live_event["event_type"])
                if live_event is not None
                else str(legacy_deployment.get("event_type") or "unknown")
            )
            source_surface = (
                str(live_event["source_surface"])
                if live_event is not None
                else str(legacy_deployment.get("source_surface") or "unknown")
            )
            published_at = (
                float(live_event["published_at"])
                if live_event is not None
                else legacy_deployment.get(
                    "published_at",
                    legacy_deployment.get("created_at", row["committed_at"]),
                )
            )
            legacy_event_count = legacy_result.get("event_count", 0)
            if (
                type(legacy_event_count) is not int
                or not 0 <= legacy_event_count <= min(
                    int(row["entry_count"]),
                    CAPTURE_OPERATION_COUNTER_MAX,
                )
            ):
                legacy_event_count = 0
            _, private_json = self._build_private_capture_operation_receipt(
                capture_id=str(row["capture_id"]),
                request_fingerprint=str(row["request_fingerprint"]),
                context_id=str(row["context_id"]),
                source_tag=str(row["source_tag"]),
                speaker=str(row["speaker"]),
                deployment_event_id=int(row["deployment_event_id"]),
                deployment_event_type=event_type,
                deployment_source_surface=source_surface,
                deployment_published_at=published_at,
                event_count=legacy_event_count,
                entry_count=int(row["entry_count"]),
                relationship_count=int(row["relationship_count"]),
                committed_at=float(row["committed_at"]),
            )
            conn.execute(
                "UPDATE capture_operations SET result_json = ? WHERE capture_id = ?",
                (private_json, str(row["capture_id"])),
            )
            scrubbed += 1
        return scrubbed

    def _capture_operation_integrity_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
        sample_limit: int = 10,
    ) -> tuple[int, list[dict[str, Any]]]:
        params: tuple[Any, ...] = ()
        where = ""
        if context_id is not None:
            where = "WHERE operation.context_id = ?"
            params = (str(context_id),)
        rows = conn.execute(
            f"""
            SELECT
                operation.*,
                event.context_id AS live_event_context_id,
                event.event_type AS live_event_type,
                event.source_surface AS live_event_source_surface,
                event.created_at AS live_event_published_at
            FROM capture_operations AS operation
            LEFT JOIN agent_context_events AS event
              ON event.event_id = operation.deployment_event_id
            {where}
            ORDER BY operation.committed_at, operation.capture_id
            """,
            params,
        ).fetchall()
        error_count = 0
        samples: list[dict[str, Any]] = []
        for row in rows:
            raw_result = str(row["result_json"])
            try:
                envelope = json.loads(raw_result)
            except (TypeError, json.JSONDecodeError):
                envelope = None
            reasons = self._capture_operation_receipt_reasons(
                row,
                envelope,
                raw_result,
                live_event=self._capture_operation_live_event(row),
            )
            if reasons:
                error_count += 1
                if len(samples) < max(0, int(sample_limit)):
                    samples.append(
                        {
                            "capture_id": str(row["capture_id"]),
                            "reasons": sorted(set(reasons)),
                        }
                    )
        return error_count, samples

    def _context_delivery_v2_table_errors(
        self,
        conn: sqlite3.Connection,
        *,
        table_names: Iterable[str] | None = None,
    ) -> list[str]:
        requested = tuple(
            table_names
            or (
                "agent_context_deliveries",
                "agent_context_delivery_receipts",
                "agent_context_delivery_ack_tombstones",
            )
        )
        errors: list[str] = []
        for table_name in requested:
            expected_columns = CONTEXT_DELIVERY_V2_COLUMN_SIGNATURES[table_name]
            schema_row = conn.execute(
                "SELECT type, sql FROM sqlite_master WHERE name = ?",
                (table_name,),
            ).fetchone()
            if schema_row is None or str(schema_row["type"]) != "table":
                errors.append(f"{table_name}:missing-table")
                continue
            actual_columns = tuple(
                (
                    str(row["name"]),
                    str(row["type"]).upper(),
                    int(row["notnull"]),
                    None if row["dflt_value"] is None else str(row["dflt_value"]),
                    int(row["pk"]),
                )
                for row in conn.execute(
                    f'PRAGMA table_info("{table_name}")'
                ).fetchall()
            )
            if actual_columns != expected_columns:
                errors.append(f"{table_name}:column-signature")

            actual_foreign_keys = {
                (
                    str(row["table"]),
                    str(row["from"]),
                    str(row["to"]),
                    str(row["on_delete"]).upper(),
                )
                for row in conn.execute(
                    f'PRAGMA foreign_key_list("{table_name}")'
                ).fetchall()
            }
            if actual_foreign_keys != CONTEXT_DELIVERY_V2_FOREIGN_KEYS[table_name]:
                errors.append(f"{table_name}:foreign-key-signature")

            actual_unique_keys: set[tuple[str, ...]] = set()
            for index_row in conn.execute(
                f'PRAGMA index_list("{table_name}")'
            ).fetchall():
                if int(index_row["unique"]) != 1:
                    continue
                index_name = str(index_row["name"])
                actual_unique_keys.add(
                    tuple(
                        str(column_row["name"])
                        for column_row in conn.execute(
                            f'PRAGMA index_info("{index_name}")'
                        ).fetchall()
                    )
                )
            if actual_unique_keys != CONTEXT_DELIVERY_V2_UNIQUE_KEYS[table_name]:
                errors.append(f"{table_name}:unique-key-signature")

            normalized_sql = self._normalized_schema_sql(str(schema_row["sql"] or ""))
            for fragment in CONTEXT_DELIVERY_V2_CHECK_FRAGMENTS[table_name]:
                if self._normalized_schema_sql(fragment) not in normalized_sql:
                    errors.append(f"{table_name}:constraint-sql")
                    break
        return errors

    def _context_delivery_v2_index_errors(
        self,
        conn: sqlite3.Connection,
    ) -> list[str]:
        errors: list[str] = []
        for index_name, (parent_table, expected_columns) in (
            CONTEXT_DELIVERY_V2_INDEX_COLUMNS.items()
        ):
            schema_row = conn.execute(
                "SELECT type, tbl_name FROM sqlite_master WHERE name = ?",
                (index_name,),
            ).fetchone()
            if (
                schema_row is None
                or str(schema_row["type"]) != "index"
                or str(schema_row["tbl_name"]) != parent_table
            ):
                errors.append(f"{index_name}:missing-or-wrong-parent")
                continue
            actual_columns = tuple(
                str(row["name"])
                for row in conn.execute(
                    f'PRAGMA index_info("{index_name}")'
                ).fetchall()
            )
            list_row = next(
                (
                    row
                    for row in conn.execute(
                        f'PRAGMA index_list("{parent_table}")'
                    ).fetchall()
                    if str(row["name"]) == index_name
                ),
                None,
            )
            if (
                actual_columns != expected_columns
                or list_row is None
                or int(list_row["unique"]) != 0
                or int(list_row["partial"]) != 0
            ):
                errors.append(f"{index_name}:index-signature")
        parent_index_name, parent_table, parent_columns = (
            CONTEXT_DELIVERY_V2_PARENT_INDEX
        )
        parent_schema_row = conn.execute(
            "SELECT type, tbl_name FROM sqlite_master WHERE name = ?",
            (parent_index_name,),
        ).fetchone()
        parent_list_row = next(
            (
                row
                for row in conn.execute(
                    f'PRAGMA index_list("{parent_table}")'
                ).fetchall()
                if str(row["name"]) == parent_index_name
            ),
            None,
        )
        parent_actual_columns = tuple(
            str(row["name"])
            for row in conn.execute(
                f'PRAGMA index_info("{parent_index_name}")'
            ).fetchall()
        )
        if (
            parent_schema_row is None
            or str(parent_schema_row["type"]) != "index"
            or str(parent_schema_row["tbl_name"]) != parent_table
            or parent_actual_columns != parent_columns
            or parent_list_row is None
            or int(parent_list_row["unique"]) != 1
            or int(parent_list_row["partial"]) != 0
        ):
            errors.append(f"{parent_index_name}:index-signature")
        return errors

    @staticmethod
    def _context_delivery_identifier_is_valid(value: Any) -> bool:
        text = value if isinstance(value, str) else ""
        return bool(
            1 <= len(text) <= 160
            and text == text.strip()
            and re.fullmatch(r"[A-Za-z0-9_.:@-]+", text)
        )

    @staticmethod
    def _context_event_context_id_is_valid(value: Any) -> bool:
        text = value if isinstance(value, str) else ""
        return bool(1 <= len(text) <= 128 and text == text.strip())

    @staticmethod
    def _context_event_public_label_is_valid(value: Any) -> bool:
        try:
            validate_public_identifier(
                value,
                field="context event label",
                max_chars=128,
            )
        except ValueError:
            return False
        return True

    @staticmethod
    def _context_event_summary_is_valid(value: Any) -> bool:
        text = value if isinstance(value, str) else ""
        return bool(
            text.strip()
            and any(
                not character.isspace()
                and not unicodedata.category(character).startswith("C")
                for character in text
            )
        )

    @staticmethod
    def _context_delivery_receipt_id_is_valid(value: Any) -> bool:
        text = value if isinstance(value, str) else ""
        return bool(re.fullmatch(r"ctxrcpt_[A-Za-z0-9_-]{43}", text))

    @staticmethod
    def _context_delivery_owner_is_valid(value: Any) -> bool:
        text = value if isinstance(value, str) else ""
        return bool(
            1 <= len(text) <= 256
            and text == text.strip()
            and all(0x20 <= ord(character) <= 0x7E for character in text)
        )

    @staticmethod
    def _context_delivery_timestamp_is_valid(value: Any) -> bool:
        return bool(
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and abs(float(value)) < 1.0e308
        )

    @staticmethod
    def _context_delivery_integer_is_valid(value: Any, *, minimum: int = 1) -> bool:
        return bool(
            isinstance(value, int)
            and not isinstance(value, bool)
            and int(value) >= int(minimum)
        )

    def _context_delivery_live_data_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
        sample_limit: int = 10,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Audit live delivery and receipt rows without trusting their schema.

        SQLite CHECK constraints protect normal writers, but maintenance tools
        and old schema versions can bypass them.  This read-time audit is the
        fail-closed boundary used by both startup migration and health.  It
        deliberately hashes receipt identifiers in samples because they are
        bearer acknowledgement capabilities.
        """

        context = None if context_id is None else str(context_id)
        deliveries = conn.execute(
            """
            SELECT *
            FROM agent_context_deliveries
            WHERE (? IS NULL OR context_id = ?)
            ORDER BY context_id, agent_id, event_id, delivery_id
            """,
            (context, context),
        ).fetchall()
        if context is None:
            receipts = conn.execute(
                """
                SELECT *
                FROM agent_context_delivery_receipts
                ORDER BY delivery_id, attempt_number, receipt_id
                """
            ).fetchall()
        else:
            receipts = conn.execute(
                """
                SELECT receipt.*
                FROM agent_context_delivery_receipts AS receipt
                JOIN agent_context_deliveries AS delivery
                  ON delivery.delivery_id = receipt.delivery_id
                WHERE delivery.context_id = ?
                ORDER BY receipt.delivery_id, receipt.attempt_number,
                         receipt.receipt_id
                """,
                (context,),
            ).fetchall()

        findings: list[dict[str, Any]] = []
        bounded_sample_limit = min(max(int(sample_limit), 1), 100)

        def add_finding(payload: dict[str, Any]) -> None:
            findings.append(payload)

        def receipt_digest(value: Any) -> str:
            return self._context_delivery_receipt_digest(
                value if isinstance(value, str) else ""
            )

        receipts_by_delivery: dict[str, list[sqlite3.Row]] = {}
        receipts_by_id: dict[str, list[sqlite3.Row]] = {}
        for receipt in receipts:
            delivery_key = (
                receipt["delivery_id"]
                if isinstance(receipt["delivery_id"], str)
                else ""
            )
            receipt_key = (
                receipt["receipt_id"]
                if isinstance(receipt["receipt_id"], str)
                else ""
            )
            receipts_by_delivery.setdefault(delivery_key, []).append(receipt)
            receipts_by_id.setdefault(receipt_key, []).append(receipt)

            errors: list[str] = []
            if not self._context_delivery_receipt_id_is_valid(receipt["receipt_id"]):
                errors.append("receipt-id-format")
            if not self._context_delivery_identifier_is_valid(receipt["delivery_id"]):
                errors.append("delivery-id-format")
            if not self._context_delivery_integer_is_valid(
                receipt["attempt_number"]
            ):
                errors.append("attempt-number")
            if not self._context_delivery_owner_is_valid(
                receipt["consumer_instance_id"]
            ):
                errors.append("consumer-instance-id")

            state = receipt["state"] if isinstance(receipt["state"], str) else ""
            if state not in {
                "leased",
                "acknowledged",
                "expired",
                "released",
                "cancelled",
            }:
                errors.append("state")
            required_timestamps = {
                "leased-at": receipt["leased_at"],
                "lease-expires-at": receipt["lease_expires_at"],
                "created-at": receipt["created_at"],
                "updated-at": receipt["updated_at"],
            }
            invalid_required = {
                label
                for label, value in required_timestamps.items()
                if not self._context_delivery_timestamp_is_valid(value)
            }
            errors.extend(sorted(invalid_required))
            if not invalid_required:
                created_at = float(receipt["created_at"])
                leased_at = float(receipt["leased_at"])
                lease_expires_at = float(receipt["lease_expires_at"])
                updated_at = float(receipt["updated_at"])
                if created_at > leased_at:
                    errors.append("created-after-leased")
                if leased_at > lease_expires_at:
                    errors.append("leased-after-expiry")
                if created_at > updated_at:
                    errors.append("created-after-updated")

            acknowledged_at = receipt["acknowledged_at"]
            released_at = receipt["released_at"]
            if acknowledged_at is not None and not (
                self._context_delivery_timestamp_is_valid(acknowledged_at)
            ):
                errors.append("acknowledged-at")
            if released_at is not None and not (
                self._context_delivery_timestamp_is_valid(released_at)
            ):
                errors.append("released-at")
            if state in {"leased", "expired"}:
                if acknowledged_at is not None or released_at is not None:
                    errors.append("nonterminal-state-timestamps")
                if (
                    state == "expired"
                    and not invalid_required
                    and float(receipt["lease_expires_at"])
                    > float(receipt["updated_at"])
                ):
                    errors.append("expired-before-lease-expiry")
            elif state == "acknowledged":
                if acknowledged_at is None or released_at is not None:
                    errors.append("acknowledged-state-timestamps")
            elif state == "released":
                if acknowledged_at is not None or released_at is None:
                    errors.append("released-state-timestamps")
            elif state == "cancelled" and acknowledged_at is not None:
                errors.append("cancelled-state-timestamps")

            if not invalid_required:
                leased_at = float(receipt["leased_at"])
                lease_expires_at = float(receipt["lease_expires_at"])
                updated_at = float(receipt["updated_at"])
                if self._context_delivery_timestamp_is_valid(acknowledged_at):
                    acknowledgement = float(acknowledged_at)
                    if not leased_at <= acknowledgement <= lease_expires_at:
                        errors.append("acknowledgement-outside-lease")
                    if acknowledgement > updated_at:
                        errors.append("acknowledged-after-updated")
                if self._context_delivery_timestamp_is_valid(released_at):
                    release = float(released_at)
                    if not leased_at <= release <= lease_expires_at:
                        errors.append("release-outside-lease")
                    if release > updated_at:
                        errors.append("released-after-updated")

            if errors:
                add_finding(
                    {
                        "kind": "receipt-row",
                        "delivery_id": delivery_key,
                        "attempt_number": (
                            int(receipt["attempt_number"])
                            if self._context_delivery_integer_is_valid(
                                receipt["attempt_number"]
                            )
                            else 0
                        ),
                        "receipt_digest": receipt_digest(receipt["receipt_id"]),
                        "errors": sorted(set(errors)),
                    }
                )

        delivery_ids = {
            row["delivery_id"] if isinstance(row["delivery_id"], str) else ""
            for row in deliveries
        }
        if context is None:
            for delivery_key, grouped_receipts in receipts_by_delivery.items():
                if delivery_key not in delivery_ids:
                    for receipt in grouped_receipts:
                        add_finding(
                            {
                                "kind": "orphan-receipt",
                                "delivery_id": delivery_key,
                                "attempt_number": (
                                    int(receipt["attempt_number"])
                                    if self._context_delivery_integer_is_valid(
                                        receipt["attempt_number"]
                                    )
                                    else 0
                                ),
                                "receipt_digest": receipt_digest(
                                    receipt["receipt_id"]
                                ),
                                "errors": ["missing-delivery"],
                            }
                        )

        for delivery in deliveries:
            errors: list[str] = []
            delivery_key = (
                delivery["delivery_id"]
                if isinstance(delivery["delivery_id"], str)
                else ""
            )
            current_receipt_id = (
                delivery["current_receipt_id"]
                if isinstance(delivery["current_receipt_id"], str)
                else ""
            )
            if not self._context_delivery_identifier_is_valid(delivery["delivery_id"]):
                errors.append("delivery-id-format")
            raw_context_id = (
                delivery["context_id"]
                if isinstance(delivery["context_id"], str)
                else ""
            )
            if not (
                1 <= len(raw_context_id) <= 128
                and raw_context_id == raw_context_id.strip()
            ):
                errors.append("context-id")
            raw_agent_id = (
                delivery["agent_id"]
                if isinstance(delivery["agent_id"], str)
                else ""
            )
            if not (
                1 <= len(raw_agent_id) <= 128
                and raw_agent_id == self._normalize_delivery_agent_id(raw_agent_id)
            ):
                errors.append("agent-id")
            if not self._context_delivery_integer_is_valid(delivery["event_id"]):
                errors.append("event-id")
            if not self._context_delivery_integer_is_valid(
                delivery["attempt_count"]
            ):
                errors.append("attempt-count")
            if not self._context_delivery_receipt_id_is_valid(current_receipt_id):
                errors.append("current-receipt-id-format")
            if not self._context_delivery_owner_is_valid(delivery["lease_owner"]):
                errors.append("lease-owner")

            state = delivery["state"] if isinstance(delivery["state"], str) else ""
            if state not in {"leased", "acknowledged", "dead_letter"}:
                errors.append("state")
            required_timestamps = {
                "first-delivered-at": delivery["first_delivered_at"],
                "last-delivered-at": delivery["last_delivered_at"],
                "lease-expires-at": delivery["lease_expires_at"],
                "created-at": delivery["created_at"],
                "updated-at": delivery["updated_at"],
            }
            invalid_required = {
                label
                for label, value in required_timestamps.items()
                if not self._context_delivery_timestamp_is_valid(value)
            }
            errors.extend(sorted(invalid_required))
            if not invalid_required:
                created_at = float(delivery["created_at"])
                first_delivered_at = float(delivery["first_delivered_at"])
                last_delivered_at = float(delivery["last_delivered_at"])
                lease_expires_at = float(delivery["lease_expires_at"])
                updated_at = float(delivery["updated_at"])
                if created_at > first_delivered_at:
                    errors.append("created-after-first-delivery")
                if first_delivered_at > last_delivered_at:
                    errors.append("first-after-last-delivery")
                if last_delivered_at > updated_at:
                    errors.append("last-delivery-after-updated")
                if last_delivered_at > lease_expires_at:
                    errors.append("last-delivery-after-expiry")

            acknowledged_at = delivery["acknowledged_at"]
            cancelled_at = delivery["cancelled_at"]
            if acknowledged_at is not None and not (
                self._context_delivery_timestamp_is_valid(acknowledged_at)
            ):
                errors.append("acknowledged-at")
            if cancelled_at is not None and not (
                self._context_delivery_timestamp_is_valid(cancelled_at)
            ):
                errors.append("cancelled-at")
            if state == "leased":
                if acknowledged_at is not None or cancelled_at is not None:
                    errors.append("leased-state-timestamps")
            elif state == "acknowledged":
                if acknowledged_at is None or cancelled_at is not None:
                    errors.append("acknowledged-state-timestamps")
            elif state == "dead_letter":
                if acknowledged_at is not None or cancelled_at is None:
                    errors.append("cancelled-state-timestamps")

            if not invalid_required:
                last_delivered_at = float(delivery["last_delivered_at"])
                lease_expires_at = float(delivery["lease_expires_at"])
                updated_at = float(delivery["updated_at"])
                if self._context_delivery_timestamp_is_valid(acknowledged_at):
                    acknowledgement = float(acknowledged_at)
                    if not last_delivered_at <= acknowledgement <= lease_expires_at:
                        errors.append("acknowledgement-outside-lease")
                    if acknowledgement > updated_at:
                        errors.append("acknowledged-after-updated")
                if self._context_delivery_timestamp_is_valid(cancelled_at):
                    cancellation = float(cancelled_at)
                    if cancellation < last_delivered_at:
                        errors.append("cancelled-before-last-delivery")
                    if cancellation > updated_at:
                        errors.append("cancelled-after-updated")

            current_matches = receipts_by_id.get(current_receipt_id, [])
            current_receipt = current_matches[0] if len(current_matches) == 1 else None
            if current_receipt is None:
                errors.append(
                    "current-receipt-missing"
                    if not current_matches
                    else "current-receipt-ambiguous"
                )
            else:
                if current_receipt["delivery_id"] != delivery["delivery_id"]:
                    errors.append("current-receipt-wrong-delivery")
                if current_receipt["attempt_number"] != delivery["attempt_count"]:
                    errors.append("current-receipt-wrong-attempt")
                if current_receipt["consumer_instance_id"] != delivery["lease_owner"]:
                    errors.append("current-receipt-owner-mismatch")

                current_receipt_state = (
                    current_receipt["state"]
                    if isinstance(current_receipt["state"], str)
                    else ""
                )
                if state == "acknowledged":
                    if current_receipt_state != "acknowledged":
                        errors.append("current-receipt-state")
                    elif (
                        self._context_delivery_timestamp_is_valid(acknowledged_at)
                        and self._context_delivery_timestamp_is_valid(
                            current_receipt["acknowledged_at"]
                        )
                        and not math.isclose(
                            float(acknowledged_at),
                            float(current_receipt["acknowledged_at"]),
                            rel_tol=0.0,
                            abs_tol=0.000001,
                        )
                    ):
                        errors.append("acknowledged-time-mismatch")
                elif state == "leased":
                    if current_receipt_state not in {
                        "leased",
                        "expired",
                        "released",
                    }:
                        errors.append("current-receipt-state")
                    elif current_receipt_state == "released":
                        if (
                            self._context_delivery_timestamp_is_valid(
                                current_receipt["released_at"]
                            )
                            and self._context_delivery_timestamp_is_valid(
                                delivery["lease_expires_at"]
                            )
                            and not math.isclose(
                                float(current_receipt["released_at"]),
                                float(delivery["lease_expires_at"]),
                                rel_tol=0.0,
                                abs_tol=0.000001,
                            )
                        ):
                            errors.append("release-time-mismatch")
                    elif (
                        self._context_delivery_timestamp_is_valid(
                            current_receipt["lease_expires_at"]
                        )
                        and self._context_delivery_timestamp_is_valid(
                            delivery["lease_expires_at"]
                        )
                        and not math.isclose(
                            float(current_receipt["lease_expires_at"]),
                            float(delivery["lease_expires_at"]),
                            rel_tol=0.0,
                            abs_tol=0.000001,
                        )
                    ):
                        errors.append("lease-expiry-mismatch")
                elif state == "dead_letter":
                    if current_receipt_state != "cancelled":
                        errors.append("current-receipt-state")

                if (
                    self._context_delivery_timestamp_is_valid(
                        current_receipt["leased_at"]
                    )
                    and self._context_delivery_timestamp_is_valid(
                        delivery["last_delivered_at"]
                    )
                    and not math.isclose(
                        float(current_receipt["leased_at"]),
                        float(delivery["last_delivered_at"]),
                        rel_tol=0.0,
                        abs_tol=0.000001,
                    )
                ):
                    errors.append("last-delivery-time-mismatch")

            if errors:
                add_finding(
                    {
                        "kind": "delivery-row",
                        "delivery_id": delivery_key,
                        "context_id": raw_context_id,
                        "agent_id": raw_agent_id,
                        "event_id": (
                            int(delivery["event_id"])
                            if self._context_delivery_integer_is_valid(
                                delivery["event_id"]
                            )
                            else 0
                        ),
                        "attempt_count": (
                            int(delivery["attempt_count"])
                            if self._context_delivery_integer_is_valid(
                                delivery["attempt_count"]
                            )
                            else 0
                        ),
                        "current_receipt_digest": receipt_digest(
                            current_receipt_id
                        ),
                        "errors": sorted(set(errors)),
                    }
                )

        return len(findings), findings[:bounded_sample_limit]

    def _context_delivery_data_errors(
        self,
        conn: sqlite3.Connection,
    ) -> list[str]:
        errors: list[str] = []
        live_integrity_error_count, _ = self._context_delivery_live_data_audit(conn)
        if live_integrity_error_count:
            errors.append(
                f"live-delivery-integrity-error:{live_integrity_error_count}"
            )
        context_mismatch_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries AS delivery
                LEFT JOIN agent_context_events AS event
                  ON event.event_id = delivery.event_id
                 AND event.context_id = delivery.context_id
                WHERE event.event_id IS NULL
                """
            ).fetchone()[0]
        )
        current_receipt_mismatch_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries AS delivery
                LEFT JOIN agent_context_delivery_receipts AS receipt
                  ON receipt.receipt_id = delivery.current_receipt_id
                 AND receipt.delivery_id = delivery.delivery_id
                 AND receipt.attempt_number = delivery.attempt_count
                WHERE receipt.receipt_id IS NULL
                """
            ).fetchone()[0]
        )
        delivery_receipt_state_mismatch_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries AS delivery
                JOIN agent_context_delivery_receipts AS receipt
                  ON receipt.receipt_id = delivery.current_receipt_id
                WHERE NOT (
                    (
                        delivery.state = 'acknowledged'
                        AND receipt.state = 'acknowledged'
                        AND delivery.acknowledged_at IS NOT NULL
                        AND receipt.acknowledged_at IS NOT NULL
                    )
                    OR (
                        delivery.state = 'leased'
                        AND (
                            (
                                receipt.state = 'leased'
                                AND receipt.consumer_instance_id = delivery.lease_owner
                                AND ABS(
                                    receipt.lease_expires_at - delivery.lease_expires_at
                                ) < 0.000001
                            )
                            OR (
                                receipt.state IN ('expired', 'released')
                                AND delivery.lease_expires_at <= receipt.lease_expires_at
                            )
                        )
                    )
                    OR (
                        delivery.state = 'dead_letter'
                        AND receipt.state = 'cancelled'
                    )
                )
                """
            ).fetchone()[0]
        )
        if context_mismatch_count:
            errors.append(f"delivery-event-context-mismatch:{context_mismatch_count}")
        if current_receipt_mismatch_count:
            errors.append(f"current-receipt-mismatch:{current_receipt_mismatch_count}")
        if delivery_receipt_state_mismatch_count:
            errors.append(
                "delivery-receipt-state-mismatch:"
                f"{delivery_receipt_state_mismatch_count}"
            )
        receipt_history_mismatch_count, _ = (
            self._context_delivery_receipt_history_audit(conn)
        )
        if receipt_history_mismatch_count:
            errors.append(
                f"receipt-history-mismatch:{receipt_history_mismatch_count}"
            )
        cursor_mismatch_count = len(self._context_delivery_cursor_mismatches(conn))
        if cursor_mismatch_count:
            errors.append(f"receipt-derived-cursor-mismatch:{cursor_mismatch_count}")
        identity_rows = conn.execute(
            """
            SELECT agent_id FROM agent_context_consumers
            UNION ALL
            SELECT agent_id FROM agent_context_deliveries
            UNION ALL
            SELECT agent_id FROM agent_context_delivery_cursors
            UNION ALL
            SELECT agent_id FROM agent_context_delivery_ack_tombstones
            """
        ).fetchall()
        noncanonical_identity_count = sum(
            1
            for row in identity_rows
            if str(row["agent_id"])
            != self._normalize_delivery_agent_id(str(row["agent_id"]))
        )
        if noncanonical_identity_count:
            errors.append(
                f"noncanonical-delivery-agent-id:{noncanonical_identity_count}"
            )
        consumer_group_integrity_error_count, _ = (
            self._context_consumer_group_integrity_audit(conn)
        )
        if consumer_group_integrity_error_count:
            errors.append(
                "consumer-group-integrity-error:"
                f"{consumer_group_integrity_error_count}"
            )
        tombstone_integrity_error_count, _ = (
            self._context_delivery_tombstone_data_audit(conn)
        )
        if tombstone_integrity_error_count:
            errors.append(
                "ack-tombstone-integrity-error:"
                f"{tombstone_integrity_error_count}"
            )
        unaudited_dead_letter_count, _ = (
            self._context_delivery_dead_letter_audit(conn)
        )
        if unaudited_dead_letter_count:
            errors.append(
                f"unaudited-dead-letter:{unaudited_dead_letter_count}"
            )
        return errors

    def _context_delivery_dead_letter_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
        sample_limit: int = 10,
    ) -> tuple[int, list[dict[str, Any]]]:
        context = None if context_id is None else str(context_id)
        rows = conn.execute(
            """
            SELECT delivery.delivery_id, delivery.context_id,
                   delivery.agent_id, delivery.event_id,
                   delivery.attempt_count, delivery.current_receipt_id,
                   delivery.cancelled_at
            FROM agent_context_deliveries AS delivery
            WHERE delivery.state = 'dead_letter'
              AND (? IS NULL OR delivery.context_id = ?)
            ORDER BY delivery.context_id, delivery.agent_id, delivery.event_id
            """,
            (context, context),
        ).fetchall()
        findings: list[dict[str, Any]] = []
        for row in rows:
            delivery_id = str(row["delivery_id"])
            audits = conn.execute(
                """
                SELECT operation_id, payload_json, created_at
                FROM store_maintenance_receipts
                WHERE operation_type = 'context-delivery-dead-letter'
                  AND context_id = ?
                  AND before_revision = ?
                  AND after_revision = 'dead_letter'
                ORDER BY created_at, operation_id
                """,
                (str(row["context_id"]), delivery_id),
            ).fetchall()
            issues: list[str] = []
            if len(audits) != 1:
                issues.append(
                    "missing-audit" if not audits else "ambiguous-audit-history"
                )
            if len(audits) == 1:
                audit = audits[0]
                payload = _decode_json(str(audit["payload_json"]), None)
                if not isinstance(payload, dict):
                    issues.append("invalid-audit-payload")
                    payload = {}
                expected_digest = self._context_delivery_receipt_digest(
                    str(row["current_receipt_id"])
                )
                if str(payload.get("agent_id") or "") != str(row["agent_id"]):
                    issues.append("agent-id-mismatch")
                try:
                    payload_event_id = int(payload.get("event_id"))
                except (TypeError, ValueError, OverflowError):
                    payload_event_id = 0
                if payload_event_id != int(row["event_id"]):
                    issues.append("event-id-mismatch")
                try:
                    payload_attempt_count = int(payload.get("attempt_count"))
                except (TypeError, ValueError, OverflowError):
                    payload_attempt_count = 0
                if payload_attempt_count != int(row["attempt_count"]):
                    issues.append("attempt-count-mismatch")
                try:
                    recorded_max_attempts = int(
                        payload.get("max_delivery_attempts")
                    )
                except (TypeError, ValueError, OverflowError):
                    recorded_max_attempts = 0
                if recorded_max_attempts < int(row["attempt_count"]):
                    issues.append("invalid-recorded-retry-budget")
                if not str(payload.get("reason") or "").strip():
                    issues.append("missing-reason")
                if str(payload.get("receipt_digest") or "") != expected_digest:
                    issues.append("receipt-digest-mismatch")
                if not str(audit["operation_id"] or "").strip():
                    issues.append("missing-operation-id")
                audit_created_at = audit["created_at"]
                dead_lettered_at = row["cancelled_at"]
                try:
                    audit_timestamp = float(audit_created_at)
                    delivery_timestamp = float(dead_lettered_at)
                except (TypeError, ValueError, OverflowError):
                    issues.append("invalid-audit-timestamp")
                else:
                    if (
                        not math.isfinite(audit_timestamp)
                        or not math.isfinite(delivery_timestamp)
                        or abs(audit_timestamp - delivery_timestamp) >= 0.000001
                    ):
                        issues.append("audit-timestamp-mismatch")
            if issues:
                findings.append(
                    {
                        "delivery_id": delivery_id,
                        "context_id": str(row["context_id"]),
                        "agent_id": str(row["agent_id"]),
                        "event_id": int(row["event_id"]),
                        "attempt_count": int(row["attempt_count"]),
                        "dead_lettered_at": row["cancelled_at"],
                        "issues": issues,
                    }
                )
        bounded_sample_limit = min(max(int(sample_limit), 1), 100)
        return len(findings), findings[:bounded_sample_limit]

    def _context_delivery_tombstone_data_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
        sample_limit: int = 10,
    ) -> tuple[int, list[dict[str, Any]]]:
        context = None if context_id is None else str(context_id)
        invalid_where = """
            (? IS NULL OR context_id = ?)
            AND (
                receipt_digest IS NULL
                OR length(receipt_digest) <> 64
                OR receipt_digest <> lower(receipt_digest)
                OR receipt_digest GLOB '*[^0-9a-f]*'
                OR typeof(delivery_id) <> 'text'
                OR length(delivery_id) NOT BETWEEN 1 AND 160
                OR delivery_id <> trim(delivery_id)
                OR delivery_id GLOB '*[^A-Za-z0-9_.:@-]*'
                OR typeof(context_id) <> 'text'
                OR length(context_id) NOT BETWEEN 1 AND 128
                OR context_id <> trim(context_id)
                OR trim(agent_id) = ''
                OR agent_id <> lower(agent_id)
                OR length(agent_id) > 128
                OR event_id < 1
                OR attempt_number < 1
                OR typeof(acknowledged_at) NOT IN ('integer', 'real')
                OR typeof(deleted_at) NOT IN ('integer', 'real')
                OR abs(acknowledged_at) >= 1.0e308
                OR abs(deleted_at) >= 1.0e308
                OR deleted_at < acknowledged_at
            )
        """
        params = (context, context)
        invalid_count = int(
            conn.execute(
                f"""
                SELECT COUNT(*)
                FROM agent_context_delivery_ack_tombstones
                WHERE {invalid_where}
                """,
                params,
            ).fetchone()[0]
        )
        duplicate_digest_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT receipt_digest
                    FROM agent_context_delivery_ack_tombstones
                    WHERE (? IS NULL OR context_id = ?)
                    GROUP BY receipt_digest
                    HAVING COUNT(*) > 1
                )
                """,
                params,
            ).fetchone()[0]
        )
        duplicate_delivery_attempt_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT delivery_id, attempt_number
                    FROM agent_context_delivery_ack_tombstones
                    WHERE (? IS NULL OR context_id = ?)
                    GROUP BY delivery_id, attempt_number
                    HAVING COUNT(*) > 1
                )
                """,
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""
            SELECT receipt_digest, delivery_id, context_id, agent_id,
                   event_id, attempt_number, acknowledged_at, deleted_at
            FROM agent_context_delivery_ack_tombstones
            WHERE {invalid_where}
            ORDER BY deleted_at, receipt_digest
            LIMIT ?
            """,
            (*params, min(max(int(sample_limit), 1), 100)),
        ).fetchall()
        samples = [
            {
                "receipt_digest": str(row["receipt_digest"] or ""),
                "delivery_id": str(row["delivery_id"] or ""),
                "context_id": str(row["context_id"] or ""),
                "agent_id": str(row["agent_id"] or ""),
                "event_id": int(row["event_id"] or 0),
                "attempt_number": int(row["attempt_number"] or 0),
                "acknowledged_at": row["acknowledged_at"],
                "deleted_at": row["deleted_at"],
            }
            for row in rows
        ]
        if duplicate_digest_count:
            samples.append({"duplicate_receipt_digest_groups": duplicate_digest_count})
        if duplicate_delivery_attempt_count:
            samples.append(
                {
                    "duplicate_delivery_attempt_groups": (
                        duplicate_delivery_attempt_count
                    )
                }
            )
        return (
            invalid_count
            + duplicate_digest_count
            + duplicate_delivery_attempt_count,
            samples[: min(max(int(sample_limit), 1), 100)],
        )

    def _canonicalize_context_delivery_identities(
        self,
        conn: sqlite3.Connection,
        *,
        updated_at: float,
    ) -> int:
        consumer_rows = conn.execute(
            """
            SELECT agent_id, consumer_kind, enabled, created_at, updated_at
            FROM agent_context_consumers
            ORDER BY agent_id
            """
        ).fetchall()
        delivery_rows = conn.execute(
            """
            SELECT delivery_id, context_id, agent_id, event_id
            FROM agent_context_deliveries
            ORDER BY delivery_id
            """
        ).fetchall()
        canonical_delivery_keys: dict[tuple[str, str, int], str] = {}
        for row in delivery_rows:
            canonical_agent = self._normalize_delivery_agent_id(str(row["agent_id"]))
            if not canonical_agent:
                raise RuntimeError("context delivery contains an empty canonical agent id")
            key = (
                str(row["context_id"]),
                canonical_agent,
                int(row["event_id"]),
            )
            prior_delivery_id = canonical_delivery_keys.get(key)
            if prior_delivery_id is not None and prior_delivery_id != str(
                row["delivery_id"]
            ):
                raise RuntimeError(
                    "context delivery agent canonicalization would merge conflicting histories"
                )
            canonical_delivery_keys[key] = str(row["delivery_id"])

        mappings = {
            str(row["agent_id"]): self._normalize_delivery_agent_id(
                str(row["agent_id"])
            )
            for row in consumer_rows
        }
        for row in delivery_rows:
            raw_agent = str(row["agent_id"])
            mappings.setdefault(
                raw_agent,
                self._normalize_delivery_agent_id(raw_agent),
            )
        tombstone_agents = [
            str(row["agent_id"])
            for row in conn.execute(
                "SELECT DISTINCT agent_id FROM agent_context_delivery_ack_tombstones"
            ).fetchall()
        ]
        for raw_agent in tombstone_agents:
            mappings.setdefault(
                raw_agent,
                self._normalize_delivery_agent_id(raw_agent),
            )
        changed = {raw: canonical for raw, canonical in mappings.items() if raw != canonical}
        if not changed:
            return 0

        consumer_by_agent = {str(row["agent_id"]): row for row in consumer_rows}
        groups_by_agent: dict[str, set[str]] = {}
        for row in conn.execute(
            "SELECT agent_id, group_id FROM agent_context_consumer_groups"
        ).fetchall():
            canonical = self._normalize_delivery_agent_id(str(row["agent_id"]))
            groups_by_agent.setdefault(canonical, set()).add(str(row["group_id"]))

        canonical_agents = sorted(set(mappings.values()))
        for canonical_agent in canonical_agents:
            if not canonical_agent:
                raise RuntimeError("context delivery contains an empty canonical agent id")
            source_rows = [
                row
                for raw_agent, row in consumer_by_agent.items()
                if self._normalize_delivery_agent_id(raw_agent) == canonical_agent
            ]
            enabled = min((int(row["enabled"]) for row in source_rows), default=1)
            created_at = min(
                (float(row["created_at"]) for row in source_rows),
                default=updated_at,
            )
            consumer_kind = (
                str(source_rows[0]["consumer_kind"])
                if source_rows
                else "migrated-v1"
            )
            conn.execute(
                """
                INSERT INTO agent_context_consumers (
                    agent_id, consumer_kind, enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    enabled = MIN(agent_context_consumers.enabled, excluded.enabled),
                    updated_at = MAX(agent_context_consumers.updated_at, excluded.updated_at)
                """,
                (
                    canonical_agent,
                    consumer_kind,
                    enabled,
                    created_at,
                    updated_at,
                ),
            )

        # Receipt history is authoritative, so derived cursors are disposable
        # during identity normalization and will be recreated on the next claim.
        conn.execute("DELETE FROM agent_context_delivery_cursors")
        for raw_agent, canonical_agent in sorted(changed.items()):
            conn.execute(
                "UPDATE agent_context_deliveries SET agent_id = ? WHERE agent_id = ?",
                (canonical_agent, raw_agent),
            )
            conn.execute(
                """
                UPDATE agent_context_delivery_ack_tombstones
                SET agent_id = ? WHERE agent_id = ?
                """,
                (canonical_agent, raw_agent),
            )
        for canonical_agent, groups in groups_by_agent.items():
            for group_id in sorted(groups):
                conn.execute(
                    """
                    INSERT OR IGNORE INTO agent_context_consumer_groups (
                        agent_id, group_id, created_at
                    ) VALUES (?, ?, ?)
                    """,
                    (canonical_agent, group_id, updated_at),
                )
        for raw_agent in sorted(changed):
            conn.execute(
                "DELETE FROM agent_context_consumer_groups WHERE agent_id = ?",
                (raw_agent,),
            )
            conn.execute(
                "DELETE FROM agent_context_consumers WHERE agent_id = ?",
                (raw_agent,),
            )
        return len(changed)

    def _derived_context_cursor_event_id(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str,
        agent_id: str,
    ) -> int:
        target_clause, target_params = self._event_target_clause(
            event_alias="event",
            agent_id=agent_id,
        )
        first_unacknowledged = conn.execute(
            f"""
            SELECT MIN(event.event_id)
            FROM agent_context_events AS event
            WHERE event.context_id = ?
              AND {target_clause}
              AND NOT EXISTS (
                  SELECT 1
                  FROM agent_context_deliveries AS delivery
                  WHERE delivery.context_id = event.context_id
                    AND delivery.agent_id = ?
                    AND delivery.event_id = event.event_id
                    AND delivery.state IN ('acknowledged', 'dead_letter')
              )
            """,
            (str(context_id), *target_params, str(agent_id)),
        ).fetchone()[0]
        if first_unacknowledged is None:
            return int(
                conn.execute(
                    """
                    SELECT COALESCE(MAX(event_id), 0)
                    FROM agent_context_events
                    WHERE context_id = ?
                    """,
                    (str(context_id),),
                ).fetchone()[0]
                or 0
            )
        return int(
            conn.execute(
                """
                SELECT COALESCE(MAX(event_id), 0)
                FROM agent_context_events
                WHERE context_id = ? AND event_id < ?
                """,
                (str(context_id), int(first_unacknowledged)),
            ).fetchone()[0]
            or 0
        )

    def _context_delivery_cursor_mismatches(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if context_id is None:
            rows = conn.execute(
                """
                SELECT context_id, agent_id, last_contiguous_event_id, updated_at
                FROM agent_context_delivery_cursors
                ORDER BY context_id, agent_id
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT context_id, agent_id, last_contiguous_event_id, updated_at
                FROM agent_context_delivery_cursors
                WHERE context_id = ?
                ORDER BY agent_id
                """,
                (str(context_id),),
            ).fetchall()
        mismatches: list[dict[str, Any]] = []
        for row in rows:
            raw_context = row["context_id"]
            raw_agent = row["agent_id"]
            raw_event_id = row["last_contiguous_event_id"]
            context = raw_context if isinstance(raw_context, str) else ""
            agent = raw_agent if isinstance(raw_agent, str) else ""
            errors: list[str] = []
            if not (
                1 <= len(context) <= 128
                and context == context.strip()
            ):
                errors.append("context-id")
            if not (
                1 <= len(agent) <= 128
                and agent == self._normalize_delivery_agent_id(agent)
            ):
                errors.append("agent-id")
            if not (
                isinstance(raw_event_id, int)
                and not isinstance(raw_event_id, bool)
                and raw_event_id >= 0
            ):
                errors.append("last-contiguous-event-id")
                stored: int | None = None
            else:
                stored = int(raw_event_id)
            if not self._context_delivery_timestamp_is_valid(row["updated_at"]):
                errors.append("updated-at")
            derived: int | None = None
            if "context-id" not in errors and "agent-id" not in errors:
                derived = self._derived_context_cursor_event_id(
                    conn,
                    context_id=context,
                    agent_id=agent,
                )
            if errors or stored != derived:
                mismatches.append(
                    {
                        "context_id": context,
                        "agent_id": agent,
                        "stored_event_id": stored,
                        "derived_event_id": derived,
                        "integrity_errors": sorted(errors),
                    }
                )
        return mismatches

    def _context_delivery_receipt_history_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
        sample_limit: int = 10,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Validate that retry receipts form the delivery's fenced history."""

        context = None if context_id is None else str(context_id)
        params: tuple[Any, ...] = (context, context)
        bounded_sample_limit = min(max(int(sample_limit), 1), 100)
        cte = """
            WITH scoped_deliveries AS (
                SELECT *
                FROM agent_context_deliveries
                WHERE (? IS NULL OR context_id = ?)
            ),
            history AS (
                SELECT
                    delivery.delivery_id,
                    MIN(receipt.attempt_number) AS min_attempt,
                    MAX(receipt.attempt_number) AS max_attempt,
                    COUNT(receipt.receipt_id) AS receipt_count,
                    MAX(
                        CASE
                            WHEN receipt.attempt_number = 1
                            THEN receipt.leased_at
                            ELSE NULL
                        END
                    ) AS first_receipt_leased_at,
                    SUM(
                        CASE
                            WHEN receipt.attempt_number = 1
                             AND receipt.consumer_instance_id =
                                 'migration-v1-unclaimed'
                            THEN 1 ELSE 0
                        END
                    ) AS first_attempt_migration_count,
                    SUM(
                        CASE
                            WHEN receipt.attempt_number < delivery.attempt_count
                             AND receipt.state NOT IN (
                                 'expired', 'released'
                             )
                            THEN 1 ELSE 0
                        END
                    ) AS invalid_historical_state_count
                FROM scoped_deliveries AS delivery
                LEFT JOIN agent_context_delivery_receipts AS receipt
                  ON receipt.delivery_id = delivery.delivery_id
                GROUP BY delivery.delivery_id
            ),
            mismatches AS (
                SELECT
                    delivery.delivery_id,
                    delivery.context_id,
                    delivery.agent_id,
                    delivery.event_id,
                    delivery.attempt_count,
                    delivery.first_delivered_at,
                    history.min_attempt,
                    history.max_attempt,
                    history.receipt_count,
                    history.first_receipt_leased_at,
                    history.first_attempt_migration_count,
                    CASE
                        WHEN history.min_attempt = 1
                         AND history.first_attempt_migration_count = 0
                         AND (
                             history.first_receipt_leased_at IS NULL
                             OR history.first_receipt_leased_at <>
                                delivery.first_delivered_at
                         )
                        THEN 1 ELSE 0
                    END AS first_receipt_anchor_mismatch,
                    history.invalid_historical_state_count
                FROM scoped_deliveries AS delivery
                JOIN history ON history.delivery_id = delivery.delivery_id
                WHERE history.receipt_count < 1
                   OR history.min_attempt < 1
                   OR history.max_attempt <> delivery.attempt_count
                   OR history.receipt_count <>
                      (history.max_attempt - history.min_attempt + 1)
                   OR COALESCE(history.invalid_historical_state_count, 0) > 0
                   OR (
                       history.min_attempt = 1
                       AND history.first_attempt_migration_count = 0
                       AND (
                           history.first_receipt_leased_at IS NULL
                           OR history.first_receipt_leased_at <>
                              delivery.first_delivered_at
                       )
                   )
                   OR (
                       history.min_attempt > 1
                       AND NOT EXISTS (
                           SELECT 1
                           FROM agent_context_delivery_receipts AS first_receipt
                           WHERE first_receipt.delivery_id = delivery.delivery_id
                             AND first_receipt.attempt_number = history.min_attempt
                             AND first_receipt.consumer_instance_id =
                                 'migration-v1-unclaimed'
                       )
                   )
            )
        """
        structural_count = int(
            conn.execute(
                cte + "SELECT COUNT(*) FROM mismatches",
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            cte
            + """
              SELECT * FROM mismatches
              ORDER BY context_id, agent_id, event_id
              LIMIT ?
              """,
            (*params, bounded_sample_limit),
        ).fetchall()
        structural_samples = [
            {
                "delivery_id": str(row["delivery_id"]),
                "context_id": str(row["context_id"]),
                "agent_id": str(row["agent_id"]),
                "event_id": int(row["event_id"]),
                "attempt_count": int(row["attempt_count"]),
                "min_receipt_attempt": (
                    None
                    if row["min_attempt"] is None
                    else int(row["min_attempt"])
                ),
                "max_receipt_attempt": (
                    None
                    if row["max_attempt"] is None
                    else int(row["max_attempt"])
                ),
                "receipt_count": int(row["receipt_count"]),
                "first_delivered_at": float(row["first_delivered_at"]),
                "first_receipt_leased_at": (
                    None
                    if row["first_receipt_leased_at"] is None
                    else float(row["first_receipt_leased_at"])
                ),
                "first_receipt_anchor_mismatch": bool(
                    row["first_receipt_anchor_mismatch"]
                ),
                "invalid_historical_state_count": int(
                    row["invalid_historical_state_count"] or 0
                ),
            }
            for row in rows
        ]
        adjacent_rows = conn.execute(
            """
            SELECT
                delivery.delivery_id,
                delivery.context_id,
                delivery.agent_id,
                delivery.event_id,
                prior.attempt_number AS prior_attempt_number,
                prior.consumer_instance_id AS prior_consumer_instance_id,
                prior.state AS prior_state,
                prior.created_at AS prior_created_at,
                prior.leased_at AS prior_leased_at,
                prior.lease_expires_at AS prior_lease_expires_at,
                prior.released_at AS prior_released_at,
                prior.updated_at AS prior_updated_at,
                next.attempt_number AS next_attempt_number,
                next.consumer_instance_id AS next_consumer_instance_id,
                next.created_at AS next_created_at,
                next.leased_at AS next_leased_at
            FROM agent_context_deliveries AS delivery
            JOIN agent_context_delivery_receipts AS prior
              ON prior.delivery_id = delivery.delivery_id
            JOIN agent_context_delivery_receipts AS next
              ON next.delivery_id = prior.delivery_id
             AND next.attempt_number = prior.attempt_number + 1
            WHERE (? IS NULL OR delivery.context_id = ?)
            ORDER BY delivery.context_id, delivery.agent_id, delivery.event_id,
                     prior.attempt_number
            """,
            params,
        ).fetchall()
        chronology_samples: list[dict[str, Any]] = []
        chronology_count = 0
        for row in adjacent_rows:
            reasons: list[str] = []
            timestamp_fields = {
                "prior-created-at": row["prior_created_at"],
                "prior-leased-at": row["prior_leased_at"],
                "prior-lease-expires-at": row["prior_lease_expires_at"],
                "prior-updated-at": row["prior_updated_at"],
                "next-created-at": row["next_created_at"],
                "next-leased-at": row["next_leased_at"],
            }
            invalid_fields = {
                label
                for label, value in timestamp_fields.items()
                if not self._context_delivery_timestamp_is_valid(value)
            }
            if invalid_fields:
                reasons.extend(sorted(invalid_fields))
            else:
                next_leased_at = float(row["next_leased_at"])
                if float(row["prior_created_at"]) > next_leased_at:
                    reasons.append("prior-created-after-next-lease")
                if float(row["prior_leased_at"]) > next_leased_at:
                    reasons.append("prior-leased-after-next-lease")
                if float(row["prior_updated_at"]) > next_leased_at:
                    reasons.append("prior-updated-after-next-lease")
                prior_state = str(row["prior_state"])
                if (
                    prior_state == "expired"
                    and float(row["prior_lease_expires_at"]) > next_leased_at
                ):
                    reasons.append("prior-expiry-after-next-lease")
                if prior_state == "released":
                    if not self._context_delivery_timestamp_is_valid(
                        row["prior_released_at"]
                    ):
                        reasons.append("prior-release-time-missing")
                    elif float(row["prior_released_at"]) > next_leased_at:
                        reasons.append("prior-release-after-next-lease")

            if not reasons:
                continue
            chronology_count += 1
            if len(chronology_samples) < bounded_sample_limit:
                chronology_samples.append(
                    {
                        "kind": "attempt-chronology",
                        "delivery_id": str(row["delivery_id"]),
                        "context_id": str(row["context_id"]),
                        "agent_id": str(row["agent_id"]),
                        "event_id": int(row["event_id"]),
                        "prior_attempt_number": int(
                            row["prior_attempt_number"]
                        ),
                        "next_attempt_number": int(row["next_attempt_number"]),
                        "prior_is_explicit_v1_migration": (
                            str(row["prior_consumer_instance_id"])
                            == "migration-v1-unclaimed"
                        ),
                        "next_is_explicit_v1_migration": (
                            str(row["next_consumer_instance_id"])
                            == "migration-v1-unclaimed"
                        ),
                        "errors": sorted(set(reasons)),
                    }
                )

        return (
            structural_count + chronology_count,
            (structural_samples + chronology_samples)[:bounded_sample_limit],
        )

    def _repair_context_delivery_cursors(
        self,
        conn: sqlite3.Connection,
        *,
        repaired_at: float,
    ) -> int:
        mismatches = self._context_delivery_cursor_mismatches(conn)
        repaired_count = 0
        for mismatch in mismatches:
            if mismatch["derived_event_id"] is None:
                raise RuntimeError(
                    "context delivery cursor identity failed integrity validation"
                )
            cursor = conn.execute(
                """
                UPDATE agent_context_delivery_cursors
                SET last_contiguous_event_id = ?, updated_at = ?
                WHERE context_id = ? AND agent_id = ?
                """,
                (
                    int(mismatch["derived_event_id"]),
                    repaired_at,
                    str(mismatch["context_id"]),
                    str(mismatch["agent_id"]),
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    "context delivery cursor changed during repair"
                )
            repaired_count += 1
        return repaired_count

    def _context_delivery_publication_receipt_inventory(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, Any]:
        """Classify repair receipts without exposing backup paths publicly."""

        rows = conn.execute(
            """
            SELECT operation_id, before_revision, after_revision,
                   payload_json, created_at
            FROM store_maintenance_receipts
            WHERE operation_type = 'context-delivery-publication-repair'
            ORDER BY created_at ASC, operation_id ASC
            """
        ).fetchall()
        pending: list[dict[str, Any]] = []
        verified: list[dict[str, Any]] = []
        invalid_count = 0
        base_fields = {
            "protocol_version",
            "verification_status",
            "cursor_mismatch_count",
            "reconciled_target_highwater",
            "target_highwater_before",
            "target_highwater_after",
            "derivation_source_sha256_after",
            "safety_backup_path",
            "safety_backup_sha256",
            "safety_backup_size_bytes",
        }
        for row in rows:
            payload = _decode_json(str(row["payload_json"]), None)
            status = (
                str(payload.get("verification_status") or "")
                if isinstance(payload, dict)
                else ""
            )
            expected_fields = (
                base_fields
                if status == "pending"
                else base_fields | {"verified_at"}
                if status == "verified"
                else set()
            )
            backup_path = (
                Path(str(payload.get("safety_backup_path") or ""))
                if isinstance(payload, dict)
                else Path()
            )
            backup_parent = (self.db_path.parent / "backups").resolve()
            payload_valid = bool(
                isinstance(payload, dict)
                and set(payload) == expected_fields
                and payload.get("protocol_version")
                == "context-delivery-publication-repair.v1"
                and type(payload.get("cursor_mismatch_count")) is int
                and int(payload["cursor_mismatch_count"]) >= 0
                and type(payload.get("reconciled_target_highwater")) is bool
                and type(payload.get("target_highwater_before")) is int
                and int(payload["target_highwater_before"]) >= 0
                and type(payload.get("target_highwater_after")) is int
                and int(payload["target_highwater_after"])
                >= int(payload["target_highwater_before"])
                and isinstance(
                    payload.get("derivation_source_sha256_after"), str
                )
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(payload["derivation_source_sha256_after"]),
                )
                is not None
                and isinstance(payload.get("safety_backup_sha256"), str)
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(payload["safety_backup_sha256"]),
                )
                is not None
                and type(payload.get("safety_backup_size_bytes")) is int
                and int(payload["safety_backup_size_bytes"]) > 0
                and backup_path.is_absolute()
                and backup_path.parent.resolve() == backup_parent
                and backup_path.name == backup_path.resolve().name
                and (
                    status != "verified"
                    or self._context_delivery_timestamp_is_valid(
                        payload.get("verified_at")
                    )
                )
            )
            operation_id = str(row["operation_id"])
            before_revision = str(row["before_revision"])
            after_revision = str(row["after_revision"])
            created_at = row["created_at"]
            row_valid = bool(
                re.fullmatch(r"s2maint_[0-9a-f]{32}", operation_id)
                and re.fullmatch(r"[0-9a-f]{64}", before_revision)
                and re.fullmatch(r"[0-9a-f]{64}", after_revision)
                and self._context_delivery_timestamp_is_valid(created_at)
            )
            if not payload_valid or not row_valid:
                invalid_count += 1
                continue
            record = {
                "operation_id": operation_id,
                "before_revision": before_revision,
                "after_revision": after_revision,
                "payload": dict(payload),
                "payload_sha256": hashlib.sha256(
                    _json_dumps(payload).encode("utf-8")
                ).hexdigest(),
                "created_at": float(created_at),
            }
            (pending if status == "pending" else verified).append(record)
        return {
            "invalid_count": invalid_count,
            "pending": pending,
            "verified": verified,
        }

    def _verify_context_delivery_publication_backup(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        backup_path = Path(str(payload["safety_backup_path"]))
        backup_sidecars = tuple(
            Path(str(backup_path) + suffix)
            for suffix in ("-wal", "-shm", "-journal")
        )

        def assert_no_backup_sidecars() -> None:
            if any(os.path.lexists(str(sidecar)) for sidecar in backup_sidecars):
                raise RuntimeError(
                    "context delivery repair backup has SQLite sidecars"
                )

        expected_parent = (self.db_path.parent / "backups").resolve()
        if backup_path.parent.resolve() != expected_parent:
            raise RuntimeError(
                "context delivery repair backup escaped its canonical directory"
            )
        assert_no_backup_sidecars()
        digest, size_bytes, metadata = self._hash_stable_regular_file(backup_path)
        if (
            digest != str(payload["safety_backup_sha256"])
            or size_bytes != int(payload["safety_backup_size_bytes"])
            or metadata.st_uid != os.getuid()
            or int(metadata.st_nlink) != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RuntimeError(
                "context delivery repair backup failed durable verification"
            )
        assert_no_backup_sidecars()
        with closing(
            sqlite3.connect(
                backup_path.as_uri() + "?mode=ro&immutable=1",
                uri=True,
            )
        ) as backup:
            quick_check = [str(row[0]) for row in backup.execute("PRAGMA quick_check")]
            integrity_check = [
                str(row[0]) for row in backup.execute("PRAGMA integrity_check")
            ]
            foreign_key_error_count = sum(
                1 for _ in backup.execute("PRAGMA foreign_key_check")
            )
        assert_no_backup_sidecars()
        if (
            quick_check != ["ok"]
            or integrity_check != ["ok"]
            or foreign_key_error_count != 0
        ):
            raise RuntimeError(
                "context delivery repair backup failed SQLite reverification"
            )
        return {
            "sha256": digest,
            "size_bytes": size_bytes,
            "quick_check": quick_check,
            "integrity_check": integrity_check,
            "foreign_key_error_count": foreign_key_error_count,
            "verified": True,
        }

    def _context_delivery_publication_repair_audit(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, Any]:
        """Classify only the derived publication state safe to rebuild offline."""

        self._validate_existing_schema_compatibility_markers(conn)
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if user_version != SQLITE_USER_VERSION:
            raise CoreAuthorityError(
                "context delivery publication repair requires authoritative v6"
            )
        self._assert_exact_schema_contract(conn, user_version=user_version)
        marker = self._core_authority_marker(conn)
        self._validate_core_authority_version_pair(conn, marker)
        if marker is None or marker.get("service_required") is not True:
            raise CoreAuthorityError(
                "context delivery publication repair requires a claimed core store"
            )

        delivery_schema_errors = self._context_delivery_v2_table_errors(conn) + (
            self._context_delivery_v2_index_errors(conn)
        )
        delivery_data_errors = self._context_delivery_data_errors(conn)
        cursor_mismatches = self._context_delivery_cursor_mismatches(conn)
        cursor_repairs_are_derived = all(
            mismatch.get("derived_event_id") is not None
            and not mismatch.get("integrity_errors")
            for mismatch in cursor_mismatches
        )
        expected_cursor_error = (
            []
            if not cursor_mismatches
            else [f"receipt-derived-cursor-mismatch:{len(cursor_mismatches)}"]
        )
        unrelated_delivery_errors = sorted(
            set(delivery_data_errors) - set(expected_cursor_error)
        )
        highwater_contract_error_count = 0
        try:
            target_highwater = self._read_context_event_target_highwater(
                conn,
                allow_missing=False,
            )
        except RuntimeError:
            target_highwater = 0
            highwater_contract_error_count = 1
        latest_event_id = int(
            conn.execute(
                "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events"
            ).fetchone()[0]
            or 0
        )
        target_reconciliation_needed = bool(
            highwater_contract_error_count == 0
            and latest_event_id > target_highwater
        )
        target_canonicalization_needed = (
            self._context_event_target_canonicalization_needed(conn)
        )
        (
            target_integrity_error_count,
            _,
            _,
            _,
        ) = self._context_event_target_integrity_audit(conn, sample_limit=1)
        event_ledger_integrity_error_count, _ = (
            self._context_event_ledger_integrity_audit(conn, sample_limit=1)
        )
        target_highwater_error_count, _ = (
            self._context_event_target_highwater_audit(conn)
        )
        repair_required = bool(
            target_reconciliation_needed or cursor_mismatches
        )
        repair_receipts = (
            self._context_delivery_publication_receipt_inventory(conn)
        )
        pending_repair_receipts = list(repair_receipts["pending"])
        repair_receipt_integrity_error_count = int(
            repair_receipts["invalid_count"]
        )
        derivation_source_sha256, derivation_source_row_count = (
            self._context_delivery_publication_derivation_digest(conn)
        )
        settled_revision_payload = {
            "schema_identity": f"sqlite-{SQLITE_APPLICATION_ID:x}-v{user_version}",
            "marker_sha256": self._core_authority_marker_sha256(marker),
            "target_highwater": target_highwater,
            "latest_event_id": latest_event_id,
            "target_reconciliation_needed": target_reconciliation_needed,
            "target_canonicalization_needed": target_canonicalization_needed,
            "delivery_schema_errors": delivery_schema_errors,
            "delivery_data_errors": delivery_data_errors,
            "cursor_mismatches": [
                {
                    "context_id": mismatch.get("context_id"),
                    "agent_id": mismatch.get("agent_id"),
                    "stored_event_id": mismatch.get("stored_event_id"),
                    "derived_event_id": mismatch.get("derived_event_id"),
                    "integrity_errors": mismatch.get("integrity_errors"),
                }
                for mismatch in cursor_mismatches
            ],
            "target_integrity_error_count": target_integrity_error_count,
            "event_ledger_integrity_error_count": (
                event_ledger_integrity_error_count
            ),
            "target_highwater_error_count": target_highwater_error_count,
            "highwater_contract_error_count": highwater_contract_error_count,
            "derivation_source_sha256": derivation_source_sha256,
            "derivation_source_row_count": derivation_source_row_count,
        }
        settled_audit_revision = hashlib.sha256(
            _json_dumps(settled_revision_payload).encode("utf-8")
        ).hexdigest()

        pending_repair_receipt_semantic_error_count = sum(
            1
            for receipt in pending_repair_receipts
            if (
                receipt["after_revision"] != settled_audit_revision
                or int(receipt["payload"]["target_highwater_after"])
                != target_highwater
                or str(
                    receipt["payload"]["derivation_source_sha256_after"]
                )
                != derivation_source_sha256
            )
        )
        verified_repair_receipt_semantic_error_count = sum(
            1
            for receipt in repair_receipts["verified"]
            if (
                str(
                    receipt["payload"]["derivation_source_sha256_after"]
                )
                == derivation_source_sha256
                and (
                    receipt["after_revision"] != settled_audit_revision
                    or int(receipt["payload"]["target_highwater_after"])
                    != target_highwater
                )
            )
        )
        repair_receipt_semantic_error_count = (
            pending_repair_receipt_semantic_error_count
            + verified_repair_receipt_semantic_error_count
        )
        repairable = bool(
            not delivery_schema_errors
            and not unrelated_delivery_errors
            and delivery_data_errors == expected_cursor_error
            and cursor_repairs_are_derived
            and not target_canonicalization_needed
            and target_integrity_error_count == 0
            and event_ledger_integrity_error_count == 0
            and target_highwater_error_count == 0
            and highwater_contract_error_count == 0
            and repair_receipt_integrity_error_count == 0
            and repair_receipt_semantic_error_count == 0
            and not pending_repair_receipts
        )
        revision_payload = {
            "settled_audit_revision": settled_audit_revision,
            "repair_receipt_integrity_error_count": (
                repair_receipt_integrity_error_count
            ),
            "repair_receipt_semantic_error_count": (
                repair_receipt_semantic_error_count
            ),
            "pending_repair_receipts": [
                {
                    "operation_id": receipt["operation_id"],
                    "before_revision": receipt["before_revision"],
                    "after_revision": receipt["after_revision"],
                    "payload_sha256": receipt["payload_sha256"],
                }
                for receipt in pending_repair_receipts
            ],
        }
        audit_revision = hashlib.sha256(
            _json_dumps(revision_payload).encode("utf-8")
        ).hexdigest()
        return {
            "protocol_version": "context-delivery-publication-repair.v1",
            "status": (
                "committed_unverified"
                if (
                    not repair_required
                    and repair_receipt_integrity_error_count == 0
                    and repair_receipt_semantic_error_count == 0
                    and len(pending_repair_receipts) == 1
                    and not delivery_schema_errors
                    and not unrelated_delivery_errors
                    and delivery_data_errors == expected_cursor_error
                    and cursor_repairs_are_derived
                    and not target_canonicalization_needed
                    and target_integrity_error_count == 0
                    and event_ledger_integrity_error_count == 0
                    and target_highwater_error_count == 0
                    and highwater_contract_error_count == 0
                )
                else "blocked"
                if not repairable
                else "repairable"
                if repair_required
                else "ready"
            ),
            "audit_revision": audit_revision,
            "settled_audit_revision": settled_audit_revision,
            "repair_required": repair_required,
            "repairable": repairable,
            "cursor_mismatch_count": len(cursor_mismatches),
            "target_reconciliation_needed": target_reconciliation_needed,
            "target_highwater": target_highwater,
            "latest_event_id": latest_event_id,
            "delivery_schema_error_count": len(delivery_schema_errors),
            "unrelated_delivery_error_count": len(unrelated_delivery_errors),
            "target_canonicalization_needed": target_canonicalization_needed,
            "target_integrity_error_count": target_integrity_error_count,
            "event_ledger_integrity_error_count": (
                event_ledger_integrity_error_count
            ),
            "target_highwater_error_count": target_highwater_error_count,
            "highwater_contract_error_count": highwater_contract_error_count,
            "derivation_source_sha256": derivation_source_sha256,
            "derivation_source_row_count": derivation_source_row_count,
            "repair_receipt_integrity_error_count": (
                repair_receipt_integrity_error_count
            ),
            "repair_receipt_semantic_error_count": (
                repair_receipt_semantic_error_count
            ),
            "pending_repair_receipt_semantic_error_count": (
                pending_repair_receipt_semantic_error_count
            ),
            "verified_repair_receipt_semantic_error_count": (
                verified_repair_receipt_semantic_error_count
            ),
            "pending_repair_receipt_count": len(pending_repair_receipts),
        }

    @staticmethod
    def _context_delivery_publication_derivation_digest(
        conn: sqlite3.Connection,
    ) -> tuple[str, int]:
        """Hash every raw row that can influence target or cursor derivation."""

        sources = (
            (
                "agent_context_events",
                """
                SELECT event_id, context_id, agent_targets_json
                FROM agent_context_events
                ORDER BY event_id
                """,
            ),
            (
                "agent_context_event_targets",
                """
                SELECT event_id, target_kind, target_id
                FROM agent_context_event_targets
                ORDER BY event_id, target_kind, target_id
                """,
            ),
            (
                "agent_context_consumers",
                """
                SELECT agent_id, consumer_kind, enabled, created_at, updated_at
                FROM agent_context_consumers
                ORDER BY agent_id
                """,
            ),
            (
                "agent_context_consumer_groups",
                """
                SELECT agent_id, group_id, created_at
                FROM agent_context_consumer_groups
                ORDER BY agent_id, group_id
                """,
            ),
            (
                "agent_context_deliveries",
                """
                SELECT delivery_id, context_id, agent_id, event_id, state,
                       attempt_count, current_receipt_id, lease_owner,
                       first_delivered_at, last_delivered_at, lease_expires_at,
                       acknowledged_at, cancelled_at, created_at, updated_at
                FROM agent_context_deliveries
                ORDER BY context_id, agent_id, event_id, delivery_id
                """,
            ),
            (
                "agent_context_delivery_receipts",
                """
                SELECT receipt_id, delivery_id, attempt_number,
                       consumer_instance_id, state, leased_at,
                       lease_expires_at, acknowledged_at, released_at,
                       created_at, updated_at
                FROM agent_context_delivery_receipts
                ORDER BY delivery_id, attempt_number, receipt_id
                """,
            ),
            (
                "agent_context_delivery_ack_tombstones",
                """
                SELECT receipt_digest, delivery_id, context_id, agent_id,
                       event_id, attempt_number, acknowledged_at, deleted_at
                FROM agent_context_delivery_ack_tombstones
                ORDER BY context_id, agent_id, event_id, attempt_number,
                         receipt_digest
                """,
            ),
            (
                "agent_context_delivery_cursors",
                """
                SELECT context_id, agent_id, last_contiguous_event_id, updated_at
                FROM agent_context_delivery_cursors
                ORDER BY context_id, agent_id
                """,
            ),
            (
                "context_event_targets_reconciled_through",
                """
                SELECT key, value_json, updated_at
                FROM store_metadata
                WHERE key = 'context_event_targets_reconciled_through'
                ORDER BY key
                """,
            ),
        )
        digest = hashlib.sha256()
        row_count = 0
        for source_name, query in sources:
            encoded_name = source_name.encode("utf-8")
            digest.update(len(encoded_name).to_bytes(4, "big"))
            digest.update(encoded_name)
            for row in conn.execute(query):
                payload = json.dumps(
                    list(row),
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                digest.update(len(payload).to_bytes(8, "big"))
                digest.update(payload)
                row_count += 1
        return digest.hexdigest(), row_count

    def audit_context_delivery_publication_repair(self) -> dict[str, Any]:
        """Return a content-free review token for the narrow offline repair."""

        with closing(self._connect_read_only()) as conn:
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("BEGIN")
            try:
                result = self._context_delivery_publication_repair_audit(conn)
            finally:
                conn.rollback()
        return result

    def _prove_context_delivery_publication_repair_durable(
        self,
        conn: sqlite3.Connection,
        *,
        lease: CoreAuthorityLease,
        receipt: dict[str, Any],
        receipt_status: str,
        require_current_derivation_binding: bool = True,
    ) -> dict[str, Any]:
        checkpoint = conn.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
        if (
            checkpoint is None
            or int(checkpoint[0]) != 0
            or int(checkpoint[1]) != int(checkpoint[2])
        ):
            raise RuntimeError(
                "context delivery publication repair checkpoint was incomplete"
            )
        lease.assert_core_for(self.db_path)
        audit = self._context_delivery_publication_repair_audit(conn)
        expected_audit_status = (
            "committed_unverified" if receipt_status == "pending" else "ready"
        )
        if audit["status"] != expected_audit_status:
            raise RuntimeError(
                "context delivery publication post-commit audit failed"
            )
        inventory = self._context_delivery_publication_receipt_inventory(conn)
        matching = [
            candidate
            for candidate in inventory[receipt_status]
            if candidate["operation_id"] == receipt["operation_id"]
            and candidate["payload_sha256"] == receipt["payload_sha256"]
            and candidate["before_revision"] == receipt["before_revision"]
            and candidate["after_revision"] == receipt["after_revision"]
        ]
        if inventory["invalid_count"] or len(matching) != 1:
            raise RuntimeError(
                "context delivery publication maintenance receipt is invalid"
            )
        payload = matching[0]["payload"]
        receipt_highwater = int(payload["target_highwater_after"])
        current_highwater = int(audit["target_highwater"])
        highwater_inconsistent = bool(
            require_current_derivation_binding
            and receipt_highwater != current_highwater
        )
        if highwater_inconsistent:
            raise RuntimeError(
                "context delivery publication receipt high-water is inconsistent"
            )
        if require_current_derivation_binding:
            if receipt["after_revision"] != audit["settled_audit_revision"]:
                raise RuntimeError(
                    "context delivery publication receipt revision is inconsistent"
                )
            if (
                str(payload["derivation_source_sha256_after"])
                != str(audit["derivation_source_sha256"])
            ):
                raise RuntimeError(
                    "context delivery publication receipt source digest is inconsistent"
                )
        quick_check = [
            str(row[0]) for row in conn.execute("PRAGMA quick_check")
        ]
        foreign_key_error_count = sum(
            1 for _ in conn.execute("PRAGMA foreign_key_check")
        )
        self._run_migrations(conn, allow_mutation=False)
        backup_verification = (
            self._verify_context_delivery_publication_backup(payload)
        )
        if quick_check != ["ok"] or foreign_key_error_count != 0:
            raise RuntimeError(
                "context delivery publication durable verification failed"
            )
        return {
            "audit": audit,
            "receipt": matching[0],
            "checkpoint": [int(value) for value in checkpoint],
            "quick_check": quick_check,
            "foreign_key_error_count": foreign_key_error_count,
            "backup_verification": backup_verification,
        }

    def _verify_pending_context_delivery_publication_repair(
        self,
        conn: sqlite3.Connection,
        *,
        lease: CoreAuthorityLease,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        pending_proof = self._prove_context_delivery_publication_repair_durable(
            conn,
            lease=lease,
            receipt=receipt,
            receipt_status="pending",
        )
        pending_payload = dict(pending_proof["receipt"]["payload"])
        pending_payload_sha256 = str(
            pending_proof["receipt"]["payload_sha256"]
        )
        conn.execute("BEGIN EXCLUSIVE")
        try:
            lease.assert_core_for(self.db_path)
            current_audit = self._context_delivery_publication_repair_audit(conn)
            if current_audit["status"] != "committed_unverified":
                raise RuntimeError(
                    "context delivery publication pending state changed"
                )
            inventory = self._context_delivery_publication_receipt_inventory(conn)
            matching = [
                candidate
                for candidate in inventory["pending"]
                if candidate["operation_id"] == receipt["operation_id"]
                and candidate["payload_sha256"] == pending_payload_sha256
                and candidate["before_revision"] == receipt["before_revision"]
                and candidate["after_revision"] == receipt["after_revision"]
                and candidate["created_at"] == receipt["created_at"]
            ]
            if inventory["invalid_count"] or len(matching) != 1:
                raise RuntimeError(
                    "context delivery publication pending receipt changed"
                )
            current_receipt = matching[0]
            current_payload = current_receipt["payload"]
            if (
                current_receipt["after_revision"]
                != current_audit["settled_audit_revision"]
                or int(current_payload["target_highwater_after"])
                != int(current_audit["target_highwater"])
                or str(current_payload["derivation_source_sha256_after"])
                != str(current_audit["derivation_source_sha256"])
            ):
                raise RuntimeError(
                    "context delivery publication pending receipt is not bound to the repaired state"
                )
            verified_payload = {
                **current_payload,
                "verification_status": "verified",
                "verified_at": max(
                    time.time(),
                    float(current_receipt["created_at"]),
                ),
            }
            cursor = conn.execute(
                """
                UPDATE store_maintenance_receipts
                SET payload_json = ?
                WHERE operation_id = ?
                  AND before_revision = ?
                  AND after_revision = ?
                  AND created_at = ?
                  AND payload_json = ?
                """,
                (
                    _json_dumps(verified_payload),
                    current_receipt["operation_id"],
                    current_receipt["before_revision"],
                    current_receipt["after_revision"],
                    current_receipt["created_at"],
                    _json_dumps(current_payload),
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    "context delivery publication pending receipt changed"
                )
            lease.assert_core_for(self.db_path)
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

        inventory = self._context_delivery_publication_receipt_inventory(conn)
        verified_matches = [
            candidate
            for candidate in inventory["verified"]
            if candidate["operation_id"] == receipt["operation_id"]
        ]
        if inventory["invalid_count"] or len(verified_matches) != 1:
            raise RuntimeError(
                "context delivery publication verified receipt did not persist"
            )
        final_proof = self._prove_context_delivery_publication_repair_durable(
            conn,
            lease=lease,
            receipt=verified_matches[0],
            receipt_status="verified",
        )
        return {
            **final_proof,
            "pending_checkpoint": pending_proof["checkpoint"],
        }

    def repair_context_delivery_publication(
        self,
        *,
        expected_revision: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Repair only deterministic target high-water and cursor derivations.

        The caller must hold one unbound authoritative-core lease while the
        service is offline. A reviewed audit revision, SQLite-verified safety
        backup, exclusive transaction, durable maintenance receipt, and
        post-commit audit fence every mutation.
        """

        if confirm is not True:
            raise ValueError(
                "context delivery publication repair requires confirm=True"
            )
        expected = str(expected_revision or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError(
                "context delivery publication repair requires a reviewed audit revision"
            )
        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is not None:
            raise CoreAuthorityError(
                "context delivery publication repair requires an unclaimed core maintenance lease"
            )

        safety_backup: dict[str, Any] | None = None
        repair_committed = False
        try:
            with closing(self._connect_existing_write()) as conn:
                before_data_version = int(
                    conn.execute("PRAGMA data_version").fetchone()[0]
                )
                before = self._context_delivery_publication_repair_audit(conn)
                if before["audit_revision"] != expected:
                    raise RuntimeError(
                        "context delivery publication repair plan is stale; rerun the audit"
                    )
                if before["status"] == "ready":
                    inventory = (
                        self._context_delivery_publication_receipt_inventory(conn)
                    )
                    latest_verified = (
                        inventory["verified"][-1]
                        if inventory["verified"]
                        else None
                    )
                    ready_proof = (
                        None
                        if latest_verified is None
                        else self._prove_context_delivery_publication_repair_durable(
                            conn,
                            lease=lease,
                            receipt=latest_verified,
                            receipt_status="verified",
                            require_current_derivation_binding=False,
                        )
                    )
                    if ready_proof is None:
                        checkpoint_row = conn.execute(
                            "PRAGMA wal_checkpoint(FULL)"
                        ).fetchone()
                        if (
                            checkpoint_row is None
                            or int(checkpoint_row[0]) != 0
                            or int(checkpoint_row[1]) != int(checkpoint_row[2])
                        ):
                            raise RuntimeError(
                                "context delivery publication ready checkpoint was incomplete"
                            )
                        lease.assert_core_for(self.db_path)
                        ready_quick_check = [
                            str(row[0])
                            for row in conn.execute("PRAGMA quick_check")
                        ]
                        ready_foreign_key_error_count = sum(
                            1 for _ in conn.execute("PRAGMA foreign_key_check")
                        )
                        self._run_migrations(conn, allow_mutation=False)
                        if (
                            ready_quick_check != ["ok"]
                            or ready_foreign_key_error_count != 0
                        ):
                            raise RuntimeError(
                                "context delivery publication ready verification failed"
                            )
                    return {
                        "action": "context-delivery-publication-repair",
                        "status": "ready",
                        "operation_id": (
                            None
                            if latest_verified is None
                            else latest_verified["operation_id"]
                        ),
                        "repair_confirmed": True,
                        "expected_revision": expected,
                        "reconciled_target_highwater": False,
                        "repaired_cursor_count": 0,
                        "safety_backup": None,
                        "before": before,
                        "after": (
                            before
                            if ready_proof is None
                            else ready_proof["audit"]
                        ),
                        "checkpoint": (
                            [int(value) for value in checkpoint_row]
                            if ready_proof is None
                            else ready_proof["checkpoint"]
                        ),
                        "quick_check": (
                            ready_quick_check
                            if ready_proof is None
                            else ready_proof["quick_check"]
                        ),
                        "foreign_key_error_count": (
                            ready_foreign_key_error_count
                            if ready_proof is None
                            else ready_proof["foreign_key_error_count"]
                        ),
                        "maintenance_receipt_verified": bool(ready_proof),
                        "verification_passed": True,
                    }
                if before["status"] == "committed_unverified":
                    inventory = (
                        self._context_delivery_publication_receipt_inventory(conn)
                    )
                    if (
                        inventory["invalid_count"]
                        or len(inventory["pending"]) != 1
                    ):
                        raise RuntimeError(
                            "context delivery publication pending receipt is ambiguous"
                        )
                    pending_receipt = inventory["pending"][0]
                    proof = (
                        self._verify_pending_context_delivery_publication_repair(
                            conn,
                            lease=lease,
                            receipt=pending_receipt,
                        )
                    )
                    return {
                        "action": "context-delivery-publication-repair",
                        "status": "verified",
                        "operation_id": pending_receipt["operation_id"],
                        "repair_confirmed": True,
                        "expected_revision": expected,
                        "reconciled_target_highwater": bool(
                            pending_receipt["payload"][
                                "reconciled_target_highwater"
                            ]
                        ),
                        "repaired_cursor_count": int(
                            pending_receipt["payload"]["cursor_mismatch_count"]
                        ),
                        "safety_backup": {
                            "backup_path": pending_receipt["payload"][
                                "safety_backup_path"
                            ],
                            **proof["backup_verification"],
                        },
                        "checkpoint": proof["checkpoint"],
                        "quick_check": proof["quick_check"],
                        "foreign_key_error_count": proof[
                            "foreign_key_error_count"
                        ],
                        "maintenance_receipt_verified": True,
                        "before": before,
                        "after": proof["audit"],
                        "verification_passed": True,
                    }
                if before["status"] != "repairable":
                    raise RuntimeError(
                        "context delivery publication state is not narrowly repairable"
                    )
                safety_backup = self._verified_safety_backup(
                    conn,
                    label="pre-context-delivery-publication-repair",
                )
                if int(conn.execute("PRAGMA data_version").fetchone()[0]) != (
                    before_data_version
                ):
                    raise RuntimeError(
                        "memory store changed during the safety backup; rerun the audit"
                    )

                conn.execute("BEGIN EXCLUSIVE")
                try:
                    lease.assert_core_for(self.db_path)
                    current = self._context_delivery_publication_repair_audit(conn)
                    if current["audit_revision"] != expected:
                        raise RuntimeError(
                            "context delivery publication repair plan changed before mutation"
                        )
                    repaired_at = time.time()
                    reconciled_target_highwater = bool(
                        current["target_reconciliation_needed"]
                    )
                    if reconciled_target_highwater:
                        highwater_update = conn.execute(
                            """
                            UPDATE store_metadata
                            SET value_json = ?, updated_at = ?
                            WHERE key = 'context_event_targets_reconciled_through'
                            """,
                            (
                                json.dumps(int(current["latest_event_id"])),
                                repaired_at,
                            ),
                        )
                        if highwater_update.rowcount != 1:
                            raise RuntimeError(
                                "context delivery target high-water changed during repair"
                            )
                    repaired_cursor_count = self._repair_context_delivery_cursors(
                        conn,
                        repaired_at=repaired_at,
                    )
                    if repaired_cursor_count != int(
                        current["cursor_mismatch_count"]
                    ):
                        raise RuntimeError(
                            "context delivery cursor repair count changed"
                        )
                    after = self._context_delivery_publication_repair_audit(conn)
                    if after["status"] != "ready":
                        raise RuntimeError(
                            "context delivery publication verification failed; transaction rolled back"
                        )
                    operation_id = "s2maint_" + uuid.uuid4().hex
                    receipt_payload = {
                        "protocol_version": (
                            "context-delivery-publication-repair.v1"
                        ),
                        "verification_status": "pending",
                        "cursor_mismatch_count": repaired_cursor_count,
                        "reconciled_target_highwater": (
                            reconciled_target_highwater
                        ),
                        "target_highwater_before": int(
                            current["target_highwater"]
                        ),
                        "target_highwater_after": int(
                            after["target_highwater"]
                        ),
                        "derivation_source_sha256_after": str(
                            after["derivation_source_sha256"]
                        ),
                        "safety_backup_path": safety_backup["backup_path"],
                        "safety_backup_sha256": safety_backup["sha256"],
                        "safety_backup_size_bytes": int(
                            safety_backup["size_bytes"]
                        ),
                    }
                    conn.execute(
                        """
                        INSERT INTO store_maintenance_receipts (
                            operation_id, operation_type, context_id,
                            before_revision, after_revision, payload_json,
                            created_at
                        ) VALUES (?, ?, NULL, ?, ?, ?, ?)
                        """,
                        (
                            operation_id,
                            "context-delivery-publication-repair",
                            expected,
                            str(after["settled_audit_revision"]),
                            _json_dumps(receipt_payload),
                            repaired_at,
                        ),
                    )
                    lease.assert_core_for(self.db_path)
                    conn.commit()
                    repair_committed = True
                except BaseException:
                    if conn.in_transaction:
                        conn.rollback()
                    raise

                inventory = self._context_delivery_publication_receipt_inventory(
                    conn
                )
                pending_matches = [
                    receipt
                    for receipt in inventory["pending"]
                    if receipt["operation_id"] == operation_id
                ]
                if inventory["invalid_count"] or len(pending_matches) != 1:
                    raise RuntimeError(
                        "context delivery publication pending receipt did not persist"
                    )
                proof = self._verify_pending_context_delivery_publication_repair(
                    conn,
                    lease=lease,
                    receipt=pending_matches[0],
                )
                verified = proof["audit"]
                checkpoint = proof["checkpoint"]
                quick_check = proof["quick_check"]
                foreign_key_error_count = proof["foreign_key_error_count"]
                receipt_verified = True
            return {
                "action": "context-delivery-publication-repair",
                "status": "repaired",
                "operation_id": operation_id,
                "repair_confirmed": True,
                "expected_revision": expected,
                "reconciled_target_highwater": reconciled_target_highwater,
                "repaired_cursor_count": repaired_cursor_count,
                "safety_backup": safety_backup,
                "checkpoint": checkpoint,
                "quick_check": quick_check,
                "foreign_key_error_count": foreign_key_error_count,
                "maintenance_receipt_verified": receipt_verified,
                "before": before,
                "after": verified,
                "verification_passed": True,
            }
        except Exception:
            if safety_backup is not None and not repair_committed:
                try:
                    self._discard_safety_backup(safety_backup)
                except Exception:
                    LOGGER.exception(
                        "failed to discard unused context delivery repair backup"
                    )
            LOGGER.exception("failed to repair context delivery publication state")
            raise

    def _context_delivery_schema_is_v2(self, conn: sqlite3.Connection) -> bool:
        return not self._context_delivery_v2_table_errors(conn) and not (
            self._context_delivery_v2_index_errors(conn)
        )

    def _context_delivery_data_is_v2(self, conn: sqlite3.Connection) -> bool:
        if not self._context_delivery_schema_is_v2(conn):
            return False
        return not self._context_delivery_data_errors(conn)

    @staticmethod
    def _create_context_delivery_v2_indexes(conn: sqlite3.Connection) -> None:
        for statement in CONTEXT_DELIVERY_V2_INDEX_STATEMENTS:
            conn.execute(statement)

    def _normalize_context_delivery_v2_indexes(
        self,
        conn: sqlite3.Connection,
    ) -> None:
        for index_name in CONTEXT_DELIVERY_V2_INDEX_COLUMNS:
            schema_row = conn.execute(
                "SELECT type FROM sqlite_master WHERE name = ?",
                (index_name,),
            ).fetchone()
            if schema_row is not None:
                if str(schema_row["type"]) != "index":
                    raise RuntimeError(
                        f"reserved context delivery index name {index_name} is not an index"
                    )
                if f"{index_name}:" in "|".join(
                    self._context_delivery_v2_index_errors(conn)
                ):
                    conn.execute(f'DROP INDEX "{index_name}"')
        parent_index_name, _, _ = CONTEXT_DELIVERY_V2_PARENT_INDEX
        parent_errors = self._context_delivery_v2_index_errors(conn)
        parent_row = conn.execute(
            "SELECT type FROM sqlite_master WHERE name = ?",
            (parent_index_name,),
        ).fetchone()
        if parent_row is not None and any(
            error.startswith(f"{parent_index_name}:") for error in parent_errors
        ):
            if str(parent_row["type"]) != "index":
                raise RuntimeError(
                    f"reserved context delivery parent index {parent_index_name} is not an index"
                )
            conn.execute(f'DROP INDEX "{parent_index_name}"')
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_agent_context_events_context_event
            ON agent_context_events(context_id, event_id)
            """
        )
        self._create_context_delivery_v2_indexes(conn)

    @staticmethod
    def _create_context_delivery_v2_tables(conn: sqlite3.Connection) -> None:
        for statement in CONTEXT_DELIVERY_V2_TABLE_STATEMENTS:
            conn.execute(statement)

    def _ensure_context_delivery_tombstone_schema(
        self,
        conn: sqlite3.Connection,
    ) -> int:
        """Install or safely rebuild the receipt-digest tombstone ledger.

        Tombstones are the only acknowledgement proof retained after an event
        is pruned.  A shape-compatible but constraint-free table must therefore
        never be accepted as healthy.  Existing rows are preserved only when
        every digest and ownership field satisfies the final contract.
        """

        table_name = "agent_context_delivery_ack_tombstones"
        schema_row = conn.execute(
            "SELECT type FROM sqlite_master WHERE name = ?",
            (table_name,),
        ).fetchone()
        if schema_row is None:
            conn.execute(CONTEXT_DELIVERY_V2_TABLE_STATEMENTS[2])
            return 0
        if str(schema_row["type"]) != "table":
            raise RuntimeError(
                f"reserved context delivery tombstone name {table_name} is not a table"
            )

        columns = self._schema_column_names(conn, table_name)
        if columns != CONTEXT_DELIVERY_V2_TOMBSTONE_COLUMNS:
            raise RuntimeError(
                "context delivery acknowledgement tombstones have an unknown schema; "
                "refusing a lossy migration"
            )
        table_errors = self._context_delivery_v2_table_errors(
            conn,
            table_names=(table_name,),
        )
        if not table_errors:
            return 0

        invalid_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_delivery_ack_tombstones
                WHERE receipt_digest IS NULL
                   OR length(receipt_digest) <> 64
                   OR receipt_digest <> lower(receipt_digest)
                   OR receipt_digest GLOB '*[^0-9a-f]*'
                   OR delivery_id IS NULL
                   OR typeof(delivery_id) <> 'text'
                   OR length(delivery_id) NOT BETWEEN 1 AND 160
                   OR delivery_id <> trim(delivery_id)
                   OR delivery_id GLOB '*[^A-Za-z0-9_.:@-]*'
                   OR context_id IS NULL
                   OR typeof(context_id) <> 'text'
                   OR length(context_id) NOT BETWEEN 1 AND 128
                   OR context_id <> trim(context_id)
                   OR agent_id IS NULL OR trim(agent_id) = ''
                   OR event_id IS NULL OR event_id < 1
                   OR attempt_number IS NULL OR attempt_number < 1
                   OR acknowledged_at IS NULL
                   OR deleted_at IS NULL
                   OR abs(acknowledged_at) >= 1.0e308
                   OR abs(deleted_at) >= 1.0e308
                   OR deleted_at < acknowledged_at
                """
            ).fetchone()[0]
        )
        duplicate_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT receipt_digest
                    FROM agent_context_delivery_ack_tombstones
                    GROUP BY receipt_digest
                    HAVING COUNT(*) > 1
                )
                """
            ).fetchone()[0]
        )
        duplicate_delivery_attempt_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT delivery_id, attempt_number
                    FROM agent_context_delivery_ack_tombstones
                    GROUP BY delivery_id, attempt_number
                    HAVING COUNT(*) > 1
                )
                """
            ).fetchone()[0]
        )
        if invalid_count or duplicate_count or duplicate_delivery_attempt_count:
            raise RuntimeError(
                "context delivery acknowledgement tombstones failed integrity "
                "validation "
                f"(invalid={invalid_count}, digest_duplicate={duplicate_count}, "
                "delivery_attempt_duplicate="
                f"{duplicate_delivery_attempt_count})"
            )

        legacy_name = "agent_context_delivery_ack_tombstones_v2_legacy"
        if self._schema_column_names(conn, legacy_name):
            raise RuntimeError("stale tombstone rebuild table already exists")
        index_name = "ix_agent_context_delivery_ack_tombstones_owner"
        index_row = conn.execute(
            "SELECT type FROM sqlite_master WHERE name = ?",
            (index_name,),
        ).fetchone()
        if index_row is not None:
            if str(index_row["type"]) != "index":
                raise RuntimeError(
                    f"reserved context delivery index name {index_name} is not an index"
                )
            conn.execute(f'DROP INDEX "{index_name}"')

        rows = conn.execute(
            """
            SELECT receipt_digest, delivery_id, context_id, agent_id, event_id,
                   attempt_number, acknowledged_at, deleted_at
            FROM agent_context_delivery_ack_tombstones
            ORDER BY receipt_digest
            """
        ).fetchall()
        conn.execute(
            """
            ALTER TABLE agent_context_delivery_ack_tombstones
            RENAME TO agent_context_delivery_ack_tombstones_v2_legacy
            """
        )
        conn.execute(CONTEXT_DELIVERY_V2_TABLE_STATEMENTS[2])
        conn.executemany(
            """
            INSERT INTO agent_context_delivery_ack_tombstones (
                receipt_digest, delivery_id, context_id, agent_id, event_id,
                attempt_number, acknowledged_at, deleted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    str(row["receipt_digest"]),
                    str(row["delivery_id"]),
                    str(row["context_id"]),
                    self._normalize_delivery_agent_id(str(row["agent_id"])),
                    int(row["event_id"]),
                    int(row["attempt_number"]),
                    float(row["acknowledged_at"]),
                    float(row["deleted_at"]),
                )
                for row in rows
            ],
        )
        conn.execute(
            "DROP TABLE agent_context_delivery_ack_tombstones_v2_legacy"
        )
        return len(rows)

    def _rebuild_context_delivery_v2_tables(
        self,
        conn: sqlite3.Connection,
        *,
        rebuilt_at: float,
    ) -> int:
        """Rebuild a same-column pre-final v2 schema without losing receipts."""

        delivery_rows = conn.execute(
            "SELECT * FROM agent_context_deliveries ORDER BY delivery_id"
        ).fetchall()
        receipt_rows = conn.execute(
            """
            SELECT * FROM agent_context_delivery_receipts
            ORDER BY delivery_id, attempt_number
            """
        ).fetchall()
        live_integrity_error_count, _ = self._context_delivery_live_data_audit(conn)
        if live_integrity_error_count:
            raise RuntimeError(
                "pre-final context delivery v2 rows failed live integrity "
                f"validation (errors={live_integrity_error_count})"
            )
        invalid_delivery_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries AS delivery
                LEFT JOIN agent_context_events AS event
                  ON event.context_id = delivery.context_id
                 AND event.event_id = delivery.event_id
                WHERE event.event_id IS NULL
                   OR delivery.state NOT IN (
                       'leased', 'acknowledged', 'dead_letter'
                   )
                   OR delivery.attempt_count < 1
                """
            ).fetchone()[0]
        )
        invalid_receipt_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_delivery_receipts AS receipt
                LEFT JOIN agent_context_deliveries AS delivery
                  ON delivery.delivery_id = receipt.delivery_id
                WHERE delivery.delivery_id IS NULL
                   OR receipt.state NOT IN (
                       'leased', 'acknowledged', 'expired', 'released', 'cancelled'
                   )
                   OR receipt.attempt_number < 1
                """
            ).fetchone()[0]
        )
        if invalid_delivery_count or invalid_receipt_count:
            raise RuntimeError(
                "pre-final context delivery v2 rows failed integrity validation "
                f"(deliveries={invalid_delivery_count}, receipts={invalid_receipt_count})"
            )
        if self._schema_column_names(conn, "agent_context_deliveries_v2_legacy"):
            raise RuntimeError("stale v2 delivery rebuild table already exists")
        if self._schema_column_names(
            conn,
            "agent_context_delivery_receipts_v2_legacy",
        ):
            raise RuntimeError("stale v2 receipt rebuild table already exists")

        # Repair/establish the composite parent key before creating the new FK.
        parent_index_name, _, _ = CONTEXT_DELIVERY_V2_PARENT_INDEX
        parent_errors = self._context_delivery_v2_index_errors(conn)
        parent_row = conn.execute(
            "SELECT type FROM sqlite_master WHERE name = ?",
            (parent_index_name,),
        ).fetchone()
        if parent_row is not None and any(
            error.startswith(f"{parent_index_name}:") for error in parent_errors
        ):
            if str(parent_row["type"]) != "index":
                raise RuntimeError(
                    f"reserved context delivery parent index {parent_index_name} is not an index"
                )
            conn.execute(f'DROP INDEX "{parent_index_name}"')
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_agent_context_events_context_event
            ON agent_context_events(context_id, event_id)
            """
        )
        for index_name in (
            *CONTEXT_DELIVERY_V2_INDEX_COLUMNS.keys(),
            "ix_agent_context_deliveries_agent_status_event",
        ):
            schema_row = conn.execute(
                "SELECT type FROM sqlite_master WHERE name = ?",
                (index_name,),
            ).fetchone()
            if schema_row is not None:
                if str(schema_row["type"]) != "index":
                    raise RuntimeError(
                        f"reserved context delivery index name {index_name} is not an index"
                    )
                conn.execute(f'DROP INDEX "{index_name}"')
        conn.execute(
            """
            ALTER TABLE agent_context_delivery_receipts
            RENAME TO agent_context_delivery_receipts_v2_legacy
            """
        )
        conn.execute(
            """
            ALTER TABLE agent_context_deliveries
            RENAME TO agent_context_deliveries_v2_legacy
            """
        )
        self._create_context_delivery_v2_tables(conn)
        conn.executemany(
            """
            INSERT INTO agent_context_deliveries (
                delivery_id, context_id, agent_id, event_id, state,
                attempt_count, current_receipt_id, lease_owner,
                first_delivered_at, last_delivered_at, lease_expires_at,
                acknowledged_at, cancelled_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                tuple(row[column] for column in CONTEXT_DELIVERY_V2_DELIVERY_COLUMNS)
                for row in delivery_rows
            ],
        )
        conn.executemany(
            """
            INSERT INTO agent_context_delivery_receipts (
                receipt_id, delivery_id, attempt_number, consumer_instance_id,
                state, leased_at, lease_expires_at, acknowledged_at,
                released_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                tuple(row[column] for column in CONTEXT_DELIVERY_V2_RECEIPT_COLUMNS)
                for row in receipt_rows
            ],
        )
        conn.execute("DROP TABLE agent_context_delivery_receipts_v2_legacy")
        conn.execute("DROP TABLE agent_context_deliveries_v2_legacy")
        self._normalize_context_delivery_v2_indexes(conn)
        self._canonicalize_context_delivery_identities(
            conn,
            updated_at=rebuilt_at,
        )
        self._repair_context_delivery_cursors(conn, repaired_at=rebuilt_at)
        return len(delivery_rows)

    def _ensure_context_delivery_schema_v2(
        self,
        conn: sqlite3.Connection,
        *,
        migrated_at: float,
    ) -> dict[str, int | bool]:
        """Install or atomically rebuild the receipt-driven delivery schema.

        The prototype schema used the final delivery table name but only had a
        reusable ``lease_token``.  Acknowledged rows are preserved with a new
        append-only receipt.  Outstanding prototype leases are preserved as
        expired attempts so the next claimant safely retries them with a newly
        fenced receipt; the reusable prototype token is never copied.
        """

        self._ensure_context_delivery_tombstone_schema(conn)
        delivery_columns = self._schema_column_names(
            conn,
            "agent_context_deliveries",
        )
        receipt_columns = self._schema_column_names(
            conn,
            "agent_context_delivery_receipts",
        )
        if (
            delivery_columns == CONTEXT_DELIVERY_V2_DELIVERY_COLUMNS
            and receipt_columns == CONTEXT_DELIVERY_V2_RECEIPT_COLUMNS
        ):
            table_errors = self._context_delivery_v2_table_errors(conn)
            if table_errors:
                self._rebuild_context_delivery_v2_tables(
                    conn,
                    rebuilt_at=migrated_at,
                )
            else:
                self._normalize_context_delivery_v2_indexes(conn)
                self._canonicalize_context_delivery_identities(
                    conn,
                    updated_at=migrated_at,
                )
            self._repair_context_delivery_cursors(
                conn,
                repaired_at=migrated_at,
            )
            data_errors = self._context_delivery_data_errors(conn)
            if data_errors:
                raise RuntimeError(
                    "context delivery v2 data failed integrity validation: "
                    + ", ".join(data_errors)
                )
            return {"rebuilt": False, "migrated_delivery_count": 0}

        if not delivery_columns:
            if receipt_columns:
                raise RuntimeError(
                    "context delivery receipts exist without a delivery table"
                )
            self._create_context_delivery_v2_tables(conn)
            self._create_context_delivery_v2_indexes(conn)
            return {"rebuilt": False, "migrated_delivery_count": 0}

        if delivery_columns == CONTEXT_DELIVERY_V2_DELIVERY_COLUMNS:
            if receipt_columns:
                raise RuntimeError(
                    "context delivery receipt schema is not compatible with v2"
                )
            table_errors = self._context_delivery_v2_table_errors(
                conn,
                table_names=("agent_context_deliveries",),
            )
            if table_errors:
                raise RuntimeError(
                    "context delivery v2 table signature mismatch: "
                    + ", ".join(table_errors)
                )
            delivery_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM agent_context_deliveries"
                ).fetchone()[0]
            )
            if delivery_count:
                raise RuntimeError(
                    "context delivery receipts are missing for existing v2 deliveries; "
                    "refusing to invent acknowledgement evidence"
                )
            conn.execute(CONTEXT_DELIVERY_V2_TABLE_STATEMENTS[1])
            self._normalize_context_delivery_v2_indexes(conn)
            return {"rebuilt": False, "migrated_delivery_count": 0}

        if delivery_columns != CONTEXT_DELIVERY_V1_DELIVERY_COLUMNS:
            raise RuntimeError(
                "agent_context_deliveries has an unknown schema; refusing a lossy migration"
            )

        if receipt_columns:
            legacy_receipt_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM agent_context_delivery_receipts"
                ).fetchone()[0]
            )
            if legacy_receipt_count:
                raise RuntimeError(
                    "prototype deliveries have receipt rows of unknown provenance; refusing migration"
                )

        invalid_status_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries
                WHERE status NOT IN ('leased', 'acknowledged')
                   OR attempt_count < 1
                """
            ).fetchone()[0]
        )
        invalid_event_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries AS delivery
                LEFT JOIN agent_context_events AS event
                  ON event.event_id = delivery.event_id
                 AND event.context_id = delivery.context_id
                WHERE event.event_id IS NULL
                """
            ).fetchone()[0]
        )
        if invalid_status_count or invalid_event_count:
            raise RuntimeError(
                "prototype context delivery rows failed integrity validation "
                f"(invalid_status={invalid_status_count}, invalid_event={invalid_event_count})"
            )

        legacy_rows = conn.execute(
            """
            SELECT *
            FROM agent_context_deliveries
            ORDER BY context_id, agent_id, event_id
            """
        ).fetchall()
        canonical_legacy_keys: set[tuple[str, str, int]] = set()
        for row in legacy_rows:
            canonical_key = (
                str(row["context_id"]),
                self._normalize_delivery_agent_id(str(row["agent_id"])),
                int(row["event_id"]),
            )
            if canonical_key in canonical_legacy_keys:
                raise RuntimeError(
                    "prototype delivery agent canonicalization would merge conflicting histories"
                )
            canonical_legacy_keys.add(canonical_key)
        if self._schema_column_names(conn, "agent_context_deliveries_v1_legacy"):
            raise RuntimeError("stale prototype delivery migration table already exists")
        if self._schema_column_names(
            conn,
            "agent_context_delivery_receipts_v1_legacy",
        ):
            raise RuntimeError("stale prototype receipt migration table already exists")

        # Index names are database-global and remain attached when a table is
        # renamed, so remove both prototype and final names before rebuilding.
        for index_name in (
            "ix_agent_context_deliveries_agent_status_event",
            "ix_agent_context_deliveries_agent_state_event",
            "ix_agent_context_deliveries_lease_expiry",
            "ix_agent_context_delivery_receipts_delivery_attempt",
            "ix_agent_context_delivery_receipts_state_expiry",
        ):
            conn.execute(f'DROP INDEX IF EXISTS "{index_name}"')
        if receipt_columns:
            conn.execute(
                """
                ALTER TABLE agent_context_delivery_receipts
                RENAME TO agent_context_delivery_receipts_v1_legacy
                """
            )
        conn.execute(
            """
            ALTER TABLE agent_context_deliveries
            RENAME TO agent_context_deliveries_v1_legacy
            """
        )
        self._create_context_delivery_v2_tables(conn)

        for row in legacy_rows:
            agent_id = self._normalize_delivery_agent_id(str(row["agent_id"]))
            if not agent_id:
                raise RuntimeError("prototype delivery contains an empty agent id")
            state = str(row["status"])
            attempt_count = int(row["attempt_count"])
            acknowledged_at = (
                None
                if row["acknowledged_at"] is None
                else float(row["acknowledged_at"])
            )
            if state == "acknowledged" and acknowledged_at is None:
                acknowledged_at = float(row["updated_at"])
            lease_expires_at = float(row["lease_expires_at"])
            receipt_state = "acknowledged"
            receipt_updated_at = float(row["updated_at"])
            if state == "leased":
                # Force a retry after upgrade. The prototype token and unknown
                # process owner must never remain capable of acknowledgement.
                lease_expires_at = min(lease_expires_at, migrated_at - 0.001)
                receipt_state = "expired"
                receipt_updated_at = max(
                    receipt_updated_at,
                    lease_expires_at,
                )
            receipt_id = "ctxrcpt_" + secrets.token_urlsafe(32)
            conn.execute(
                """
                INSERT INTO agent_context_consumers (
                    agent_id,
                    consumer_kind,
                    enabled,
                    created_at,
                    updated_at
                )
                VALUES (?, 'migrated-v1', 1, ?, ?)
                ON CONFLICT(agent_id) DO NOTHING
                """,
                (agent_id, migrated_at, migrated_at),
            )
            conn.execute(
                """
                INSERT INTO agent_context_deliveries (
                    delivery_id,
                    context_id,
                    agent_id,
                    event_id,
                    state,
                    attempt_count,
                    current_receipt_id,
                    lease_owner,
                    first_delivered_at,
                    last_delivered_at,
                    lease_expires_at,
                    acknowledged_at,
                    cancelled_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'migration-v1-unclaimed', ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    str(row["delivery_id"]),
                    str(row["context_id"]),
                    agent_id,
                    int(row["event_id"]),
                    state,
                    attempt_count,
                    receipt_id,
                    float(row["first_delivered_at"]),
                    float(row["last_delivered_at"]),
                    lease_expires_at,
                    acknowledged_at,
                    float(row["created_at"]),
                    float(row["updated_at"]),
                ),
            )
            conn.execute(
                """
                INSERT INTO agent_context_delivery_receipts (
                    receipt_id,
                    delivery_id,
                    attempt_number,
                    consumer_instance_id,
                    state,
                    leased_at,
                    lease_expires_at,
                    acknowledged_at,
                    released_at,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, 'migration-v1-unclaimed', ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    receipt_id,
                    str(row["delivery_id"]),
                    attempt_count,
                    receipt_state,
                    float(row["last_delivered_at"]),
                    lease_expires_at,
                    acknowledged_at,
                    float(row["created_at"]),
                    receipt_updated_at,
                ),
            )

        # Prototype cursor values were watermark based rather than proven by
        # receipts. Rebuild them lazily from the preserved acknowledgements.
        conn.execute("DELETE FROM agent_context_delivery_cursors")
        if receipt_columns:
            conn.execute("DROP TABLE agent_context_delivery_receipts_v1_legacy")
        conn.execute("DROP TABLE agent_context_deliveries_v1_legacy")
        self._normalize_context_delivery_v2_indexes(conn)
        self._canonicalize_context_delivery_identities(
            conn,
            updated_at=migrated_at,
        )
        schema_errors = self._context_delivery_v2_table_errors(conn) + (
            self._context_delivery_v2_index_errors(conn)
        )
        data_errors = self._context_delivery_data_errors(conn)
        if schema_errors or data_errors:
            raise RuntimeError(
                "context delivery migration verification failed: "
                + ", ".join(schema_errors + data_errors)
            )
        return {
            "rebuilt": True,
            "migrated_delivery_count": len(legacy_rows),
        }

    def _context_event_target_reconciliation_needed(
        self,
        conn: sqlite3.Connection,
    ) -> bool:
        migration_applied = bool(
            conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("context_event_targets_v2",),
            ).fetchone()
        )
        highwater = self._read_context_event_target_highwater(
            conn,
            allow_missing=not migration_applied,
        )
        latest_event_id = int(
            conn.execute(
                "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events"
            ).fetchone()[0]
            or 0
        )
        return latest_event_id > max(0, highwater)

    @staticmethod
    def _read_context_event_target_highwater(
        conn: sqlite3.Connection,
        *,
        allow_missing: bool,
    ) -> int:
        """Read one exact canonical nonnegative target high-water value."""

        row = conn.execute(
            "SELECT value_json FROM store_metadata WHERE key = ?",
            ("context_event_targets_reconciled_through",),
        ).fetchone()
        if row is None:
            if allow_missing:
                return 0
            raise RuntimeError("context event target high-water is missing")
        raw_value = str(row["value_json"])
        try:
            decoded = json.loads(raw_value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "context event target high-water is malformed"
            ) from exc
        if (
            type(decoded) is not int
            or decoded < 0
            or raw_value != json.dumps(decoded)
        ):
            raise RuntimeError(
                "context event target high-water is noncanonical"
            )
        return int(decoded)

    def _context_event_target_canonicalization_needed(
        self,
        conn: sqlite3.Connection,
    ) -> bool:
        rows = conn.execute(
            """
            SELECT DISTINCT target_id
            FROM agent_context_event_targets
            WHERE target_kind = 'agent'
            """
        ).fetchall()
        return any(
            str(row["target_id"])
            != self._normalize_delivery_agent_id(str(row["target_id"]))
            for row in rows
        )

    def _context_event_target_integrity_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
        after_event_id: int = 0,
        missing_targets_only: bool = False,
        sample_limit: int = 10,
    ) -> tuple[
        int,
        list[dict[str, Any]],
        int,
        list[dict[str, Any]],
    ]:
        """Validate every routed event's normalized target contract.

        Old writers may have persisted a malformed or empty
        ``agent_targets_json`` envelope which reconciliation intentionally
        leaves unrouted; delivery health reports those separately.  A valid
        nonempty envelope with no rows is lost routing evidence and fails this
        audit.  Once any normalized row is present, the route is authoritative
        and must be sanctioned, canonical, and semantically identical to the
        event envelope.
        """

        context = None if context_id is None else str(context_id)
        missing_target_filter = (
            "AND target.event_id IS NULL" if missing_targets_only else ""
        )
        rows = conn.execute(
            f"""
            SELECT event.event_id,
                   event.context_id,
                   event.agent_targets_json,
                   target.target_kind,
                   target.target_id
            FROM agent_context_events AS event
            LEFT JOIN agent_context_event_targets AS target
              ON target.event_id = event.event_id
            WHERE (? IS NULL OR event.context_id = ?)
              AND event.event_id > ?
              {missing_target_filter}
            ORDER BY event.event_id, target.target_kind, target.target_id
            """,
            (context, context, max(0, int(after_event_id))),
        ).fetchall()
        bounded_sample_limit = min(max(int(sample_limit), 1), 100)
        error_count = 0
        error_samples: list[dict[str, Any]] = []
        noncanonical_agent_target_count = 0
        noncanonical_agent_target_samples: list[dict[str, Any]] = []

        event_id: int | None = None
        event_context = ""
        targets_json = ""
        target_records: list[tuple[str, str]] = []
        target_reasons: set[str] = set()

        def finish_event() -> None:
            nonlocal error_count
            if event_id is None:
                return
            reasons = set(target_reasons)
            try:
                raw_targets = json.loads(targets_json)
            except (TypeError, ValueError, json.JSONDecodeError):
                raw_targets = None
            has_target_records = bool(target_records)
            if not isinstance(raw_targets, list):
                expected_records: list[tuple[str, str]] | None = None
                if has_target_records:
                    reasons.add("agent-targets-json-not-list")
            else:
                normalized_targets = self._normalize_event_targets(raw_targets)
                if raw_targets != normalized_targets and (
                    has_target_records or normalized_targets
                ):
                    reasons.add("agent-targets-envelope-noncanonical")
                expected_records = sorted(
                    self._normalized_event_target_records(
                        normalized_targets
                    )
                )
                if not has_target_records and expected_records:
                    reasons.add("missing-target-rows")
                elif has_target_records and sorted(target_records) != expected_records:
                    reasons.add("target-row-envelope-mismatch")
            if not reasons:
                return
            error_count += 1
            if len(error_samples) >= bounded_sample_limit:
                return
            error_samples.append(
                {
                    "event_id": event_id,
                    "context_id": event_context,
                    "reasons": sorted(reasons),
                    "target_records": [
                        {"target_kind": kind, "target_id": target}
                        for kind, target in target_records[:64]
                    ],
                    "expected_target_records": (
                        None
                        if expected_records is None
                        else [
                            {"target_kind": kind, "target_id": target}
                            for kind, target in expected_records[:64]
                        ]
                    ),
                }
            )

        for row in rows:
            row_event_id = int(row["event_id"])
            if event_id is not None and row_event_id != event_id:
                finish_event()
                target_records = []
                target_reasons = set()
            if event_id != row_event_id:
                event_id = row_event_id
                event_context = str(row["context_id"])
                targets_json = str(row["agent_targets_json"])

            if row["target_kind"] is None:
                continue
            target_kind = str(row["target_kind"])
            target_id = str(row["target_id"])
            target_records.append((target_kind, target_id))
            if target_kind == "agent":
                canonical_target = self._normalize_delivery_agent_id(target_id)
                if not target_id.strip() or not canonical_target:
                    target_reasons.add("agent-target-empty")
                elif target_id != canonical_target:
                    target_reasons.add("agent-target-noncanonical")
                    noncanonical_agent_target_count += 1
                    if (
                        len(noncanonical_agent_target_samples)
                        < bounded_sample_limit
                    ):
                        noncanonical_agent_target_samples.append(
                            {
                                "event_id": row_event_id,
                                "target_id": target_id,
                                "canonical_target_id": canonical_target,
                            }
                        )
            elif target_kind == "group":
                if target_id not in CONTEXT_EVENT_TARGET_GROUPS:
                    target_reasons.add("group-target-not-allowed")
            elif target_kind == "broadcast":
                if target_id != "*":
                    target_reasons.add("broadcast-target-not-star")
            else:
                target_reasons.add("target-kind-not-allowed")
        finish_event()
        return (
            error_count,
            error_samples,
            noncanonical_agent_target_count,
            noncanonical_agent_target_samples,
        )

    def _context_event_ledger_integrity_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None = None,
        after_event_id: int = 0,
        sample_limit: int = 10,
    ) -> tuple[int, list[dict[str, Any]]]:
        """Validate immutable event addressing without exposing event content."""

        context = None if context_id is None else str(context_id)
        rows = conn.execute(
            """
            SELECT event_id, context_id, source_surface, event_type, summary,
                   created_at
            FROM agent_context_events
            WHERE (? IS NULL OR context_id = ?)
              AND event_id > ?
            ORDER BY event_id
            """,
            (context, context, max(0, int(after_event_id))),
        ).fetchall()
        bounded_sample_limit = min(max(int(sample_limit), 1), 100)
        error_count = 0
        samples: list[dict[str, Any]] = []
        for row in rows:
            reasons: list[str] = []
            raw_context_id = row["context_id"]
            if not self._context_event_context_id_is_valid(raw_context_id):
                reasons.append("context-id-invalid")
            if not self._context_event_public_label_is_valid(
                row["source_surface"]
            ):
                reasons.append("source-surface-invalid")
            if not self._context_event_public_label_is_valid(row["event_type"]):
                reasons.append("event-type-invalid")
            if not self._context_event_summary_is_valid(row["summary"]):
                reasons.append("summary-evidence-invalid")
            if not self._context_delivery_timestamp_is_valid(row["created_at"]):
                reasons.append("created-at-invalid")
            if not reasons:
                continue
            error_count += 1
            if len(samples) >= bounded_sample_limit:
                continue
            samples.append(
                {
                    "event_id": int(row["event_id"]),
                    "reasons": reasons,
                    "context_id_length": (
                        len(raw_context_id)
                        if isinstance(raw_context_id, str)
                        else 0
                    ),
                }
            )
        return error_count, samples

    @staticmethod
    def _context_consumer_group_integrity_audit(
        conn: sqlite3.Connection,
        *,
        sample_limit: int = 10,
    ) -> tuple[int, list[dict[str, str]]]:
        allowed_groups = tuple(sorted(CONTEXT_EVENT_TARGET_GROUPS))
        placeholders = ", ".join("?" for _ in allowed_groups)
        rows = conn.execute(
            f"""
            SELECT agent_id, group_id
            FROM agent_context_consumer_groups
            WHERE group_id NOT IN ({placeholders})
            ORDER BY agent_id, group_id
            """,
            allowed_groups,
        ).fetchall()
        bounded_sample_limit = min(max(int(sample_limit), 1), 100)
        return len(rows), [
            {
                "agent_id": str(row["agent_id"]),
                "group_id": str(row["group_id"]),
                "reason": "consumer-group-not-allowed",
            }
            for row in rows[:bounded_sample_limit]
        ]

    def _context_event_target_highwater_audit(
        self,
        conn: sqlite3.Connection,
    ) -> tuple[int, list[dict[str, Any]]]:
        latest_event_id = int(
            conn.execute(
                "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events"
            ).fetchone()[0]
            or 0
        )
        try:
            highwater = self._read_context_event_target_highwater(
                conn,
                allow_missing=False,
            )
        except RuntimeError:
            return 1, [
                {
                    "latest_event_id": latest_event_id,
                    "reason": "target-reconciliation-highwater-invalid",
                }
            ]
        if highwater <= latest_event_id:
            return 0, []
        return 1, [
            {
                "reconciled_through_event_id": highwater,
                "latest_event_id": latest_event_id,
                "reason": "target-reconciliation-highwater-ahead-of-ledger",
            }
        ]

    def _canonicalize_context_event_targets(
        self,
        conn: sqlite3.Connection,
    ) -> int:
        rows = conn.execute(
            """
            SELECT event_id, target_id, created_at
            FROM agent_context_event_targets
            WHERE target_kind = 'agent'
            ORDER BY event_id, target_id
            """
        ).fetchall()
        changed_event_ids: set[int] = set()
        for row in rows:
            raw_target = str(row["target_id"])
            canonical_target = self._normalize_delivery_agent_id(raw_target)
            if not canonical_target:
                raise RuntimeError(
                    "context event contains an empty canonical agent target"
                )
            if canonical_target == raw_target:
                continue
            event_id = int(row["event_id"])
            conn.execute(
                """
                INSERT OR IGNORE INTO agent_context_event_targets (
                    event_id, target_kind, target_id, created_at
                ) VALUES (?, 'agent', ?, ?)
                """,
                (event_id, canonical_target, float(row["created_at"])),
            )
            conn.execute(
                """
                DELETE FROM agent_context_event_targets
                WHERE event_id = ? AND target_kind = 'agent' AND target_id = ?
                """,
                (event_id, raw_target),
            )
            changed_event_ids.add(event_id)

        for event_id in sorted(changed_event_ids):
            target_rows = conn.execute(
                """
                SELECT target_kind, target_id
                FROM agent_context_event_targets
                WHERE event_id = ?
                ORDER BY target_kind, target_id
                """,
                (event_id,),
            ).fetchall()
            targets = [
                "broadcast"
                if str(target["target_kind"]) == "broadcast"
                else str(target["target_id"])
                for target in target_rows
            ]
            conn.execute(
                """
                UPDATE agent_context_events
                SET agent_targets_json = ?
                WHERE event_id = ?
                """,
                (_json_dumps(targets), event_id),
            )
        return len(changed_event_ids)

    def _reconcile_context_event_targets(
        self,
        conn: sqlite3.Connection,
        *,
        reconciled_at: float,
        strict_existing_targets: bool = False,
    ) -> int:
        migration_applied = bool(
            conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("context_event_targets_v2",),
            ).fetchone()
        )
        highwater = self._read_context_event_target_highwater(
            conn,
            allow_missing=not migration_applied,
        )
        rows = conn.execute(
            """
            SELECT event_id, context_id, agent_targets_json, created_at
            FROM agent_context_events
            WHERE event_id > ?
            ORDER BY event_id ASC
            """,
            (max(0, highwater),),
        ).fetchall()
        affected_contexts = {
            str(row["context_id"])
            for row in rows
        }
        inserted_count = 0
        for row in rows:
            event_id = int(row["event_id"])
            raw_targets = _decode_json(str(row["agent_targets_json"]), None)
            if not isinstance(raw_targets, list):
                if strict_existing_targets:
                    raise RuntimeError(
                        "context event target envelope changed before atomic publication"
                    )
                # Invalid envelopes remain deliberately unrouted and visible in
                # delivery health. Advancing the scan highwater avoids turning
                # every connection into a writer while still failing closed.
                continue
            targets = self._normalize_event_targets(raw_targets)
            target_records = sorted(
                self._normalized_event_target_records(targets)
            )
            existing_target_records = [
                (str(target["target_kind"]), str(target["target_id"]))
                for target in conn.execute(
                    """
                    SELECT target_kind, target_id
                    FROM agent_context_event_targets
                    WHERE event_id = ?
                    ORDER BY target_kind, target_id
                    """,
                    (event_id,),
                ).fetchall()
            ]
            if strict_existing_targets and (
                raw_targets != targets
                or (
                    existing_target_records
                    and existing_target_records != target_records
                )
            ):
                raise RuntimeError(
                    "context event target rows changed before atomic publication"
                )
            if not target_records:
                if strict_existing_targets and existing_target_records:
                    raise RuntimeError(
                        "context event target rows changed before atomic publication"
                    )
                continue
            if raw_targets != targets:
                conn.execute(
                    """
                    UPDATE agent_context_events
                    SET agent_targets_json = ?
                    WHERE event_id = ?
                    """,
                    (_json_dumps(targets), event_id),
                )
            if not strict_existing_targets or not existing_target_records:
                cursor = conn.executemany(
                    """
                    INSERT OR IGNORE INTO agent_context_event_targets (
                        event_id,
                        target_kind,
                        target_id,
                        created_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            event_id,
                            target_kind,
                            target_id,
                            float(row["created_at"]),
                        )
                        for target_kind, target_id in target_records
                    ],
                )
                inserted_count += max(0, int(cursor.rowcount))
        # Cursor values are derived from the complete routed ledger, including
        # events that are deliberately ineligible for a consumer. Reconcile
        # every existing cursor in each affected namespace before publishing
        # the matching target high-water. This also closes the rolling-writer
        # race where an older process commits an event after connection
        # preflight but before this writer obtains BEGIN IMMEDIATE.
        for affected_context in sorted(affected_contexts):
            cursor_rows = conn.execute(
                """
                SELECT agent_id
                FROM agent_context_delivery_cursors
                WHERE context_id = ?
                ORDER BY agent_id
                """,
                (affected_context,),
            ).fetchall()
            for cursor_row in cursor_rows:
                self._advance_context_cursor(
                    conn,
                    context_id=affected_context,
                    agent_id=str(cursor_row["agent_id"]),
                    now=reconciled_at,
                )
        if rows:
            highwater = int(rows[-1]["event_id"])
        latest_event_id = int(
            conn.execute(
                "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events"
            ).fetchone()[0]
            or 0
        )
        highwater = min(max(0, highwater), latest_event_id)
        conn.execute(
            """
            INSERT INTO store_metadata (key, value_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            """,
            (
                "context_event_targets_reconciled_through",
                json.dumps(max(0, highwater)),
                reconciled_at,
            ),
        )
        return inserted_count

    @staticmethod
    def _redact_legacy_text_value(raw_value: Any) -> tuple[str, int]:
        raw_text = str(raw_value or "")
        safe_text, redaction_count = redact_capture_text(raw_text)
        safe_text, digest_removals = strip_untrusted_raw_digest_text(safe_text)
        return safe_text, int(redaction_count) + int(digest_removals)

    @staticmethod
    def _redact_legacy_json_document(raw_value: Any) -> tuple[str, int]:
        raw_text = str(raw_value or "")
        try:
            decoded = json.loads(raw_text)
        except (TypeError, ValueError, json.JSONDecodeError):
            safe_text, redaction_count = redact_capture_text(raw_text)
            safe_text, digest_removals = strip_untrusted_raw_digest_text(safe_text)
            return safe_text, int(redaction_count) + int(digest_removals)
        safe_value, redaction_count = redact_sensitive_value(decoded)
        safe_value, digest_removals = strip_untrusted_raw_digest_fields(safe_value)
        mutation_count = int(redaction_count) + int(digest_removals)
        if not mutation_count:
            return raw_text, 0
        try:
            encoded = json.dumps(
                safe_value,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError):
            return json.dumps("[REDACTED_UNSERIALIZABLE]"), max(
                1,
                mutation_count,
            )
        return encoded, mutation_count

    def _scrub_legacy_secret_content(self, conn: sqlite3.Connection) -> int:
        """Repair legacy secret content in one startup transaction.

        Durable identifiers are intentionally not rewritten here because doing
        so would invalidate graph and delivery foreign keys. New identifier
        inputs are fail-closed; a separate integrity audit reports any legacy
        identifier that still needs governed repair. Memory rows whose tag or
        source contains credential material are deleted with their cascading
        retrieval artifacts because identifiers, embeddings, and spikes were
        derived before redaction. Metadata-only findings are repaired in place
        and their surface-term index is rebuilt; metadata does not participate
        in the stored embedding/spike derivation, so deleting those memories
        would be unnecessary data loss.
        """

        content_columns: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
            ("memory_events", "event_id", (("payload_json", "json"),)),
            (
                "memory_relationships",
                "relationship_id",
                (("evidence_json", "json"),),
            ),
            (
                "context_relationships",
                "context_link_id",
                (("evidence_json", "json"),),
            ),
            (
                "agent_context_events",
                "event_id",
                (("summary", "text"), ("payload_json", "json")),
            ),
            (
                "capture_operations",
                "capture_id",
                (("result_json", "json"),),
            ),
            (
                "store_maintenance_receipts",
                "operation_id",
                (("payload_json", "json"),),
            ),
            ("store_metadata", "key", (("value_json", "json"),)),
        )
        changed_cells: dict[str, int] = {}
        contaminated_memory_ids: list[str] = []
        repaired_memory_metadata: list[
            tuple[str, str, str, str, str, dict[str, Any]]
        ] = []
        contaminated_memory_reasons = {
            "tag": 0,
            "source_text": 0,
            "metadata_json": 0,
        }
        memory_rows = conn.execute(
            """
            SELECT memory_id, context_id, tag, source_text, metadata_json
            FROM memory_entries
            """
        ).fetchall()
        for row in memory_rows:
            raw_tag = str(row["tag"] or "")
            raw_source_text = str(row["source_text"] or "")
            raw_metadata_json = str(row["metadata_json"] or "")
            safe_tag, tag_redactions = self._redact_legacy_text_value(raw_tag)
            safe_source_text, source_redactions = self._redact_legacy_text_value(
                raw_source_text
            )
            safe_metadata_json, metadata_redactions = self._redact_legacy_json_document(
                raw_metadata_json
            )
            tag_mutated = bool(tag_redactions and safe_tag != raw_tag)
            source_mutated = bool(
                source_redactions and safe_source_text != raw_source_text
            )
            metadata_mutated = bool(
                metadata_redactions and safe_metadata_json != raw_metadata_json
            )
            if not (tag_mutated or source_mutated or metadata_mutated):
                continue
            memory_id = str(row["memory_id"])
            contaminated_memory_reasons["tag"] += int(tag_mutated)
            contaminated_memory_reasons["source_text"] += int(
                source_mutated
            )
            contaminated_memory_reasons["metadata_json"] += int(
                metadata_mutated
            )
            if tag_mutated or source_mutated:
                contaminated_memory_ids.append(memory_id)
                continue
            if metadata_mutated:
                safe_metadata = _decode_json(safe_metadata_json, {})
                if not isinstance(safe_metadata, dict):
                    safe_metadata = {}
                repaired_memory_metadata.append(
                    (
                        memory_id,
                        str(row["context_id"]),
                        str(row["tag"]),
                        str(row["source_text"]),
                        safe_metadata_json,
                        safe_metadata,
                    )
                )

        for memory_id in contaminated_memory_ids:
            conn.execute(
                "DELETE FROM memory_entries WHERE memory_id = ?",
                (memory_id,),
            )
        if contaminated_memory_ids:
            changed_cells["memory_entries.removed_contaminated_rows"] = len(
                contaminated_memory_ids
            )

        for (
            memory_id,
            context_id,
            tag,
            source_text,
            safe_metadata_json,
            safe_metadata,
        ) in repaired_memory_metadata:
            conn.execute(
                "UPDATE memory_entries SET metadata_json = ? WHERE memory_id = ?",
                (safe_metadata_json, memory_id),
            )
            conn.execute(
                "DELETE FROM memory_surface_terms WHERE memory_id = ?",
                (memory_id,),
            )
            surface_rows = self._surface_term_rows(
                memory_id=memory_id,
                context_id=context_id,
                tag=tag,
                source_text=source_text,
                metadata=safe_metadata,
            )
            if surface_rows:
                conn.executemany(
                    """
                    INSERT INTO memory_surface_terms (
                        memory_id, context_id, term, weight
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    surface_rows,
                )
        if repaired_memory_metadata:
            changed_cells["memory_entries.metadata_json"] = len(
                repaired_memory_metadata
            )

        for table_name, primary_key, columns in content_columns:
            selected_columns = ", ".join(
                [primary_key, *(column for column, _ in columns)]
            )
            rows = conn.execute(
                f'SELECT {selected_columns} FROM "{table_name}"'
            ).fetchall()
            for row in rows:
                updates: dict[str, str] = {}
                for column_name, value_kind in columns:
                    raw_value = str(row[column_name] or "")
                    if value_kind == "json":
                        safe_value, redaction_count = (
                            self._redact_legacy_json_document(raw_value)
                        )
                    else:
                        safe_value, redaction_count = (
                            self._redact_legacy_text_value(raw_value)
                        )
                    if redaction_count and safe_value != raw_value:
                        updates[column_name] = safe_value
                        count_key = f"{table_name}.{column_name}"
                        changed_cells[count_key] = changed_cells.get(count_key, 0) + 1
                if not updates:
                    continue
                assignments = ", ".join(
                    f'"{column_name}" = ?' for column_name in updates
                )
                conn.execute(
                    f'UPDATE "{table_name}" SET {assignments} '
                    f'WHERE "{primary_key}" = ?',
                    (*updates.values(), row[primary_key]),
                )
        index_rows_changed = len(contaminated_memory_ids) + len(
            repaired_memory_metadata
        )

        if changed_cells:
            operation_id = "s2maint_" + uuid.uuid4().hex
            conn.execute(
                """
                INSERT INTO store_maintenance_receipts (
                    operation_id, operation_type, context_id,
                    before_revision, after_revision, payload_json, created_at
                )
                VALUES (?, 'secret-content-scrub', 'all',
                        'legacy-content', 'redacted-content-v1', ?, ?)
                """,
                (
                    operation_id,
                    _json_dumps(
                        {
                            "content_free": True,
                            "changed_cell_count": sum(changed_cells.values()),
                            "changed_cells_by_column": changed_cells,
                            "removed_contaminated_memory_count": len(
                                contaminated_memory_ids
                            ),
                            "repaired_memory_metadata_count": len(
                                repaired_memory_metadata
                            ),
                            "removed_memory_reason_counts": (
                                contaminated_memory_reasons
                            ),
                            "retrieval_artifacts_reconciled": True,
                        }
                    ),
                    time.time(),
                ),
            )
        return index_rows_changed

    @staticmethod
    def _legacy_secret_identifier_counts(
        conn: sqlite3.Connection,
    ) -> dict[str, int]:
        """Count credential-shaped durable identifiers without exposing values."""

        columns_by_table: dict[str, list[str]] = {}
        for table_name, column_name in sorted(
            LEGACY_SECRET_IDENTIFIER_COLUMNS
            | LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS
        ):
            columns_by_table.setdefault(table_name, []).append(column_name)
        findings: dict[str, int] = {}
        for table_name, columns in columns_by_table.items():
            if not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (table_name,),
            ).fetchone():
                continue
            rows = conn.execute(
                f'SELECT {", ".join(columns)} FROM "{table_name}"'
            ).fetchall()
            for row in rows:
                for column_name in columns:
                    _, redaction_count = redact_capture_text(
                        str(row[column_name] or "")
                    )
                    if redaction_count:
                        key = f"{table_name}.{column_name}"
                        findings[key] = findings.get(key, 0) + 1
        return findings

    @staticmethod
    def _retire_legacy_ack_receipts(conn: sqlite3.Connection) -> bool:
        """Drop the obsolete pre-v2 acknowledgement table only when empty.

        A non-empty table may contain a hashed lease credential and cannot be
        silently discarded or summarized. Such stores require an explicit
        governed repair, so startup fails closed without returning row values.
        """

        table_name = "agent_context_ack_receipts"
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone():
            return False
        row_count = int(
            conn.execute(
                f'SELECT COUNT(*) FROM "{table_name}"'
            ).fetchone()[0]
            or 0
        )
        if row_count:
            raise RuntimeError(
                "legacy acknowledgement receipts require governed repair "
                f"(affected_rows={row_count})"
            )
        conn.execute(f'DROP TABLE "{table_name}"')
        return True

    def _run_migrations(
        self,
        conn: sqlite3.Connection,
        *,
        allow_mutation: bool = True,
    ) -> None:
        lease = self._assert_filesystem_authority()
        required_migrations = set(self._base_authority_migrations())
        core_migration_required = bool(
            lease.role == "core" and lease.durable_epoch is not None
        )
        if core_migration_required:
            required_migrations.add("authoritative_core_v1")
        migration_placeholders = ", ".join("?" for _ in required_migrations)
        applied_migrations = {
            str(row["key"])
            for row in conn.execute(
                f"SELECT key FROM store_migrations WHERE key IN ({migration_placeholders})",
                tuple(sorted(required_migrations)),
            ).fetchall()
        }
        delivery_schema_ready = self._context_delivery_schema_is_v2(conn)
        delivery_data_ready = (
            self._context_delivery_data_is_v2(conn)
            if delivery_schema_ready
            else False
        )
        target_reconciliation_needed = (
            self._context_event_target_reconciliation_needed(conn)
        )
        startup_target_integrity_required = not bool(
            getattr(self, "_target_integrity_verified", False)
        )
        target_canonicalization_needed = bool(
            startup_target_integrity_required
            and self._context_event_target_canonicalization_needed(conn)
        )
        target_integrity_error_count = 0
        if startup_target_integrity_required:
            target_integrity_error_count, _, _, _ = (
                self._context_event_target_integrity_audit(conn)
            )
        else:
            # A valid envelope losing all normalized rows is a cheap, indexed
            # invariant to check on every connection.  This prevents a live
            # store instance from silently returning an empty lease forever,
            # while the expensive full parity scan remains startup-gated.
            target_integrity_error_count, _, _, _ = (
                self._context_event_target_integrity_audit(
                    conn,
                    missing_targets_only=True,
                )
            )
        event_ledger_integrity_error_count = 0
        if startup_target_integrity_required:
            event_ledger_integrity_error_count, _ = (
                self._context_event_ledger_integrity_audit(conn)
            )
        target_highwater_error_count, _ = (
            self._context_event_target_highwater_audit(conn)
        )
        capture_schema_errors = self._capture_operation_schema_errors(conn)
        startup_capture_integrity_required = not bool(
            getattr(self, "_capture_integrity_verified", False)
        )
        capture_integrity_error_count = 0
        if not capture_schema_errors and startup_capture_integrity_required:
            capture_integrity_error_count, _ = self._capture_operation_integrity_audit(
                conn
            )
        if (
            applied_migrations == required_migrations
            and delivery_schema_ready
            and delivery_data_ready
            and not target_reconciliation_needed
            and not target_canonicalization_needed
            and target_integrity_error_count == 0
            and event_ledger_integrity_error_count == 0
            and target_highwater_error_count == 0
            and not capture_schema_errors
            and capture_integrity_error_count == 0
        ):
            self._target_integrity_verified = True
            self._capture_integrity_verified = True
            return

        if not allow_mutation:
            raise CoreAuthorityError(
                "authoritative v6 memory requires governed repair before startup"
            )

        # Recheck after acquiring the writer lock. Another process may have
        # completed the migration between the optimistic read and this point.
        with self._transaction(conn, immediate=True):
            index_rows_changed = 0
            target_integrity_after_event_id = 0
            capture_schema_errors = self._capture_operation_schema_errors(conn)
            if capture_schema_errors:
                raise RuntimeError(
                    "capture operation ledger failed schema validation "
                    f"(samples={capture_schema_errors[:3]!r})"
                )
            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("capture_operations_v1",),
            ).fetchone():
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("capture_operations_v1", time.time()),
                )
            self._scrub_legacy_capture_operation_receipts(conn)
            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("capture_operations_private_receipts_v1",),
            ).fetchone():
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("capture_operations_private_receipts_v1", time.time()),
                )
            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("secret_content_scrub_v1",),
            ).fetchone():
                index_rows_changed += self._scrub_legacy_secret_content(conn)
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("secret_content_scrub_v1", time.time()),
                )
            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("raw_digest_oracle_scrub_v1",),
            ).fetchone():
                index_rows_changed += self._scrub_legacy_secret_content(conn)
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("raw_digest_oracle_scrub_v1", time.time()),
                )
            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("secret_content_scrub_v2",),
            ).fetchone():
                index_rows_changed += self._scrub_legacy_secret_content(conn)
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("secret_content_scrub_v2", time.time()),
                )
            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("secret_content_scrub_v3",),
            ).fetchone():
                index_rows_changed += self._scrub_legacy_secret_content(conn)
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("secret_content_scrub_v3", time.time()),
                )
            if not startup_target_integrity_required:
                target_integrity_after_event_id = (
                    self._read_context_event_target_highwater(
                        conn,
                        allow_missing=False,
                    )
                )
            target_migration_was_applied = bool(
                conn.execute(
                    "SELECT 1 FROM store_migrations WHERE key = ?",
                    ("context_event_targets_v2",),
                ).fetchone()
            )
            if (
                not conn.execute(
                    "SELECT 1 FROM store_migrations WHERE key = ?",
                    ("context_deliveries_v2",),
                ).fetchone()
                or not self._context_delivery_schema_is_v2(conn)
                or not self._context_delivery_data_is_v2(conn)
            ):
                self._ensure_context_delivery_schema_v2(
                    conn,
                    migrated_at=time.time(),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("context_deliveries_v2", time.time()),
                )

            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("secret_identifier_audit_v1",),
            ).fetchone():
                identifier_findings = self._legacy_secret_identifier_counts(conn)
                if identifier_findings:
                    raise RuntimeError(
                        "legacy secret-bearing identifiers require governed repair "
                        f"(affected_cells={sum(identifier_findings.values())}, "
                        f"columns={sorted(identifier_findings)})"
                    )
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("secret_identifier_audit_v1", time.time()),
                )
            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("legacy_ack_receipts_retirement_v1",),
            ).fetchone():
                self._retire_legacy_ack_receipts(conn)
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("legacy_ack_receipts_retirement_v1", time.time()),
                )

            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("memory_spikes_v1",),
            ).fetchone():
                rows = conn.execute(
                    """
                    SELECT memory_id, context_id, spike_indices_json
                    FROM memory_entries
                    """
                ).fetchall()
                for row in rows:
                    spike_rows = [
                        (
                            str(row["memory_id"]),
                            str(row["context_id"]),
                            int(spike_index),
                        )
                        for spike_index in sorted(
                            {
                                int(value)
                                for value in _decode_json(
                                    str(row["spike_indices_json"]),
                                    [],
                                )
                            }
                        )
                    ]
                    if spike_rows:
                        cursor = conn.executemany(
                            """
                            INSERT OR IGNORE INTO memory_spikes (
                                memory_id,
                                context_id,
                                spike_index
                            )
                            VALUES (?, ?, ?)
                            """,
                            spike_rows,
                        )
                        index_rows_changed += max(0, int(cursor.rowcount))
                conn.execute(
                    """
                    INSERT OR REPLACE INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("memory_spikes_v1", time.time()),
                )

            if not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("memory_surface_terms_v1",),
            ).fetchone():
                rows = conn.execute(
                    """
                    SELECT memory_id, context_id, tag, source_text, metadata_json
                    FROM memory_entries
                    """
                ).fetchall()
                for row in rows:
                    surface_rows = self._surface_term_rows(
                        memory_id=str(row["memory_id"]),
                        context_id=str(row["context_id"]),
                        tag=str(row["tag"]),
                        source_text=str(row["source_text"]),
                        metadata=_decode_json(str(row["metadata_json"]), {}),
                    )
                    if surface_rows:
                        cursor = conn.executemany(
                            """
                            INSERT OR IGNORE INTO memory_surface_terms (
                                memory_id,
                                context_id,
                                term,
                                weight
                            )
                            VALUES (?, ?, ?, ?)
                            """,
                            surface_rows,
                        )
                        index_rows_changed += max(0, int(cursor.rowcount))
                conn.execute(
                    """
                    INSERT OR REPLACE INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("memory_surface_terms_v1", time.time()),
                )

            if (
                not conn.execute(
                    "SELECT 1 FROM store_migrations WHERE key = ?",
                    ("context_event_targets_v2",),
                ).fetchone()
                or self._context_event_target_reconciliation_needed(conn)
            ):
                self._reconcile_context_event_targets(
                    conn,
                    reconciled_at=time.time(),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("context_event_targets_v2", time.time()),
                )
            # Canonicalization is a one-time legacy migration.  Once the v2
            # marker exists, changing routed target evidence would hide
            # corruption; the integrity gate below must fail closed instead.
            if (
                not target_migration_was_applied
                and self._context_event_target_canonicalization_needed(conn)
            ):
                self._canonicalize_context_event_targets(conn)

            (
                target_integrity_error_count,
                target_integrity_samples,
                _,
                _,
            ) = self._context_event_target_integrity_audit(
                conn,
                after_event_id=target_integrity_after_event_id,
            )
            if not startup_target_integrity_required:
                (
                    missing_target_error_count,
                    missing_target_samples,
                    _,
                    _,
                ) = self._context_event_target_integrity_audit(
                    conn,
                    missing_targets_only=True,
                )
                if missing_target_error_count:
                    target_integrity_error_count += missing_target_error_count
                    target_integrity_samples.extend(missing_target_samples)
            if target_integrity_error_count:
                raise RuntimeError(
                    "context event targets failed integrity validation "
                    f"(routed_events={target_integrity_error_count}, "
                    f"samples={target_integrity_samples[:3]!r})"
                )
            (
                event_ledger_integrity_error_count,
                event_ledger_integrity_samples,
            ) = self._context_event_ledger_integrity_audit(
                conn,
                after_event_id=target_integrity_after_event_id,
            )
            if event_ledger_integrity_error_count:
                raise RuntimeError(
                    "context event ledger failed integrity validation "
                    f"(events={event_ledger_integrity_error_count}, "
                    f"samples={event_ledger_integrity_samples[:3]!r})"
                )
            target_highwater_error_count, target_highwater_samples = (
                self._context_event_target_highwater_audit(conn)
            )
            if target_highwater_error_count:
                raise RuntimeError(
                    "context event target reconciliation highwater failed "
                    f"integrity validation (samples={target_highwater_samples!r})"
                )
            (
                capture_integrity_error_count,
                capture_integrity_samples,
            ) = self._capture_operation_integrity_audit(conn)
            if capture_integrity_error_count:
                raise RuntimeError(
                    "capture operation ledger failed integrity validation "
                    f"(operations={capture_integrity_error_count}, "
                    f"samples={capture_integrity_samples[:3]!r})"
                )

            if core_migration_required and not conn.execute(
                "SELECT 1 FROM store_migrations WHERE key = ?",
                ("authoritative_core_v1",),
            ).fetchone():
                conn.execute(
                    """
                    INSERT INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("authoritative_core_v1", time.time()),
                )

            if index_rows_changed:
                generation_row = conn.execute(
                    "SELECT value_json FROM store_metadata WHERE key = ?",
                    ("semantic_index_generation",),
                ).fetchone()
                try:
                    generation = int(
                        _decode_json(str(generation_row["value_json"]), 0)
                        if generation_row is not None
                        else 0
                    )
                except (TypeError, ValueError, OverflowError):
                    generation = 0
                conn.execute(
                    """
                    INSERT INTO store_metadata (key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        "semantic_index_generation",
                        json.dumps(generation + 1),
                        time.time(),
                    ),
                )
        self._target_integrity_verified = True
        self._capture_integrity_verified = True

    def _protect_path(self, path: Path, *, directory: bool) -> None:
        try:
            if path.exists():
                path.chmod(0o700 if directory else 0o600)
        except PermissionError:
            LOGGER.warning("could not chmod private memory-store path %s", path)

    def _ensure_directory(self, path: Path, *, owned: bool) -> None:
        """Create a directory without silently repairing an unsafe existing path.

        Directories owned by SYNAPSE-S2 are part of the persistence trust
        boundary.  An existing directory therefore has to arrive with the
        exact owner and mode we require; changing it in place would turn a
        pre-existing shared path into an apparently trusted one.  Missing
        components are created one at a time so every pathname transition is
        inspected instead of delegated to ``mkdir(parents=True)``.
        """

        target = Path(path).expanduser().absolute()
        missing: list[Path] = []
        cursor = target
        while True:
            try:
                metadata = os.lstat(cursor)
            except FileNotFoundError:
                missing.append(cursor)
                parent = cursor.parent
                if parent == cursor:
                    raise PermissionError(
                        f"directory has no existing trusted ancestor: {target}"
                    )
                cursor = parent
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise PermissionError(
                    f"directory path component is not a real directory: {cursor}"
                )
            break

        for candidate in reversed(missing):
            created = False
            try:
                os.mkdir(candidate, 0o700)
                created = True
            except FileExistsError:
                # A concurrent creator is acceptable only when it published the
                # exact private directory contract expected below.
                pass
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise PermissionError(
                    f"directory path component changed during creation: {candidate}"
                )
            if created:
                os.chmod(candidate, 0o700, follow_symlinks=False)
                metadata = os.lstat(candidate)
                self._fsync_directory(candidate.parent)
            if owned and (
                metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise PermissionError(
                    f"owned directory must already be private: {candidate}"
                )

        final = os.lstat(target)
        if stat.S_ISLNK(final.st_mode) or not stat.S_ISDIR(final.st_mode):
            raise PermissionError(f"directory path is not a real directory: {target}")
        if owned and (
            final.st_uid != os.getuid()
            or stat.S_IMODE(final.st_mode) != 0o700
        ):
            raise PermissionError(
                f"owned directory must already be private: {target}"
            )

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _fsync_file(path: Path) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _unique_private_temp_path(parent: Path, *, prefix: str) -> Path:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=prefix,
            suffix=".tmp",
            dir=str(parent),
        )
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        return Path(raw_path)

    def _initialize(self) -> None:
        try:
            with closing(self._connect()):
                return
        except Exception:
            LOGGER.exception("failed to initialize SYNAPSE-S2 memory store at %s", self.db_path)
            raise

    def stable_memory_id(self, *, context_id: str, tag: str) -> str:
        key = f"{context_id}\x1f{tag}".encode("utf-8")
        return "s2_" + hashlib.sha256(key).hexdigest()[:32]

    def stable_relationship_id(
        self,
        *,
        context_id: str,
        source_memory_id: str,
        target_memory_id: str,
        relation_type: str,
    ) -> str:
        key = (
            f"{context_id}\x1f{source_memory_id}\x1f"
            f"{target_memory_id}\x1f{relation_type}"
        ).encode("utf-8")
        return "s2r_" + hashlib.sha256(key).hexdigest()[:32]

    def stable_context_link_id(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        relation_type: str,
        direction: str = "bidirectional",
    ) -> str:
        normalized_direction = self._normalize_context_link_direction(direction)
        source = str(source_context_id).strip()
        target = str(target_context_id).strip()
        if normalized_direction == "bidirectional" and target < source:
            source, target = target, source
        key = (
            f"{source}\x1f{target}\x1f{str(relation_type).strip()}\x1f"
            f"{normalized_direction}"
        ).encode("utf-8")
        return "s2cl_" + hashlib.sha256(key).hexdigest()[:32]

    def _record_namespace_catalog_conn(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str,
        observed_at: float | None = None,
    ) -> None:
        """Remember a namespace independently of its remaining memory rows.

        The catalog deliberately uses the versioned ``store_metadata``
        extension point rather than changing the certified v6 SQLite schema.
        It is therefore included in logical snapshots and verified recovery
        bundles without weakening the exact schema contract.  Callers invoke
        this helper inside the same transaction that first observes durable
        namespace activity.
        """

        clean_context = reject_sensitive_identifier(
            context_id,
            field="context_id",
        )
        if not self._context_event_context_id_is_valid(clean_context):
            raise ValueError(
                "context_id must be stripped, nonempty, and at most 128 characters"
            )
        timestamp = time.time() if observed_at is None else float(observed_at)
        if not self._context_delivery_timestamp_is_valid(timestamp):
            raise ValueError("namespace observation time must be a finite timestamp")
        key = f"{NAMESPACE_CATALOG_METADATA_PREFIX}{clean_context}"
        row = conn.execute(
            "SELECT value_json FROM store_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        created_at = timestamp
        last_seen_at = timestamp
        if row is not None:
            existing = _decode_json(str(row["value_json"]), {})
            if isinstance(existing, dict):
                try:
                    candidate = float(existing.get("created_at", timestamp))
                except (TypeError, ValueError, OverflowError):
                    candidate = timestamp
                if self._context_delivery_timestamp_is_valid(candidate):
                    created_at = min(candidate, timestamp)
                try:
                    prior_last_seen = float(existing.get("last_seen_at", timestamp))
                except (TypeError, ValueError, OverflowError):
                    prior_last_seen = timestamp
                if self._context_delivery_timestamp_is_valid(prior_last_seen):
                    last_seen_at = max(prior_last_seen, timestamp)
        payload = {
            "schema": NAMESPACE_CATALOG_SCHEMA,
            "context_id": clean_context,
            "state": "active",
            "created_at": created_at,
            "last_seen_at": last_seen_at,
        }
        conn.execute(
            """
            INSERT INTO store_metadata (key, value_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            """,
            (key, _json_dumps(payload), last_seen_at),
        )

    @staticmethod
    def _validate_capture_id(capture_id: Any) -> str:
        if type(capture_id) is not str or CAPTURE_ID_RE.fullmatch(capture_id) is None:
            raise ValueError(
                "capture_id must be canonical s2cap_ followed by 32 lowercase hex characters"
            )
        return capture_id

    @staticmethod
    def _validate_capture_fingerprint(request_fingerprint: Any) -> str:
        if (
            type(request_fingerprint) is not str
            or CAPTURE_REQUEST_FINGERPRINT_RE.fullmatch(request_fingerprint) is None
        ):
            raise ValueError(
                "request_fingerprint must be exactly 64 lowercase hex characters"
            )
        return request_fingerprint

    @staticmethod
    def _validate_capture_identity_text(
        value: Any,
        *,
        field: str,
        max_length: int,
    ) -> str:
        if (
            type(value) is not str
            or not value
            or value != value.strip()
            or len(value) > max_length
        ):
            raise ValueError(
                f"{field} must be a stripped, nonempty string no longer than {max_length} characters"
            )
        return reject_sensitive_identifier(value, field=field)

    @staticmethod
    def _validate_capture_timestamp(value: Any, *, field: str) -> float:
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or abs(float(value)) >= 1.0e308
        ):
            raise ValueError(f"{field} must be a finite timestamp")
        return float(value)

    def _normalize_capture_plan_entries(
        self,
        entries: Iterable[dict[str, Any]],
        *,
        context_id: str,
        default_timestamp: float,
    ) -> list[dict[str, Any]]:
        if isinstance(entries, (str, bytes, dict)):
            raise ValueError("entries must be an iterable of objects")
        try:
            raw_entries = list(entries)
        except TypeError as exc:
            raise ValueError("entries must be an iterable of objects") from exc
        normalized: list[dict[str, Any]] = []
        seen_memory_ids: set[str] = set()
        for index, raw_entry in enumerate(raw_entries):
            if not isinstance(raw_entry, dict):
                raise ValueError(f"entries[{index}] must be an object")
            entry_context = raw_entry.get("context_id", context_id)
            if entry_context != context_id:
                raise ValueError(f"entries[{index}].context_id must match capture context_id")
            tag = self._validate_capture_identity_text(
                raw_entry.get("tag"),
                field=f"entries[{index}].tag",
                max_length=200,
            )
            source_text = raw_entry.get("source_text", "")
            if type(source_text) is not str:
                raise ValueError(f"entries[{index}].source_text must be a string")
            source_text, _ = redact_capture_text(source_text)
            metadata = raw_entry.get("metadata", {})
            if not isinstance(metadata, dict):
                raise ValueError(f"entries[{index}].metadata must be an object")
            metadata_json = _capture_json_dumps(
                metadata,
                field=f"entries[{index}].metadata",
            )
            embedding_dimensions = raw_entry.get("embedding_dimensions")
            if type(embedding_dimensions) is not int or embedding_dimensions <= 0:
                raise ValueError(
                    f"entries[{index}].embedding_dimensions must be a positive exact integer"
                )
            spike_indices = raw_entry.get("spike_indices", [])
            neuron_indices = raw_entry.get("neuron_indices", [])
            if not isinstance(spike_indices, (list, tuple)):
                raise ValueError(f"entries[{index}].spike_indices must be a list")
            if not isinstance(neuron_indices, (list, tuple)):
                raise ValueError(f"entries[{index}].neuron_indices must be a list")
            if any(type(value) is not int for value in spike_indices):
                raise ValueError(
                    f"entries[{index}].spike_indices must contain exact integers"
                )
            if any(
                value < 0 or value >= embedding_dimensions
                for value in spike_indices
            ):
                raise ValueError(
                    f"entries[{index}].spike_indices must be within embedding dimensions"
                )
            if any(type(value) is not int or value < 0 for value in neuron_indices):
                raise ValueError(
                    f"entries[{index}].neuron_indices must contain non-negative exact integers"
                )
            clean_spike_indices = sorted(set(spike_indices))
            clean_neuron_indices = list(dict.fromkeys(neuron_indices))
            registered_at = self._validate_capture_timestamp(
                raw_entry.get("registered_at", default_timestamp),
                field=f"entries[{index}].registered_at",
            )
            memory_id = self.stable_memory_id(context_id=context_id, tag=tag)
            supplied_memory_id = raw_entry.get("memory_id")
            if supplied_memory_id is not None and supplied_memory_id != memory_id:
                raise ValueError(
                    f"entries[{index}].memory_id does not match the stable store identity"
                )
            if memory_id in seen_memory_ids:
                raise ValueError(f"entries[{index}] duplicates memory_id {memory_id}")
            seen_memory_ids.add(memory_id)
            normalized.append(
                {
                    "memory_id": memory_id,
                    "tag": tag,
                    "context_id": context_id,
                    "source_text": source_text,
                    "metadata": json.loads(metadata_json),
                    "metadata_json": metadata_json,
                    "embedding_dimensions": embedding_dimensions,
                    "clean_spike_indices": clean_spike_indices,
                    "clean_neuron_indices": clean_neuron_indices,
                    "spike_json": _json_list(clean_spike_indices),
                    "neuron_json": _json_list(clean_neuron_indices),
                    "registered_at": registered_at,
                }
            )
        return normalized

    def _normalize_capture_plan_relationships(
        self,
        relationships: Iterable[dict[str, Any]],
        *,
        context_id: str,
        default_timestamp: float,
    ) -> list[dict[str, Any]]:
        if isinstance(relationships, (str, bytes, dict)):
            raise ValueError("relationships must be an iterable of objects")
        try:
            raw_relationships = list(relationships)
        except TypeError as exc:
            raise ValueError("relationships must be an iterable of objects") from exc
        normalized: list[dict[str, Any]] = []
        seen_relationship_ids: set[str] = set()
        for index, raw_relationship in enumerate(raw_relationships):
            if not isinstance(raw_relationship, dict):
                raise ValueError(f"relationships[{index}] must be an object")
            relationship_context = raw_relationship.get("context_id", context_id)
            if relationship_context != context_id:
                raise ValueError(
                    f"relationships[{index}].context_id must match capture context_id"
                )
            source_memory_id = self._validate_capture_identity_text(
                raw_relationship.get("source_memory_id"),
                field=f"relationships[{index}].source_memory_id",
                max_length=160,
            )
            target_memory_id = self._validate_capture_identity_text(
                raw_relationship.get("target_memory_id"),
                field=f"relationships[{index}].target_memory_id",
                max_length=160,
            )
            relation_type = self._validate_capture_identity_text(
                raw_relationship.get("relation_type"),
                field=f"relationships[{index}].relation_type",
                max_length=200,
            )
            raw_weight = raw_relationship.get("weight")
            if (
                not isinstance(raw_weight, (int, float))
                or isinstance(raw_weight, bool)
                or not math.isfinite(float(raw_weight))
                or not 0.0 <= float(raw_weight) <= 1.0
            ):
                raise ValueError(
                    f"relationships[{index}].weight must be finite and between 0 and 1"
                )
            evidence = raw_relationship.get("evidence", {})
            if not isinstance(evidence, dict):
                raise ValueError(f"relationships[{index}].evidence must be an object")
            evidence_json = _capture_json_dumps(
                evidence,
                field=f"relationships[{index}].evidence",
            )
            created_at = self._validate_capture_timestamp(
                raw_relationship.get("created_at", default_timestamp),
                field=f"relationships[{index}].created_at",
            )
            updated_at = self._validate_capture_timestamp(
                raw_relationship.get("updated_at", created_at),
                field=f"relationships[{index}].updated_at",
            )
            if updated_at < created_at:
                raise ValueError(
                    f"relationships[{index}].updated_at must not precede created_at"
                )
            relationship_id = self.stable_relationship_id(
                context_id=context_id,
                source_memory_id=source_memory_id,
                target_memory_id=target_memory_id,
                relation_type=relation_type,
            )
            supplied_relationship_id = raw_relationship.get("relationship_id")
            if (
                supplied_relationship_id is not None
                and supplied_relationship_id != relationship_id
            ):
                raise ValueError(
                    f"relationships[{index}].relationship_id does not match the stable store identity"
                )
            if relationship_id in seen_relationship_ids:
                raise ValueError(
                    f"relationships[{index}] duplicates relationship_id {relationship_id}"
                )
            seen_relationship_ids.add(relationship_id)
            normalized.append(
                {
                    "relationship_id": relationship_id,
                    "context_id": context_id,
                    "source_memory_id": source_memory_id,
                    "target_memory_id": target_memory_id,
                    "relation_type": relation_type,
                    "weight": float(raw_weight),
                    "evidence_json": evidence_json,
                    "created_at": created_at,
                    "updated_at": updated_at,
                }
            )
        return normalized

    def _normalize_capture_plan_deployment(
        self,
        deployment: dict[str, Any],
        *,
        context_id: str,
        default_timestamp: float,
    ) -> dict[str, Any]:
        if not isinstance(deployment, dict):
            raise ValueError("deployment must be an object")
        deployment_context = deployment.get("context_id", context_id)
        if deployment_context != context_id:
            raise ValueError("deployment.context_id must match capture context_id")
        source_surface = self._validate_capture_identity_text(
            deployment.get("source_surface"),
            field="deployment.source_surface",
            max_length=200,
        )
        event_type = self._validate_capture_identity_text(
            deployment.get("event_type"),
            field="deployment.event_type",
            max_length=200,
        )
        summary = deployment.get("summary", "")
        if type(summary) is not str:
            raise ValueError("deployment.summary must be a string")
        payload = deployment.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("deployment.payload must be an object")
        payload_json = _capture_json_dumps(payload, field="deployment.payload")
        raw_targets = deployment.get("agent_targets", ["mcp-clients"])
        if not isinstance(raw_targets, (list, tuple)):
            raise ValueError("deployment.agent_targets must be a list of strings")
        if any(type(value) is not str or not value.strip() for value in raw_targets):
            raise ValueError("deployment.agent_targets must contain nonempty strings")
        targets = self._normalize_event_targets(raw_targets)
        if not targets:
            targets = ["mcp-clients"]
        if not self._normalized_event_target_records(targets):
            raise ValueError("deployment.agent_targets did not resolve to valid targets")
        created_at = self._validate_capture_timestamp(
            deployment.get("created_at", default_timestamp),
            field="deployment.created_at",
        )
        return {
            "context_id": context_id,
            "source_surface": source_surface,
            "event_type": event_type,
            "summary": summary,
            "payload_json": payload_json,
            "targets": targets,
            "created_at": created_at,
        }

    def _capture_operation_envelope_from_row(
        self,
        row: sqlite3.Row,
        *,
        live_event: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raw_result = str(row["result_json"])
        try:
            envelope = json.loads(raw_result)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"capture operation {row['capture_id']} has invalid result_json"
            ) from exc
        reasons = self._capture_operation_receipt_reasons(
            row,
            envelope,
            raw_result,
            live_event=live_event,
        )
        if reasons:
            raise RuntimeError(
                f"capture operation {row['capture_id']} has an invalid private receipt "
                f"(reasons={sorted(set(reasons))!r})"
            )
        return envelope

    def get_capture_operation(self, capture_id: str) -> dict[str, Any] | None:
        clean_capture_id = self._validate_capture_id(capture_id)
        with closing(self._connect_read_only()) as conn:
            row = conn.execute(
                """
                SELECT
                    operation.*,
                    event.context_id AS live_event_context_id,
                    event.event_type AS live_event_type,
                    event.source_surface AS live_event_source_surface,
                    event.created_at AS live_event_published_at
                FROM capture_operations AS operation
                LEFT JOIN agent_context_events AS event
                  ON event.event_id = operation.deployment_event_id
                WHERE operation.capture_id = ?
                """,
                (clean_capture_id,),
            ).fetchone()
        if row is None:
            return None
        envelope = self._capture_operation_envelope_from_row(
            row,
            live_event=self._capture_operation_live_event(row),
        )
        return {**envelope, "idempotent_replay": True}

    def commit_capture_plan(
        self,
        *,
        capture_id: str,
        request_fingerprint: str,
        context_id: str,
        source_tag: str,
        speaker: str,
        entries: Iterable[dict[str, Any]],
        relationships: Iterable[dict[str, Any]],
        deployment: dict[str, Any],
        result: dict[str, Any],
        fault_hook: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Atomically commit a pure capture plan or replay its durable receipt."""

        clean_capture_id = self._validate_capture_id(capture_id)
        clean_fingerprint = self._validate_capture_fingerprint(request_fingerprint)
        clean_context = self._validate_capture_identity_text(
            context_id,
            field="context_id",
            max_length=128,
        )
        clean_source_tag = self._validate_capture_identity_text(
            source_tag,
            field="source_tag",
            max_length=200,
        )
        clean_speaker = self._validate_capture_identity_text(
            speaker,
            field="speaker",
            max_length=128,
        )
        if type(result) is not dict:
            raise ValueError("result must be an object")
        if fault_hook is not None and not callable(fault_hook):
            raise ValueError("fault_hook must be callable")
        plan_timestamp = time.time()
        normalized_entries = self._normalize_capture_plan_entries(
            entries,
            context_id=clean_context,
            default_timestamp=plan_timestamp,
        )
        normalized_relationships = self._normalize_capture_plan_relationships(
            relationships,
            context_id=clean_context,
            default_timestamp=plan_timestamp,
        )
        plan_memory_ids = {
            str(entry["memory_id"])
            for entry in normalized_entries
        }
        for index, relationship in enumerate(normalized_relationships):
            missing_endpoints = [
                field
                for field in ("source_memory_id", "target_memory_id")
                if str(relationship[field]) not in plan_memory_ids
            ]
            if missing_endpoints:
                raise ValueError(
                    f"relationships[{index}] endpoints must reference entries in "
                    "the same capture plan; missing "
                    + ", ".join(missing_endpoints)
                )
        event_count = self._capture_operation_bounded_count(
            result.get("event_count"),
            field="result.event_count",
        )
        if event_count > len(normalized_entries):
            raise ValueError("result.event_count must not exceed capture entry_count")
        self._capture_operation_bounded_count(
            len(normalized_entries),
            field="entry_count",
        )
        self._capture_operation_bounded_count(
            len(normalized_relationships),
            field="relationship_count",
        )
        normalized_deployment = self._normalize_capture_plan_deployment(
            deployment,
            context_id=clean_context,
            default_timestamp=plan_timestamp,
        )

        with closing(self._connect()) as conn:
            with self._transaction(conn, immediate=True):
                existing = conn.execute(
                    "SELECT * FROM capture_operations WHERE capture_id = ?",
                    (clean_capture_id,),
                ).fetchone()
                if existing is not None:
                    mismatch_fields = [
                        field
                        for field, expected in (
                            ("request_fingerprint", clean_fingerprint),
                            ("context_id", clean_context),
                            ("source_tag", clean_source_tag),
                            ("speaker", clean_speaker),
                        )
                        if str(existing[field]) != expected
                    ]
                    if mismatch_fields:
                        raise ValueError(
                            "capture_id is already committed with a different "
                            + ", ".join(mismatch_fields)
                        )
                    envelope = self._capture_operation_envelope_from_row(existing)
                    return {**envelope, "idempotent_replay": True}

                for entry in normalized_entries:
                    self._upsert_entry_conn(conn, **entry)
                if fault_hook is not None:
                    fault_hook("after_entries")

                for relationship in normalized_relationships:
                    self._upsert_relationship_conn(conn, **relationship)
                if fault_hook is not None:
                    fault_hook("after_relationships")

                deployment_event = self._publish_context_event_conn(
                    conn,
                    **normalized_deployment,
                )
                if fault_hook is not None:
                    fault_hook("after_deployment")

                committed_at = time.time()
                envelope, envelope_json = (
                    self._build_private_capture_operation_receipt(
                        capture_id=clean_capture_id,
                        request_fingerprint=clean_fingerprint,
                        context_id=clean_context,
                        source_tag=clean_source_tag,
                        speaker=clean_speaker,
                        deployment_event_id=int(deployment_event["event_id"]),
                        deployment_event_type=str(deployment_event["event_type"]),
                        deployment_source_surface=str(
                            deployment_event["source_surface"]
                        ),
                        deployment_published_at=float(
                            deployment_event["created_at"]
                        ),
                        event_count=event_count,
                        entry_count=len(normalized_entries),
                        relationship_count=len(normalized_relationships),
                        committed_at=committed_at,
                    )
                )
                if fault_hook is not None:
                    fault_hook("before_ledger")
                conn.execute(
                    """
                    INSERT INTO capture_operations (
                        capture_id,
                        protocol,
                        request_fingerprint,
                        context_id,
                        source_tag,
                        speaker,
                        result_json,
                        deployment_event_id,
                        entry_count,
                        relationship_count,
                        committed_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        clean_capture_id,
                        CAPTURE_PROTOCOL_VERSION,
                        clean_fingerprint,
                        clean_context,
                        clean_source_tag,
                        clean_speaker,
                        envelope_json,
                        int(deployment_event["event_id"]),
                        len(normalized_entries),
                        len(normalized_relationships),
                        committed_at,
                    ),
                )
        return {**envelope, "idempotent_replay": False}

    @staticmethod
    def _normalize_recall_scope(scope: str) -> str:
        normalized = str(scope or "local").strip().lower()
        if normalized == "broad":
            normalized = "all"
        if normalized not in {"local", "connected", "all"}:
            raise ValueError("recall scope must be local, connected, or all")
        return normalized

    @staticmethod
    def _normalize_context_link_direction(direction: str) -> str:
        normalized = str(direction or "bidirectional").strip().lower()
        if normalized in {"both", "two-way", "two_way", "undirected"}:
            normalized = "bidirectional"
        if normalized in {"one-way", "one_way", "outbound"}:
            normalized = "directed"
        if normalized not in {"directed", "bidirectional"}:
            raise ValueError("direction must be directed or bidirectional")
        return normalized

    def upsert_entry(
        self,
        *,
        tag: str,
        context_id: str,
        source_text: str,
        metadata: dict[str, Any] | None,
        embedding_dimensions: int,
        spike_indices: Iterable[int],
        neuron_indices: Iterable[int],
        registered_at: float | None = None,
    ) -> dict[str, Any]:
        clean_context_id = reject_sensitive_identifier(
            context_id,
            field="context_id",
        )
        clean_tag = reject_sensitive_identifier(tag, field="tag")
        safe_source_text, _ = redact_capture_text(str(source_text or ""))
        safe_metadata = _json_safe(metadata or {}, {})
        if type(embedding_dimensions) is not int or embedding_dimensions <= 0:
            raise ValueError("embedding_dimensions must be a positive exact integer")
        raw_spike_indices = list(spike_indices)
        if any(type(value) is not int for value in raw_spike_indices):
            raise ValueError("spike_indices must contain exact integers, not booleans")
        if any(
            value < 0 or value >= embedding_dimensions
            for value in raw_spike_indices
        ):
            raise ValueError(
                "spike_indices must be within [0, embedding_dimensions)"
            )
        raw_neuron_indices = list(neuron_indices)
        if any(type(value) is not int for value in raw_neuron_indices):
            raise ValueError("neuron_indices must contain exact integers, not booleans")
        if any(value < 0 for value in raw_neuron_indices):
            raise ValueError("neuron_indices must be non-negative")
        memory_id = self.stable_memory_id(
            context_id=clean_context_id,
            tag=clean_tag,
        )
        now = float(registered_at or time.time())
        metadata_json = _json_dumps(safe_metadata)
        clean_spike_indices = sorted(set(raw_spike_indices))
        clean_neuron_indices = list(dict.fromkeys(raw_neuron_indices))
        spike_json = _json_list(clean_spike_indices)
        neuron_json = _json_list(clean_neuron_indices)
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    entry = self._upsert_entry_conn(
                        conn,
                        memory_id=memory_id,
                        tag=clean_tag,
                        context_id=clean_context_id,
                        source_text=safe_source_text,
                        metadata=safe_metadata,
                        metadata_json=metadata_json,
                        embedding_dimensions=int(embedding_dimensions),
                        clean_spike_indices=clean_spike_indices,
                        clean_neuron_indices=clean_neuron_indices,
                        spike_json=spike_json,
                        neuron_json=neuron_json,
                        registered_at=now,
                    )
            return entry
        except Exception:
            LOGGER.exception("failed to upsert memory entry tag=%s context_id=%s", tag, context_id)
            raise

    def _upsert_entry_conn(
        self,
        conn: sqlite3.Connection,
        *,
        memory_id: str,
        tag: str,
        context_id: str,
        source_text: str,
        metadata: dict[str, Any],
        metadata_json: str,
        embedding_dimensions: int,
        clean_spike_indices: list[int],
        clean_neuron_indices: list[int],
        spike_json: str,
        neuron_json: str,
        registered_at: float,
    ) -> dict[str, Any]:
        updated_at = time.time()
        self._record_namespace_catalog_conn(
            conn,
            context_id=context_id,
            observed_at=updated_at,
        )
        conn.execute(
            """
            INSERT INTO memory_entries (
                memory_id,
                tag,
                context_id,
                source_text,
                metadata_json,
                embedding_dimensions,
                spike_indices_json,
                neuron_indices_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(memory_id) DO UPDATE SET
                tag = excluded.tag,
                context_id = excluded.context_id,
                source_text = excluded.source_text,
                metadata_json = excluded.metadata_json,
                embedding_dimensions = excluded.embedding_dimensions,
                spike_indices_json = excluded.spike_indices_json,
                neuron_indices_json = excluded.neuron_indices_json,
                updated_at = excluded.updated_at
            """,
            (
                memory_id,
                tag,
                context_id,
                source_text,
                metadata_json,
                embedding_dimensions,
                spike_json,
                neuron_json,
                registered_at,
                updated_at,
            ),
        )
        conn.execute(
            "DELETE FROM memory_spikes WHERE memory_id = ?",
            (memory_id,),
        )
        if clean_spike_indices:
            conn.executemany(
                """
                INSERT INTO memory_spikes (
                    memory_id,
                    context_id,
                    spike_index
                )
                VALUES (?, ?, ?)
                """,
                [
                    (memory_id, context_id, spike_index)
                    for spike_index in clean_spike_indices
                ],
            )
        conn.execute(
            "DELETE FROM memory_surface_terms WHERE memory_id = ?",
            (memory_id,),
        )
        surface_rows = self._surface_term_rows(
            memory_id=memory_id,
            context_id=context_id,
            tag=tag,
            source_text=source_text,
            metadata=metadata,
        )
        if surface_rows:
            conn.executemany(
                """
                INSERT INTO memory_surface_terms (
                    memory_id,
                    context_id,
                    term,
                    weight
                )
                VALUES (?, ?, ?, ?)
                """,
                surface_rows,
            )
        conn.execute(
            """
            INSERT INTO memory_events (
                memory_id,
                event_type,
                payload_json,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                memory_id,
                "upsert",
                _json_dumps(
                    {
                        "tag": tag,
                        "context_id": context_id,
                        "embedding_dimensions": embedding_dimensions,
                        "spike_count": len(clean_spike_indices),
                    }
                ),
                updated_at,
            ),
        )
        row = conn.execute(
            "SELECT * FROM memory_entries WHERE memory_id = ?",
            (memory_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError(f"memory entry {memory_id} was not readable after upsert")
        return self._row_to_entry(row)

    def get_entry(self, memory_id: str) -> dict[str, Any] | None:
        try:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    "SELECT * FROM memory_entries WHERE memory_id = ?",
                    (str(memory_id),),
                ).fetchone()
            return self._row_to_entry(row) if row is not None else None
        except Exception:
            LOGGER.exception("failed to read memory entry %s", memory_id)
            raise

    def list_entries(
        self,
        *,
        context_id: str | None = None,
        limit: int = 50,
        include_global: bool = False,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        bounded_limit = min(max(int(limit), 1), 10_000)
        try:
            with self._read_connection_scope(_conn) as conn:
                if context_id is None:
                    rows = conn.execute(
                        """
                        SELECT * FROM memory_entries
                        ORDER BY updated_at DESC, created_at DESC
                        LIMIT ?
                        """,
                        (bounded_limit,),
                    ).fetchall()
                elif include_global and context_id != "global":
                    rows = conn.execute(
                        """
                        SELECT * FROM memory_entries
                        WHERE context_id IN (?, 'global')
                        ORDER BY updated_at DESC, created_at DESC
                        LIMIT ?
                        """,
                        (context_id, bounded_limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM memory_entries
                        WHERE context_id = ?
                        ORDER BY updated_at DESC, created_at DESC
                        LIMIT ?
                        """,
                        (context_id, bounded_limit),
                    ).fetchall()
            return [self._row_to_entry(row) for row in rows]
        except Exception:
            LOGGER.exception("failed to list memory entries for context_id=%s", context_id)
            raise

    def list_entries_by_ids(
        self,
        memory_ids: Iterable[str],
        *,
        context_id: str | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        """Batch-load entries by primary key while preserving caller order."""
        ordered_ids: list[str] = []
        seen: set[str] = set()
        bounded_limit = min(max(int(limit), 1), 10_000)
        for raw_memory_id in memory_ids:
            memory_id = str(raw_memory_id or "").strip()
            if not memory_id or memory_id in seen:
                continue
            seen.add(memory_id)
            ordered_ids.append(memory_id)
            if len(ordered_ids) >= bounded_limit:
                break
        if not ordered_ids:
            return []

        placeholders = ",".join("?" for _ in ordered_ids)
        clauses = [f"memory_id IN ({placeholders})"]
        params: list[Any] = list(ordered_ids)
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        where_sql = " AND ".join(clauses)
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM memory_entries
                    WHERE {where_sql}
                    """,
                    tuple(params),
                ).fetchall()
            entries_by_id = {
                str(row["memory_id"]): self._row_to_entry(row)
                for row in rows
            }
            return [
                entries_by_id[memory_id]
                for memory_id in ordered_ids
                if memory_id in entries_by_id
            ]
        except Exception:
            LOGGER.exception("failed to batch-list memory entries")
            raise

    def namespace_graph_snapshot(
        self,
        *,
        context_id: str,
        entry_scan_limit: int = 10_000,
        relationship_scan_limit: int = 20_000,
        include_source_text: bool = True,
        include_relationship_evidence: bool = True,
        include_node_metadata: bool = True,
    ) -> dict[str, Any]:
        """Read a stable, context-isolated graph snapshot for UI drill-down.

        Rows are selected by primary-key order so repeated calls over unchanged
        data return the same bounded sample. Deleted/pruned rows cannot appear
        because those operations remove the durable rows and cascading edges.
        """
        context = str(context_id or "").strip()
        if not context:
            raise ValueError("context_id is required")
        if type(include_source_text) is not bool:
            raise ValueError("include_source_text must be a boolean")
        if type(include_relationship_evidence) is not bool:
            raise ValueError("include_relationship_evidence must be a boolean")
        if type(include_node_metadata) is not bool:
            raise ValueError("include_node_metadata must be a boolean")
        bounded_entry_limit = min(max(int(entry_scan_limit), 1), 10_000)
        bounded_relationship_limit = min(
            max(int(relationship_scan_limit), 1),
            50_000,
        )
        try:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN")
                entry_stats = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS entry_total,
                        COALESCE(MIN(created_at), 0.0) AS first_created_at,
                        COALESCE(MAX(updated_at), 0.0) AS last_updated_at
                    FROM memory_entries
                    WHERE context_id = ?
                    """,
                    (context,),
                ).fetchone()
                entry_columns = """
                    memory_id,
                    tag,
                    context_id,
                    metadata_json,
                    created_at,
                    updated_at
                """
                if include_source_text:
                    entry_columns += ", source_text"
                entry_rows = conn.execute(
                    f"""
                    SELECT {entry_columns}
                    FROM memory_entries
                    WHERE context_id = ?
                    ORDER BY memory_id
                    LIMIT ?
                    """,
                    (context, bounded_entry_limit),
                ).fetchall()
                # Count only edges whose two durable endpoints are still in the
                # requested context.  Foreign keys keep new data consistent, but
                # older databases can contain rows written before that guarantee
                # (or manually repaired rows).  A drill-down must never report an
                # edge that it cannot safely render.
                relationship_total = int(
                    conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM memory_relationships AS r
                        JOIN memory_entries AS source
                            ON source.memory_id = r.source_memory_id
                            AND source.context_id = r.context_id
                        JOIN memory_entries AS target
                            ON target.memory_id = r.target_memory_id
                            AND target.context_id = r.context_id
                        WHERE r.context_id = ?
                        """,
                        (context,),
                    ).fetchone()[0]
                )
                relationship_evidence_column = (
                    ", r.evidence_json" if include_relationship_evidence else ""
                )
                relationship_rows = conn.execute(
                    f"""
                    SELECT
                        r.relationship_id,
                        r.context_id,
                        r.source_memory_id,
                        r.target_memory_id,
                        r.relation_type,
                        r.weight,
                        r.created_at,
                        r.updated_at
                        {relationship_evidence_column},
                        source.tag AS source_tag,
                        target.tag AS target_tag
                    FROM memory_relationships AS r
                    JOIN memory_entries AS source
                        ON source.memory_id = r.source_memory_id
                        AND source.context_id = r.context_id
                    JOIN memory_entries AS target
                        ON target.memory_id = r.target_memory_id
                        AND target.context_id = r.context_id
                    WHERE r.context_id = ?
                    ORDER BY r.relationship_id
                    LIMIT ?
                    """,
                    (context, bounded_relationship_limit),
                ).fetchall()
                conn.commit()
            entry_total = int(entry_stats["entry_total"] if entry_stats else 0)
            return {
                "context_id": context,
                "entry_total": entry_total,
                "relationship_total": relationship_total,
                "first_created_at": float(
                    entry_stats["first_created_at"] if entry_stats else 0.0
                ),
                "last_updated_at": float(
                    entry_stats["last_updated_at"] if entry_stats else 0.0
                ),
                "entries": [
                    self._row_to_namespace_graph_entry(
                        row,
                        include_source_text=include_source_text,
                        include_node_metadata=include_node_metadata,
                    )
                    for row in entry_rows
                ],
                "relationships": [
                    self._row_to_namespace_graph_relationship(
                        row,
                        include_evidence=include_relationship_evidence,
                    )
                    for row in relationship_rows
                ],
                "entry_scan_limit": bounded_entry_limit,
                "relationship_scan_limit": bounded_relationship_limit,
                "entry_scan_truncated": entry_total > len(entry_rows),
                "relationship_scan_truncated": relationship_total
                > len(relationship_rows),
                "selection_order": {
                    "entries": "memory_id ascending",
                    "relationships": "relationship_id ascending",
                },
                "read_only": True,
            }
        except Exception:
            LOGGER.exception(
                "failed to read namespace graph snapshot context_id=%s",
                context,
            )
            raise

    def _row_to_namespace_graph_entry(
        self,
        row: sqlite3.Row,
        *,
        include_source_text: bool,
        include_node_metadata: bool,
    ) -> dict[str, Any]:
        raw_metadata = _decode_json(str(row["metadata_json"]), {})
        raw_metadata = raw_metadata if isinstance(raw_metadata, dict) else {}
        metadata_keys = (
            _NAMESPACE_GRAPH_NODE_METADATA_KEYS
            if include_node_metadata
            else _NAMESPACE_GRAPH_CLUSTER_METADATA_KEYS
        )
        projected_metadata = {
            key: raw_metadata[key]
            for key in metadata_keys
            if key in raw_metadata
        }
        raw_embedding_provider = raw_metadata.get("embedding_provider")
        if include_node_metadata and isinstance(raw_embedding_provider, dict):
            projected_metadata["embedding_provider"] = {
                key: raw_embedding_provider[key]
                for key in _NAMESPACE_GRAPH_EMBEDDING_PROVIDER_KEYS
                if key in raw_embedding_provider
            }
        safe_metadata = _json_safe(projected_metadata, {})
        return {
            "memory_id": redact_capture_text(str(row["memory_id"]))[0],
            "tag": redact_capture_text(str(row["tag"]))[0],
            "context_id": redact_capture_text(str(row["context_id"]))[0],
            "source_text": (
                redact_capture_text(str(row["source_text"]))[0]
                if include_source_text
                else ""
            ),
            "metadata": safe_metadata if isinstance(safe_metadata, dict) else {},
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    def _row_to_namespace_graph_relationship(
        self,
        row: sqlite3.Row,
        *,
        include_evidence: bool,
    ) -> dict[str, Any]:
        safe_evidence: Any = {}
        if include_evidence:
            safe_evidence = _json_safe(
                _decode_json(str(row["evidence_json"]), {}),
                {},
            )
        return {
            "relationship_id": redact_capture_text(str(row["relationship_id"]))[0],
            "context_id": redact_capture_text(str(row["context_id"]))[0],
            "source_memory_id": redact_capture_text(str(row["source_memory_id"]))[0],
            "target_memory_id": redact_capture_text(str(row["target_memory_id"]))[0],
            "source_tag": redact_capture_text(str(row["source_tag"]))[0],
            "target_tag": redact_capture_text(str(row["target_tag"]))[0],
            "relation_type": redact_capture_text(str(row["relation_type"]))[0],
            "weight": round(float(row["weight"]), 6),
            "evidence": safe_evidence if isinstance(safe_evidence, dict) else {},
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    @staticmethod
    def _retrieval_page_limit(value: Any, *, field: str) -> int:
        if (
            type(value) is not int
            or value < 1
            or value > _RETRIEVAL_PAGE_MAX_LIMIT
        ):
            raise ValueError(
                f"{field} must be an exact integer between 1 and "
                f"{_RETRIEVAL_PAGE_MAX_LIMIT}"
            )
        return value

    @staticmethod
    def _retrieval_expected_revision(value: Any) -> str | None:
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or _RETRIEVAL_SNAPSHOT_REVISION_RE.fullmatch(value) is None
        ):
            raise ValueError(
                "expected_revision must be a lowercase 64-character sha256 digest"
            )
        return value

    @staticmethod
    def _canonical_retrieval_context_ids(
        context_ids: Iterable[str],
    ) -> tuple[str, ...]:
        if isinstance(context_ids, (str, bytes, bytearray, dict)):
            raise ValueError("context_ids must be a bounded iterable of identifiers")
        try:
            iterator = iter(context_ids)
        except TypeError as exc:
            raise ValueError(
                "context_ids must be a bounded iterable of identifiers"
            ) from exc

        selected: list[str] = []
        seen: set[str] = set()
        for raw_context_id in iterator:
            if len(selected) >= _RETRIEVAL_MAX_CONTEXTS:
                raise ValueError(
                    f"context_ids may contain at most {_RETRIEVAL_MAX_CONTEXTS} identifiers"
                )
            context_id = validate_public_identifier(
                raw_context_id,
                field="context_id",
                max_chars=128,
            )
            if unicodedata.normalize("NFC", context_id) != context_id:
                raise ValueError("context_id must use canonical NFC text")
            if context_id in seen:
                raise ValueError("context_ids must not contain duplicates")
            seen.add(context_id)
            selected.append(context_id)
        if not selected:
            raise ValueError("context_ids must contain at least one identifier")
        return tuple(sorted(selected))

    @classmethod
    def _retrieval_context_scope(
        cls,
        *,
        context_id: Any,
        include_global: Any,
    ) -> tuple[str, ...]:
        if type(include_global) is not bool:
            raise ValueError("include_global must be an exact boolean")
        context = validate_public_identifier(
            context_id,
            field="context_id",
            max_chars=128,
        )
        if unicodedata.normalize("NFC", context) != context:
            raise ValueError("context_id must use canonical NFC text")
        selected = [context]
        if include_global and context != "global":
            selected.append("global")
        return cls._canonical_retrieval_context_ids(selected)

    @staticmethod
    def _retrieval_position(
        value: Any,
        *,
        id_field: str,
        allow_done: bool = False,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError(f"position must be an object containing updated_at and {id_field}")
        if allow_done and set(value) == {"done"}:
            if value["done"] is not True:
                raise ValueError("done position must contain the exact boolean true")
            return {"done": True}
        if set(value) != {"updated_at", id_field}:
            raise ValueError(
                f"position must contain exactly updated_at and {id_field}"
            )
        updated_at = value["updated_at"]
        if (
            isinstance(updated_at, bool)
            or not isinstance(updated_at, (int, float))
            or not math.isfinite(float(updated_at))
            or float(updated_at) < 0.0
        ):
            raise ValueError("position updated_at must be a finite non-negative number")
        row_id = validate_public_identifier(
            value[id_field],
            field=id_field,
            max_chars=200,
        )
        return {"updated_at": float(updated_at), id_field: row_id}

    @classmethod
    def _retrieval_generation_snapshot_revision(
        cls,
        *,
        conn: sqlite3.Connection,
        kind: str,
        context_ids: tuple[str, ...],
        channels: tuple[str, ...],
        counts: dict[str, int],
    ) -> str:
        """Build a stable revision from transaction-coupled content counters.

        This avoids reading and hashing every memory body for every bounded
        page. Counters are advanced by TEMP writer triggers in the same commit
        as the corresponding content change. They are namespace-specific, so
        unrelated namespace activity does not invalidate a reviewed cursor.
        """

        supported_channels = {"memory", "relationship", "cortex"}
        if (
            not channels
            or len(channels) != len(set(channels))
            or any(channel not in supported_channels for channel in channels)
        ):
            raise ValueError("retrieval generation channels are invalid")
        normalized_counts: dict[str, int] = {}
        for name, value in sorted(counts.items()):
            if (
                not isinstance(name, str)
                or not name
                or type(value) is not int
                or value < 0
            ):
                raise RuntimeError("retrieval snapshot count is invalid")
            normalized_counts[name] = value

        keys = [
            f"{_RETRIEVAL_GENERATION_KEY_PREFIX}.{channel}.{context_id}"
            for channel in channels
            for context_id in context_ids
        ]
        placeholders = ",".join("?" for _ in keys)
        rows = conn.execute(
            f"""
            SELECT key, value_json
            FROM store_metadata
            WHERE key IN ({placeholders})
            """,
            tuple(keys),
        ).fetchall()
        values_by_key = {str(row["key"]): str(row["value_json"]) for row in rows}

        semantic_row = conn.execute(
            "SELECT value_json FROM store_metadata WHERE key = ?",
            ("semantic_index_generation",),
        ).fetchone()
        if semantic_row is None:
            semantic_index_generation = 0
        else:
            try:
                semantic_index_generation = json.loads(
                    str(semantic_row["value_json"])
                )
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "semantic index generation is not valid JSON"
                ) from exc
            if (
                type(semantic_index_generation) is not int
                or semantic_index_generation < 0
                or semantic_index_generation > _RETRIEVAL_GENERATION_MAX
            ):
                raise RuntimeError("semantic index generation is invalid")
        generations: dict[str, list[dict[str, Any]]] = {}
        for channel in channels:
            channel_values: list[dict[str, Any]] = []
            for context_id in context_ids:
                key = (
                    f"{_RETRIEVAL_GENERATION_KEY_PREFIX}.{channel}.{context_id}"
                )
                raw_value = values_by_key.get(key)
                if raw_value is None:
                    generation = 0
                else:
                    try:
                        generation = json.loads(raw_value)
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise RuntimeError(
                            "retrieval snapshot generation is not valid JSON"
                        ) from exc
                    if (
                        type(generation) is not int
                        or generation < 0
                        or generation > _RETRIEVAL_GENERATION_MAX
                    ):
                        raise RuntimeError(
                            "retrieval snapshot generation is invalid"
                        )
                channel_values.append(
                    {"context_id": context_id, "generation": generation}
                )
            generations[channel] = channel_values
        payload = {
            "schema": "synapse-s2.retrieval-snapshot.v2",
            "kind": kind,
            "context_ids": list(context_ids),
            "generations": generations,
            "semantic_index_generation": semantic_index_generation,
            "counts": normalized_counts,
        }
        return hashlib.sha256(_json_dumps(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _assert_retrieval_revision(
        *,
        expected_revision: str | None,
        actual_revision: str,
    ) -> None:
        if expected_revision is not None and not secrets.compare_digest(
            expected_revision,
            actual_revision,
        ):
            raise RetrievalSnapshotStaleError(
                expected_revision=expected_revision,
                actual_revision=actual_revision,
            )

    @staticmethod
    def _require_retrieval_continuation_revision(
        *,
        position: dict[str, Any] | None,
        expected_revision: str | None,
        field: str,
    ) -> None:
        if position is not None and expected_revision is None:
            raise ValueError(
                f"expected_revision is required when {field} is supplied"
            )

    @staticmethod
    def _retrieval_keyset_position(
        row: sqlite3.Row | dict[str, Any],
        *,
        id_field: str,
    ) -> dict[str, Any]:
        return {
            "updated_at": float(row["updated_at"]),
            id_field: str(row[id_field]),
        }

    def retrieval_memory_page(
        self,
        *,
        context_ids: Iterable[str],
        limit: int = 100,
        position: dict[str, Any] | None = None,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        """Return one stable keyset page from explicitly selected namespaces."""

        selected = self._canonical_retrieval_context_ids(context_ids)
        bounded_limit = self._retrieval_page_limit(limit, field="limit")
        page_position = self._retrieval_position(
            position,
            id_field="memory_id",
        )
        expected = self._retrieval_expected_revision(expected_revision)
        self._require_retrieval_continuation_revision(
            position=page_position,
            expected_revision=expected,
            field="position",
        )
        placeholders = ",".join("?" for _ in selected)

        with closing(self._connect_read_only()) as conn:
            with self._transaction(conn):
                total = int(
                    conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM memory_entries
                    WHERE context_id IN ({placeholders})
                    """,
                    selected,
                    ).fetchone()[0]
                )
                counts = {"entries": total}
                revision = self._retrieval_generation_snapshot_revision(
                    conn=conn,
                    kind="memory-page",
                    context_ids=selected,
                    channels=("memory",),
                    counts=counts,
                )
                self._assert_retrieval_revision(
                    expected_revision=expected,
                    actual_revision=revision,
                )

                params: list[Any] = list(selected)
                keyset_sql = ""
                if page_position is not None:
                    keyset_sql = (
                        "AND (updated_at < ? OR "
                        "(updated_at = ? AND memory_id < ?))"
                    )
                    params.extend(
                        (
                            page_position["updated_at"],
                            page_position["updated_at"],
                            page_position["memory_id"],
                        )
                    )
                params.append(bounded_limit + 1)
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM memory_entries
                    WHERE context_id IN ({placeholders})
                    {keyset_sql}
                    ORDER BY updated_at DESC, memory_id DESC
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()

        has_more = len(rows) > bounded_limit
        page_rows = rows[:bounded_limit]
        entries = [self._row_to_entry(row) for row in page_rows]
        return {
            "schema": "synapse-s2.retrieval-memory-page.v1",
            "context_ids": list(selected),
            "snapshot_revision": revision,
            "total": counts["entries"],
            "returned": len(entries),
            "has_more": has_more,
            "next_position": (
                self._retrieval_keyset_position(page_rows[-1], id_field="memory_id")
                if has_more and page_rows
                else None
            ),
            "entries": entries,
            "read_only": True,
        }

    def retrieval_graph_page(
        self,
        *,
        context_id: str,
        include_global: bool = False,
        entry_limit: int = 100,
        relationship_limit: int = 100,
        entry_position: dict[str, Any] | None = None,
        relationship_position: dict[str, Any] | None = None,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        """Page graph nodes and edges independently from one read transaction.

        A completed stream returns ``{"done": True}`` as its next position.  That
        sentinel lets a future cursor keep one stream exhausted while continuing
        the other without accidentally restarting the completed stream.
        """

        selected = self._retrieval_context_scope(
            context_id=context_id,
            include_global=include_global,
        )
        bounded_entry_limit = self._retrieval_page_limit(
            entry_limit,
            field="entry_limit",
        )
        bounded_relationship_limit = self._retrieval_page_limit(
            relationship_limit,
            field="relationship_limit",
        )
        selected_entry_position = self._retrieval_position(
            entry_position,
            id_field="memory_id",
            allow_done=True,
        )
        selected_relationship_position = self._retrieval_position(
            relationship_position,
            id_field="relationship_id",
            allow_done=True,
        )
        expected = self._retrieval_expected_revision(expected_revision)
        self._require_retrieval_continuation_revision(
            position=selected_entry_position,
            expected_revision=expected,
            field="entry_position",
        )
        self._require_retrieval_continuation_revision(
            position=selected_relationship_position,
            expected_revision=expected,
            field="relationship_position",
        )
        placeholders = ",".join("?" for _ in selected)

        with closing(self._connect_read_only()) as conn:
            with self._transaction(conn):
                entry_total = int(
                    conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM memory_entries
                    WHERE context_id IN ({placeholders})
                    """,
                    selected,
                    ).fetchone()[0]
                )
                relationship_total = int(
                    conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM memory_relationships AS r
                    JOIN memory_entries AS source
                        ON source.memory_id = r.source_memory_id
                        AND source.context_id = r.context_id
                    JOIN memory_entries AS target
                        ON target.memory_id = r.target_memory_id
                        AND target.context_id = r.context_id
                    WHERE r.context_id IN ({placeholders})
                    """,
                    selected,
                    ).fetchone()[0]
                )
                counts = {
                    "entries": entry_total,
                    "relationships": relationship_total,
                }
                revision = self._retrieval_generation_snapshot_revision(
                    conn=conn,
                    kind="graph-page",
                    context_ids=selected,
                    channels=("memory", "relationship"),
                    counts=counts,
                )
                self._assert_retrieval_revision(
                    expected_revision=expected,
                    actual_revision=revision,
                )

                entry_rows: list[sqlite3.Row] = []
                entry_stream_done = bool(
                    selected_entry_position
                    and selected_entry_position.get("done") is True
                )
                if not entry_stream_done:
                    entry_params: list[Any] = list(selected)
                    entry_keyset_sql = ""
                    if selected_entry_position is not None:
                        entry_keyset_sql = (
                            "AND (updated_at < ? OR "
                            "(updated_at = ? AND memory_id < ?))"
                        )
                        entry_params.extend(
                            (
                                selected_entry_position["updated_at"],
                                selected_entry_position["updated_at"],
                                selected_entry_position["memory_id"],
                            )
                        )
                    entry_params.append(bounded_entry_limit + 1)
                    entry_rows = conn.execute(
                        f"""
                        SELECT *
                        FROM memory_entries
                        WHERE context_id IN ({placeholders})
                          {entry_keyset_sql}
                        ORDER BY updated_at DESC, memory_id DESC
                        LIMIT ?
                        """,
                        tuple(entry_params),
                    ).fetchall()

                relationship_rows: list[sqlite3.Row] = []
                relationship_stream_done = bool(
                    selected_relationship_position
                    and selected_relationship_position.get("done") is True
                )
                if not relationship_stream_done:
                    relationship_params: list[Any] = list(selected)
                    relationship_keyset_sql = ""
                    if selected_relationship_position is not None:
                        relationship_keyset_sql = (
                            "AND (r.updated_at < ? OR "
                            "(r.updated_at = ? AND r.relationship_id < ?))"
                        )
                        relationship_params.extend(
                            (
                                selected_relationship_position["updated_at"],
                                selected_relationship_position["updated_at"],
                                selected_relationship_position["relationship_id"],
                            )
                        )
                    relationship_params.append(bounded_relationship_limit + 1)
                    relationship_rows = conn.execute(
                        f"""
                        SELECT
                            r.*,
                            source.tag AS source_tag,
                            target.tag AS target_tag
                        FROM memory_relationships AS r
                        JOIN memory_entries AS source
                            ON source.memory_id = r.source_memory_id
                            AND source.context_id = r.context_id
                        JOIN memory_entries AS target
                            ON target.memory_id = r.target_memory_id
                            AND target.context_id = r.context_id
                        WHERE r.context_id IN ({placeholders})
                          {relationship_keyset_sql}
                        ORDER BY r.updated_at DESC, r.relationship_id DESC
                        LIMIT ?
                        """,
                        tuple(relationship_params),
                    ).fetchall()

                page_relationship_rows = relationship_rows[
                    :bounded_relationship_limit
                ]
                endpoint_ids = sorted(
                    {
                        str(row[field])
                        for row in page_relationship_rows
                        for field in ("source_memory_id", "target_memory_id")
                    }
                )
                endpoint_rows: list[sqlite3.Row] = []
                for offset in range(0, len(endpoint_ids), 300):
                    endpoint_chunk = endpoint_ids[offset : offset + 300]
                    endpoint_placeholders = ",".join("?" for _ in endpoint_chunk)
                    endpoint_rows.extend(
                        conn.execute(
                            f"""
                            SELECT *
                            FROM memory_entries
                            WHERE memory_id IN ({endpoint_placeholders})
                              AND context_id IN ({placeholders})
                            """,
                            tuple(endpoint_chunk) + selected,
                        ).fetchall()
                    )
                hydrated_endpoint_ids = {
                    str(row["memory_id"]) for row in endpoint_rows
                }
                if hydrated_endpoint_ids != set(endpoint_ids):
                    raise RuntimeError(
                        "retrieval graph page could not hydrate every edge endpoint"
                    )

        entry_has_more = len(entry_rows) > bounded_entry_limit
        relationship_has_more = (
            len(relationship_rows) > bounded_relationship_limit
        )
        page_entry_rows = entry_rows[:bounded_entry_limit]
        entries = [self._row_to_entry(row) for row in page_entry_rows]
        relationships = [
            self._row_to_relationship(row) for row in page_relationship_rows
        ]
        endpoint_entries = sorted(
            (self._row_to_entry(row) for row in endpoint_rows),
            key=lambda item: (item["updated_at"], item["memory_id"]),
            reverse=True,
        )
        next_entry_position: dict[str, Any]
        if entry_has_more and page_entry_rows:
            next_entry_position = self._retrieval_keyset_position(
                page_entry_rows[-1],
                id_field="memory_id",
            )
        else:
            next_entry_position = {"done": True}
        next_relationship_position: dict[str, Any]
        if relationship_has_more and page_relationship_rows:
            next_relationship_position = self._retrieval_keyset_position(
                page_relationship_rows[-1],
                id_field="relationship_id",
            )
        else:
            next_relationship_position = {"done": True}
        return {
            "schema": "synapse-s2.retrieval-graph-page.v1",
            "context_ids": list(selected),
            "include_global": bool(include_global),
            "snapshot_revision": revision,
            "entry_total": counts["entries"],
            "relationship_total": counts["relationships"],
            "entry_returned": len(entries),
            "relationship_returned": len(relationships),
            "entry_has_more": entry_has_more,
            "relationship_has_more": relationship_has_more,
            "entry_next_position": next_entry_position,
            "relationship_next_position": next_relationship_position,
            "entries": entries,
            "relationships": relationships,
            "endpoint_entries": endpoint_entries,
            "read_only": True,
        }

    def retrieval_cortex_page(
        self,
        *,
        context_id: str,
        include_global: bool = False,
        limit: int = 100,
        position: dict[str, Any] | None = None,
        expected_revision: str | None = None,
    ) -> dict[str, Any]:
        """Return only durable Cortex Governor entries from a stable snapshot."""

        selected = self._retrieval_context_scope(
            context_id=context_id,
            include_global=include_global,
        )
        bounded_limit = self._retrieval_page_limit(limit, field="limit")
        page_position = self._retrieval_position(
            position,
            id_field="memory_id",
        )
        expected = self._retrieval_expected_revision(expected_revision)
        self._require_retrieval_continuation_revision(
            position=page_position,
            expected_revision=expected,
            field="position",
        )
        placeholders = ",".join("?" for _ in selected)
        cortex_filter = (
            "CASE WHEN json_valid(metadata_json) "
            "THEN json_type(metadata_json, '$.cortex_governor') "
            "END = 'true'"
        )

        with closing(self._connect_read_only()) as conn:
            with self._transaction(conn):
                total = int(
                    conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM memory_entries
                    WHERE context_id IN ({placeholders})
                      AND {cortex_filter}
                    """,
                    selected,
                    ).fetchone()[0]
                )
                counts = {"entries": total}
                revision = self._retrieval_generation_snapshot_revision(
                    conn=conn,
                    kind="cortex-page",
                    context_ids=selected,
                    channels=("cortex",),
                    counts=counts,
                )
                self._assert_retrieval_revision(
                    expected_revision=expected,
                    actual_revision=revision,
                )

                params: list[Any] = list(selected)
                keyset_sql = ""
                if page_position is not None:
                    keyset_sql = (
                        "AND (updated_at < ? OR "
                        "(updated_at = ? AND memory_id < ?))"
                    )
                    params.extend(
                        (
                            page_position["updated_at"],
                            page_position["updated_at"],
                            page_position["memory_id"],
                        )
                    )
                params.append(bounded_limit + 1)
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM memory_entries
                    WHERE context_id IN ({placeholders})
                      AND {cortex_filter}
                      {keyset_sql}
                    ORDER BY updated_at DESC, memory_id DESC
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()

        has_more = len(rows) > bounded_limit
        page_rows = rows[:bounded_limit]
        entries = [self._row_to_entry(row) for row in page_rows]
        return {
            "schema": "synapse-s2.retrieval-cortex-page.v1",
            "context_ids": list(selected),
            "include_global": bool(include_global),
            "snapshot_revision": revision,
            "total": counts["entries"],
            "returned": len(entries),
            "has_more": has_more,
            "next_position": (
                self._retrieval_keyset_position(page_rows[-1], id_field="memory_id")
                if has_more and page_rows
                else None
            ),
            "entries": entries,
            "read_only": True,
        }

    def entries_revision(
        self,
        *,
        context_id: str | None = None,
        include_global: bool = False,
        context_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Return a cheap revision fingerprint for entry-list caches."""
        clauses: list[str] = []
        params: list[Any] = []
        clean_context_ids: list[str] = []
        if context_ids is not None:
            clean_context_ids = list(
                dict.fromkeys(
                    str(value).strip()
                    for value in context_ids
                    if str(value).strip()
                )
            )
            if clean_context_ids:
                placeholders = ",".join("?" for _ in clean_context_ids)
                clauses.append(f"context_id IN ({placeholders})")
                params.extend(clean_context_ids)
        elif context_id is not None:
            if include_global and context_id != "global":
                clauses.append("context_id IN (?, 'global')")
                params.append(str(context_id))
            else:
                clauses.append("context_id = ?")
                params.append(str(context_id))
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        try:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    f"""
                    SELECT
                        COUNT(*) AS entry_count,
                        COALESCE(MAX(updated_at), 0.0) AS max_updated_at,
                        COALESCE(MAX(created_at), 0.0) AS max_created_at
                    FROM memory_entries
                    {where_sql}
                    """,
                    tuple(params),
                ).fetchone()
                generation_row = conn.execute(
                    "SELECT value_json FROM store_metadata WHERE key = ?",
                    ("semantic_index_generation",),
                ).fetchone()
            entry_count = int(row["entry_count"] if row is not None else 0)
            max_updated_at = float(row["max_updated_at"] if row is not None else 0.0)
            max_created_at = float(row["max_created_at"] if row is not None else 0.0)
            try:
                semantic_index_generation = int(
                    _decode_json(str(generation_row["value_json"]), 0)
                    if generation_row is not None
                    else 0
                )
            except (TypeError, ValueError, OverflowError):
                semantic_index_generation = 0
            revision_seed = (
                f"{context_id or '*'}\x1f{include_global}\x1f"
                f"{','.join(clean_context_ids)}\x1f"
                f"{entry_count}\x1f{max_updated_at:.9f}\x1f{max_created_at:.9f}\x1f"
                f"{semantic_index_generation}"
            )
            return {
                "context_id": str(context_id or ""),
                "context_ids": clean_context_ids,
                "include_global": bool(include_global),
                "entry_count": entry_count,
                "max_updated_at": max_updated_at,
                "max_created_at": max_created_at,
                "semantic_index_generation": semantic_index_generation,
                "revision": hashlib.sha256(revision_seed.encode("utf-8")).hexdigest()[:16],
            }
        except Exception:
            LOGGER.exception("failed to compute memory entry revision")
            raise

    def recall_candidates(
        self,
        *,
        context_id: str,
        query_spikes: set[int],
        firing_values: list[float],
        limit: int,
        recall_scope: str = "local",
        recall_contexts: Iterable[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        if not query_spikes:
            return []
        scope_records = list(
            recall_contexts
            if recall_contexts is not None
            else self.resolve_recall_contexts(
                context_id=context_id,
                scope=recall_scope,
            )
        )
        scope_by_context = {
            str(record.get("context_id") or ""): dict(record)
            for record in scope_records
            if str(record.get("context_id") or "")
        }
        if not scope_by_context:
            return []
        context_placeholders = ",".join("?" for _ in scope_by_context)
        clean_query_spikes = sorted({int(value) for value in query_spikes})
        placeholders = ",".join("?" for _ in clean_query_spikes)
        bounded_limit = min(max(int(limit), 1), 10_000)
        candidate_limit = min(max(bounded_limit * 16, 128), 10_000)
        params: list[Any] = [
            *scope_by_context.keys(),
            *clean_query_spikes,
            candidate_limit,
        ]
        candidates: list[dict[str, Any]] = []
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    f"""
                    SELECT
                        e.*,
                        COUNT(*) AS overlap_count
                    FROM memory_spikes AS s
                    JOIN memory_entries AS e
                        ON e.memory_id = s.memory_id
                    WHERE
                        s.context_id IN ({context_placeholders})
                        AND s.spike_index IN ({placeholders})
                    GROUP BY e.memory_id
                    ORDER BY
                        overlap_count DESC,
                        e.updated_at DESC,
                        e.memory_id ASC
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()
        except Exception:
            LOGGER.exception("failed to query indexed recall candidates")
            raise
        query_spike_set = set(clean_query_spikes)
        for row in rows:
            entry = self._row_to_entry(row)
            trace_spikes = set(int(idx) for idx in entry["spike_indices"])
            if not trace_spikes:
                continue
            overlap = int(row["overlap_count"])
            union = len(query_spike_set | trace_spikes)
            jaccard = overlap / max(1, union)
            if jaccard <= 0.0:
                continue
            neuron_activity = 0.0
            for neuron_idx in entry["neuron_indices"]:
                idx = int(neuron_idx)
                if 0 <= idx < len(firing_values):
                    neuron_activity += float(firing_values[idx])
            activity_bonus = min(
                neuron_activity / max(1, len(entry["neuron_indices"])),
                1.0,
            )
            candidate = dict(entry)
            candidate["score"] = round(float(jaccard + 0.05 * activity_bonus), 6)
            candidate.update(scope_by_context.get(str(entry["context_id"]), {}))
            candidates.append(candidate)
        candidates.sort(
            key=lambda item: (
                -float(item["score"]),
                -float(item["updated_at"]),
                str(item["memory_id"]),
            )
        )
        return candidates[:bounded_limit]

    def surface_recall_candidates(
        self,
        *,
        context_id: str,
        query_terms: Iterable[str],
        limit: int,
        recall_scope: str = "local",
        recall_contexts: Iterable[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        clean_terms: list[str] = []
        seen_terms: set[str] = set()
        for raw_term in query_terms:
            for term in self._surface_terms(str(raw_term or "")):
                if term in seen_terms:
                    continue
                seen_terms.add(term)
                clean_terms.append(term)
        if not clean_terms:
            return []
        scope_records = list(
            recall_contexts
            if recall_contexts is not None
            else self.resolve_recall_contexts(
                context_id=context_id,
                scope=recall_scope,
            )
        )
        scope_by_context = {
            str(record.get("context_id") or ""): dict(record)
            for record in scope_records
            if str(record.get("context_id") or "")
        }
        if not scope_by_context:
            return []
        bounded_limit = min(max(int(limit), 1), 10_000)
        placeholders = ",".join("?" for _ in clean_terms)
        context_placeholders = ",".join("?" for _ in scope_by_context)
        params: list[Any] = [*scope_by_context.keys(), *clean_terms, bounded_limit]
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    f"""
                    WITH matched AS (
                        SELECT
                            memory_id,
                            COUNT(*) AS overlap_count,
                            SUM(weight) AS term_weight
                        FROM memory_surface_terms
                        WHERE
                            context_id IN ({context_placeholders})
                            AND term IN ({placeholders})
                        GROUP BY memory_id
                        ORDER BY
                            overlap_count DESC,
                            term_weight DESC,
                            memory_id ASC
                        LIMIT ?
                    )
                    SELECT
                        e.*,
                        matched.overlap_count,
                        matched.term_weight
                    FROM matched
                    JOIN memory_entries AS e
                        ON e.memory_id = matched.memory_id
                    ORDER BY
                        matched.overlap_count DESC,
                        matched.term_weight DESC,
                        e.updated_at DESC,
                        e.memory_id ASC
                    """,
                    tuple(params),
                ).fetchall()
            candidates: list[dict[str, Any]] = []
            for row in rows:
                entry = self._row_to_entry(row)
                entry["surface_overlap_count"] = int(row["overlap_count"] or 0)
                entry["surface_term_weight"] = round(float(row["term_weight"] or 0.0), 6)
                entry.update(scope_by_context.get(str(entry["context_id"]), {}))
                candidates.append(entry)
            return candidates
        except Exception:
            LOGGER.exception("failed to query surface recall candidates")
            raise

    def _surface_term_rows(
        self,
        *,
        memory_id: str,
        context_id: str,
        tag: str,
        source_text: str,
        metadata: dict[str, Any] | None,
    ) -> list[tuple[str, str, str, float]]:
        weighted_terms: dict[str, float] = {}

        def add_terms(value: Any, weight: float) -> None:
            for term in self._surface_terms(str(value or "")):
                weighted_terms[term] = max(weighted_terms.get(term, 0.0), float(weight))

        safe_metadata = metadata if isinstance(metadata, dict) else {}
        add_terms(tag, 2.0)
        add_terms(safe_metadata.get("display_label", ""), 4.0)
        add_terms(safe_metadata.get("display_summary", ""), 3.0)
        for key, weight in (
            ("semantic_facets", 3.5),
            ("detail_badges", 2.5),
            ("keywords", 2.5),
        ):
            values = safe_metadata.get(key)
            if isinstance(values, (list, tuple, set)):
                for value in list(values)[:32]:
                    add_terms(value, weight)
            else:
                add_terms(values, weight)
        add_terms(str(source_text or "")[:MAX_SURFACE_INDEX_SOURCE_CHARS], 1.0)

        rows = [
            (str(memory_id), str(context_id), term, round(weight, 6))
            for term, weight in sorted(
                weighted_terms.items(),
                key=lambda item: (-item[1], item[0]),
            )[:512]
        ]
        return rows

    def _surface_terms(self, value: str) -> list[str]:
        terms: list[str] = []
        seen: set[str] = set()
        for match in SURFACE_TERM_RE.finditer(str(value or "").lower()):
            term = match.group(0).strip("._/:-")
            if len(term) < 2 or term in seen:
                continue
            seen.add(term)
            terms.append(term)
        return terms

    def upsert_context_link(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        relation_type: str,
        confidence: float = 1.0,
        evidence: dict[str, Any] | None = None,
        direction: str = "bidirectional",
        approved_by: str = "operator",
        approved_at: float | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Persist one explicitly approved context-to-context connection.

        Similarity suggestions intentionally use a separate read-only path and
        never call this method. Bidirectional links are stored canonically so
        approving A<->B and B<->A updates the same durable record.
        """
        source = str(source_context_id or "").strip()
        target = str(target_context_id or "").strip()
        relation = str(relation_type or "related").strip() or "related"
        approver = str(approved_by or "").strip()
        normalized_direction = self._normalize_context_link_direction(direction)
        if not source or not target:
            raise ValueError("source_context_id and target_context_id are required")
        if source == target:
            raise ValueError("a context cannot be linked to itself")
        if not approver:
            raise ValueError("approved_by is required for a durable context link")
        if normalized_direction == "bidirectional" and target < source:
            source, target = target, source
        context_link_id = self.stable_context_link_id(
            source_context_id=source,
            target_context_id=target,
            relation_type=relation,
            direction=normalized_direction,
        )
        now = time.time()
        approval_time = float(approved_at or now)
        raw_confidence = float(confidence)
        if not math.isfinite(raw_confidence):
            raise ValueError("confidence must be a finite number")
        bounded_confidence = min(max(raw_confidence, 0.0), 1.0)
        safe_evidence = dict(evidence) if isinstance(evidence, dict) else {}
        safe_evidence.setdefault("automatic_cross_namespace_write", False)
        safe_evidence.setdefault("approval_required_for_creation", True)
        safe_evidence.setdefault("approval_confirmed", True)
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    conn.execute(
                        """
                        INSERT INTO context_relationships (
                            context_link_id,
                            source_context_id,
                            target_context_id,
                            relation_type,
                            direction,
                            confidence,
                            evidence_json,
                            enabled,
                            approved_by,
                            approved_at,
                            created_at,
                            updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(context_link_id) DO UPDATE SET
                            confidence = excluded.confidence,
                            evidence_json = excluded.evidence_json,
                            enabled = excluded.enabled,
                            approved_by = excluded.approved_by,
                            approved_at = excluded.approved_at,
                            updated_at = excluded.updated_at
                        """,
                        (
                            context_link_id,
                            source,
                            target,
                            relation,
                            normalized_direction,
                            bounded_confidence,
                            _json_dumps(safe_evidence),
                            1 if enabled else 0,
                            approver,
                            approval_time,
                            now,
                            now,
                        ),
                    )
                    link_row = conn.execute(
                        "SELECT * FROM context_relationships WHERE context_link_id = ?",
                        (context_link_id,),
                    ).fetchone()
            if link_row is None:
                raise RuntimeError(
                    f"context link {context_link_id} was not readable after upsert"
                )
            return self._row_to_context_link(link_row)
        except Exception:
            LOGGER.exception(
                "failed to upsert context link source=%s target=%s",
                source,
                target,
            )
            raise

    def list_context_links(
        self,
        *,
        context_id: str | None = None,
        context_link_id: str | None = None,
        source_context_id: str | None = None,
        target_context_id: str | None = None,
        relation_type: str | None = None,
        enabled_only: bool = False,
        limit: int = 1000,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("(source_context_id = ? OR target_context_id = ?)")
            params.extend([str(context_id), str(context_id)])
        if context_link_id is not None:
            clauses.append("context_link_id = ?")
            params.append(str(context_link_id))
        if source_context_id is not None:
            clauses.append("source_context_id = ?")
            params.append(str(source_context_id))
        if target_context_id is not None:
            clauses.append("target_context_id = ?")
            params.append(str(target_context_id))
        if relation_type is not None:
            clauses.append("relation_type = ?")
            params.append(str(relation_type))
        if enabled_only:
            clauses.append("enabled = 1")
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        bounded_limit = min(max(int(limit), 1), 10_000)
        try:
            with self._read_connection_scope(_conn) as conn:
                if not enabled_only:
                    rows = conn.execute(
                        f"""
                        SELECT *
                        FROM context_relationships
                        {where_sql}
                        ORDER BY confidence DESC, updated_at DESC, context_link_id
                        LIMIT ?
                        """,
                        (*params, bounded_limit),
                    ).fetchall()
                    return [self._row_to_context_link(row) for row in rows]

                # Governed link expiry is an authorization boundary, not a
                # maintenance schedule.  Enforce it on every recall read even
                # if the asynchronous expiry sweep has not yet materialized
                # ``enabled = 0``. Legacy approved links remain compatible
                # until explicitly adopted into the governance ledger. Read
                # successive ordered pages before applying the caller limit;
                # otherwise expired high-confidence rows can hide a later
                # effective bridge and make the hydration capsule contradict
                # actual connected recall.
                observed_at = time.time()
                effective: list[dict[str, Any]] = []
                page_size = min(max(bounded_limit, 256), 2_000)
                offset = 0
                while len(effective) < bounded_limit:
                    rows = conn.execute(
                        f"""
                        SELECT *
                        FROM context_relationships
                        {where_sql}
                        ORDER BY confidence DESC, updated_at DESC, context_link_id
                        LIMIT ? OFFSET ?
                        """,
                        (*params, page_size, offset),
                    ).fetchall()
                    if not rows:
                        break
                    offset += len(rows)
                    for row in rows:
                        link = self._row_to_context_link(row)
                        evidence = link.get("evidence")
                        governance = (
                            evidence.get("governance")
                            if isinstance(evidence, dict)
                            else None
                        )
                        if isinstance(governance, dict):
                            if governance.get("state") != "approved":
                                continue
                            expires_at = governance.get("link_expires_at")
                            if expires_at is not None:
                                try:
                                    if observed_at >= float(expires_at):
                                        continue
                                except (TypeError, ValueError, OverflowError):
                                    # Malformed policy data can never broaden
                                    # connected recall.
                                    continue
                        effective.append(link)
                        if len(effective) >= bounded_limit:
                            break
                    if len(rows) < page_size:
                        break
                return effective
        except Exception:
            LOGGER.exception("failed to list context links")
            raise

    def delete_context_link(self, *, context_link_id: str) -> dict[str, Any]:
        link_id = str(context_link_id or "").strip()
        if not link_id:
            raise ValueError("context_link_id is required")
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    row = conn.execute(
                        "SELECT * FROM context_relationships WHERE context_link_id = ?",
                        (link_id,),
                    ).fetchone()
                    link = self._row_to_context_link(row) if row is not None else None
                    if row is not None:
                        conn.execute(
                            "DELETE FROM context_relationships WHERE context_link_id = ?",
                            (link_id,),
                        )
            if link is None:
                return {"deleted": False, "context_link_id": link_id, "link": None}
            return {"deleted": True, "context_link_id": link_id, "link": link}
        except Exception:
            LOGGER.exception("failed to delete context link %s", link_id)
            raise

    def list_context_summaries(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        """Return graph-ready summaries for every durable context id."""
        bounded_limit = min(max(int(limit), 1), 10_000)
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    """
                    WITH namespace_catalog AS (
                        SELECT
                            substr(key, length(?) + 1) AS context_id,
                            updated_at AS last_catalog_at
                        FROM store_metadata
                        WHERE substr(key, 1, length(?)) = ?
                          AND length(key) > length(?)
                    ),
                    contexts AS (
                        SELECT context_id FROM memory_entries
                        UNION SELECT context_id FROM agent_context_events
                        UNION SELECT source_context_id FROM context_relationships
                        UNION SELECT target_context_id FROM context_relationships
                        UNION SELECT context_id FROM namespace_catalog
                    ),
                    entry_stats AS (
                        SELECT
                            context_id,
                            COUNT(*) AS entry_count,
                            MAX(updated_at) AS last_entry_at
                        FROM memory_entries
                        GROUP BY context_id
                    ),
                    relationship_stats AS (
                        SELECT context_id, COUNT(*) AS relationship_count
                        FROM memory_relationships
                        GROUP BY context_id
                    ),
                    spike_stats AS (
                        SELECT context_id, COUNT(*) AS spike_index_count
                        FROM memory_spikes
                        GROUP BY context_id
                    ),
                    surface_stats AS (
                        SELECT context_id, COUNT(*) AS surface_term_count
                        FROM memory_surface_terms
                        GROUP BY context_id
                    ),
                    event_stats AS (
                        SELECT
                            context_id,
                            COUNT(*) AS context_event_count,
                            MAX(created_at) AS last_event_at
                        FROM agent_context_events
                        GROUP BY context_id
                    ),
                    link_events AS (
                        SELECT source_context_id AS context_id, updated_at
                        FROM context_relationships
                        UNION ALL
                        SELECT target_context_id AS context_id, updated_at
                        FROM context_relationships
                    ),
                    link_stats AS (
                        SELECT
                            context_id,
                            COUNT(*) AS context_link_count,
                            MAX(updated_at) AS last_link_at
                        FROM link_events
                        GROUP BY context_id
                    )
                    SELECT
                        contexts.context_id,
                        COALESCE(entry_stats.entry_count, 0) AS entry_count,
                        COALESCE(relationship_stats.relationship_count, 0)
                            AS relationship_count,
                        COALESCE(spike_stats.spike_index_count, 0) AS spike_index_count,
                        COALESCE(surface_stats.surface_term_count, 0) AS surface_term_count,
                        COALESCE(event_stats.context_event_count, 0) AS context_event_count,
                        COALESCE(link_stats.context_link_count, 0) AS context_link_count,
                        MAX(
                            COALESCE(entry_stats.last_entry_at, 0.0),
                            COALESCE(event_stats.last_event_at, 0.0),
                            COALESCE(link_stats.last_link_at, 0.0),
                            COALESCE(namespace_catalog.last_catalog_at, 0.0)
                        ) AS last_activity_at
                    FROM contexts
                    LEFT JOIN namespace_catalog USING (context_id)
                    LEFT JOIN entry_stats USING (context_id)
                    LEFT JOIN relationship_stats USING (context_id)
                    LEFT JOIN spike_stats USING (context_id)
                    LEFT JOIN surface_stats USING (context_id)
                    LEFT JOIN event_stats USING (context_id)
                    LEFT JOIN link_stats USING (context_id)
                    ORDER BY entry_count DESC, last_activity_at DESC, contexts.context_id
                    LIMIT ?
                    """,
                    (
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        bounded_limit,
                    ),
                ).fetchall()
            return [
                {
                    "context_id": str(row["context_id"]),
                    "entry_count": int(row["entry_count"]),
                    "relationship_count": int(row["relationship_count"]),
                    "spike_index_count": int(row["spike_index_count"]),
                    "surface_term_count": int(row["surface_term_count"]),
                    "context_event_count": int(row["context_event_count"]),
                    "context_link_count": int(row["context_link_count"]),
                    "last_activity_at": float(row["last_activity_at"]),
                    "size": int(row["entry_count"]),
                }
                for row in rows
            ]
        except Exception:
            LOGGER.exception("failed to list durable context summaries")
            raise

    def count_contexts(self) -> int:
        """Return the namespace count without aggregating derived indexes."""

        try:
            with closing(self._connect()) as conn:
                row = conn.execute(
                    """
                    WITH namespace_catalog AS (
                        SELECT substr(key, length(?) + 1) AS context_id
                        FROM store_metadata
                        WHERE substr(key, 1, length(?)) = ?
                          AND length(key) > length(?)
                    ),
                    contexts AS (
                        SELECT context_id FROM memory_entries
                        UNION SELECT context_id FROM agent_context_events
                        UNION SELECT source_context_id FROM context_relationships
                        UNION SELECT target_context_id FROM context_relationships
                        UNION SELECT context_id FROM namespace_catalog
                    )
                    SELECT COUNT(*) FROM contexts
                    """,
                    (
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                    ),
                ).fetchone()
            return int(row[0] if row is not None else 0)
        except Exception:
            LOGGER.exception("failed to count durable contexts")
            raise

    def list_context_summaries_lightweight(
        self,
        *,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Return map summaries without scanning spike or surface-term indexes."""

        bounded_limit = min(max(int(limit), 1), 10_000)
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    """
                    WITH namespace_catalog AS (
                        SELECT
                            substr(key, length(?) + 1) AS context_id,
                            updated_at AS last_catalog_at
                        FROM store_metadata
                        WHERE substr(key, 1, length(?)) = ?
                          AND length(key) > length(?)
                    ),
                    contexts AS (
                        SELECT context_id FROM memory_entries
                        UNION SELECT context_id FROM agent_context_events
                        UNION SELECT source_context_id FROM context_relationships
                        UNION SELECT target_context_id FROM context_relationships
                        UNION SELECT context_id FROM namespace_catalog
                    ),
                    entry_stats AS (
                        SELECT context_id, COUNT(*) AS entry_count,
                               MAX(updated_at) AS last_entry_at
                        FROM memory_entries
                        GROUP BY context_id
                    ),
                    relationship_stats AS (
                        SELECT context_id, COUNT(*) AS relationship_count
                        FROM memory_relationships
                        GROUP BY context_id
                    ),
                    event_stats AS (
                        SELECT context_id, COUNT(*) AS context_event_count,
                               MAX(created_at) AS last_event_at
                        FROM agent_context_events
                        GROUP BY context_id
                    ),
                    link_events AS (
                        SELECT source_context_id AS context_id, updated_at
                        FROM context_relationships
                        UNION ALL
                        SELECT target_context_id AS context_id, updated_at
                        FROM context_relationships
                    ),
                    link_stats AS (
                        SELECT context_id, COUNT(*) AS context_link_count,
                               MAX(updated_at) AS last_link_at
                        FROM link_events
                        GROUP BY context_id
                    )
                    SELECT
                        contexts.context_id,
                        COALESCE(entry_stats.entry_count, 0) AS entry_count,
                        COALESCE(relationship_stats.relationship_count, 0)
                            AS relationship_count,
                        COALESCE(event_stats.context_event_count, 0)
                            AS context_event_count,
                        COALESCE(link_stats.context_link_count, 0)
                            AS context_link_count,
                        MAX(
                            COALESCE(entry_stats.last_entry_at, 0.0),
                            COALESCE(event_stats.last_event_at, 0.0),
                            COALESCE(link_stats.last_link_at, 0.0),
                            COALESCE(namespace_catalog.last_catalog_at, 0.0)
                        ) AS last_activity_at
                    FROM contexts
                    LEFT JOIN namespace_catalog USING (context_id)
                    LEFT JOIN entry_stats USING (context_id)
                    LEFT JOIN relationship_stats USING (context_id)
                    LEFT JOIN event_stats USING (context_id)
                    LEFT JOIN link_stats USING (context_id)
                    ORDER BY entry_count DESC, last_activity_at DESC,
                             contexts.context_id
                    LIMIT ?
                    """,
                    (
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        bounded_limit,
                    ),
                ).fetchall()
            return [
                {
                    "context_id": str(row["context_id"]),
                    "entry_count": int(row["entry_count"]),
                    "relationship_count": int(row["relationship_count"]),
                    "context_event_count": int(row["context_event_count"]),
                    "context_link_count": int(row["context_link_count"]),
                    "last_activity_at": float(row["last_activity_at"]),
                    "size": int(row["entry_count"]),
                    "derived_density_metrics_included": False,
                }
                for row in rows
            ]
        except Exception:
            LOGGER.exception("failed to list lightweight durable context summaries")
            raise

    def resolve_recall_contexts(
        self,
        *,
        context_id: str,
        scope: str = "local",
    ) -> list[dict[str, Any]]:
        """Resolve an explicit, one-hop bounded recall scope with provenance."""
        context = str(context_id or "default").strip() or "default"
        normalized_scope = self._normalize_recall_scope(scope)
        records: list[dict[str, Any]] = [
            {
                "context_id": context,
                "recall_scope": normalized_scope,
                "recall_provenance": "local",
                "via_context_link_id": "",
                "via_relation_type": "",
            }
        ]
        seen = {context}
        if normalized_scope == "connected":
            for link in self.list_context_links(
                context_id=context,
                enabled_only=True,
                limit=10_000,
            ):
                source = str(link["source_context_id"])
                target = str(link["target_context_id"])
                direction = str(link["direction"])
                neighbor = ""
                if source == context:
                    neighbor = target
                elif target == context and direction == "bidirectional":
                    neighbor = source
                if not neighbor or neighbor in seen or neighbor == "global":
                    continue
                seen.add(neighbor)
                records.append(
                    {
                        "context_id": neighbor,
                        "recall_scope": normalized_scope,
                        "recall_provenance": "connected",
                        "via_context_link_id": str(link["context_link_id"]),
                        "via_relation_type": str(link["relation_type"]),
                        "via_direction": direction,
                    }
                )
        elif normalized_scope == "all":
            for summary in self.list_context_summaries(limit=10_000):
                candidate = str(summary["context_id"])
                if candidate in seen or candidate == "global":
                    continue
                seen.add(candidate)
                records.append(
                    {
                        "context_id": candidate,
                        "recall_scope": normalized_scope,
                        "recall_provenance": "all",
                        "via_context_link_id": "",
                        "via_relation_type": "",
                    }
                )
        if "global" not in seen:
            records.append(
                {
                    "context_id": "global",
                    "recall_scope": normalized_scope,
                    "recall_provenance": "global",
                    "via_context_link_id": "",
                    "via_relation_type": "",
                }
            )
        return records

    def context_similarity(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        max_phase_delay_ticks: int = 4,
    ) -> dict[str, Any]:
        source = str(source_context_id or "").strip()
        target = str(target_context_id or "").strip()
        if not source or not target or source == target:
            raise ValueError("two distinct context ids are required")
        profiles = self._context_similarity_profiles({source, target})
        return self._build_context_similarity(
            source_context_id=source,
            target_context_id=target,
            profiles=profiles,
            max_phase_delay_ticks=max_phase_delay_ticks,
        )

    def suggest_context_links(
        self,
        *,
        context_id: str | None = None,
        limit: int = 50,
        min_score: float = 0.05,
        include_linked: bool = False,
        max_phase_delay_ticks: int = 4,
    ) -> list[dict[str, Any]]:
        """Return read-only density-normalized context-link suggestions."""
        if int(limit) <= 0:
            return []
        selected = str(context_id or "").strip()
        summaries = self.list_context_summaries(limit=10_000)
        context_ids = [
            str(summary["context_id"])
            for summary in summaries
            if str(summary["context_id"]) != "global"
            and int(summary["entry_count"]) > 0
        ]
        if selected and selected not in context_ids:
            return []
        profiles = self._context_similarity_profiles(set(context_ids))
        existing_pairs = {
            frozenset(
                (str(link["source_context_id"]), str(link["target_context_id"]))
            )
            for link in self.list_context_links(enabled_only=True, limit=10_000)
        }
        suggestions: list[dict[str, Any]] = []
        for left_index, source in enumerate(context_ids):
            for target in context_ids[left_index + 1 :]:
                if selected and selected not in {source, target}:
                    continue
                already_linked = frozenset((source, target)) in existing_pairs
                if already_linked and not include_linked:
                    continue
                suggestion = self._build_context_similarity(
                    source_context_id=source,
                    target_context_id=target,
                    profiles=profiles,
                    max_phase_delay_ticks=max_phase_delay_ticks,
                )
                if float(suggestion["score"]) < float(min_score):
                    continue
                suggestion["already_linked"] = already_linked
                suggestions.append(suggestion)
        suggestions.sort(
            key=lambda item: (
                float(item["score"]),
                float(item["surface_containment"]),
                int(item["surface_overlap_count"]),
                int(item["spike_overlap_count"]),
                str(item["source_context_id"]),
                str(item["target_context_id"]),
            ),
            reverse=True,
        )
        bounded_limit = min(max(int(limit), 1), 1000)
        return suggestions[:bounded_limit]

    def _context_similarity_profiles(
        self,
        context_ids: set[str],
    ) -> dict[str, dict[str, set[Any]]]:
        profiles: dict[str, dict[str, set[Any]]] = {
            context_id: {"surface_terms": set(), "spike_indices": set()}
            for context_id in context_ids
        }
        if not context_ids:
            return profiles
        placeholders = ",".join("?" for _ in context_ids)
        ordered = sorted(context_ids)
        try:
            with closing(self._connect()) as conn:
                term_rows = conn.execute(
                    f"""
                    SELECT DISTINCT context_id, term
                    FROM memory_surface_terms
                    WHERE context_id IN ({placeholders})
                    """,
                    tuple(ordered),
                ).fetchall()
                spike_rows = conn.execute(
                    f"""
                    SELECT DISTINCT context_id, spike_index
                    FROM memory_spikes
                    WHERE context_id IN ({placeholders})
                    """,
                    tuple(ordered),
                ).fetchall()
            for row in term_rows:
                term = str(row["term"])
                if len(term) < 3 or term in CONTEXT_SUGGESTION_STOP_TERMS:
                    continue
                profiles[str(row["context_id"])]["surface_terms"].add(term)
            for row in spike_rows:
                profiles[str(row["context_id"])]["spike_indices"].add(
                    int(row["spike_index"])
                )
            return profiles
        except Exception:
            LOGGER.exception("failed to build context similarity profiles")
            raise

    def _build_context_similarity(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        profiles: dict[str, dict[str, set[Any]]],
        max_phase_delay_ticks: int,
    ) -> dict[str, Any]:
        source_profile = profiles.get(
            source_context_id,
            {"surface_terms": set(), "spike_indices": set()},
        )
        target_profile = profiles.get(
            target_context_id,
            {"surface_terms": set(), "spike_indices": set()},
        )
        source_terms = set(source_profile["surface_terms"])
        target_terms = set(target_profile["surface_terms"])
        source_spikes = {int(value) for value in source_profile["spike_indices"]}
        target_spikes = {int(value) for value in target_profile["spike_indices"]}
        shared_terms = source_terms & target_terms
        shared_spikes = source_spikes & target_spikes
        surface_denominator = len(source_terms) + len(target_terms)
        spike_denominator = len(source_spikes) + len(target_spikes)
        surface_dice = (
            (2.0 * len(shared_terms)) / surface_denominator
            if surface_denominator
            else 0.0
        )
        spike_dice = (
            (2.0 * len(shared_spikes)) / spike_denominator
            if spike_denominator
            else 0.0
        )
        surface_containment = (
            len(shared_terms) / min(len(source_terms), len(target_terms))
            if source_terms and target_terms
            else 0.0
        )
        spike_containment = (
            len(shared_spikes) / min(len(source_spikes), len(target_spikes))
            if source_spikes and target_spikes
            else 0.0
        )
        baseline_scores: list[tuple[float, float]] = []
        if surface_denominator:
            baseline_scores.append((surface_dice, 0.7))
        if spike_denominator:
            baseline_scores.append((spike_dice, 0.3))
        baseline_weight = sum(weight for _score, weight in baseline_scores)
        dice_score = (
            sum(score * weight for score, weight in baseline_scores) / baseline_weight
            if baseline_weight
            else 0.0
        )
        # Symmetric Dice remains the density-normalized baseline.  It can
        # nevertheless bury a genuinely focused namespace beside a very large
        # one because the dense side dominates the denominator.  Apply a
        # conservative asymmetric-containment lift only when at least two
        # meaningful surface terms overlap. Spike containment may strengthen
        # that corroborated signal but can never independently create it.
        surface_relevance = (
            max(surface_dice, (0.5 * surface_dice) + (0.5 * surface_containment))
            if len(shared_terms) >= 2
            else surface_dice
        )
        spike_relevance = (
            max(spike_dice, (0.75 * spike_dice) + (0.25 * spike_containment))
            if len(shared_terms) >= 2 and len(shared_spikes) >= 3
            else spike_dice
        )
        available_scores: list[tuple[float, float]] = []
        if surface_denominator:
            available_scores.append((surface_relevance, 0.7))
        if spike_denominator:
            available_scores.append((spike_relevance, 0.3))
        total_weight = sum(weight for _score, weight in available_scores)
        relevance_score = (
            sum(score * weight for score, weight in available_scores) / total_weight
            if total_weight
            else 0.0
        )
        # Namespace-wide spike unions can saturate as a corpus grows. A dense
        # namespace may then contain every spike in a small unrelated one.
        # Require at least one shared semantic surface term before spike
        # overlap can produce a suggestion score; retain the pure Dice value
        # in evidence for inspection.
        if not shared_terms:
            relevance_score = 0.0
        bounded_max_delay = min(max(int(max_phase_delay_ticks), 0), 64)
        suggested_phase_delay_ticks = min(
            bounded_max_delay,
            max(0, int(round(bounded_max_delay * (1.0 - relevance_score)))),
        )
        pair = sorted((source_context_id, target_context_id))
        suggestion_seed = (
            f"{pair[0]}\x1f{pair[1]}\x1fdensity-dice-containment-v2".encode("utf-8")
        )
        evidence = {
            "method": "density-normalized-dice-plus-containment-v2",
            "surface_dice": round(surface_dice, 6),
            "spike_dice": round(spike_dice, 6),
            "dice_score": round(dice_score, 6),
            "relevance_score": round(relevance_score, 6),
            "surface_containment": round(surface_containment, 6),
            "spike_containment": round(spike_containment, 6),
            "containment_lift_applied": bool(
                len(shared_terms) >= 2
            ),
            "surface_overlap_count": len(shared_terms),
            "surface_source_count": len(source_terms),
            "surface_target_count": len(target_terms),
            "spike_overlap_count": len(shared_spikes),
            "spike_source_count": len(source_spikes),
            "spike_target_count": len(target_spikes),
            "shared_surface_terms": sorted(shared_terms)[:20],
            "shared_spike_indices": sorted(shared_spikes)[:20],
            "suggested_phase_delay_ticks": suggested_phase_delay_ticks,
            "max_visual_phase_delay_ticks": bounded_max_delay,
            "delay_semantics": "visualization-only",
            "automatic_cross_namespace_write": False,
        }
        return {
            "suggestion_id": "s2cs_" + hashlib.sha256(suggestion_seed).hexdigest()[:32],
            "source_context_id": source_context_id,
            "target_context_id": target_context_id,
            "score": round(relevance_score, 6),
            "weight": round(relevance_score, 6),
            "confidence": round(relevance_score, 6),
            "dice_score": evidence["dice_score"],
            "relevance_score": round(relevance_score, 6),
            "surface_dice": round(surface_dice, 6),
            "spike_dice": round(spike_dice, 6),
            "surface_containment": round(surface_containment, 6),
            "spike_containment": round(spike_containment, 6),
            "surface_overlap_count": len(shared_terms),
            "spike_overlap_count": len(shared_spikes),
            "suggested_phase_delay_ticks": suggested_phase_delay_ticks,
            "max_visual_phase_delay_ticks": bounded_max_delay,
            "delay_semantics": "visualization-only",
            "evidence": evidence,
            "persisted": False,
            "requires_approval": True,
            "automatic_cross_namespace_write": False,
        }

    def upsert_relationship(
        self,
        *,
        context_id: str,
        source_memory_id: str,
        target_memory_id: str,
        relation_type: str,
        weight: float,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        relationship_id = self.stable_relationship_id(
            context_id=context_id,
            source_memory_id=source_memory_id,
            target_memory_id=target_memory_id,
            relation_type=relation_type,
        )
        now = time.time()
        bounded_weight = min(max(float(weight), 0.0), 1.0)
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    return self._upsert_relationship_conn(
                        conn,
                        relationship_id=relationship_id,
                        context_id=str(context_id),
                        source_memory_id=str(source_memory_id),
                        target_memory_id=str(target_memory_id),
                        relation_type=str(relation_type),
                        weight=bounded_weight,
                        evidence_json=_json_dumps(evidence or {}),
                        created_at=now,
                        updated_at=now,
                    )
        except Exception:
            LOGGER.exception(
                "failed to upsert relationship context_id=%s source=%s target=%s",
                context_id,
                source_memory_id,
                target_memory_id,
            )
            raise

    def _upsert_relationship_conn(
        self,
        conn: sqlite3.Connection,
        *,
        relationship_id: str,
        context_id: str,
        source_memory_id: str,
        target_memory_id: str,
        relation_type: str,
        weight: float,
        evidence_json: str,
        created_at: float,
        updated_at: float,
    ) -> dict[str, Any]:
        conn.execute(
            """
            INSERT INTO memory_relationships (
                relationship_id,
                context_id,
                source_memory_id,
                target_memory_id,
                relation_type,
                weight,
                evidence_json,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(relationship_id) DO UPDATE SET
                weight = excluded.weight,
                evidence_json = excluded.evidence_json,
                updated_at = excluded.updated_at
            """,
            (
                relationship_id,
                context_id,
                source_memory_id,
                target_memory_id,
                relation_type,
                weight,
                evidence_json,
                created_at,
                updated_at,
            ),
        )
        relationship_row = conn.execute(
            """
            SELECT
                r.*,
                source.tag AS source_tag,
                target.tag AS target_tag
            FROM memory_relationships AS r
            JOIN memory_entries AS source
                ON source.memory_id = r.source_memory_id
            JOIN memory_entries AS target
                ON target.memory_id = r.target_memory_id
            WHERE r.relationship_id = ?
            """,
            (relationship_id,),
        ).fetchone()
        if relationship_row is None:
            raise RuntimeError(
                f"relationship {relationship_id} was not readable after upsert"
            )
        return self._row_to_relationship(relationship_row)

    def get_relationship(self, relationship_id: str) -> dict[str, Any] | None:
        relationships = self.list_relationships(
            relationship_id=relationship_id,
            limit=1,
        )
        return relationships[0] if relationships else None

    def list_relationships(
        self,
        *,
        context_id: str | None = None,
        relationship_id: str | None = None,
        source_memory_id: str | None = None,
        target_memory_id: str | None = None,
        relation_type: str | None = None,
        limit: int = 100,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("r.context_id = ?")
            params.append(str(context_id))
        if relationship_id is not None:
            clauses.append("r.relationship_id = ?")
            params.append(str(relationship_id))
        if source_memory_id is not None:
            clauses.append("r.source_memory_id = ?")
            params.append(str(source_memory_id))
        if target_memory_id is not None:
            clauses.append("r.target_memory_id = ?")
            params.append(str(target_memory_id))
        if relation_type is not None:
            clauses.append("r.relation_type = ?")
            params.append(str(relation_type))
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        bounded_limit = min(max(int(limit), 1), 10_000)
        params.append(bounded_limit)
        try:
            with self._read_connection_scope(_conn) as conn:
                rows = conn.execute(
                    f"""
                    SELECT
                        r.*,
                        source.tag AS source_tag,
                        target.tag AS target_tag
                    FROM memory_relationships AS r
                    JOIN memory_entries AS source
                        ON source.memory_id = r.source_memory_id
                    JOIN memory_entries AS target
                        ON target.memory_id = r.target_memory_id
                    {where_sql}
                    ORDER BY r.weight DESC, r.updated_at DESC
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()
            return [self._row_to_relationship(row) for row in rows]
        except Exception:
            LOGGER.exception("failed to list memory relationships")
            raise

    def delete_entry(
        self,
        *,
        context_id: str | None = None,
        memory_id: str | None = None,
        tag: str | None = None,
    ) -> dict[str, Any]:
        clauses: list[str] = []
        params: list[Any] = []
        if memory_id:
            clauses.append("memory_id = ?")
            params.append(str(memory_id))
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        if tag:
            clauses.append("tag = ?")
            params.append(str(tag))
        if not clauses or (not memory_id and not tag):
            raise ValueError("delete_entry requires memory_id or tag")
        where_sql = " AND ".join(clauses)
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    row = conn.execute(
                        f"SELECT * FROM memory_entries WHERE {where_sql} LIMIT 1",
                        tuple(params),
                    ).fetchone()
                    if row is None:
                        entry = None
                        entry_id = str(memory_id or "")
                        relationship_count = 0
                        memory_event_count = 0
                    else:
                        entry = self._row_to_entry(row)
                        entry_id = entry["memory_id"]
                        relationship_count = int(
                            conn.execute(
                                """
                                SELECT COUNT(*)
                                FROM memory_relationships
                                WHERE source_memory_id = ? OR target_memory_id = ?
                                """,
                                (entry_id, entry_id),
                            ).fetchone()[0]
                        )
                        memory_event_count = int(
                            conn.execute(
                                "SELECT COUNT(*) FROM memory_events WHERE memory_id = ?",
                                (entry_id,),
                            ).fetchone()[0]
                        )
                        conn.execute(
                            "DELETE FROM memory_entries WHERE memory_id = ?",
                            (entry_id,),
                        )
            if entry is None:
                return {
                    "deleted": False,
                    "deleted_memory_id": entry_id,
                    "deleted_relationship_count": 0,
                    "deleted_memory_event_count": 0,
                    "entry": None,
                }
            return {
                "deleted": True,
                "deleted_memory_id": entry_id,
                "deleted_relationship_count": relationship_count,
                "deleted_memory_event_count": memory_event_count,
                "entry": entry,
            }
        except Exception:
            LOGGER.exception(
                "failed to delete memory entry context_id=%s memory_id=%s tag=%s",
                context_id,
                memory_id,
                tag,
            )
            raise

    def delete_relationship(
        self,
        *,
        relationship_id: str,
        context_id: str | None = None,
    ) -> dict[str, Any]:
        relationship_id_text = str(relationship_id)
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    context_clause = ""
                    params: list[Any] = [relationship_id_text]
                    if context_id is not None:
                        context_clause = "AND r.context_id = ?"
                        params.append(str(context_id))
                    relationship_row = conn.execute(
                        f"""
                        SELECT
                            r.*,
                            source.tag AS source_tag,
                            target.tag AS target_tag
                        FROM memory_relationships AS r
                        JOIN memory_entries AS source
                            ON source.memory_id = r.source_memory_id
                        JOIN memory_entries AS target
                            ON target.memory_id = r.target_memory_id
                        WHERE r.relationship_id = ? {context_clause}
                        """,
                        tuple(params),
                    ).fetchone()
                    relationship = (
                        self._row_to_relationship(relationship_row)
                        if relationship_row is not None
                        else None
                    )
                    if relationship_row is not None:
                        delete_params: list[Any] = [relationship_id_text]
                        delete_context_clause = ""
                        if context_id is not None:
                            delete_context_clause = "AND context_id = ?"
                            delete_params.append(str(context_id))
                        conn.execute(
                            f"""
                            DELETE FROM memory_relationships
                            WHERE relationship_id = ? {delete_context_clause}
                            """,
                            tuple(delete_params),
                        )
            if relationship is None:
                return {
                    "deleted": False,
                    "relationship_id": relationship_id_text,
                    "relationship": None,
                }
            return {
                "deleted": True,
                "relationship_id": relationship_id_text,
                "relationship": relationship,
            }
        except Exception:
            LOGGER.exception(
                "failed to delete memory relationship context_id=%s relationship_id=%s",
                context_id,
                relationship_id,
            )
            raise

    def delete_relationships_by_mode(
        self,
        *,
        context_id: str,
        mode: str,
        source_memory_id: str | None = None,
        target_memory_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = str(mode or "").strip().lower()
        if normalized not in {"temporal", "associative"}:
            raise ValueError("mode must be temporal or associative")
        clauses = ["context_id = ?"]
        params: list[Any] = [str(context_id)]
        if normalized == "temporal":
            clauses.append("(relation_type LIKE 'temporal%' OR relation_type = 'typed_context_sequence')")
        else:
            clauses.append("(relation_type LIKE 'semantic%' OR relation_type LIKE 'associative%')")
        if source_memory_id:
            clauses.append("source_memory_id = ?")
            params.append(str(source_memory_id))
        if target_memory_id:
            clauses.append("target_memory_id = ?")
            params.append(str(target_memory_id))
        where_sql = " AND ".join(clauses)
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    rows = conn.execute(
                        f"""
                        SELECT relationship_id
                        FROM memory_relationships
                        WHERE {where_sql}
                        ORDER BY updated_at DESC
                        """,
                        tuple(params),
                    ).fetchall()
                    relationship_ids = [str(row["relationship_id"]) for row in rows]
                    if relationship_ids:
                        conn.executemany(
                            "DELETE FROM memory_relationships WHERE relationship_id = ?",
                            [(relationship_id,) for relationship_id in relationship_ids],
                        )
            return {
                "deleted": bool(relationship_ids),
                "mode": normalized,
                "deleted_relationship_count": len(relationship_ids),
                "deleted_relationship_ids": relationship_ids,
            }
        except Exception:
            LOGGER.exception(
                "failed to delete %s relationships context_id=%s",
                normalized,
                context_id,
            )
            raise

    def publish_context_event(
        self,
        *,
        context_id: str,
        source_surface: str,
        event_type: str,
        summary: str,
        payload: dict[str, Any] | None = None,
        agent_targets: Iterable[str] | None = None,
        created_at: float | None = None,
    ) -> dict[str, Any]:
        context = reject_sensitive_identifier(
            context_id if context_id is not None else "",
            field="context_id",
        )
        if not self._context_event_context_id_is_valid(context):
            raise ValueError(
                "context_id must be stripped, nonempty, and at most 128 characters"
            )
        clean_source_surface = str(source_surface or "unknown").strip()[:128] or "unknown"
        clean_event_type = str(event_type or "context-update").strip()[:128] or "context-update"
        clean_source_surface = validate_public_identifier(
            clean_source_surface,
            field="source_surface",
            max_chars=128,
        )
        clean_event_type = validate_public_identifier(
            clean_event_type,
            field="event_type",
            max_chars=128,
        )
        safe_summary, _ = redact_capture_text(str(summary or ""))
        if not self._context_event_summary_is_valid(safe_summary):
            raise ValueError(
                "context event summary must contain non-control evidence text"
            )
        safe_payload, payload_redactions = redact_sensitive_value(payload or {})
        safe_payload, raw_digest_removals = strip_untrusted_raw_digest_fields(
            safe_payload
        )
        if not isinstance(safe_payload, dict):
            safe_payload = {}
        boundary_mutations = int(payload_redactions) + int(raw_digest_removals)
        if boundary_mutations:
            try:
                prior_redactions = max(
                    0,
                    int(safe_payload.get("context_bus_redaction_count", 0) or 0),
                )
            except (TypeError, ValueError):
                prior_redactions = 0
            safe_payload = {
                **safe_payload,
                "context_bus_redaction_count": prior_redactions + boundary_mutations,
                "raw_payload_stored": False,
            }
        targets = self._normalize_event_targets(agent_targets)
        if not targets:
            targets = ["mcp-clients"]
        now = time.time() if created_at is None else float(created_at)
        if not self._context_delivery_timestamp_is_valid(now):
            raise ValueError("created_at must be a finite timestamp")
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    return self._publish_context_event_conn(
                        conn,
                        context_id=context,
                        source_surface=clean_source_surface,
                        event_type=clean_event_type,
                        summary=safe_summary,
                        payload_json=_json_dumps(safe_payload),
                        targets=targets,
                        created_at=now,
                    )
        except Exception:
            LOGGER.exception(
                "failed to publish context event context_id=%s event_type=%s",
                context_id,
                event_type,
            )
            raise

    def _publish_context_event_conn(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str,
        source_surface: str,
        event_type: str,
        summary: str,
        payload_json: str,
        targets: list[str],
        created_at: float,
    ) -> dict[str, Any]:
        self._record_namespace_catalog_conn(
            conn,
            context_id=context_id,
            observed_at=created_at,
        )
        cursor = conn.execute(
            """
            INSERT INTO agent_context_events (
                context_id,
                source_surface,
                event_type,
                summary,
                payload_json,
                agent_targets_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                context_id,
                source_surface,
                event_type,
                summary,
                payload_json,
                _json_dumps(targets),
                created_at,
            ),
        )
        event_id = int(cursor.lastrowid)
        target_records = self._normalized_event_target_records(targets)
        conn.executemany(
            """
            INSERT INTO agent_context_event_targets (
                event_id,
                target_kind,
                target_id,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            [
                (event_id, target_kind, target_id, created_at)
                for target_kind, target_id in target_records
            ],
        )
        # Publishing owns the canonical target rows, but the durable routing
        # high-water and receipt-derived cursors must cross the same atomic
        # boundary. Reusing reconciliation also catches a committed event from
        # a rolling old writer without skipping it by blindly assigning this
        # event ID as the new high-water.
        self._reconcile_context_event_targets(
            conn,
            reconciled_at=time.time(),
            strict_existing_targets=True,
        )
        event_row = conn.execute(
            "SELECT * FROM agent_context_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if event_row is None:
            raise RuntimeError(f"context event {event_id} was not readable after publish")
        return self._row_to_context_event(event_row)

    @classmethod
    def _normalize_event_targets(
        cls,
        agent_targets: Iterable[str] | None,
    ) -> list[str]:
        targets: list[str] = []
        seen: set[str] = set()
        for value in agent_targets or ():
            raw_target = str(value or "").strip()[:128]
            folded = raw_target.casefold()
            if folded in {"*", "all", "all-agents", "broadcast"}:
                target = "broadcast"
            elif folded in CONTEXT_EVENT_TARGET_GROUPS:
                target = folded
            else:
                target = cls._normalize_delivery_agent_id(raw_target)
            if not target or target in seen:
                continue
            seen.add(target)
            targets.append(target)
            if len(targets) >= 64:
                break
        return targets

    @classmethod
    def _normalized_event_target_records(
        cls,
        agent_targets: Iterable[str],
    ) -> list[tuple[str, str]]:
        records: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for raw_target in agent_targets:
            target = str(raw_target or "").strip()[:128]
            folded = target.casefold()
            if not folded:
                continue
            if folded in {"*", "all", "all-agents", "broadcast"}:
                record = ("broadcast", "*")
            elif folded in CONTEXT_EVENT_TARGET_GROUPS:
                record = ("group", folded)
            else:
                canonical_agent = cls._normalize_delivery_agent_id(target)
                if not canonical_agent:
                    continue
                record = ("agent", canonical_agent)
            if record in seen:
                continue
            seen.add(record)
            records.append(record)
        return records

    @staticmethod
    def _normalize_delivery_agent_id(agent_id: str) -> str:
        raw = reject_sensitive_identifier(
            agent_id,
            field="agent_id",
        ).strip()
        cleaned = re.sub(r"[^A-Za-z0-9_.:@-]+", "_", raw).strip("._-:@")
        return cleaned.casefold()[:128]

    @staticmethod
    def _context_delivery_max_attempts() -> int:
        raw = os.getenv("SYNAPSE_S2_CONTEXT_MAX_DELIVERY_ATTEMPTS", "5")
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "SYNAPSE_S2_CONTEXT_MAX_DELIVERY_ATTEMPTS must be an integer"
            ) from exc
        return min(max(value, 2), 100)

    @staticmethod
    def _context_delivery_receipt_digest(receipt_id: str) -> str:
        return hashlib.sha256(
            b"context-delivery-ack-tombstone:v1\x00"
            + str(receipt_id).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _normalize_consumer_groups(
        consumer_groups: Iterable[str] | None,
    ) -> tuple[str, ...]:
        groups: list[str] = []
        seen: set[str] = set()
        for value in consumer_groups or ():
            group = str(value or "").strip().casefold()[:128]
            if group not in CONTEXT_EVENT_TARGET_GROUPS or group in seen:
                continue
            seen.add(group)
            groups.append(group)
        return tuple(groups)

    @classmethod
    def _event_target_clause(
        cls,
        *,
        event_alias: str,
        agent_id: str,
        consumer_groups: Iterable[str] | None = None,
    ) -> tuple[str, tuple[str, ...]]:
        agent = cls._normalize_delivery_agent_id(agent_id)
        groups = cls._normalize_consumer_groups(consumer_groups)
        use_persisted_groups = consumer_groups is None
        declared_group_clause = "0"
        declared_group_params: tuple[str, ...] = ()
        if groups:
            placeholders = ", ".join("?" for _ in groups)
            declared_group_clause = f"target.target_id IN ({placeholders})"
            declared_group_params = tuple(groups)
        persisted_group_clause = "0"
        persisted_group_params: tuple[str, ...] = ()
        if use_persisted_groups:
            persisted_group_clause = """
                EXISTS (
                    SELECT 1
                    FROM agent_context_consumer_groups AS membership
                    WHERE membership.agent_id = ?
                      AND membership.group_id = target.target_id
                )
            """
            persisted_group_params = (agent,)
        clause = f"""
            EXISTS (
                SELECT 1
                FROM agent_context_event_targets AS target
                WHERE target.event_id = {event_alias}.event_id
                  AND (
                      target.target_kind = 'broadcast'
                      OR (
                          target.target_kind = 'agent'
                          AND target.target_id = ? COLLATE NOCASE
                      )
                      OR (
                          target.target_kind = 'group'
                          AND (
                              {declared_group_clause}
                              OR {persisted_group_clause}
                          )
                      )
                  )
            )
        """
        return clause, (agent, *declared_group_params, *persisted_group_params)

    def _register_context_consumer(
        self,
        conn: sqlite3.Connection,
        *,
        agent_id: str,
        consumer_instance_id: str,
        consumer_groups: Iterable[str] | None,
        now: float,
    ) -> None:
        agent = self._normalize_delivery_agent_id(agent_id)
        if not agent:
            raise ValueError("agent_id is required for context delivery")
        instance = str(consumer_instance_id or "").strip()
        if not instance:
            raise ValueError("consumer_instance_id is required for context delivery")
        groups = self._normalize_consumer_groups(consumer_groups)
        conn.execute(
            """
            INSERT INTO agent_context_consumers (
                agent_id,
                consumer_kind,
                enabled,
                created_at,
                updated_at
            )
            VALUES (?, 'local-mcp', 1, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET updated_at = excluded.updated_at
            """,
            (agent, now, now),
        )
        enabled_row = conn.execute(
            "SELECT enabled FROM agent_context_consumers WHERE agent_id = ?",
            (agent,),
        ).fetchone()
        if enabled_row is None or not bool(enabled_row["enabled"]):
            raise ValueError(f"context consumer {agent!r} is disabled")
        # Membership is an authoritative declaration from the trusted caller,
        # not an additive cache. Removing a group from policy revokes it on the
        # next claim instead of leaving stale delivery access behind.
        conn.execute(
            "DELETE FROM agent_context_consumer_groups WHERE agent_id = ?",
            (agent,),
        )
        for group in groups:
            conn.execute(
                """
                INSERT INTO agent_context_consumer_groups (
                    agent_id,
                    group_id,
                    created_at
                )
                VALUES (?, ?, ?)
                ON CONFLICT(agent_id, group_id) DO NOTHING
                """,
                (agent, group, now),
            )

    def _context_delivery_metrics(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str,
        agent_id: str,
        cursor_event_id: int,
    ) -> dict[str, int]:
        target_clause, target_params = self._event_target_clause(
            event_alias="event",
            agent_id=agent_id,
        )
        latest_event_id = int(
            conn.execute(
                """
                SELECT COALESCE(MAX(event_id), 0)
                FROM agent_context_events
                WHERE context_id = ?
                """,
                (context_id,),
            ).fetchone()[0]
            or 0
        )
        latest_eligible_event_id = int(
            conn.execute(
                f"""
                SELECT COALESCE(MAX(event.event_id), 0)
                FROM agent_context_events AS event
                WHERE event.context_id = ? AND {target_clause}
                """,
                (context_id, *target_params),
            ).fetchone()[0]
            or 0
        )
        pending_event_count = int(
            conn.execute(
                f"""
                SELECT COUNT(*)
                FROM agent_context_events AS event
                WHERE event.context_id = ?
                  AND event.event_id > ?
                  AND {target_clause}
                  AND NOT EXISTS (
                      SELECT 1
                      FROM agent_context_deliveries AS delivery
                      WHERE delivery.context_id = event.context_id
                        AND delivery.agent_id = ?
                        AND delivery.event_id = event.event_id
                        AND delivery.state IN ('acknowledged', 'dead_letter')
                  )
                """,
                (
                    context_id,
                    max(0, int(cursor_event_id)),
                    *target_params,
                    agent_id,
                ),
            ).fetchone()[0]
        )
        acknowledged_delivery_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries
                WHERE context_id = ?
                  AND agent_id = ?
                  AND state = 'acknowledged'
                """,
                (context_id, agent_id),
            ).fetchone()[0]
        )
        terminal_delivery_count = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM agent_context_deliveries
                WHERE context_id = ?
                  AND agent_id = ?
                  AND state IN ('acknowledged', 'dead_letter')
                """,
                (context_id, agent_id),
            ).fetchone()[0]
        )
        return {
            "latest_event_id": latest_event_id,
            "latest_eligible_event_id": latest_eligible_event_id,
            "pending_event_count": pending_event_count,
            "acknowledged_delivery_count": acknowledged_delivery_count,
            "terminal_delivery_count": terminal_delivery_count,
        }

    def _ensure_context_cursor(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str,
        agent_id: str,
        now: float,
    ) -> sqlite3.Row:
        conn.execute(
            """
            INSERT INTO agent_context_delivery_cursors (
                context_id,
                agent_id,
                last_contiguous_event_id,
                updated_at
            )
            VALUES (?, ?, 0, ?)
            ON CONFLICT(context_id, agent_id) DO NOTHING
            """,
            (context_id, agent_id, now),
        )
        row = conn.execute(
            """
            SELECT *
            FROM agent_context_delivery_cursors
            WHERE context_id = ? AND agent_id = ?
            """,
            (context_id, agent_id),
        ).fetchone()
        if row is None:
            raise RuntimeError(
                f"context cursor for {agent_id} was not readable after creation"
            )
        return row

    def _advance_context_cursor(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str,
        agent_id: str,
        now: float,
    ) -> dict[str, Any]:
        cursor_row = self._ensure_context_cursor(
            conn,
            context_id=context_id,
            agent_id=agent_id,
            now=now,
        )
        current_event_id = max(0, int(cursor_row["last_contiguous_event_id"]))
        next_event_id = self._derived_context_cursor_event_id(
            conn,
            context_id=context_id,
            agent_id=agent_id,
        )
        if next_event_id != current_event_id:
            conn.execute(
                """
                UPDATE agent_context_delivery_cursors
                SET last_contiguous_event_id = ?, updated_at = ?
                WHERE context_id = ? AND agent_id = ?
                """,
                (next_event_id, now, context_id, agent_id),
            )
        cursor_row = conn.execute(
            """
            SELECT *
            FROM agent_context_delivery_cursors
            WHERE context_id = ? AND agent_id = ?
            """,
            (context_id, agent_id),
        ).fetchone()
        if cursor_row is None:
            raise RuntimeError(f"context cursor for {agent_id} disappeared")
        metrics = self._context_delivery_metrics(
            conn,
            context_id=context_id,
            agent_id=agent_id,
            cursor_event_id=int(cursor_row["last_contiguous_event_id"]),
        )
        return self._row_to_context_cursor(cursor_row, **metrics)

    def list_context_events(
        self,
        *,
        context_id: str | None = None,
        event_id: int | None = None,
        since_event_id: int = 0,
        before_event_id: int | None = None,
        agent_id: str | None = None,
        consumer_groups: Iterable[str] | None = None,
        order: str = "asc",
        limit: int = 100,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        normalized_order = str(order or "asc").strip().lower()
        if normalized_order not in {"asc", "desc"}:
            raise ValueError("context event order must be asc or desc")
        if event_id is not None:
            clauses.append("event_id = ?")
            params.append(int(event_id))
        else:
            clauses.append("event_id > ?")
            params.append(max(0, int(since_event_id)))
            if normalized_order == "desc" and before_event_id is not None:
                clauses.append("event_id < ?")
                params.append(max(1, int(before_event_id)))
        if agent_id is not None:
            target_clause, target_params = self._event_target_clause(
                event_alias="agent_context_events",
                agent_id=str(agent_id),
                consumer_groups=consumer_groups,
            )
            clauses.append(target_clause)
            params.extend(target_params)
        where_sql = "WHERE " + " AND ".join(clauses)
        bounded_limit = min(max(int(limit), 1), 10_000)
        params.append(bounded_limit)
        try:
            with self._read_connection_scope(_conn) as conn:
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM agent_context_events
                    {where_sql}
                    ORDER BY event_id {normalized_order.upper()}
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()
            return [self._row_to_context_event(row) for row in rows]
        except Exception:
            LOGGER.exception("failed to list context events")
            raise

    def delete_context_event(
        self,
        *,
        context_id: str,
        event_id: int,
    ) -> dict[str, Any]:
        bounded_event_id = max(0, int(event_id))
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    row = conn.execute(
                        """
                        SELECT *
                        FROM agent_context_events
                        WHERE context_id = ? AND event_id = ?
                        """,
                        (str(context_id), bounded_event_id),
                    ).fetchone()
                    event = self._row_to_context_event(row) if row is not None else None
                    if row is not None:
                        affected_cursor_agents = [
                            str(cursor_row["agent_id"])
                            for cursor_row in conn.execute(
                                """
                                SELECT agent_id
                                FROM agent_context_delivery_cursors
                                WHERE context_id = ?
                                ORDER BY agent_id
                                """,
                                (str(context_id),),
                            ).fetchall()
                        ]
                        active_lease_count = int(
                            conn.execute(
                                """
                                SELECT COUNT(*)
                                FROM agent_context_deliveries
                                WHERE context_id = ?
                                  AND event_id = ?
                                  AND state = 'leased'
                                  AND lease_expires_at > ?
                                """,
                                (str(context_id), bounded_event_id, time.time()),
                            ).fetchone()[0]
                        )
                        if active_lease_count:
                            raise ValueError(
                                "context event has active delivery leases; release or wait for expiry before pruning"
                            )
                        acknowledged_receipts = conn.execute(
                            """
                            SELECT
                                receipt.receipt_id,
                                receipt.delivery_id,
                                receipt.attempt_number,
                                receipt.acknowledged_at,
                                delivery.context_id,
                                delivery.agent_id,
                                delivery.event_id
                            FROM agent_context_delivery_receipts AS receipt
                            JOIN agent_context_deliveries AS delivery
                              ON delivery.delivery_id = receipt.delivery_id
                            WHERE delivery.context_id = ?
                              AND delivery.event_id = ?
                              AND receipt.state = 'acknowledged'
                            """,
                            (str(context_id), bounded_event_id),
                        ).fetchall()
                        deleted_at = time.time()
                        for receipt in acknowledged_receipts:
                            conn.execute(
                                """
                                INSERT OR IGNORE INTO agent_context_delivery_ack_tombstones (
                                    receipt_digest,
                                    delivery_id,
                                    context_id,
                                    agent_id,
                                    event_id,
                                    attempt_number,
                                    acknowledged_at,
                                    deleted_at
                                )
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    self._context_delivery_receipt_digest(
                                        str(receipt["receipt_id"])
                                    ),
                                    str(receipt["delivery_id"]),
                                    str(receipt["context_id"]),
                                    str(receipt["agent_id"]),
                                    int(receipt["event_id"]),
                                    int(receipt["attempt_number"]),
                                    float(receipt["acknowledged_at"]),
                                    deleted_at,
                                ),
                            )
                        conn.execute(
                            """
                            DELETE FROM agent_context_events
                            WHERE context_id = ? AND event_id = ?
                            """,
                            (str(context_id), bounded_event_id),
                        )
                        target_highwater = (
                            self._read_context_event_target_highwater(
                                conn,
                                allow_missing=False,
                            )
                        )
                        latest_event_id = int(
                            conn.execute(
                                """
                                SELECT COALESCE(MAX(event_id), 0)
                                FROM agent_context_events
                                """
                            ).fetchone()[0]
                            or 0
                        )
                        if target_highwater > latest_event_id:
                            conn.execute(
                                """
                                UPDATE store_metadata
                                SET value_json = ?, updated_at = ?
                                WHERE key = 'context_event_targets_reconciled_through'
                                """,
                                (json.dumps(latest_event_id), deleted_at),
                            )
                        # Cursor values are derived from the retained ledger,
                        # not monotonic external watermarks.  Deleting any
                        # event can change that derivation even for a consumer
                        # that never had a delivery row for the pruned event,
                        # so repair every cursor in the affected namespace in
                        # the same transaction as the delete.
                        for cursor_agent_id in affected_cursor_agents:
                            self._advance_context_cursor(
                                conn,
                                context_id=str(context_id),
                                agent_id=cursor_agent_id,
                                now=deleted_at,
                            )
            if event is None:
                return {
                    "deleted": False,
                    "event_id": bounded_event_id,
                    "event": None,
                }
            return {
                "deleted": True,
                "event_id": bounded_event_id,
                "event": event,
            }
        except ValueError:
            LOGGER.warning(
                "refused context event deletion context_id=%s event_id=%s",
                context_id,
                event_id,
            )
            raise
        except Exception:
            LOGGER.exception(
                "failed to delete context event context_id=%s event_id=%s",
                context_id,
                event_id,
            )
            raise

    def lease_context_events(
        self,
        *,
        context_id: str,
        agent_id: str,
        consumer_instance_id: str,
        consumer_groups: Iterable[str] | None = None,
        limit: int = 20,
        lease_seconds: float = 60.0,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Lease the oldest eligible context events with durable attempt receipts.

        Delivery is intentionally at-least-once.  A stable ``delivery_id`` is
        the consumer deduplication key; each retry receives a new opaque
        ``receipt_id`` that fences acknowledgements from expired attempts.
        """

        context = str(context_id or "").strip()
        agent = self._normalize_delivery_agent_id(agent_id)
        instance = str(consumer_instance_id or "").strip()
        if not context:
            raise ValueError("context_id is required for context delivery")
        if len(context) > 128:
            raise ValueError("context_id exceeds 128 characters")
        if not agent:
            raise ValueError("agent_id is required for context delivery")
        if not instance:
            raise ValueError("consumer_instance_id is required for context delivery")
        if not self._context_delivery_owner_is_valid(instance):
            raise ValueError(
                "consumer_instance_id must be 1-256 printable ASCII characters"
            )
        bounded_limit = min(max(int(limit), 1), 500)
        raw_lease_seconds = float(lease_seconds)
        if not math.isfinite(raw_lease_seconds):
            raise ValueError("lease_seconds must be finite")
        bounded_lease_seconds = min(max(raw_lease_seconds, 1.0), 3600.0)
        current_time = time.time() if now is None else float(now)
        if not math.isfinite(current_time):
            raise ValueError("now must be finite")
        max_delivery_attempts = self._context_delivery_max_attempts()

        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    self._register_context_consumer(
                        conn,
                        agent_id=agent,
                        consumer_instance_id=instance,
                        consumer_groups=consumer_groups,
                        now=current_time,
                    )
                    cursor = self._advance_context_cursor(
                        conn,
                        context_id=context,
                        agent_id=agent,
                        now=current_time,
                    )
                    cursor_event_id = int(cursor["last_event_id"])
                    target_clause, target_params = self._event_target_clause(
                        event_alias="event",
                        agent_id=agent,
                    )
                    candidate_rows = conn.execute(
                        f"""
                        SELECT event.*
                        FROM agent_context_events AS event
                        WHERE event.context_id = ?
                          AND event.event_id > ?
                          AND {target_clause}
                          AND NOT EXISTS (
                              SELECT 1
                              FROM agent_context_deliveries AS delivery
                              WHERE delivery.context_id = event.context_id
                                AND delivery.agent_id = ?
                                AND delivery.event_id = event.event_id
                                AND delivery.state IN (
                                    'acknowledged',
                                    'dead_letter'
                                )
                          )
                        ORDER BY event.event_id ASC
                        LIMIT ?
                        """,
                        (
                            context,
                            cursor_event_id,
                            *target_params,
                            agent,
                            bounded_limit + 1,
                        ),
                    ).fetchall()
                    has_more = len(candidate_rows) > bounded_limit
                    deliveries: list[dict[str, Any]] = []
                    blocking_delivery: dict[str, Any] | None = None
                    for event_row in candidate_rows[:bounded_limit]:
                        event_id = int(event_row["event_id"])
                        delivery_row = conn.execute(
                            """
                            SELECT *
                            FROM agent_context_deliveries
                            WHERE context_id = ?
                              AND agent_id = ?
                              AND event_id = ?
                            """,
                            (context, agent, event_id),
                        ).fetchone()
                        redelivered = False
                        if delivery_row is not None:
                            lease_expires_at = float(delivery_row["lease_expires_at"])
                            lease_owner = str(delivery_row["lease_owner"])
                            if lease_expires_at > current_time:
                                if lease_owner != instance:
                                    blocking_delivery = {
                                        "delivery_id": str(delivery_row["delivery_id"]),
                                        "event_id": event_id,
                                        "reason": "active-lease",
                                        "lease_owner": lease_owner,
                                        "lease_expires_at": lease_expires_at,
                                    }
                                    break
                                receipt_row = conn.execute(
                                    """
                                    SELECT *
                                    FROM agent_context_delivery_receipts
                                    WHERE receipt_id = ?
                                    """,
                                    (str(delivery_row["current_receipt_id"]),),
                                ).fetchone()
                                if (
                                    receipt_row is None
                                    or str(receipt_row["state"]) != "leased"
                                    or str(receipt_row["delivery_id"])
                                    != str(delivery_row["delivery_id"])
                                    or int(receipt_row["attempt_number"])
                                    != int(delivery_row["attempt_count"])
                                    or str(receipt_row["consumer_instance_id"])
                                    != lease_owner
                                    or not math.isclose(
                                        float(receipt_row["lease_expires_at"]),
                                        lease_expires_at,
                                        rel_tol=0.0,
                                        abs_tol=0.000001,
                                    )
                                ):
                                    raise RuntimeError(
                                        "active context delivery receipt failed "
                                        "integrity validation"
                                    )
                                deliveries.append(
                                    self._context_delivery_payload(
                                        delivery_row,
                                        receipt_row,
                                        event_row,
                                        redelivered=False,
                                    )
                                )
                                continue
                            conn.execute(
                                """
                                UPDATE agent_context_delivery_receipts
                                SET state = 'expired', updated_at = ?
                                WHERE receipt_id = ? AND state = 'leased'
                                """,
                                (current_time, str(delivery_row["current_receipt_id"])),
                            )
                            delivery_id = str(delivery_row["delivery_id"])
                            prior_attempt_count = int(delivery_row["attempt_count"])
                            if prior_attempt_count >= max_delivery_attempts:
                                blocking_delivery = {
                                    "delivery_id": delivery_id,
                                    "event_id": event_id,
                                    "attempt_count": prior_attempt_count,
                                    "max_delivery_attempts": max_delivery_attempts,
                                    "reason": "retry-exhausted",
                                    "requires_governed_dead_letter": True,
                                }
                                break
                            attempt_count = prior_attempt_count + 1
                            redelivered = True
                        else:
                            delivery_id = "ctxdel_" + uuid.uuid4().hex
                            attempt_count = 1

                        receipt_id = "ctxrcpt_" + secrets.token_urlsafe(32)
                        lease_expires_at = current_time + bounded_lease_seconds
                        if delivery_row is None:
                            conn.execute(
                                """
                                INSERT INTO agent_context_deliveries (
                                    delivery_id,
                                    context_id,
                                    agent_id,
                                    event_id,
                                    state,
                                    attempt_count,
                                    current_receipt_id,
                                    lease_owner,
                                    first_delivered_at,
                                    last_delivered_at,
                                    lease_expires_at,
                                    acknowledged_at,
                                    cancelled_at,
                                    created_at,
                                    updated_at
                                )
                                VALUES (?, ?, ?, ?, 'leased', ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                                """,
                                (
                                    delivery_id,
                                    context,
                                    agent,
                                    event_id,
                                    attempt_count,
                                    receipt_id,
                                    instance,
                                    current_time,
                                    current_time,
                                    lease_expires_at,
                                    current_time,
                                    current_time,
                                ),
                            )
                        else:
                            conn.execute(
                                """
                                UPDATE agent_context_deliveries
                                SET state = 'leased',
                                    attempt_count = ?,
                                    current_receipt_id = ?,
                                    lease_owner = ?,
                                    last_delivered_at = ?,
                                    lease_expires_at = ?,
                                    acknowledged_at = NULL,
                                    updated_at = ?
                                WHERE delivery_id = ?
                                """,
                                (
                                    attempt_count,
                                    receipt_id,
                                    instance,
                                    current_time,
                                    lease_expires_at,
                                    current_time,
                                    delivery_id,
                                ),
                            )
                        conn.execute(
                            """
                            INSERT INTO agent_context_delivery_receipts (
                                receipt_id,
                                delivery_id,
                                attempt_number,
                                consumer_instance_id,
                                state,
                                leased_at,
                                lease_expires_at,
                                acknowledged_at,
                                released_at,
                                created_at,
                                updated_at
                            )
                            VALUES (?, ?, ?, ?, 'leased', ?, ?, NULL, NULL, ?, ?)
                            """,
                            (
                                receipt_id,
                                delivery_id,
                                attempt_count,
                                instance,
                                current_time,
                                lease_expires_at,
                                current_time,
                                current_time,
                            ),
                        )
                        delivery_row = conn.execute(
                            "SELECT * FROM agent_context_deliveries WHERE delivery_id = ?",
                            (delivery_id,),
                        ).fetchone()
                        receipt_row = conn.execute(
                            """
                            SELECT * FROM agent_context_delivery_receipts
                            WHERE receipt_id = ?
                            """,
                            (receipt_id,),
                        ).fetchone()
                        if delivery_row is None or receipt_row is None:
                            raise RuntimeError("context delivery was not readable after lease")
                        deliveries.append(
                            self._context_delivery_payload(
                                delivery_row,
                                receipt_row,
                                event_row,
                                redelivered=redelivered,
                            )
                        )
                    cursor = self._advance_context_cursor(
                        conn,
                        context_id=context,
                        agent_id=agent,
                        now=current_time,
                    )

            events: list[dict[str, Any]] = []
            for delivery in deliveries:
                event_payload = dict(delivery["event"])
                event_payload["delivery"] = {
                    key: value
                    for key, value in delivery.items()
                    if key != "event"
                }
                events.append(event_payload)
            return {
                "protocol_version": "context-delivery.v2",
                "delivery_mode": "leased-at-least-once",
                "context_id": context,
                "agent_id": agent,
                "consumer_instance_id": instance,
                "lease_seconds": bounded_lease_seconds,
                "max_delivery_attempts": max_delivery_attempts,
                "delivery_count": len(deliveries),
                "deliveries": deliveries,
                "events": events,
                "ack_required": bool(deliveries),
                "has_more": bool(has_more or blocking_delivery),
                "blocking_delivery": blocking_delivery,
                "cursor": cursor,
                "remaining_pending_count": int(cursor["pending_event_count"]),
            }
        except Exception:
            LOGGER.exception(
                "failed to lease context events context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise

    def acknowledge_context_deliveries(
        self,
        *,
        context_id: str,
        agent_id: str,
        acknowledgements: Iterable[dict[str, Any]],
        now: float | None = None,
    ) -> dict[str, Any]:
        context = str(context_id or "").strip()
        agent = self._normalize_delivery_agent_id(agent_id)
        if not context or not agent:
            raise ContextDeliveryRejected(
                "context_id and agent_id are required for acknowledgement"
            )
        current_time = time.time() if now is None else float(now)
        if not math.isfinite(current_time):
            raise ContextDeliveryRejected("now must be finite")
        requested: list[str] = []
        seen: set[str] = set()
        for raw_ack in acknowledgements:
            if not isinstance(raw_ack, dict):
                raise ContextDeliveryRejected(
                    "each acknowledgement must be an object"
                )
            receipt_id = str(
                raw_ack.get("receipt_id")
                or raw_ack.get("lease_token")
                or ""
            ).strip()
            if not receipt_id:
                raise ContextDeliveryRejected(
                    "receipt_id is required for acknowledgement"
                )
            if receipt_id in seen:
                continue
            seen.add(receipt_id)
            requested.append(receipt_id)
            if len(requested) > 500:
                raise ContextDeliveryRejected(
                    "at most 500 delivery receipts may be acknowledged"
                )
        if any(
            not self._context_delivery_receipt_id_is_valid(receipt_id)
            for receipt_id in requested
        ):
            raise ContextDeliveryRejected(
                "receipt_id has an invalid context delivery format"
            )

        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    consumer_row = conn.execute(
                        "SELECT enabled FROM agent_context_consumers WHERE agent_id = ?",
                        (agent,),
                    ).fetchone()
                    if consumer_row is None or not bool(consumer_row["enabled"]):
                        raise ContextDeliveryRejected(
                            f"unknown or disabled context consumer {agent!r}"
                        )
                    acknowledged: list[dict[str, Any]] = []
                    for receipt_id in requested:
                        row = conn.execute(
                            """
                            SELECT
                                receipt.*,
                                delivery.context_id,
                                delivery.agent_id,
                                delivery.event_id,
                                delivery.state AS delivery_state,
                                delivery.current_receipt_id
                            FROM agent_context_delivery_receipts AS receipt
                            JOIN agent_context_deliveries AS delivery
                              ON delivery.delivery_id = receipt.delivery_id
                            WHERE receipt.receipt_id = ?
                            """,
                            (receipt_id,),
                        ).fetchone()
                        if row is None:
                            tombstone = conn.execute(
                                """
                                SELECT *
                                FROM agent_context_delivery_ack_tombstones
                                WHERE receipt_digest = ?
                                """,
                                (self._context_delivery_receipt_digest(receipt_id),),
                            ).fetchone()
                            if tombstone is None:
                                raise ContextDeliveryRejected(
                                    "unknown context delivery receipt"
                                )
                            if (
                                str(tombstone["context_id"]) != context
                                or str(tombstone["agent_id"]) != agent
                            ):
                                raise ContextDeliveryRejected(
                                    "delivery receipt does not belong to the supplied context and agent"
                                )
                            acknowledged.append(
                                {
                                    "receipt_id": receipt_id,
                                    "delivery_id": str(tombstone["delivery_id"]),
                                    "event_id": int(tombstone["event_id"]),
                                    "attempt_count": int(tombstone["attempt_number"]),
                                    "acknowledged_at": float(
                                        tombstone["acknowledged_at"]
                                    ),
                                    "idempotent": True,
                                    "event_deleted": True,
                                }
                            )
                            continue
                        if str(row["context_id"]) != context or str(row["agent_id"]) != agent:
                            raise ContextDeliveryRejected(
                                "delivery receipt does not belong to the supplied context and agent"
                            )
                        receipt_state = str(row["state"])
                        delivery_state = str(row["delivery_state"])
                        if receipt_state == "acknowledged" and delivery_state == "acknowledged":
                            acknowledged.append(
                                {
                                    "receipt_id": receipt_id,
                                    "delivery_id": str(row["delivery_id"]),
                                    "event_id": int(row["event_id"]),
                                    "attempt_count": int(row["attempt_number"]),
                                    "acknowledged_at": float(row["acknowledged_at"]),
                                    "idempotent": True,
                                }
                            )
                            continue
                        if receipt_state != "leased" or delivery_state != "leased":
                            raise ContextDeliveryRejected(
                                "context delivery receipt is stale, expired, or no longer acknowledgeable"
                            )
                        if float(row["lease_expires_at"]) <= current_time:
                            conn.execute(
                                """
                                UPDATE agent_context_delivery_receipts
                                SET state = 'expired', updated_at = ?
                                WHERE receipt_id = ? AND state = 'leased'
                                """,
                                (current_time, receipt_id),
                            )
                            raise ContextDeliveryRejected(
                                "context delivery receipt lease has expired"
                            )
                        if str(row["current_receipt_id"]) != receipt_id:
                            raise ContextDeliveryRejected(
                                "context delivery receipt was superseded by a retry"
                            )
                        conn.execute(
                            """
                            UPDATE agent_context_delivery_receipts
                            SET state = 'acknowledged',
                                acknowledged_at = ?,
                                updated_at = ?
                            WHERE receipt_id = ?
                            """,
                            (current_time, current_time, receipt_id),
                        )
                        conn.execute(
                            """
                            UPDATE agent_context_deliveries
                            SET state = 'acknowledged',
                                acknowledged_at = ?,
                                updated_at = ?
                            WHERE delivery_id = ?
                            """,
                            (current_time, current_time, str(row["delivery_id"])),
                        )
                        acknowledged.append(
                            {
                                "receipt_id": receipt_id,
                                "delivery_id": str(row["delivery_id"]),
                                "event_id": int(row["event_id"]),
                                "attempt_count": int(row["attempt_number"]),
                                "acknowledged_at": current_time,
                                "idempotent": False,
                            }
                        )
                    cursor = self._advance_context_cursor(
                        conn,
                        context_id=context,
                        agent_id=agent,
                        now=current_time,
                    )
            return {
                "protocol_version": "context-delivery.v2",
                "delivery_mode": "leased-at-least-once",
                "context_id": context,
                "agent_id": agent,
                "acknowledged_count": len(acknowledged),
                "acknowledged": acknowledged,
                "rejected": [],
                "cursor": cursor,
            }
        except ValueError:
            LOGGER.warning(
                "refused context delivery acknowledgement context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise
        except Exception:
            LOGGER.exception(
                "failed to acknowledge context deliveries context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise

    def release_context_deliveries(
        self,
        *,
        context_id: str,
        agent_id: str,
        consumer_instance_id: str,
        receipt_ids: Iterable[str],
        now: float | None = None,
    ) -> dict[str, Any]:
        context = str(context_id or "").strip()
        agent = self._normalize_delivery_agent_id(agent_id)
        instance = str(consumer_instance_id or "").strip()
        current_time = time.time() if now is None else float(now)
        if not math.isfinite(current_time):
            raise ContextDeliveryRejected("now must be finite")
        requested: list[str] = []
        seen: set[str] = set()
        for raw_receipt_id in receipt_ids:
            receipt_id = str(raw_receipt_id or "").strip()
            if not receipt_id:
                raise ContextDeliveryRejected(
                    "receipt_ids must not contain empty values"
                )
            if receipt_id in seen:
                continue
            seen.add(receipt_id)
            requested.append(receipt_id)
            if len(requested) > 500:
                raise ContextDeliveryRejected(
                    "at most 500 delivery receipts may be released"
                )
        if not context or not agent or not instance or not requested:
            raise ContextDeliveryRejected(
                "context_id, agent_id, consumer_instance_id, and receipt_ids are required"
            )
        if len(context) > 128:
            raise ContextDeliveryRejected("context_id exceeds 128 characters")
        if not self._context_delivery_owner_is_valid(instance):
            raise ContextDeliveryRejected(
                "consumer_instance_id must be 1-256 printable ASCII characters"
            )
        if any(
            not self._context_delivery_receipt_id_is_valid(receipt_id)
            for receipt_id in requested
        ):
            raise ContextDeliveryRejected(
                "receipt_id has an invalid context delivery format"
            )
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    released: list[str] = []
                    for receipt_id in requested:
                        row = conn.execute(
                            """
                            SELECT receipt.*, delivery.context_id, delivery.agent_id,
                                   delivery.current_receipt_id, delivery.state AS delivery_state
                            FROM agent_context_delivery_receipts AS receipt
                            JOIN agent_context_deliveries AS delivery
                              ON delivery.delivery_id = receipt.delivery_id
                            WHERE receipt.receipt_id = ?
                            """,
                            (receipt_id,),
                        ).fetchone()
                        if row is None:
                            raise ContextDeliveryRejected(
                                "unknown context delivery receipt"
                            )
                        if (
                            str(row["context_id"]) != context
                            or str(row["agent_id"]) != agent
                            or str(row["consumer_instance_id"]) != instance
                            or str(row["current_receipt_id"]) != receipt_id
                            or str(row["state"]) != "leased"
                            or str(row["delivery_state"]) != "leased"
                            or float(row["lease_expires_at"]) <= current_time
                        ):
                            raise ContextDeliveryRejected(
                                "context delivery receipt is not releasable by this consumer"
                            )
                        conn.execute(
                            """
                            UPDATE agent_context_delivery_receipts
                            SET state = 'released', released_at = ?, updated_at = ?
                            WHERE receipt_id = ?
                            """,
                            (current_time, current_time, receipt_id),
                        )
                        conn.execute(
                            """
                            UPDATE agent_context_deliveries
                            SET lease_expires_at = ?, updated_at = ?
                            WHERE delivery_id = ?
                            """,
                            (current_time, current_time, str(row["delivery_id"])),
                        )
                        released.append(receipt_id)
            return {
                "protocol_version": "context-delivery.v2",
                "context_id": context,
                "agent_id": agent,
                "released_count": len(released),
                "released_receipt_ids": released,
            }
        except ValueError:
            LOGGER.warning(
                "refused context delivery release context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise
        except Exception:
            LOGGER.exception(
                "failed to release context deliveries context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise

    def dead_letter_context_delivery(
        self,
        *,
        context_id: str,
        agent_id: str,
        delivery_id: str,
        reason: str,
        confirm: bool = False,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Governedly quarantine a retry-exhausted delivery with an audit receipt."""

        context = reject_sensitive_identifier(
            context_id,
            field="context_id",
        ).strip()
        agent = self._normalize_delivery_agent_id(agent_id)
        delivery_key = reject_sensitive_identifier(
            delivery_id,
            field="delivery_id",
        ).strip()
        rationale, _ = redact_capture_text(str(reason or "").strip())
        rationale = rationale[:2000]
        if not confirm:
            raise ContextDeliveryRejected(
                "dead-letter quarantine requires confirm=True"
            )
        if not context or not agent or not delivery_key or not rationale:
            raise ContextDeliveryRejected(
                "context_id, agent_id, delivery_id, and reason are required"
            )
        current_time = time.time() if now is None else float(now)
        if not math.isfinite(current_time):
            raise ContextDeliveryRejected("now must be finite")
        max_delivery_attempts = self._context_delivery_max_attempts()
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    row = conn.execute(
                        """
                        SELECT delivery.*, receipt.state AS receipt_state,
                               receipt.lease_expires_at AS receipt_lease_expires_at
                        FROM agent_context_deliveries AS delivery
                        JOIN agent_context_delivery_receipts AS receipt
                          ON receipt.receipt_id = delivery.current_receipt_id
                         AND receipt.delivery_id = delivery.delivery_id
                        WHERE delivery.delivery_id = ?
                        """,
                        (delivery_key,),
                    ).fetchone()
                    if row is None:
                        raise ContextDeliveryRejected(
                            f"unknown context delivery {delivery_key!r}"
                        )
                    if (
                        str(row["context_id"]) != context
                        or str(row["agent_id"]) != agent
                    ):
                        raise ContextDeliveryRejected(
                            "delivery does not belong to the supplied context and agent"
                        )
                    if str(row["state"]) == "dead_letter":
                        audit = conn.execute(
                            """
                            SELECT operation_id, created_at
                            FROM store_maintenance_receipts
                            WHERE operation_type = 'context-delivery-dead-letter'
                              AND context_id = ?
                              AND before_revision = ?
                              AND after_revision = 'dead_letter'
                            ORDER BY created_at DESC
                            LIMIT 1
                            """,
                            (context, delivery_key),
                        ).fetchone()
                        if audit is None:
                            raise RuntimeError(
                                "dead-letter delivery is missing its governance audit"
                            )
                        cursor = self._advance_context_cursor(
                            conn,
                            context_id=context,
                            agent_id=agent,
                            now=current_time,
                        )
                        return {
                            "protocol_version": "context-delivery.v2",
                            "action": "context-delivery-dead-letter",
                            "context_id": context,
                            "agent_id": agent,
                            "delivery_id": delivery_key,
                            "event_id": int(row["event_id"]),
                            "attempt_count": int(row["attempt_count"]),
                            "operation_id": str(audit["operation_id"]),
                            "dead_lettered_at": float(audit["created_at"]),
                            "idempotent": True,
                            "cursor": cursor,
                        }
                    if str(row["state"]) != "leased":
                        raise ContextDeliveryRejected(
                            "only a leased retry history can be dead-lettered"
                        )
                    attempt_count = int(row["attempt_count"])
                    if attempt_count < max_delivery_attempts:
                        raise ContextDeliveryRejected(
                            "delivery has not exhausted the configured retry budget "
                            f"({attempt_count}/{max_delivery_attempts})"
                        )
                    if (
                        str(row["receipt_state"]) == "leased"
                        and float(row["receipt_lease_expires_at"]) > current_time
                    ):
                        raise ContextDeliveryRejected(
                            "delivery still has an active lease; release it or wait for expiry"
                        )
                    if str(row["receipt_state"]) not in {
                        "leased",
                        "expired",
                        "released",
                    }:
                        raise ContextDeliveryRejected(
                            "current delivery receipt is not quarantineable"
                        )

                    receipt_id = str(row["current_receipt_id"])
                    conn.execute(
                        """
                        UPDATE agent_context_delivery_receipts
                        SET state = 'cancelled', updated_at = ?
                        WHERE receipt_id = ?
                        """,
                        (current_time, receipt_id),
                    )
                    conn.execute(
                        """
                        UPDATE agent_context_deliveries
                        SET state = 'dead_letter', cancelled_at = ?, updated_at = ?
                        WHERE delivery_id = ?
                        """,
                        (current_time, current_time, delivery_key),
                    )
                    operation_id = "s2maint_" + uuid.uuid4().hex
                    conn.execute(
                        """
                        INSERT INTO store_maintenance_receipts (
                            operation_id, operation_type, context_id,
                            before_revision, after_revision, payload_json,
                            created_at
                        ) VALUES (?, 'context-delivery-dead-letter', ?, ?,
                                  'dead_letter', ?, ?)
                        """,
                        (
                            operation_id,
                            context,
                            delivery_key,
                            _json_dumps(
                                {
                                    "agent_id": agent,
                                    "event_id": int(row["event_id"]),
                                    "attempt_count": attempt_count,
                                    "max_delivery_attempts": max_delivery_attempts,
                                    "reason": rationale,
                                    "receipt_digest": (
                                        self._context_delivery_receipt_digest(
                                            receipt_id
                                        )
                                    ),
                                }
                            ),
                            current_time,
                        ),
                    )
                    cursor = self._advance_context_cursor(
                        conn,
                        context_id=context,
                        agent_id=agent,
                        now=current_time,
                    )
            return {
                "protocol_version": "context-delivery.v2",
                "action": "context-delivery-dead-letter",
                "context_id": context,
                "agent_id": agent,
                "delivery_id": delivery_key,
                "event_id": int(row["event_id"]),
                "attempt_count": attempt_count,
                "max_delivery_attempts": max_delivery_attempts,
                "operation_id": operation_id,
                "dead_lettered_at": current_time,
                "reason": rationale,
                "idempotent": False,
                "cursor": cursor,
            }
        except ValueError:
            LOGGER.warning(
                "refused context delivery dead-letter context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise
        except Exception:
            LOGGER.exception(
                "failed to dead-letter context delivery context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise

    def ack_context_events(
        self,
        *,
        context_id: str,
        agent_id: str,
        last_event_id: int,
    ) -> dict[str, Any]:
        # Deliberately reject every cursor-only acknowledgement, including zero
        # and already-advanced watermarks.  Returning an idempotent success here
        # would let callers mistake observation state for proof that an exact
        # leased delivery was durably processed.
        str(context_id)
        self._normalize_delivery_agent_id(agent_id)
        int(last_event_id)
        LOGGER.warning(
            "refused legacy context watermark acknowledgement context_id=%s agent_id=%s",
            context_id,
            agent_id,
        )
        raise ContextDeliveryRejected(
            "legacy watermark acknowledgement is disabled; lease events and acknowledge exact receipt_id values"
        )

    def list_context_cursors(
        self,
        *,
        context_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 100,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(self._normalize_delivery_agent_id(agent_id))
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        bounded_limit = min(max(int(limit), 1), 10_000)
        params.append(bounded_limit)
        try:
            owns_transaction = _conn is None
            with self._read_connection_scope(_conn) as conn:
                if owns_transaction:
                    conn.execute("BEGIN")
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM agent_context_delivery_cursors
                    {where_sql}
                    ORDER BY updated_at DESC, context_id ASC, agent_id ASC
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()
                cursors = []
                for row in rows:
                    context = str(row["context_id"])
                    metrics = self._context_delivery_metrics(
                        conn,
                        context_id=context,
                        agent_id=str(row["agent_id"]),
                        cursor_event_id=int(row["last_contiguous_event_id"]),
                    )
                    cursors.append(
                        self._row_to_context_cursor(
                            row,
                            **metrics,
                        )
                    )
                if owns_transaction:
                    conn.commit()
            return cursors
        except Exception:
            LOGGER.exception("failed to list context cursors")
            raise

    def list_context_deliveries(
        self,
        *,
        context_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 1000,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(self._normalize_delivery_agent_id(agent_id))
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(min(max(int(limit), 1), 10_000))
        with self._read_connection_scope(_conn) as conn:
            rows = conn.execute(
                f"""
                SELECT *
                FROM agent_context_deliveries
                {where_sql}
                ORDER BY event_id ASC, agent_id ASC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "delivery_id": str(row["delivery_id"]),
                "context_id": str(row["context_id"]),
                "agent_id": str(row["agent_id"]),
                "event_id": int(row["event_id"]),
                "state": str(row["state"]),
                "attempt_count": int(row["attempt_count"]),
                "current_receipt_id": str(row["current_receipt_id"]),
                "lease_owner": str(row["lease_owner"]),
                "first_delivered_at": float(row["first_delivered_at"]),
                "last_delivered_at": float(row["last_delivered_at"]),
                "lease_expires_at": float(row["lease_expires_at"]),
                "acknowledged_at": (
                    None
                    if row["acknowledged_at"] is None
                    else float(row["acknowledged_at"])
                ),
                "cancelled_at": (
                    None
                    if row["cancelled_at"] is None
                    else float(row["cancelled_at"])
                ),
                "created_at": float(row["created_at"]),
                "updated_at": float(row["updated_at"]),
            }
            for row in rows
        ]

    def list_context_delivery_receipts(
        self,
        *,
        context_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 1000,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("delivery.context_id = ?")
            params.append(str(context_id))
        if agent_id is not None:
            clauses.append("delivery.agent_id = ?")
            params.append(self._normalize_delivery_agent_id(agent_id))
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(min(max(int(limit), 1), 10_000))
        with self._read_connection_scope(_conn) as conn:
            rows = conn.execute(
                f"""
                SELECT receipt.*, delivery.context_id, delivery.agent_id,
                       delivery.event_id
                FROM agent_context_delivery_receipts AS receipt
                JOIN agent_context_deliveries AS delivery
                  ON delivery.delivery_id = receipt.delivery_id
                {where_sql}
                ORDER BY delivery.event_id ASC, receipt.attempt_number ASC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "receipt_id": str(row["receipt_id"]),
                "delivery_id": str(row["delivery_id"]),
                "context_id": str(row["context_id"]),
                "agent_id": str(row["agent_id"]),
                "event_id": int(row["event_id"]),
                "attempt_number": int(row["attempt_number"]),
                "consumer_instance_id": str(row["consumer_instance_id"]),
                "state": str(row["state"]),
                "leased_at": float(row["leased_at"]),
                "lease_expires_at": float(row["lease_expires_at"]),
                "acknowledged_at": (
                    None
                    if row["acknowledged_at"] is None
                    else float(row["acknowledged_at"])
                ),
                "released_at": (
                    None
                    if row["released_at"] is None
                    else float(row["released_at"])
                ),
                "created_at": float(row["created_at"]),
                "updated_at": float(row["updated_at"]),
            }
            for row in rows
        ]

    def list_context_delivery_ack_tombstones(
        self,
        *,
        context_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 1000,
        _conn: sqlite3.Connection | None = None,
    ) -> list[dict[str, Any]]:
        """Return deletion-safe ACK evidence without exposing receipt secrets."""

        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(self._normalize_delivery_agent_id(agent_id))
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(min(max(int(limit), 1), 10_000))
        with self._read_connection_scope(_conn) as conn:
            rows = conn.execute(
                f"""
                SELECT receipt_digest, delivery_id, context_id, agent_id,
                       event_id, attempt_number, acknowledged_at, deleted_at
                FROM agent_context_delivery_ack_tombstones
                {where_sql}
                ORDER BY deleted_at ASC, receipt_digest ASC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "receipt_digest": str(row["receipt_digest"]),
                "digest_algorithm": "sha256-domain-separated-v1",
                "delivery_id": str(row["delivery_id"]),
                "context_id": str(row["context_id"]),
                "agent_id": str(row["agent_id"]),
                "event_id": int(row["event_id"]),
                "attempt_number": int(row["attempt_number"]),
                "acknowledged_at": float(row["acknowledged_at"]),
                "deleted_at": float(row["deleted_at"]),
            }
            for row in rows
        ]

    def context_delivery_health(
        self,
        *,
        context_id: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        current_time = time.time() if now is None else float(now)
        if not math.isfinite(current_time):
            raise ValueError("now must be finite")
        event_filter = "" if context_id is None else "WHERE event.context_id = ?"
        delivery_filter = "" if context_id is None else "WHERE delivery.context_id = ?"
        event_params: tuple[Any, ...] = () if context_id is None else (str(context_id),)
        delivery_params: tuple[Any, ...] = (
            () if context_id is None else (str(context_id),)
        )
        with closing(self._connect_read_only()) as conn:
            conn.execute("BEGIN")
            unrouted_event_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_events AS event
                    {event_filter}
                    {"AND" if event_filter else "WHERE"} NOT EXISTS (
                        SELECT 1
                        FROM agent_context_event_targets AS target
                        WHERE target.event_id = event.event_id
                    )
                    """,
                    event_params,
                ).fetchone()[0]
            )
            (
                target_integrity_error_count,
                target_integrity_error_samples,
                noncanonical_target_count,
                noncanonical_target_samples,
            ) = self._context_event_target_integrity_audit(
                conn,
                context_id=context_id,
            )
            (
                event_ledger_integrity_error_count,
                event_ledger_integrity_error_samples,
            ) = self._context_event_ledger_integrity_audit(
                conn,
                context_id=context_id,
            )
            (
                consumer_group_integrity_error_count,
                consumer_group_integrity_error_samples,
            ) = self._context_consumer_group_integrity_audit(conn)
            (
                target_reconciliation_highwater_error_count,
                target_reconciliation_highwater_error_samples,
            ) = self._context_event_target_highwater_audit(conn)
            missing_current_receipt_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    {delivery_filter}
                    {"AND" if delivery_filter else "WHERE"} NOT EXISTS (
                        SELECT 1
                        FROM agent_context_delivery_receipts AS receipt
                        WHERE receipt.receipt_id = delivery.current_receipt_id
                          AND receipt.delivery_id = delivery.delivery_id
                          AND receipt.attempt_number = delivery.attempt_count
                    )
                    """,
                    delivery_params,
                ).fetchone()[0]
            )
            acknowledgement_mismatch_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    {delivery_filter}
                    {"AND" if delivery_filter else "WHERE"} delivery.state = 'acknowledged'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM agent_context_delivery_receipts AS receipt
                          WHERE receipt.receipt_id = delivery.current_receipt_id
                            AND receipt.delivery_id = delivery.delivery_id
                            AND receipt.state = 'acknowledged'
                      )
                    """,
                    delivery_params,
                ).fetchone()[0]
            )
            delivery_receipt_state_mismatch_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    JOIN agent_context_delivery_receipts AS receipt
                      ON receipt.receipt_id = delivery.current_receipt_id
                    {delivery_filter}
                    {"AND" if delivery_filter else "WHERE"} NOT (
                        (
                            delivery.state = 'acknowledged'
                            AND receipt.state = 'acknowledged'
                            AND delivery.acknowledged_at IS NOT NULL
                            AND receipt.acknowledged_at IS NOT NULL
                        )
                        OR (
                            delivery.state = 'leased'
                            AND (
                                (
                                    receipt.state = 'leased'
                                    AND receipt.consumer_instance_id = delivery.lease_owner
                                    AND ABS(
                                        receipt.lease_expires_at - delivery.lease_expires_at
                                    ) < 0.000001
                                )
                                OR (
                                    receipt.state IN ('expired', 'released')
                                    AND delivery.lease_expires_at <= receipt.lease_expires_at
                                )
                            )
                        )
                        OR (
                            delivery.state = 'dead_letter'
                            AND receipt.state = 'cancelled'
                        )
                    )
                    """,
                    delivery_params,
                ).fetchone()[0]
            )
            event_context_mismatch_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    LEFT JOIN agent_context_events AS event
                      ON event.event_id = delivery.event_id
                     AND event.context_id = delivery.context_id
                    {delivery_filter}
                    {"AND" if delivery_filter else "WHERE"} event.event_id IS NULL
                    """,
                    delivery_params,
                ).fetchone()[0]
            )
            expired_active_lease_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    {delivery_filter}
                    {"AND" if delivery_filter else "WHERE"} delivery.state = 'leased'
                      AND delivery.attempt_count < ?
                      AND delivery.lease_expires_at <= ?
                    """,
                    (
                        *delivery_params,
                        self._context_delivery_max_attempts(),
                        current_time,
                    ),
                ).fetchone()[0]
            )
            max_delivery_attempts = self._context_delivery_max_attempts()
            retry_exhausted_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    {delivery_filter}
                    {"AND" if delivery_filter else "WHERE"}
                        delivery.state = 'leased'
                      AND delivery.attempt_count >= ?
                      AND delivery.lease_expires_at <= ?
                    """,
                    (*delivery_params, max_delivery_attempts, current_time),
                ).fetchone()[0]
            )
            dead_letter_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    {delivery_filter}
                    {"AND" if delivery_filter else "WHERE"}
                        delivery.state = 'dead_letter'
                    """,
                    delivery_params,
                ).fetchone()[0]
            )
            if context_id is None:
                legacy_unverified_cursor_count = int(
                    conn.execute("SELECT COUNT(*) FROM agent_context_cursors").fetchone()[0]
                )
            else:
                legacy_unverified_cursor_count = int(
                    conn.execute(
                        "SELECT COUNT(*) FROM agent_context_cursors WHERE context_id = ?",
                        (str(context_id),),
                    ).fetchone()[0]
                )
            delivery_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_deliveries AS delivery
                    {delivery_filter}
                    """,
                    delivery_params,
                ).fetchone()[0]
            )
            receipt_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_delivery_receipts AS receipt
                    JOIN agent_context_deliveries AS delivery
                      ON delivery.delivery_id = receipt.delivery_id
                    {delivery_filter}
                    """,
                    delivery_params,
                ).fetchone()[0]
            )
            tombstone_filter = (
                "" if context_id is None else "WHERE context_id = ?"
            )
            tombstone_params: tuple[Any, ...] = (
                () if context_id is None else (str(context_id),)
            )
            tombstone_count = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM agent_context_delivery_ack_tombstones
                    {tombstone_filter}
                    """,
                    tombstone_params,
                ).fetchone()[0]
            )
            schema_errors = self._context_delivery_v2_table_errors(conn) + (
                self._context_delivery_v2_index_errors(conn)
            )
            receipt_history_mismatch_count, receipt_history_samples = (
                self._context_delivery_receipt_history_audit(
                    conn,
                    context_id=context_id,
                )
            )
            live_integrity_error_count, live_integrity_samples = (
                self._context_delivery_live_data_audit(
                    conn,
                    context_id=context_id,
                )
            )
            tombstone_integrity_error_count, tombstone_integrity_samples = (
                self._context_delivery_tombstone_data_audit(
                    conn,
                    context_id=context_id,
                )
            )
            unaudited_dead_letter_count, unaudited_dead_letter_samples = (
                self._context_delivery_dead_letter_audit(
                    conn,
                    context_id=context_id,
                )
            )
            foreign_key_errors = conn.execute("PRAGMA foreign_key_check").fetchall()
            cursor_mismatches = self._context_delivery_cursor_mismatches(
                conn,
                context_id=context_id,
            )
            conn.commit()
        structural_error_count = (
            unrouted_event_count
            + target_integrity_error_count
            + event_ledger_integrity_error_count
            + consumer_group_integrity_error_count
            + target_reconciliation_highwater_error_count
            + missing_current_receipt_count
            + acknowledgement_mismatch_count
            + delivery_receipt_state_mismatch_count
            + event_context_mismatch_count
            + receipt_history_mismatch_count
            + live_integrity_error_count
            + tombstone_integrity_error_count
            + unaudited_dead_letter_count
            + len(cursor_mismatches)
            + len(schema_errors)
            + len(foreign_key_errors)
        )
        return {
            "protocol_version": "context-delivery.v2",
            "delivery_mode": "leased-at-least-once",
            "context_id": context_id,
            "status": (
                "ready"
                if structural_error_count == 0 and retry_exhausted_count == 0
                else "degraded"
            ),
            "structural_error_count": structural_error_count,
            "unrouted_event_count": unrouted_event_count,
            "target_integrity_error_count": target_integrity_error_count,
            "target_integrity_error_samples": target_integrity_error_samples,
            "event_ledger_integrity_error_count": (
                event_ledger_integrity_error_count
            ),
            "event_ledger_integrity_error_samples": (
                event_ledger_integrity_error_samples
            ),
            "consumer_group_integrity_error_count": (
                consumer_group_integrity_error_count
            ),
            "consumer_group_integrity_error_samples": (
                consumer_group_integrity_error_samples
            ),
            "target_reconciliation_highwater_error_count": (
                target_reconciliation_highwater_error_count
            ),
            "target_reconciliation_highwater_error_samples": (
                target_reconciliation_highwater_error_samples
            ),
            "noncanonical_target_count": noncanonical_target_count,
            "noncanonical_target_samples": noncanonical_target_samples,
            "missing_current_receipt_count": missing_current_receipt_count,
            "acknowledgement_mismatch_count": acknowledgement_mismatch_count,
            "delivery_receipt_state_mismatch_count": (
                delivery_receipt_state_mismatch_count
            ),
            "event_context_mismatch_count": event_context_mismatch_count,
            "receipt_history_mismatch_count": receipt_history_mismatch_count,
            "receipt_history_mismatch_samples": receipt_history_samples,
            "live_delivery_integrity_error_count": live_integrity_error_count,
            "live_delivery_integrity_error_samples": live_integrity_samples,
            "ack_tombstone_integrity_error_count": (
                tombstone_integrity_error_count
            ),
            "ack_tombstone_integrity_error_samples": tombstone_integrity_samples,
            "unaudited_dead_letter_count": unaudited_dead_letter_count,
            "unaudited_dead_letter_samples": unaudited_dead_letter_samples,
            "receipt_derived_cursor_mismatch_count": len(cursor_mismatches),
            "receipt_derived_cursor_mismatch_samples": cursor_mismatches[:10],
            "schema_error_count": len(schema_errors),
            "schema_error_samples": schema_errors[:10],
            "foreign_key_error_count": len(foreign_key_errors),
            "foreign_key_error_samples": [list(row) for row in foreign_key_errors[:10]],
            "expired_active_lease_count": expired_active_lease_count,
            "max_delivery_attempts": max_delivery_attempts,
            "retry_exhausted_count": retry_exhausted_count,
            "dead_letter_count": dead_letter_count,
            "legacy_unverified_cursor_count": legacy_unverified_cursor_count,
            "delivery_count": delivery_count,
            "receipt_count": receipt_count,
            "ack_tombstone_count": tombstone_count,
            "checked_at": current_time,
        }

    def stats(
        self,
        *,
        context_id: str | None = None,
        _conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        try:
            owns_transaction = _conn is None
            with self._read_connection_scope(_conn) as conn:
                if owns_transaction:
                    conn.execute("BEGIN")
                journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0])
                synchronous_level = int(
                    conn.execute("PRAGMA synchronous").fetchone()[0]
                )
                stats_now = time.time()
                max_delivery_attempts = self._context_delivery_max_attempts()
                if context_id is None:
                    entry_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_entries"
                    ).fetchone()[0]
                    relationship_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_relationships"
                    ).fetchone()[0]
                    spike_index_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_spikes"
                    ).fetchone()[0]
                    surface_term_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_surface_terms"
                    ).fetchone()[0]
                    context_bus_event_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_events"
                    ).fetchone()[0]
                    latest_context_event_row = conn.execute(
                        "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events"
                    ).fetchone()
                    context_bus_ack_cursor_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_delivery_cursors"
                    ).fetchone()[0]
                    context_bus_legacy_cursor_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_cursors"
                    ).fetchone()[0]
                    context_bus_delivery_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_deliveries"
                    ).fetchone()[0]
                    context_bus_active_lease_count = conn.execute(
                        """
                        SELECT COUNT(*) FROM agent_context_deliveries
                        WHERE state = 'leased' AND lease_expires_at > ?
                        """,
                        (stats_now,),
                    ).fetchone()[0]
                    context_bus_expired_retryable_lease_count = conn.execute(
                        """
                        SELECT COUNT(*) FROM agent_context_deliveries
                        WHERE state = 'leased'
                          AND attempt_count < ?
                          AND lease_expires_at <= ?
                        """,
                        (max_delivery_attempts, stats_now),
                    ).fetchone()[0]
                    context_bus_ack_receipt_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_delivery_receipts
                        WHERE state = 'acknowledged'
                        """
                    ).fetchone()[0]
                    context_bus_ack_tombstone_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_delivery_ack_tombstones
                        """
                    ).fetchone()[0]
                    context_bus_retry_exhausted_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_deliveries
                        WHERE state = 'leased'
                          AND attempt_count >= ?
                          AND lease_expires_at <= ?
                        """,
                        (max_delivery_attempts, stats_now),
                    ).fetchone()[0]
                    context_bus_dead_letter_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_deliveries
                        WHERE state = 'dead_letter'
                        """
                    ).fetchone()[0]
                    context_link_count = conn.execute(
                        "SELECT COUNT(*) FROM context_relationships"
                    ).fetchone()[0]
                else:
                    entry_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_entries WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    relationship_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_relationships WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    spike_index_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_spikes WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    surface_term_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_surface_terms WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    context_bus_event_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_events WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    latest_context_event_row = conn.execute(
                        "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()
                    context_bus_ack_cursor_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_delivery_cursors WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    context_bus_legacy_cursor_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_cursors WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    context_bus_delivery_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_deliveries WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    context_bus_active_lease_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_deliveries
                        WHERE context_id = ?
                          AND state = 'leased'
                          AND lease_expires_at > ?
                        """,
                        (context_id, stats_now),
                    ).fetchone()[0]
                    context_bus_expired_retryable_lease_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_deliveries
                        WHERE context_id = ?
                          AND state = 'leased'
                          AND attempt_count < ?
                          AND lease_expires_at <= ?
                        """,
                        (context_id, max_delivery_attempts, stats_now),
                    ).fetchone()[0]
                    context_bus_ack_receipt_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_delivery_receipts AS receipt
                        JOIN agent_context_deliveries AS delivery
                          ON delivery.delivery_id = receipt.delivery_id
                        WHERE delivery.context_id = ?
                          AND receipt.state = 'acknowledged'
                        """,
                        (context_id,),
                    ).fetchone()[0]
                    context_bus_ack_tombstone_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_delivery_ack_tombstones
                        WHERE context_id = ?
                        """,
                        (context_id,),
                    ).fetchone()[0]
                    context_bus_retry_exhausted_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_deliveries
                        WHERE context_id = ?
                          AND state = 'leased'
                          AND attempt_count >= ?
                          AND lease_expires_at <= ?
                        """,
                        (context_id, max_delivery_attempts, stats_now),
                    ).fetchone()[0]
                    context_bus_dead_letter_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM agent_context_deliveries
                        WHERE context_id = ? AND state = 'dead_letter'
                        """,
                        (context_id,),
                    ).fetchone()[0]
                    context_link_count = conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM context_relationships
                        WHERE source_context_id = ? OR target_context_id = ?
                        """,
                        (context_id, context_id),
                    ).fetchone()[0]
                capture_filter = "" if context_id is None else "WHERE context_id = ?"
                capture_params: tuple[Any, ...] = (
                    () if context_id is None else (str(context_id),)
                )
                capture_operation_row = conn.execute(
                    f"""
                    SELECT
                        COUNT(*) AS operation_count,
                        COALESCE(SUM(entry_count), 0) AS entry_count,
                        COALESCE(SUM(relationship_count), 0) AS relationship_count,
                        COALESCE(MAX(committed_at), 0.0) AS latest_committed_at
                    FROM capture_operations
                    {capture_filter}
                    """,
                    capture_params,
                ).fetchone()
                capture_operation_pruned_deployment_count = int(
                    conn.execute(
                        f"""
                        SELECT COUNT(*)
                        FROM capture_operations AS operation
                        {"WHERE operation.context_id = ? AND" if context_id is not None else "WHERE"}
                            NOT EXISTS (
                                SELECT 1
                                FROM agent_context_events AS event
                                WHERE event.event_id = operation.deployment_event_id
                            )
                        """,
                        capture_params,
                    ).fetchone()[0]
                )
                capture_operation_schema_errors = (
                    self._capture_operation_schema_errors(conn)
                )
                (
                    capture_operation_integrity_error_count,
                    capture_operation_integrity_error_samples,
                ) = self._capture_operation_integrity_audit(
                    conn,
                    context_id=context_id,
                )
                event_count = conn.execute("SELECT COUNT(*) FROM memory_events").fetchone()[0]
                context_rows = conn.execute(
                    """
                    WITH catalog AS (
                        SELECT substr(key, length(?) + 1) AS context_id
                        FROM store_metadata
                        WHERE substr(key, 1, length(?)) = ?
                          AND length(key) > length(?)
                    ),
                    contexts AS (
                        SELECT context_id FROM memory_entries
                        UNION SELECT context_id FROM catalog
                    ),
                    counts AS (
                        SELECT context_id, COUNT(*) AS count
                        FROM memory_entries
                        GROUP BY context_id
                    )
                    SELECT contexts.context_id, COALESCE(counts.count, 0) AS count
                    FROM contexts
                    LEFT JOIN counts USING (context_id)
                    ORDER BY contexts.context_id
                    """,
                    (
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                        NAMESPACE_CATALOG_METADATA_PREFIX,
                    ),
                ).fetchall()
                if owns_transaction:
                    conn.commit()
            return {
                "memory_db_path": str(self.db_path),
                "journal_mode": journal_mode,
                "synchronous_level": synchronous_level,
                "durability_profile": (
                    "full" if synchronous_level >= 2 else "balanced"
                ),
                "entry_count": int(entry_count),
                "event_count": int(event_count),
                "relationship_count": int(relationship_count),
                "spike_index_count": int(spike_index_count),
                "surface_term_count": int(surface_term_count),
                "context_bus_event_count": int(context_bus_event_count),
                "context_bus_latest_event_id": int(latest_context_event_row[0] or 0),
                "context_bus_ack_cursor_count": int(context_bus_ack_cursor_count),
                "context_bus_verified_cursor_count": int(context_bus_ack_cursor_count),
                "context_bus_legacy_unverified_cursor_count": int(
                    context_bus_legacy_cursor_count
                ),
                "context_bus_delivery_count": int(context_bus_delivery_count),
                "context_bus_active_lease_count": int(context_bus_active_lease_count),
                "context_bus_expired_retryable_lease_count": int(
                    context_bus_expired_retryable_lease_count
                ),
                "context_bus_ack_receipt_count": int(context_bus_ack_receipt_count),
                "context_bus_ack_tombstone_count": int(
                    context_bus_ack_tombstone_count
                ),
                "context_bus_retry_exhausted_count": int(
                    context_bus_retry_exhausted_count
                ),
                "context_bus_dead_letter_count": int(
                    context_bus_dead_letter_count
                ),
                "context_bus_max_delivery_attempts": max_delivery_attempts,
                "context_link_count": int(context_link_count),
                "capture_protocol_version": CAPTURE_PROTOCOL_VERSION,
                "capture_operation_count": int(
                    capture_operation_row["operation_count"]
                ),
                "capture_operation_entry_count": int(
                    capture_operation_row["entry_count"]
                ),
                "capture_operation_relationship_count": int(
                    capture_operation_row["relationship_count"]
                ),
                "capture_operation_latest_committed_at": float(
                    capture_operation_row["latest_committed_at"]
                ),
                "capture_operation_pruned_deployment_count": int(
                    capture_operation_pruned_deployment_count
                ),
                "capture_operation_schema_error_count": len(
                    capture_operation_schema_errors
                ),
                "capture_operation_schema_error_samples": (
                    capture_operation_schema_errors[:10]
                ),
                "capture_operation_integrity_error_count": int(
                    capture_operation_integrity_error_count
                ),
                "capture_operation_integrity_error_samples": (
                    capture_operation_integrity_error_samples
                ),
                "capture_operation_health": (
                    "ready"
                    if not capture_operation_schema_errors
                    and capture_operation_integrity_error_count == 0
                    else "degraded"
                ),
                "contexts": {str(row["context_id"]): int(row["count"]) for row in context_rows},
            }
        except Exception:
            LOGGER.exception("failed to collect memory-store stats")
            raise

    def _verified_safety_backup(
        self,
        source: sqlite3.Connection,
        *,
        label: str,
        allowed_foreign_key_errors: Iterable[Iterable[Any]] = (),
    ) -> dict[str, Any]:
        backup_dir = self.db_path.parent / "backups"
        self._ensure_directory(backup_dir, owned=True)
        page_count = int(source.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(source.execute("PRAGMA page_size").fetchone()[0])
        estimated_backup_bytes = max(
            int(self.db_path.stat().st_size),
            page_count * page_size,
        )
        reserve_bytes = int(
            os.getenv(
                "SYNAPSE_S2_BACKUP_MIN_FREE_BYTES",
                str(512 * 1024 * 1024),
            )
        )
        if reserve_bytes < 0:
            raise ValueError("SYNAPSE_S2_BACKUP_MIN_FREE_BYTES must be non-negative")
        free_bytes_before = int(shutil.disk_usage(backup_dir).free)
        required_free_bytes = estimated_backup_bytes + reserve_bytes
        if free_bytes_before < required_free_bytes:
            raise OSError(
                "insufficient free space for verified safety backup: "
                f"need {required_free_bytes} bytes, have {free_bytes_before}"
            )
        stamp = time.strftime("%Y%m%d-%H%M%S")
        nonce = uuid.uuid4().hex[:12]
        output_path = backup_dir / (
            f"{self.db_path.stem}-{label}-{stamp}-{nonce}.sqlite3"
        )
        temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        published = False
        try:
            with closing(sqlite3.connect(temp_path)) as destination:
                source.backup(destination)
                destination.commit()
                quick_check = [
                    str(row[0])
                    for row in destination.execute("PRAGMA quick_check").fetchall()
                ]
                integrity_check = [
                    str(row[0])
                    for row in destination.execute("PRAGMA integrity_check").fetchall()
                ]
                foreign_key_errors = [
                    list(row)
                    for row in destination.execute("PRAGMA foreign_key_check").fetchall()
                ]
                backup_tables = {
                    str(row[0])
                    for row in destination.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                entry_count = (
                    int(
                        destination.execute(
                            "SELECT COUNT(*) FROM memory_entries"
                        ).fetchone()[0]
                    )
                    if "memory_entries" in backup_tables
                    else 0
                )
                event_count = (
                    int(
                        destination.execute(
                            "SELECT COUNT(*) FROM memory_events"
                        ).fetchone()[0]
                    )
                    if "memory_events" in backup_tables
                    else 0
                )
            allowed_foreign_key_error_keys = sorted(
                _json_dumps(list(row)) for row in allowed_foreign_key_errors
            )
            foreign_key_error_keys = sorted(
                _json_dumps(list(row)) for row in foreign_key_errors
            )
            if (
                quick_check != ["ok"]
                or integrity_check != ["ok"]
                or foreign_key_error_keys != allowed_foreign_key_error_keys
            ):
                raise RuntimeError(
                    "pre-repair safety backup failed SQLite verification"
                )
            with temp_path.open("rb") as handle:
                os.fsync(handle.fileno())
            os.link(temp_path, output_path, follow_symlinks=False)
            published = True
            temp_metadata = os.lstat(temp_path)
            output_metadata = os.lstat(output_path)
            if self._regular_file_identity(temp_metadata) != self._regular_file_identity(
                output_metadata
            ):
                raise RuntimeError("safety backup publication identity mismatch")
            os.chmod(output_path, 0o600, follow_symlinks=False)
            self._fsync_file(output_path)
            temp_path.unlink()
            dir_fd = os.open(backup_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            digest = hashlib.sha256()
            with output_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return {
                "backup_path": str(output_path),
                "sha256": digest.hexdigest(),
                "size_bytes": output_path.stat().st_size,
                "quick_check": quick_check,
                "integrity_check": integrity_check,
                "foreign_key_error_count": len(foreign_key_errors),
                "allowed_foreign_key_error_count": len(
                    allowed_foreign_key_error_keys
                ),
                "entry_count": entry_count,
                "event_count": event_count,
                "estimated_backup_bytes": estimated_backup_bytes,
                "reserved_free_bytes": reserve_bytes,
                "free_bytes_before": free_bytes_before,
                "required_free_bytes": required_free_bytes,
                "verified": True,
                "created_at": time.time(),
            }
        except BaseException:
            incomplete_paths = [temp_path]
            if published:
                incomplete_paths.append(output_path)
            for incomplete_path in incomplete_paths:
                try:
                    incomplete_path.unlink(missing_ok=True)
                except OSError:
                    LOGGER.exception(
                        "failed to remove incomplete safety backup %s",
                        incomplete_path,
                    )
            try:
                dir_fd = os.open(backup_dir, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                LOGGER.exception(
                    "failed to fsync backup directory after incomplete backup cleanup"
                )
            raise

    @staticmethod
    def _acquire_file_lock(
        path: Path,
        *,
        mode: int,
        timeout_seconds: float,
    ) -> int:
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        observed: os.stat_result | None = None
        try:
            try:
                descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
                os.fchmod(descriptor, 0o600)
            except FileExistsError:
                observed = os.lstat(path)
                descriptor = os.open(path, flags)
        except OSError as exc:
            if descriptor >= 0:
                os.close(descriptor)
            raise PermissionError(
                f"maintenance gate is not a safe private lock file: {path}"
            ) from exc

        opened = os.fstat(descriptor)
        if observed is None:
            try:
                observed = os.lstat(path)
            except OSError as exc:
                os.close(descriptor)
                raise PermissionError(
                    f"maintenance gate disappeared during creation: {path}"
                ) from exc

        def valid_lock(metadata: os.stat_result) -> bool:
            return bool(
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == os.getuid()
                and int(metadata.st_nlink) == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600
            )

        visible_identity = (int(observed.st_dev), int(observed.st_ino))
        opened_identity = (int(opened.st_dev), int(opened.st_ino))
        if (
            not valid_lock(observed)
            or not valid_lock(opened)
            or visible_identity != opened_identity
        ):
            os.close(descriptor)
            raise PermissionError(
                f"maintenance gate must already be one private owner-controlled file: {path}"
            )

        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        while True:
            try:
                fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
                held = os.fstat(descriptor)
                visible = os.lstat(path)
                if (
                    not valid_lock(held)
                    or not valid_lock(visible)
                    or (int(held.st_dev), int(held.st_ino)) != opened_identity
                    or (int(visible.st_dev), int(visible.st_ino))
                    != opened_identity
                ):
                    raise PermissionError(
                        "maintenance gate identity or permissions changed while acquiring it"
                    )
                return descriptor
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    raise TimeoutError(f"timed out waiting for maintenance gate {path}")
                time.sleep(0.02)
            except BaseException:
                os.close(descriptor)
                raise

    @staticmethod
    def _release_file_lock(descriptor: int) -> None:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def _maintenance_lock_dir(self) -> Path:
        lock_dir = self.db_path.parent / "maintenance-locks"
        self._ensure_directory(lock_dir, owned=True)
        return lock_dir

    def _acquire_writer_gate(self) -> int:
        lock_dir = self._maintenance_lock_dir()
        turnstile_fd = self._acquire_file_lock(
            lock_dir / "writer-turnstile.lock",
            mode=fcntl.LOCK_EX,
            timeout_seconds=10.0,
        )
        try:
            return self._acquire_file_lock(
                lock_dir / "writer-gate.lock",
                mode=fcntl.LOCK_SH,
                timeout_seconds=10.0,
            )
        finally:
            self._release_file_lock(turnstile_fd)

    def _acquire_maintenance_lock(self, label: str) -> tuple[int, int, int]:
        lock_dir = self._maintenance_lock_dir()
        safe_label = re.sub(r"[^a-z0-9_.-]+", "-", str(label).lower()).strip("-")
        lock_path = lock_dir / f"{safe_label or 'maintenance'}.lock"
        operation_fd = self._acquire_file_lock(
            lock_path,
            mode=fcntl.LOCK_EX,
            timeout_seconds=0.0,
        )
        turnstile_fd: int | None = None
        writer_gate_fd: int | None = None
        try:
            # Holding the turnstile prevents new shared writer locks while the
            # exclusive gate drains every in-flight store transaction.
            turnstile_fd = self._acquire_file_lock(
                lock_dir / "writer-turnstile.lock",
                mode=fcntl.LOCK_EX,
                timeout_seconds=10.0,
            )
            writer_gate_fd = self._acquire_file_lock(
                lock_dir / "writer-gate.lock",
                mode=fcntl.LOCK_EX,
                timeout_seconds=10.0,
            )
            return operation_fd, turnstile_fd, writer_gate_fd
        except BaseException:
            if writer_gate_fd is not None:
                self._release_file_lock(writer_gate_fd)
            if turnstile_fd is not None:
                self._release_file_lock(turnstile_fd)
            self._release_file_lock(operation_fd)
            raise

    def _release_maintenance_lock(self, descriptors: tuple[int, int, int]) -> None:
        operation_fd, turnstile_fd, writer_gate_fd = descriptors
        self._release_file_lock(writer_gate_fd)
        self._release_file_lock(turnstile_fd)
        self._release_file_lock(operation_fd)

    def _discard_safety_backup(self, backup: dict[str, Any]) -> None:
        """Remove an unused repair-attempt backup without accepting arbitrary paths."""

        raw_path = str(backup.get("backup_path") or "").strip()
        if not raw_path:
            return
        backup_dir = (self.db_path.parent / "backups").resolve()
        candidate = Path(raw_path).resolve()
        if candidate.parent != backup_dir:
            raise RuntimeError(
                f"refusing to remove safety backup outside {backup_dir}: {candidate}"
            )
        candidate.unlink(missing_ok=True)
        dir_fd = os.open(backup_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _normalize_semantic_index_schema(
        self,
        conn: sqlite3.Connection,
        audit: dict[str, Any],
    ) -> dict[str, list[str]]:
        """Replace malformed derived schema inside an already protected transaction."""

        invalid_names = set(audit.get("_invalid_schema_object_names") or [])
        object_types = dict(audit.get("_schema_object_types") or {})
        if "memory_entries" in invalid_names:
            raise RuntimeError("canonical memory_entries schema is not repairable")
        quarantined: list[str] = []
        normalized: list[str] = []

        def quarantine_table(name: str) -> None:
            quarantine_name = f"{name}_invalid_{uuid.uuid4().hex[:12]}"
            conn.execute(
                f'ALTER TABLE "{name}" RENAME TO "{quarantine_name}"'
            )
            quarantined.append(quarantine_name)

        def remove_reserved_object(name: str, object_type: str) -> None:
            if object_type == "index":
                conn.execute(f'DROP INDEX "{name}"')
            elif object_type == "table":
                quarantine_table(name)
            elif object_type == "view":
                conn.execute(f'DROP VIEW "{name}"')
            else:
                raise RuntimeError(
                    f"cannot normalize reserved schema object {name} of type {object_type}"
                )

        for table_name in SEMANTIC_INDEX_EXPECTED_TABLE_COLUMNS:
            if table_name == "memory_entries" or table_name not in invalid_names:
                continue
            object_type = str(object_types.get(table_name) or "")
            if object_type == "table" and table_name in {
                "memory_spikes",
                "memory_surface_terms",
            }:
                conn.execute(f'DROP TABLE "{table_name}"')
            else:
                remove_reserved_object(table_name, object_type)
            normalized.append(table_name)

        for index_name in SEMANTIC_INDEX_EXPECTED_INDEX_COLUMNS:
            current = conn.execute(
                "SELECT type FROM sqlite_master WHERE name = ?",
                (index_name,),
            ).fetchone()
            if current is None:
                continue
            if index_name in invalid_names or any(
                parent in normalized
                for parent in (
                    SEMANTIC_INDEX_EXPECTED_INDEX_PARENTS[index_name],
                )
            ):
                remove_reserved_object(index_name, str(current[0]))
                normalized.append(index_name)

        for statement in SEMANTIC_INDEX_SCHEMA_STATEMENTS:
            conn.execute(statement)
        return {
            "normalized_schema_objects": sorted(set(normalized)),
            "quarantined_schema_objects": sorted(quarantined),
        }

    def _semantic_index_audit(
        self,
        conn: sqlite3.Connection,
        *,
        context_id: str | None,
        sample_limit: int,
        memory_ids: Iterable[str] | None = None,
        include_integrity_checks: bool = True,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        required_schema_objects = set(SEMANTIC_INDEX_REQUIRED_SCHEMA_OBJECTS)
        schema_placeholders = ",".join("?" for _ in required_schema_objects)
        schema_rows = conn.execute(
            f"""
            SELECT name, type, tbl_name
            FROM sqlite_master
            WHERE name IN ({schema_placeholders})
            """,
            tuple(sorted(required_schema_objects)),
        ).fetchall()
        schema_object_types = {
            str(row["name"]): str(row["type"])
            for row in schema_rows
        }
        schema_object_parents = {
            str(row["name"]): str(row["tbl_name"])
            for row in schema_rows
        }
        present_schema_objects = set(schema_object_types)
        missing_schema_objects = sorted(required_schema_objects - present_schema_objects)
        invalid_schema_samples: list[dict[str, Any]] = []
        invalid_schema_object_names: set[str] = set()

        def invalid_schema(name: str, reason: str, actual: Any = None) -> None:
            invalid_schema_object_names.add(name)
            if len(invalid_schema_samples) < sample_limit:
                invalid_schema_samples.append(
                    {"name": name, "reason": reason, "actual": actual}
                )

        for table_name, expected_columns in SEMANTIC_INDEX_EXPECTED_TABLE_COLUMNS.items():
            if table_name not in present_schema_objects:
                continue
            if schema_object_types.get(table_name) != "table":
                invalid_schema(
                    table_name,
                    "expected table",
                    schema_object_types.get(table_name),
                )
                continue
            actual_columns = tuple(
                (
                    str(row[1]),
                    str(row[2]).upper(),
                    int(row[3]),
                    int(row[5]),
                )
                for row in conn.execute(
                    f'PRAGMA table_info("{table_name}")'
                ).fetchall()
            )
            if actual_columns != expected_columns:
                invalid_schema(
                    table_name,
                    "column signature mismatch",
                    actual_columns,
                )

        for index_name, expected_columns in SEMANTIC_INDEX_EXPECTED_INDEX_COLUMNS.items():
            if index_name not in present_schema_objects:
                continue
            expected_parent = SEMANTIC_INDEX_EXPECTED_INDEX_PARENTS[index_name]
            if schema_object_types.get(index_name) != "index":
                invalid_schema(
                    index_name,
                    "expected index",
                    schema_object_types.get(index_name),
                )
                continue
            actual_columns = tuple(
                str(row[2])
                for row in conn.execute(
                    f'PRAGMA index_info("{index_name}")'
                ).fetchall()
            )
            index_list_rows = conn.execute(
                f'PRAGMA index_list("{expected_parent}")'
            ).fetchall()
            index_list_row = next(
                (row for row in index_list_rows if str(row[1]) == index_name),
                None,
            )
            unique = int(index_list_row[2]) if index_list_row is not None else -1
            if (
                schema_object_parents.get(index_name) != expected_parent
                or actual_columns != expected_columns
                or unique != 0
            ):
                invalid_schema(
                    index_name,
                    "index signature mismatch",
                    {
                        "parent": schema_object_parents.get(index_name),
                        "columns": actual_columns,
                        "unique": unique,
                    },
                )

        for table_name in ("memory_spikes", "memory_surface_terms"):
            if (
                table_name not in present_schema_objects
                or table_name in invalid_schema_object_names
                or schema_object_types.get(table_name) != "table"
            ):
                continue
            foreign_keys = tuple(
                (
                    str(row[2]),
                    str(row[3]),
                    str(row[4]),
                    str(row[6]).upper(),
                )
                for row in conn.execute(
                    f'PRAGMA foreign_key_list("{table_name}")'
                ).fetchall()
            )
            if foreign_keys != (("memory_entries", "memory_id", "memory_id", "CASCADE"),):
                invalid_schema(
                    table_name,
                    "foreign-key signature mismatch",
                    foreign_keys,
                )

        present_entry_columns = (
            {
                str(row[1])
                for row in conn.execute("PRAGMA table_info(memory_entries)").fetchall()
            }
            if "memory_entries" in present_schema_objects
            else set()
        )
        missing_entry_columns = sorted(
            SEMANTIC_INDEX_REQUIRED_ENTRY_COLUMNS - present_entry_columns
        )
        missing_schema_objects.extend(
            f"memory_entries.{column}" for column in missing_entry_columns
        )
        entry_source_available = (
            "memory_entries" in present_schema_objects
            and not missing_entry_columns
            and "memory_entries" not in invalid_schema_object_names
        )
        spike_index_available = (
            schema_object_types.get("memory_spikes") == "table"
            and "memory_spikes" not in invalid_schema_object_names
        )
        surface_index_available = (
            schema_object_types.get("memory_surface_terms") == "table"
            and "memory_surface_terms" not in invalid_schema_object_names
        )
        metadata_store_available = (
            schema_object_types.get("store_metadata") == "table"
            and "store_metadata" not in invalid_schema_object_names
        )
        params: tuple[Any, ...] = ()
        where_sql = ""
        if context_id is not None:
            where_sql = "WHERE context_id = ?"
            params = (str(context_id),)
        rows = (
            conn.execute(
                f"""
                SELECT
                    memory_id,
                    context_id,
                    tag,
                    source_text,
                    metadata_json,
                    embedding_dimensions,
                    created_at,
                    updated_at,
                    spike_indices_json
                FROM memory_entries
                {where_sql}
                ORDER BY memory_id
                """,
                params,
            ).fetchall()
            if entry_source_available
            else []
        )
        selected_memory_ids = (
            {
                str(memory_id)
                for memory_id in memory_ids
                if str(memory_id).strip()
            }
            if memory_ids is not None
            else None
        )
        if selected_memory_ids is not None:
            rows = [
                row
                for row in rows
                if str(row["memory_id"]) in selected_memory_ids
            ]

        mismatch_memory_ids: list[str] = []
        mismatch_samples: list[dict[str, Any]] = []
        source_errors: list[dict[str, str]] = []
        expected_spike_count = 0
        actual_spike_count = 0
        expected_surface_term_count = 0
        actual_surface_term_count = 0
        spike_mismatch_count = 0
        surface_term_mismatch_count = 0
        audit_hasher = hashlib.sha256()
        audit_hasher.update(
            f"{context_id or '*'}|{SEMANTIC_INDEX_ALGORITHM_FINGERPRINT}".encode(
                "utf-8"
            )
        )

        quick_check_rows = (
            [str(row[0]) for row in conn.execute("PRAGMA quick_check").fetchall()]
            if include_integrity_checks
            else ["not-run-targeted-audit"]
        )
        quick_check_ok = (
            quick_check_rows == ["ok"] if include_integrity_checks else True
        )
        foreign_key_rows = (
            [
                [item for item in row]
                for row in conn.execute("PRAGMA foreign_key_check").fetchall()
            ]
            if include_integrity_checks
            else []
        )
        repairable_foreign_key_rows: list[list[Any]] = []
        blocking_foreign_key_rows: list[list[Any]] = []
        for foreign_key_row in foreign_key_rows:
            table_name = str(foreign_key_row[0]) if foreign_key_row else ""
            parent_name = (
                str(foreign_key_row[2]) if len(foreign_key_row) > 2 else ""
            )
            derived_orphan = (
                table_name in {"memory_spikes", "memory_surface_terms"}
                and parent_name == "memory_entries"
            )
            if derived_orphan and context_id is not None:
                try:
                    row_context = conn.execute(
                        f'SELECT context_id FROM "{table_name}" WHERE rowid = ?',
                        (foreign_key_row[1],),
                    ).fetchone()
                    derived_orphan = (
                        row_context is not None
                        and str(row_context[0]) == str(context_id)
                    )
                except sqlite3.Error:
                    derived_orphan = False
            if derived_orphan:
                repairable_foreign_key_rows.append(foreign_key_row)
            else:
                blocking_foreign_key_rows.append(foreign_key_row)
        generation_row = (
            conn.execute(
                "SELECT value_json FROM store_metadata WHERE key = ?",
                ("semantic_index_generation",),
            ).fetchone()
            if metadata_store_available
            else None
        )
        try:
            semantic_index_generation = int(
                _decode_json(str(generation_row["value_json"]), 0)
                if generation_row is not None
                else 0
            )
        except (TypeError, ValueError, OverflowError):
            semantic_index_generation = 0
        def safe_row_float(row: sqlite3.Row, key: str) -> float:
            try:
                return float(row[key])
            except (TypeError, ValueError, OverflowError):
                return 0.0

        max_created_at = max(
            (safe_row_float(row, "created_at") for row in rows),
            default=0.0,
        )
        max_updated_at = max(
            (safe_row_float(row, "updated_at") for row in rows),
            default=0.0,
        )
        source_revision_seed = (
            f"{context_id or '*'}\x1f{len(rows)}\x1f{max_created_at:.9f}\x1f"
            f"{max_updated_at:.9f}\x1f{semantic_index_generation}\x1f"
            f"{SEMANTIC_INDEX_ALGORITHM_FINGERPRINT}"
        )
        source_revision = hashlib.sha256(
            source_revision_seed.encode("utf-8")
        ).hexdigest()[:32]
        audit_hasher.update(source_revision.encode("ascii"))

        for row in rows:
            memory_id = str(row["memory_id"])
            row_context = str(row["context_id"])
            raw_embedding_dimensions = row["embedding_dimensions"]
            dimensions_source_valid = (
                type(raw_embedding_dimensions) is int
                and raw_embedding_dimensions > 0
            )
            embedding_dimensions = (
                int(raw_embedding_dimensions) if dimensions_source_valid else 0
            )
            raw_spikes = _decode_json(str(row["spike_indices_json"]), None)
            spike_source_valid = (
                isinstance(raw_spikes, list)
                and dimensions_source_valid
                and all(
                    type(value) is int
                    and 0 <= value < embedding_dimensions
                    for value in raw_spikes
                )
                and raw_spikes == sorted(set(raw_spikes))
            )
            expected_spikes: list[int] = []
            if spike_source_valid:
                expected_spikes = list(raw_spikes)
            raw_metadata = _decode_json(str(row["metadata_json"]), None)
            metadata_source_valid = isinstance(raw_metadata, dict)
            safe_metadata = raw_metadata if metadata_source_valid else {}
            if (
                not dimensions_source_valid
                or not spike_source_valid
                or not metadata_source_valid
            ):
                source_errors.append(
                    {
                        "memory_id": memory_id,
                        "context_id": row_context,
                        "error": ", ".join(
                            label
                            for label, valid in (
                                (
                                    "invalid embedding_dimensions",
                                    dimensions_source_valid,
                                ),
                                ("invalid spike_indices_json", spike_source_valid),
                                ("invalid metadata_json", metadata_source_valid),
                            )
                            if not valid
                        ),
                    }
                )

            actual_spike_rows = (
                conn.execute(
                    """
                    SELECT context_id, spike_index
                    FROM memory_spikes
                    WHERE memory_id = ?
                    ORDER BY spike_index
                    """,
                    (memory_id,),
                ).fetchall()
                if spike_index_available
                else []
            )
            actual_spikes = [int(item["spike_index"]) for item in actual_spike_rows]
            spike_context_mismatch = any(
                str(item["context_id"]) != row_context for item in actual_spike_rows
            )

            expected_surface_rows = self._surface_term_rows(
                memory_id=memory_id,
                context_id=row_context,
                tag=str(row["tag"]),
                source_text=str(row["source_text"]),
                metadata=safe_metadata,
            )
            expected_surface = {
                term: float(weight)
                for _memory_id, _context_id, term, weight in expected_surface_rows
            }
            actual_surface_rows = (
                conn.execute(
                    """
                    SELECT context_id, term, weight
                    FROM memory_surface_terms
                    WHERE memory_id = ?
                    ORDER BY term
                    """,
                    (memory_id,),
                ).fetchall()
                if surface_index_available
                else []
            )
            actual_surface = {
                str(item["term"]): float(item["weight"])
                for item in actual_surface_rows
            }
            surface_context_mismatch = any(
                str(item["context_id"]) != row_context for item in actual_surface_rows
            )
            surface_values_mismatch = set(expected_surface) != set(actual_surface) or any(
                not math.isclose(
                    expected_surface[term],
                    actual_surface.get(term, float("nan")),
                    rel_tol=0.0,
                    abs_tol=1e-9,
                )
                for term in expected_surface
            )
            audit_hasher.update(
                _json_dumps(
                    {
                        "memory_id": memory_id,
                        "context_id": row_context,
                        "tag": str(row["tag"]),
                        "source_text": str(row["source_text"]),
                        "embedding_dimensions": embedding_dimensions,
                        "raw_spikes": raw_spikes,
                        "raw_metadata": raw_metadata,
                        "actual_spikes": [
                            [str(item["context_id"]), int(item["spike_index"])]
                            for item in actual_spike_rows
                        ],
                        "actual_surface": [
                            [
                                str(item["context_id"]),
                                str(item["term"]),
                                float(item["weight"]),
                            ]
                            for item in actual_surface_rows
                        ],
                    }
                ).encode("utf-8")
            )

            spike_mismatch = (
                not spike_source_valid
                or spike_context_mismatch
                or expected_spikes != actual_spikes
            )
            surface_mismatch = (
                not metadata_source_valid
                or surface_context_mismatch
                or surface_values_mismatch
            )
            if spike_mismatch:
                spike_mismatch_count += 1
            if surface_mismatch:
                surface_term_mismatch_count += 1
            if spike_mismatch or surface_mismatch:
                mismatch_memory_ids.append(memory_id)
                if len(mismatch_samples) < sample_limit:
                    missing_spikes = sorted(set(expected_spikes) - set(actual_spikes))
                    unexpected_spikes = sorted(set(actual_spikes) - set(expected_spikes))
                    missing_terms = sorted(set(expected_surface) - set(actual_surface))
                    unexpected_terms = sorted(set(actual_surface) - set(expected_surface))
                    mismatch_samples.append(
                        {
                            "memory_id": memory_id,
                            "context_id": row_context,
                            "tag": str(row["tag"]),
                            "spike_mismatch": spike_mismatch,
                            "surface_term_mismatch": surface_mismatch,
                            "expected_spike_count": len(expected_spikes),
                            "actual_spike_count": len(actual_spikes),
                            "expected_surface_term_count": len(expected_surface),
                            "actual_surface_term_count": len(actual_surface),
                            "missing_spike_sample": missing_spikes[:20],
                            "unexpected_spike_sample": unexpected_spikes[:20],
                            "missing_surface_term_sample": missing_terms[:20],
                            "unexpected_surface_term_sample": unexpected_terms[:20],
                            "context_mismatch": bool(
                                spike_context_mismatch or surface_context_mismatch
                            ),
                        }
                    )

            expected_spike_count += len(expected_spikes)
            actual_spike_count += len(actual_spikes)
            expected_surface_term_count += len(expected_surface)
            actual_surface_term_count += len(actual_surface)

        orphan_filter = ""
        orphan_params: tuple[Any, ...] = ()
        if context_id is not None:
            orphan_filter = "AND indexed.context_id = ?"
            orphan_params = (str(context_id),)
        orphan_spike_count = (
            int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM memory_spikes AS indexed
                    LEFT JOIN memory_entries AS entry
                        ON entry.memory_id = indexed.memory_id
                    WHERE entry.memory_id IS NULL {orphan_filter}
                    """,
                    orphan_params,
                ).fetchone()[0]
            )
            if include_integrity_checks
            and entry_source_available
            and spike_index_available
            else 0
        )
        orphan_surface_term_count = (
            int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM memory_surface_terms AS indexed
                    LEFT JOIN memory_entries AS entry
                        ON entry.memory_id = indexed.memory_id
                    WHERE entry.memory_id IS NULL {orphan_filter}
                    """,
                    orphan_params,
                ).fetchone()[0]
            )
            if include_integrity_checks
            and entry_source_available
            and surface_index_available
            else 0
        )
        audit_hasher.update(
            _json_dumps(
                {
                    "orphan_spike_count": orphan_spike_count,
                    "orphan_surface_term_count": orphan_surface_term_count,
                    "quick_check": quick_check_rows,
                    "foreign_key_errors": foreign_key_rows,
                    "missing_schema_objects": missing_schema_objects,
                    "invalid_schema_objects": invalid_schema_samples,
                }
            ).encode("utf-8")
        )
        mismatch_count = len(mismatch_memory_ids)
        ready = (
            mismatch_count == 0
            and orphan_spike_count == 0
            and orphan_surface_term_count == 0
            and not source_errors
            and quick_check_ok
            and not foreign_key_rows
            and not missing_schema_objects
            and not invalid_schema_object_names
        )
        source_schema_blocked = not entry_source_available
        blocked = bool(
            source_errors
            or not quick_check_ok
            or blocking_foreign_key_rows
            or source_schema_blocked
        )
        return {
            "action": "semantic-index-audit",
            "status": "ready" if ready else ("blocked" if blocked else "degraded"),
            "memory_db_path": str(self.db_path),
            "context_id": context_id,
            "audit_revision": audit_hasher.hexdigest()[:32],
            "source_revision": source_revision,
            "semantic_index_algorithm_version": SEMANTIC_INDEX_ALGORITHM_VERSION,
            "semantic_index_algorithm_fingerprint": (
                SEMANTIC_INDEX_ALGORITHM_FINGERPRINT
            ),
            "semantic_index_generation": semantic_index_generation,
            "checked_memory_count": len(rows),
            "mismatched_memory_count": mismatch_count,
            "spike_mismatch_count": spike_mismatch_count,
            "surface_term_mismatch_count": surface_term_mismatch_count,
            "expected_spike_index_count": expected_spike_count,
            "actual_spike_index_count": actual_spike_count,
            "expected_surface_term_count": expected_surface_term_count,
            "actual_surface_term_count": actual_surface_term_count,
            "orphan_spike_count": orphan_spike_count,
            "orphan_surface_term_count": orphan_surface_term_count,
            "source_error_count": len(source_errors),
            "source_error_samples": source_errors[:sample_limit],
            "quick_check": quick_check_rows,
            "quick_check_ok": quick_check_ok,
            "foreign_key_error_count": len(foreign_key_rows),
            "foreign_key_error_samples": foreign_key_rows[:sample_limit],
            "repairable_foreign_key_error_count": len(
                repairable_foreign_key_rows
            ),
            "blocking_foreign_key_error_count": len(blocking_foreign_key_rows),
            "missing_schema_objects": missing_schema_objects,
            "invalid_schema_object_count": len(invalid_schema_object_names),
            "invalid_schema_object_names": sorted(invalid_schema_object_names),
            "invalid_schema_object_samples": invalid_schema_samples,
            "mismatch_samples": mismatch_samples,
            "sample_limit": sample_limit,
            "integrity_checks_included": include_integrity_checks,
            "repairable": not blocked,
            "checked_at": time.time(),
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            "_mismatch_memory_ids": mismatch_memory_ids,
            "_invalid_schema_object_names": sorted(invalid_schema_object_names),
            "_schema_object_types": schema_object_types,
            "_repairable_foreign_key_rows": repairable_foreign_key_rows,
        }

    @staticmethod
    def _public_semantic_index_audit(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in payload.items()
            if not str(key).startswith("_")
        }

    def audit_semantic_indexes(
        self,
        *,
        context_id: str | None = None,
        sample_limit: int = 20,
    ) -> dict[str, Any]:
        bounded_sample_limit = min(max(int(sample_limit), 1), 1000)
        try:
            public_audit: dict[str, Any] | None = None
            for attempt in range(1, 3):
                with closing(self._connect_read_only()) as conn:
                    data_version_before = int(
                        conn.execute("PRAGMA data_version").fetchone()[0]
                    )
                    with self._transaction(conn):
                        audit = self._semantic_index_audit(
                            conn,
                            context_id=context_id,
                            sample_limit=bounded_sample_limit,
                        )
                    data_version_after = int(
                        conn.execute("PRAGMA data_version").fetchone()[0]
                    )
                public_audit = self._public_semantic_index_audit(audit)
                public_audit.update(
                    {
                        "snapshot_attempts": attempt,
                        "snapshot_data_version_before": data_version_before,
                        "snapshot_data_version_after": data_version_after,
                        "snapshot_stable": (
                            data_version_before == data_version_after
                        ),
                    }
                )
                if data_version_before == data_version_after:
                    return public_audit
            assert public_audit is not None
            if public_audit["status"] != "blocked":
                public_audit["status"] = "degraded"
            public_audit["repairable"] = False
            public_audit["snapshot_stale"] = True
            return public_audit
        except Exception:
            LOGGER.exception(
                "failed to audit semantic indexes context_id=%s",
                context_id,
            )
            raise

    def repair_semantic_indexes(
        self,
        *,
        context_id: str | None = None,
        confirm: bool = False,
        expected_revision: str | None = None,
        sample_limit: int = 20,
    ) -> dict[str, Any]:
        if confirm is not True:
            raise ValueError("semantic index repair requires confirm=True")
        expected = str(expected_revision or "").strip()
        if not expected:
            raise ValueError(
                "semantic index repair requires expected_revision from a reviewed audit"
            )
        bounded_sample_limit = min(max(int(sample_limit), 1), 1000)
        started = time.perf_counter()
        safety_backup: dict[str, Any] | None = None
        repair_committed = False
        maintenance_lock_fds: tuple[int, int, int] | None = None
        try:
            with closing(self._connect_existing_write()) as conn:
                data_version_before_audit = int(
                    conn.execute("PRAGMA data_version").fetchone()[0]
                )
                with self._transaction(conn):
                    before = self._semantic_index_audit(
                        conn,
                        context_id=context_id,
                        sample_limit=bounded_sample_limit,
                    )
                    planned_candidates = self._semantic_index_audit(
                        conn,
                        context_id=context_id,
                        sample_limit=bounded_sample_limit,
                        memory_ids=before["_mismatch_memory_ids"],
                        include_integrity_checks=False,
                    )
                data_version_after_audit = int(
                    conn.execute("PRAGMA data_version").fetchone()[0]
                )
                if data_version_after_audit != data_version_before_audit:
                    raise RuntimeError(
                        "memory store changed during audit; rerun the audit before repair"
                    )
                if before["audit_revision"] != expected:
                    raise RuntimeError(
                        "semantic index repair plan is stale; rerun the audit and review its revision"
                    )
                if not before["repairable"]:
                    raise RuntimeError(
                        "semantic index repair refused because canonical source or SQLite integrity is invalid"
                    )
                needs_repair = bool(
                    before["_mismatch_memory_ids"]
                    or before["orphan_spike_count"]
                    or before["orphan_surface_term_count"]
                    or before["missing_schema_objects"]
                    or before["invalid_schema_object_count"]
                )
                if not needs_repair:
                    public_before = self._public_semantic_index_audit(before)
                    return {
                        "action": "semantic-index-repair",
                        "status": "ready",
                        "memory_db_path": str(self.db_path),
                        "context_id": context_id,
                        "repair_confirmed": True,
                        "expected_revision": expected,
                        "operation_id": None,
                        "repaired_memory_count": 0,
                        "repaired_memory_ids": [],
                        "orphan_spikes_removed": 0,
                        "orphan_surface_terms_removed": 0,
                        "schema_objects_created": [],
                        "normalized_schema_objects": [],
                        "quarantined_schema_objects": [],
                        "semantic_index_generation_before": before[
                            "semantic_index_generation"
                        ],
                        "semantic_index_generation_after": before[
                            "semantic_index_generation"
                        ],
                        "safety_backup": None,
                        "writer_lock_ms": 0.0,
                        "before": public_before,
                        "after": public_before,
                        "verification_passed": True,
                        "elapsed_ms": round(
                            (time.perf_counter() - started) * 1000.0,
                            3,
                        ),
                    }

                maintenance_lock_fds = self._acquire_maintenance_lock(
                    "semantic-index-repair"
                )
                safety_backup = self._verified_safety_backup(
                    conn,
                    label="pre-semantic-index-repair",
                    allowed_foreign_key_errors=before[
                        "_repairable_foreign_key_rows"
                    ],
                )
                if int(conn.execute("PRAGMA data_version").fetchone()[0]) != (
                    data_version_after_audit
                ):
                    raise RuntimeError(
                        "memory store changed during safety backup; rerun the audit before repair"
                    )

                writer_started = time.perf_counter()
                with self._transaction(
                    conn,
                    immediate=True,
                    cooperate_with_maintenance=False,
                ):
                    if int(conn.execute("PRAGMA data_version").fetchone()[0]) != (
                        data_version_after_audit
                    ):
                        raise RuntimeError(
                            "memory store changed before writer lock; repair was not applied"
                        )
                    current_candidates = self._semantic_index_audit(
                        conn,
                        context_id=context_id,
                        sample_limit=bounded_sample_limit,
                        memory_ids=before["_mismatch_memory_ids"],
                        include_integrity_checks=False,
                    )
                    if current_candidates["audit_revision"] != planned_candidates[
                        "audit_revision"
                    ]:
                        raise RuntimeError(
                            "semantic index candidates changed after planning; repair was not applied"
                        )
                    schema_objects_created = sorted(
                        {
                            *(str(value) for value in before["missing_schema_objects"]),
                            *(
                                str(value)
                                for value in before["invalid_schema_object_names"]
                            ),
                        }
                    )
                    schema_normalization = self._normalize_semantic_index_schema(
                        conn,
                        before,
                    )
                    # Normalization may have recreated a missing or quarantined
                    # derived table. Install its connection-local generation
                    # triggers before any repaired rows are written.
                    self._install_retrieval_revision_triggers(conn)
                    normalized_schema_objects = schema_normalization[
                        "normalized_schema_objects"
                    ]
                    quarantined_schema_objects = schema_normalization[
                        "quarantined_schema_objects"
                    ]
                    repaired_memory_ids: list[str] = []
                    for memory_id in before["_mismatch_memory_ids"]:
                        row = conn.execute(
                            """
                            SELECT
                                memory_id,
                                context_id,
                                tag,
                                source_text,
                                metadata_json,
                                spike_indices_json
                            FROM memory_entries
                            WHERE memory_id = ?
                            """,
                            (memory_id,),
                        ).fetchone()
                        if row is None:
                            continue
                        row_context = str(row["context_id"])
                        expected_spikes = list(
                            _decode_json(str(row["spike_indices_json"]), [])
                        )
                        expected_surface_rows = self._surface_term_rows(
                            memory_id=memory_id,
                            context_id=row_context,
                            tag=str(row["tag"]),
                            source_text=str(row["source_text"]),
                            metadata=_decode_json(str(row["metadata_json"]), {}),
                        )
                        conn.execute(
                            "DELETE FROM memory_spikes WHERE memory_id = ?",
                            (memory_id,),
                        )
                        if expected_spikes:
                            conn.executemany(
                                """
                                INSERT INTO memory_spikes (
                                    memory_id,
                                    context_id,
                                    spike_index
                                )
                                VALUES (?, ?, ?)
                                """,
                                [
                                    (memory_id, row_context, spike_index)
                                    for spike_index in expected_spikes
                                ],
                            )
                        conn.execute(
                            "DELETE FROM memory_surface_terms WHERE memory_id = ?",
                            (memory_id,),
                        )
                        if expected_surface_rows:
                            conn.executemany(
                                """
                                INSERT INTO memory_surface_terms (
                                    memory_id,
                                    context_id,
                                    term,
                                    weight
                                )
                                VALUES (?, ?, ?, ?)
                                """,
                                expected_surface_rows,
                            )
                        repaired_memory_ids.append(memory_id)

                    context_clause = ""
                    context_params: tuple[Any, ...] = ()
                    if context_id is not None:
                        context_clause = "AND context_id = ?"
                        context_params = (str(context_id),)
                    orphan_spikes_removed = conn.execute(
                        f"""
                        DELETE FROM memory_spikes
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM memory_entries
                            WHERE memory_entries.memory_id = memory_spikes.memory_id
                        )
                        {context_clause}
                        """,
                        context_params,
                    ).rowcount
                    orphan_surface_terms_removed = conn.execute(
                        f"""
                        DELETE FROM memory_surface_terms
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM memory_entries
                            WHERE memory_entries.memory_id = memory_surface_terms.memory_id
                        )
                        {context_clause}
                        """,
                        context_params,
                    ).rowcount

                    changed = bool(
                        repaired_memory_ids
                        or orphan_spikes_removed
                        or orphan_surface_terms_removed
                        or schema_objects_created
                    )
                    generation_row = conn.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("semantic_index_generation",),
                    ).fetchone()
                    try:
                        generation_before = int(
                            _decode_json(str(generation_row["value_json"]), 0)
                            if generation_row is not None
                            else 0
                        )
                    except (TypeError, ValueError, OverflowError):
                        generation_before = 0
                    generation_after = generation_before + (1 if changed else 0)
                    if changed:
                        conn.execute(
                            """
                            INSERT INTO store_metadata (key, value_json, updated_at)
                            VALUES (?, ?, ?)
                            ON CONFLICT(key) DO UPDATE SET
                                value_json = excluded.value_json,
                                updated_at = excluded.updated_at
                            """,
                            (
                                "semantic_index_generation",
                                json.dumps(generation_after),
                                time.time(),
                            ),
                        )

                    targeted_after = self._semantic_index_audit(
                        conn,
                        context_id=context_id,
                        sample_limit=bounded_sample_limit,
                        memory_ids=before["_mismatch_memory_ids"],
                        include_integrity_checks=False,
                    )
                    if targeted_after["status"] != "ready":
                        raise RuntimeError(
                            "semantic index verification failed; transaction rolled back"
                        )
                    remaining_orphan_spikes = int(
                        conn.execute(
                            f"""
                            SELECT COUNT(*)
                            FROM memory_spikes
                            WHERE NOT EXISTS (
                                SELECT 1
                                FROM memory_entries
                                WHERE memory_entries.memory_id = memory_spikes.memory_id
                            )
                            {context_clause}
                            """,
                            context_params,
                        ).fetchone()[0]
                    )
                    remaining_orphan_surface_terms = int(
                        conn.execute(
                            f"""
                            SELECT COUNT(*)
                            FROM memory_surface_terms
                            WHERE NOT EXISTS (
                                SELECT 1
                                FROM memory_entries
                                WHERE memory_entries.memory_id = memory_surface_terms.memory_id
                            )
                            {context_clause}
                            """,
                            context_params,
                        ).fetchone()[0]
                    )
                    if remaining_orphan_spikes or remaining_orphan_surface_terms:
                        raise RuntimeError(
                            "semantic index orphan verification failed; transaction rolled back"
                        )
                    target_ids = sorted(before["_mismatch_memory_ids"])
                    target_digest = hashlib.sha256(
                        "\n".join(target_ids).encode("utf-8")
                    ).hexdigest()
                    operation_id = "s2maint_" + uuid.uuid4().hex
                    conn.execute(
                        """
                        INSERT INTO store_maintenance_receipts (
                            operation_id,
                            operation_type,
                            context_id,
                            before_revision,
                            after_revision,
                            payload_json,
                            created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            operation_id,
                            "semantic-index-repair",
                            context_id,
                            planned_candidates["audit_revision"],
                            targeted_after["audit_revision"],
                            _json_dumps(
                                {
                                    "revision_scope": "repair-targets",
                                    "full_before_revision": before["audit_revision"],
                                    "repair_target_count": len(target_ids),
                                    "repair_target_sha256": target_digest,
                                    "repair_target_sample": target_ids[
                                        :bounded_sample_limit
                                    ],
                                    "schema_objects_created": schema_objects_created,
                                    "normalized_schema_objects": (
                                        normalized_schema_objects
                                    ),
                                    "quarantined_schema_objects": (
                                        quarantined_schema_objects
                                    ),
                                    "repaired_memory_count": len(repaired_memory_ids),
                                    "orphan_spikes_removed": max(
                                        0,
                                        int(orphan_spikes_removed),
                                    ),
                                    "orphan_surface_terms_removed": max(
                                        0,
                                        int(orphan_surface_terms_removed),
                                    ),
                                    "semantic_index_generation_before": generation_before,
                                    "semantic_index_generation_after": generation_after,
                                    "algorithm_fingerprint": (
                                        SEMANTIC_INDEX_ALGORITHM_FINGERPRINT
                                    ),
                                    "safety_backup_path": safety_backup["backup_path"],
                                    "safety_backup_sha256": safety_backup["sha256"],
                                }
                            ),
                            time.time(),
                        ),
                    )
                repair_committed = True
                writer_lock_ms = round(
                    (time.perf_counter() - writer_started) * 1000.0,
                    3,
                )

                with self._transaction(conn):
                    after = self._semantic_index_audit(
                        conn,
                        context_id=context_id,
                        sample_limit=bounded_sample_limit,
                    )

            return {
                "action": "semantic-index-repair",
                "status": after["status"],
                "memory_db_path": str(self.db_path),
                "context_id": context_id,
                "repair_confirmed": True,
                "expected_revision": expected,
                "operation_id": operation_id,
                "repaired_memory_count": len(repaired_memory_ids),
                "repaired_memory_ids": repaired_memory_ids[:bounded_sample_limit],
                "orphan_spikes_removed": max(0, int(orphan_spikes_removed)),
                "orphan_surface_terms_removed": max(
                    0,
                    int(orphan_surface_terms_removed),
                ),
                "schema_objects_created": schema_objects_created,
                "normalized_schema_objects": normalized_schema_objects,
                "quarantined_schema_objects": quarantined_schema_objects,
                "semantic_index_generation_before": generation_before,
                "semantic_index_generation_after": generation_after,
                "safety_backup": safety_backup,
                "writer_lock_ms": writer_lock_ms,
                "before": self._public_semantic_index_audit(before),
                "after": self._public_semantic_index_audit(after),
                "verification_passed": after["status"] == "ready",
                "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 3),
            }
        except Exception:
            if safety_backup is not None and not repair_committed:
                try:
                    self._discard_safety_backup(safety_backup)
                except Exception:
                    LOGGER.exception(
                        "failed to discard unused semantic-index repair backup"
                    )
            LOGGER.exception(
                "failed to repair semantic indexes context_id=%s",
                context_id,
            )
            raise
        finally:
            if maintenance_lock_fds is not None:
                self._release_maintenance_lock(maintenance_lock_fds)

    def export_json(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        context_id: str | None = None,
        limit: int = 10_000,
    ) -> dict[str, Any]:
        bounded_limit = min(max(int(limit), 1), 10_000)
        with closing(self._connect_read_only()) as conn:
            conn.execute("BEGIN")
            payload = {
                "version": 2,
                "exported_at": time.time(),
                "memory_db_path": str(self.db_path),
                "context_id": context_id,
                "stats": self.stats(context_id=context_id, _conn=conn),
                "entries": self.list_entries(
                    context_id=context_id,
                    limit=bounded_limit,
                    _conn=conn,
                ),
                "relationships": self.list_relationships(
                    context_id=context_id,
                    limit=bounded_limit,
                    _conn=conn,
                ),
                "context_links": self.list_context_links(
                    context_id=context_id,
                    limit=bounded_limit,
                    _conn=conn,
                ),
                "context_events": self.list_context_events(
                    context_id=context_id,
                    limit=bounded_limit,
                    _conn=conn,
                ),
                "context_cursors": self.list_context_cursors(
                    context_id=context_id,
                    limit=bounded_limit,
                    _conn=conn,
                ),
                "context_deliveries": self.list_context_deliveries(
                    context_id=context_id,
                    limit=bounded_limit,
                    _conn=conn,
                ),
                "context_delivery_receipts": (
                    self.list_context_delivery_receipts(
                        context_id=context_id,
                        limit=bounded_limit,
                        _conn=conn,
                    )
                ),
                "context_delivery_ack_tombstones": (
                    self.list_context_delivery_ack_tombstones(
                        context_id=context_id,
                        limit=bounded_limit,
                        _conn=conn,
                    )
                ),
            }
            if context_id is None:
                count_queries: dict[str, tuple[str, tuple[Any, ...]]] = {
                    "entries": ("SELECT COUNT(*) FROM memory_entries", ()),
                    "relationships": (
                        "SELECT COUNT(*) FROM memory_relationships",
                        (),
                    ),
                    "context_links": (
                        "SELECT COUNT(*) FROM context_relationships",
                        (),
                    ),
                    "context_events": (
                        "SELECT COUNT(*) FROM agent_context_events",
                        (),
                    ),
                    "context_cursors": (
                        "SELECT COUNT(*) FROM agent_context_delivery_cursors",
                        (),
                    ),
                    "context_deliveries": (
                        "SELECT COUNT(*) FROM agent_context_deliveries",
                        (),
                    ),
                    "context_delivery_receipts": (
                        "SELECT COUNT(*) FROM agent_context_delivery_receipts",
                        (),
                    ),
                    "context_delivery_ack_tombstones": (
                        "SELECT COUNT(*) FROM agent_context_delivery_ack_tombstones",
                        (),
                    ),
                }
            else:
                context = str(context_id)
                count_queries = {
                    "entries": (
                        "SELECT COUNT(*) FROM memory_entries WHERE context_id = ?",
                        (context,),
                    ),
                    "relationships": (
                        "SELECT COUNT(*) FROM memory_relationships WHERE context_id = ?",
                        (context,),
                    ),
                    "context_links": (
                        """
                        SELECT COUNT(*) FROM context_relationships
                        WHERE source_context_id = ? OR target_context_id = ?
                        """,
                        (context, context),
                    ),
                    "context_events": (
                        "SELECT COUNT(*) FROM agent_context_events WHERE context_id = ?",
                        (context,),
                    ),
                    "context_cursors": (
                        """
                        SELECT COUNT(*) FROM agent_context_delivery_cursors
                        WHERE context_id = ?
                        """,
                        (context,),
                    ),
                    "context_deliveries": (
                        "SELECT COUNT(*) FROM agent_context_deliveries WHERE context_id = ?",
                        (context,),
                    ),
                    "context_delivery_receipts": (
                        """
                        SELECT COUNT(*)
                        FROM agent_context_delivery_receipts AS receipt
                        JOIN agent_context_deliveries AS delivery
                          ON delivery.delivery_id = receipt.delivery_id
                        WHERE delivery.context_id = ?
                        """,
                        (context,),
                    ),
                    "context_delivery_ack_tombstones": (
                        """
                        SELECT COUNT(*)
                        FROM agent_context_delivery_ack_tombstones
                        WHERE context_id = ?
                        """,
                        (context,),
                    ),
                }
            available_counts = {
                key: int(conn.execute(query, params).fetchone()[0])
                for key, (query, params) in count_queries.items()
            }
            # Receipt ids are bearer capabilities. Exports retain audit linkage
            # through domain-separated digests, never the live ACK credential.
            for delivery in payload["context_deliveries"]:
                receipt_id = str(delivery.pop("current_receipt_id", ""))
                delivery["current_receipt_digest"] = (
                    self._context_delivery_receipt_digest(receipt_id)
                    if receipt_id
                    else ""
                )
            for receipt in payload["context_delivery_receipts"]:
                receipt_id = str(receipt.pop("receipt_id", ""))
                receipt["receipt_digest"] = (
                    self._context_delivery_receipt_digest(receipt_id)
                    if receipt_id
                    else ""
                )
            surface_counts = {
                key: {
                    "available_count": available_counts[key],
                    "exported_count": len(payload[key]),
                    "truncated": available_counts[key] > len(payload[key]),
                }
                for key in available_counts
            }
            payload["export_contract"] = {
                "requested_limit": int(limit),
                "applied_limit_per_surface": bounded_limit,
                "snapshot_consistency": "sqlite-read-transaction",
                "credential_policy": "receipt-identifiers-redacted-to-digests",
                "complete": not any(
                    item["truncated"] for item in surface_counts.values()
                ),
                "surfaces": surface_counts,
            }
            conn.commit()
        if path is not None:
            reject_sensitive_identifier(path, field="export_path")
            output_path = Path(path).expanduser()
            self._ensure_directory(output_path.parent, owned=False)
            if output_path.is_symlink():
                raise ValueError("export_path must not be a symlink")
            temp_path = self._unique_private_temp_path(
                output_path.parent,
                prefix=f".{output_path.name}.",
            )
            fd = os.open(temp_path, os.O_WRONLY | os.O_TRUNC)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    fd = -1
                    handle.write(json.dumps(payload, indent=2, sort_keys=True))
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_path, output_path)
                self._protect_path(output_path, directory=False)
                self._fsync_file(output_path)
                self._fsync_directory(output_path.parent)
            finally:
                if fd >= 0:
                    os.close(fd)
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
            payload["export_path"] = str(output_path)
        return payload

    @staticmethod
    def _backup_receipt_path(path: Path) -> Path:
        return path.with_name(path.name + ".receipt.json")

    @staticmethod
    def _restore_receipt_path(path: Path) -> Path:
        return path.with_name(path.name + ".restore.receipt.json")

    def _backup_verification_staging_dir(self) -> Path:
        path = self.db_path.parent / "recovery-staging"
        self._ensure_directory(path, owned=True)
        return path

    @staticmethod
    def _canonical_payload_digest(payload: dict[str, Any]) -> str:
        canonical = {
            key: value
            for key, value in payload.items()
            if key
            not in {
                "receipt_digest",
                "receipt_authenticator",
                "receipt_signature",
            }
        }
        return hashlib.sha256(_json_dumps(canonical).encode("utf-8")).hexdigest()

    def _write_private_bytes_exclusive(self, path: Path, value: bytes) -> bool:
        temporary = self._unique_private_temp_path(path.parent, prefix=f".{path.name}.")
        published = False
        try:
            flags = os.O_WRONLY | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags)
            try:
                offset = 0
                while offset < len(value):
                    offset += os.write(descriptor, value[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.link(temporary, path, follow_symlinks=False)
                published = True
            except FileExistsError:
                pass
            if published:
                os.chmod(path, 0o600, follow_symlinks=False)
                self._fsync_file(path)
                self._fsync_directory(path.parent)
            return published
        finally:
            temporary.unlink(missing_ok=True)

    def _backup_receipt_signing_key(
        self,
        *,
        create: bool,
    ) -> tuple[Ed25519PrivateKey | None, bytes | None, str | None]:
        key_dir = self.db_path.parent / "recovery-keys"
        private_path = key_dir / "backup-receipt-ed25519.private"
        public_path = key_dir / "backup-receipt-ed25519.public"
        if create:
            self._ensure_directory(key_dir, owned=True)
            if not private_path.exists() and not private_path.is_symlink():
                generated = Ed25519PrivateKey.generate()
                raw_private = generated.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
                self._write_private_bytes_exclusive(private_path, raw_private)
        if private_path.is_symlink() or public_path.is_symlink():
            raise ValueError("backup receipt authority keys must not be symlinks")
        private_key: Ed25519PrivateKey | None = None
        public_bytes: bytes | None = None
        if private_path.exists():
            descriptor, metadata = self._open_regular_nofollow(private_path)
            try:
                if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
                    raise PermissionError("backup receipt private key is not private")
                raw_private = os.read(descriptor, 33)
            finally:
                os.close(descriptor)
            if len(raw_private) != 32:
                raise RuntimeError("backup receipt private key has an invalid size")
            private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if create and not public_path.exists():
                self._write_private_bytes_exclusive(public_path, public_bytes)
            if public_path.exists():
                public_descriptor, public_metadata = self._open_regular_nofollow(
                    public_path
                )
                try:
                    if (
                        public_metadata.st_uid != os.getuid()
                        or stat.S_IMODE(public_metadata.st_mode) & 0o022
                    ):
                        raise PermissionError(
                            "backup receipt public key is not owner-controlled"
                        )
                    persisted_public = os.read(public_descriptor, 33)
                finally:
                    os.close(public_descriptor)
                if not secrets.compare_digest(persisted_public, public_bytes):
                    raise RuntimeError(
                        "backup receipt public and private authority keys disagree"
                    )
        elif public_path.exists():
            descriptor, metadata = self._open_regular_nofollow(public_path)
            try:
                if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
                    raise PermissionError("backup receipt public key is not owner-controlled")
                public_bytes = os.read(descriptor, 33)
            finally:
                os.close(descriptor)
            if len(public_bytes) != 32:
                raise RuntimeError("backup receipt public key has an invalid size")
        elif create:
            raise RuntimeError("backup receipt signing authority could not be created")
        key_id = hashlib.sha256(public_bytes).hexdigest() if public_bytes else None
        return private_key, public_bytes, key_id

    def _authenticate_receipt(self, payload: dict[str, Any]) -> None:
        private_key, public_bytes, key_id = self._backup_receipt_signing_key(
            create=True
        )
        if private_key is None or public_bytes is None or key_id is None:
            raise RuntimeError("backup receipt signing authority is unavailable")
        payload["auth_algorithm"] = "ed25519"
        payload["auth_key_id"] = key_id
        payload["signing_public_key"] = base64.b64encode(public_bytes).decode("ascii")
        payload["receipt_digest"] = self._canonical_payload_digest(payload)
        signed_payload = {
            key: value for key, value in payload.items() if key != "receipt_signature"
        }
        payload["receipt_signature"] = base64.b64encode(
            private_key.sign(_json_dumps(signed_payload).encode("utf-8"))
        ).decode("ascii")

    def _verify_receipt_authenticator(self, payload: dict[str, Any]) -> bool:
        if payload.get("auth_algorithm") != "ed25519":
            raise ValueError("backup receipt authentication algorithm is not supported")
        try:
            public_bytes = base64.b64decode(
                str(payload.get("signing_public_key") or ""), validate=True
            )
            signature = base64.b64decode(
                str(payload.get("receipt_signature") or ""), validate=True
            )
        except (ValueError, TypeError) as exc:
            raise ValueError("backup receipt signature encoding is invalid") from exc
        if len(public_bytes) != 32 or len(signature) != 64:
            raise ValueError("backup receipt signature is invalid")
        key_id = hashlib.sha256(public_bytes).hexdigest()
        if not secrets.compare_digest(str(payload.get("auth_key_id") or ""), key_id):
            raise ValueError("backup receipt signing key identifier is invalid")
        signed_payload = {
            key: value for key, value in payload.items() if key != "receipt_signature"
        }
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                signature,
                _json_dumps(signed_payload).encode("utf-8"),
            )
        except InvalidSignature as exc:
            raise ValueError("backup receipt signature verification failed") from exc
        _private, local_public, local_key_id = self._backup_receipt_signing_key(
            create=False
        )
        locally_trusted = bool(
            local_public is not None
            and local_key_id is not None
            and secrets.compare_digest(local_key_id, key_id)
        )
        configured_ids = {
            value.strip().lower()
            for value in os.getenv("SYNAPSE_S2_TRUSTED_BACKUP_KEY_IDS", "").split(",")
            if BACKUP_DIGEST_RE.fullmatch(value.strip().lower())
        }
        return locally_trusted or key_id in configured_ids

    @staticmethod
    def _regular_file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
        return (
            int(value.st_dev),
            int(value.st_ino),
            int(value.st_size),
            int(value.st_mtime_ns),
            int(value.st_ctime_ns),
        )

    @staticmethod
    def _validate_backup_artifact_name(value: Any, *, field: str) -> str:
        name = str(value or "").strip()
        if (
            not name
            or len(name) > 255
            or name in {".", ".."}
            or Path(name).name != name
            or "/" in name
            or "\\" in name
        ):
            raise ValueError(f"{field} must be a single local file name")
        reject_sensitive_identifier(name, field=field)
        return name

    @staticmethod
    def _open_regular_nofollow(path: Path) -> tuple[int, os.stat_result]:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("backup artifact must be a regular file")
            if metadata.st_size <= 0:
                raise ValueError("backup artifact must not be empty")
            return descriptor, metadata
        except BaseException:
            os.close(descriptor)
            raise

    def _hash_stable_regular_file(self, path: Path) -> tuple[str, int, os.stat_result]:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ValueError("backup artifact must be a non-symlink regular file")
        descriptor, opened = self._open_regular_nofollow(path)
        digest = hashlib.sha256()
        try:
            if self._regular_file_identity(before) != self._regular_file_identity(opened):
                raise RuntimeError("backup artifact changed while it was opened")
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after_fd = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after_path = os.lstat(path)
        identity = self._regular_file_identity(opened)
        if (
            self._regular_file_identity(after_fd) != identity
            or self._regular_file_identity(after_path) != identity
        ):
            raise RuntimeError("backup artifact changed during verification")
        return digest.hexdigest(), int(opened.st_size), opened

    def _copy_stable_regular_file(self, source: Path, destination: Path) -> dict[str, Any]:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(source) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                raise RuntimeError("backup artifact has an ambiguous SQLite sidecar")
        maximum_bytes = int(
            os.getenv("SYNAPSE_S2_BACKUP_MAX_BYTES", str(64 * 1024 * 1024 * 1024))
        )
        if maximum_bytes <= 0:
            raise ValueError("SYNAPSE_S2_BACKUP_MAX_BYTES must be positive")
        source_fd, source_metadata = self._open_regular_nofollow(source)
        destination_flags = os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_CLOEXEC"):
            destination_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            destination_flags |= os.O_NOFOLLOW
        destination_fd = os.open(destination, destination_flags)
        digest = hashlib.sha256()
        try:
            source_path_metadata = os.lstat(source)
            if self._regular_file_identity(source_path_metadata) != self._regular_file_identity(
                source_metadata
            ):
                raise RuntimeError("backup artifact changed while it was opened")
            if source_metadata.st_size > maximum_bytes:
                raise ValueError("backup artifact exceeds the configured size limit")
            free_bytes = int(shutil.disk_usage(destination.parent).free)
            copy_reserve = int(
                os.getenv("SYNAPSE_S2_BACKUP_COPY_RESERVE_BYTES", str(64 * 1024 * 1024))
            )
            if copy_reserve < 0:
                raise ValueError("SYNAPSE_S2_BACKUP_COPY_RESERVE_BYTES must be non-negative")
            if free_bytes < int(source_metadata.st_size) + copy_reserve:
                raise OSError("insufficient free space for isolated backup verification")
            copied = 0
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    offset += os.write(destination_fd, chunk[offset:])
                copied += len(chunk)
                if copied > maximum_bytes:
                    raise ValueError("backup artifact exceeds the configured size limit")
            os.fsync(destination_fd)
            source_after = os.fstat(source_fd)
            destination_after = os.fstat(destination_fd)
        finally:
            os.close(destination_fd)
            os.close(source_fd)
        source_path_after = os.lstat(source)
        source_identity = self._regular_file_identity(source_metadata)
        if (
            self._regular_file_identity(source_after) != source_identity
            or self._regular_file_identity(source_path_after) != source_identity
        ):
            raise RuntimeError("backup artifact changed during isolated copy")
        if int(destination_after.st_size) != int(source_metadata.st_size):
            raise RuntimeError("isolated backup copy has an unexpected size")
        return {
            "sha256": digest.hexdigest(),
            "size_bytes": int(destination_after.st_size),
        }

    def _write_private_json_exclusive(self, path: Path, payload: dict[str, Any]) -> None:
        if path.exists() or path.is_symlink():
            raise FileExistsError("receipt path already exists; refusing to overwrite it")
        temporary = self._unique_private_temp_path(path.parent, prefix=f".{path.name}.")
        published = False
        try:
            flags = os.O_WRONLY | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags)
            try:
                encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(
                    "utf-8"
                )
                offset = 0
                while offset < len(encoded):
                    offset += os.write(descriptor, encoded[offset:])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.link(temporary, path, follow_symlinks=False)
            published = True
            temporary_metadata = os.lstat(temporary)
            published_metadata = os.lstat(path)
            if self._regular_file_identity(temporary_metadata) != self._regular_file_identity(
                published_metadata
            ):
                raise RuntimeError("receipt publication identity mismatch")
            os.chmod(path, 0o600, follow_symlinks=False)
            self._fsync_file(path)
            temporary.unlink()
            self._fsync_directory(path.parent)
        except BaseException:
            temporary.unlink(missing_ok=True)
            if published:
                path.unlink(missing_ok=True)
            self._fsync_directory(path.parent)
            raise

    def _read_trusted_backup_receipt(
        self,
        path: Path,
        *,
        artifact: Path,
    ) -> tuple[dict[str, Any], bool]:
        descriptor, metadata = self._open_regular_nofollow(path)
        try:
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
                raise PermissionError("backup receipt must be private and owned by this user")
            if metadata.st_size > 1024 * 1024:
                raise ValueError("backup receipt exceeds the size limit")
            raw = b""
            while len(raw) <= 1024 * 1024:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                raw += chunk
        finally:
            os.close(descriptor)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("backup receipt is not valid JSON") from exc
        if not isinstance(payload, dict) or payload.get("schema") not in {
            BACKUP_RECEIPT_SCHEMA,
            LEGACY_BACKUP_RECEIPT_SCHEMA,
        }:
            raise ValueError("backup receipt schema is not supported")
        legacy_expected_keys = {
            "schema",
            "artifact_name",
            "artifact_sha256",
            "artifact_size_bytes",
            "schema_sha256",
            "schema_contract_version",
            "recovery_runtime_id",
            "snapshot_revision",
            "critical_counts",
            "highwaters",
            "semantic_index_revision",
            "purpose",
            "pinned",
            "restore_eligible",
            "created_at",
            "source_store_name",
            "auth_algorithm",
            "auth_key_id",
            "signing_public_key",
            "receipt_digest",
            "receipt_signature",
        }
        expected_keys = (
            legacy_expected_keys
            | {
                "logical_snapshot_schema",
                "logical_snapshot_sha256",
                "logical_snapshot_table_count",
                "logical_snapshot_column_count",
                "logical_snapshot_row_count",
                "logical_snapshot_value_bytes",
            }
            if payload.get("schema") == BACKUP_RECEIPT_SCHEMA
            else legacy_expected_keys
        )
        if set(payload) != expected_keys:
            raise ValueError("backup receipt fields do not match the supported contract")
        artifact_name = self._validate_backup_artifact_name(
            payload.get("artifact_name"), field="receipt artifact_name"
        )
        if artifact_name != artifact.name or artifact.parent != path.parent:
            raise ValueError("backup receipt does not identify this artifact")
        artifact_digest = str(payload.get("artifact_sha256") or "").lower()
        signed_digest_fields = (
            "artifact_sha256",
            "schema_sha256",
            "snapshot_revision",
            "receipt_digest",
        )
        if payload.get("schema") == BACKUP_RECEIPT_SCHEMA:
            signed_digest_fields += ("logical_snapshot_sha256",)
        if any(
            not BACKUP_DIGEST_RE.fullmatch(str(payload.get(field) or "").lower())
            for field in signed_digest_fields
        ):
            raise ValueError("backup receipt digest field is invalid")
        if (
            type(payload.get("artifact_size_bytes")) is not int
            or int(payload["artifact_size_bytes"]) <= 0
            or type(payload.get("pinned")) is not bool
            or payload.get("restore_eligible") is not True
            or not isinstance(payload.get("critical_counts"), dict)
            or not isinstance(payload.get("highwaters"), dict)
            or not isinstance(payload.get("created_at"), (int, float))
            or not math.isfinite(float(payload["created_at"]))
        ):
            raise ValueError("backup receipt field types are invalid")
        if payload.get("schema") == BACKUP_RECEIPT_SCHEMA:
            if (
                payload.get("logical_snapshot_schema")
                != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                or any(
                    type(payload.get(field)) is not int
                    or int(payload[field]) < 0
                    for field in (
                        "logical_snapshot_table_count",
                        "logical_snapshot_column_count",
                        "logical_snapshot_row_count",
                        "logical_snapshot_value_bytes",
                    )
                )
            ):
                raise ValueError("backup logical snapshot fields are invalid")
        for count_map_name in ("critical_counts", "highwaters"):
            count_map = payload[count_map_name]
            if any(
                not isinstance(key, str)
                or type(value) is not int
                or int(value) < 0
                for key, value in count_map.items()
            ):
                raise ValueError("backup receipt count fields are invalid")
        receipt_digest = str(payload.get("receipt_digest") or "").lower()
        if (
            not BACKUP_DIGEST_RE.fullmatch(receipt_digest)
            or not secrets.compare_digest(receipt_digest, self._canonical_payload_digest(payload))
        ):
            raise ValueError("backup receipt digest validation failed")
        identity_trusted = self._verify_receipt_authenticator(payload)
        return payload, identity_trusted

    @staticmethod
    def _sqlite_schema_fingerprint(conn: sqlite3.Connection) -> dict[str, Any]:
        rows = conn.execute(
            """
            SELECT type, name, tbl_name, COALESCE(sql, '') AS sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name, tbl_name, sql
            """
        ).fetchall()
        canonical = [
            [str(row["type"]), str(row["name"]), str(row["tbl_name"]), str(row["sql"])]
            for row in rows
        ]
        tables = sorted(row[1] for row in canonical if row[0] == "table")
        indexes = sorted(row[1] for row in canonical if row[0] == "index")
        return {
            "sha256": hashlib.sha256(_json_dumps(canonical).encode("utf-8")).hexdigest(),
            "table_count": len(tables),
            "index_count": len(indexes),
            "missing_critical_table_count": len(BACKUP_CRITICAL_TABLES - set(tables)),
        }

    @staticmethod
    def _logical_snapshot_value_frame(value: Any) -> bytes:
        """Encode one SQLite value without lossy text coercion.

        The encoding is deliberately small, versioned by
        ``LOGICAL_SNAPSHOT_DIGEST_SCHEMA``, and shared by hashing and SQL sort
        order.  Sorting the exact frames avoids declared-collation ties and
        makes the digest independent of page layout, rowid allocation, vacuum,
        and SQLite query-plan choices.
        """

        if value is None:
            tag, payload = b"n", b""
        elif isinstance(value, bytes):
            tag, payload = b"b", value
        elif isinstance(value, str):
            tag, payload = b"s", value.encode("utf-8")
        elif type(value) is int:
            tag, payload = b"i", str(value).encode("ascii")
        elif type(value) is float:
            tag, payload = b"f", struct.pack(">d", value)
        else:
            raise TypeError(
                f"unsupported SQLite value type in logical snapshot: {type(value).__name__}"
            )
        return tag + len(payload).to_bytes(8, "big") + payload

    @staticmethod
    def _logical_snapshot_hash_frame(
        digest: Any,
        tag: bytes,
        payload: bytes,
    ) -> None:
        digest.update(tag)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)

    @classmethod
    def _canonical_logical_snapshot_digest(
        cls,
        conn: sqlite3.Connection,
        *,
        install_progress_handler: bool = True,
    ) -> dict[str, Any]:
        """Hash the complete logical store through a bounded streaming scan."""

        maximum_tables = int(
            os.getenv("SYNAPSE_S2_LOGICAL_DIGEST_MAX_TABLES", "128")
        )
        maximum_columns = int(
            os.getenv("SYNAPSE_S2_LOGICAL_DIGEST_MAX_COLUMNS", "4096")
        )
        maximum_rows = int(
            os.getenv("SYNAPSE_S2_LOGICAL_DIGEST_MAX_ROWS", "20000000")
        )
        maximum_value_bytes = int(
            os.getenv(
                "SYNAPSE_S2_LOGICAL_DIGEST_MAX_VALUE_BYTES",
                str(64 * 1024**2),
            )
        )
        maximum_total_value_bytes = int(
            os.getenv(
                "SYNAPSE_S2_LOGICAL_DIGEST_MAX_TOTAL_VALUE_BYTES",
                str(64 * 1024**3),
            )
        )
        maximum_seconds = float(
            os.getenv("SYNAPSE_S2_LOGICAL_DIGEST_TIMEOUT_SECONDS", "120")
        )
        maximum_vm_steps = int(
            os.getenv(
                "SYNAPSE_S2_LOGICAL_DIGEST_MAX_VM_STEPS",
                "500000000",
            )
        )
        if (
            maximum_tables <= 0
            or maximum_columns <= 0
            or maximum_rows < 0
            or maximum_value_bytes <= 0
            or maximum_total_value_bytes <= 0
            or not math.isfinite(maximum_seconds)
            or maximum_seconds <= 0
            or maximum_vm_steps <= 0
        ):
            raise ValueError("logical snapshot digest limits must be positive and finite")

        deadline = time.monotonic() + maximum_seconds
        progress_calls = 0
        steps_per_callback = 10_000

        def digest_progress() -> int:
            nonlocal progress_calls
            progress_calls += 1
            return int(
                time.monotonic() >= deadline
                or progress_calls * steps_per_callback > maximum_vm_steps
            )

        if install_progress_handler:
            conn.set_progress_handler(digest_progress, steps_per_callback)
        conn.create_function(
            "s2_logical_value_frame",
            1,
            cls._logical_snapshot_value_frame,
            deterministic=True,
        )
        try:
            schema_rows = conn.execute(
                """
                SELECT type, name, tbl_name, COALESCE(sql, '') AS sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type COLLATE BINARY, name COLLATE BINARY,
                         tbl_name COLLATE BINARY, sql COLLATE BINARY
                """
            ).fetchall()
            canonical_schema = [
                [str(row[0]), str(row[1]), str(row[2]), str(row[3])]
                for row in schema_rows
            ]
            schema_sha256 = hashlib.sha256(
                _json_dumps(canonical_schema).encode("utf-8")
            ).hexdigest()
            application_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            table_names = [
                str(row[0])
                for row in conn.execute(
                    """
                    SELECT name
                    FROM sqlite_schema
                    WHERE type = 'table'
                      AND (name NOT LIKE 'sqlite_%' OR name = 'sqlite_sequence')
                    ORDER BY name COLLATE BINARY
                    """
                ).fetchall()
            ]
            if len(table_names) > maximum_tables:
                raise RuntimeError("logical snapshot exceeds its table limit")

            table_specs: list[tuple[str, list[list[Any]], int]] = []
            total_columns = 0
            total_rows = 0
            for table_name in table_names:
                escaped_table = table_name.replace('"', '""')
                column_rows = conn.execute(
                    f'PRAGMA table_xinfo("{escaped_table}")'
                ).fetchall()
                columns = [
                    [
                        int(row[0]),
                        str(row[1]),
                        str(row[2] or ""),
                        int(row[3]),
                        row[4],
                        int(row[5]),
                        int(row[6]),
                    ]
                    for row in column_rows
                ]
                if not columns:
                    raise RuntimeError(
                        "logical snapshot encountered a table without columns"
                    )
                total_columns += len(columns)
                if total_columns > maximum_columns:
                    raise RuntimeError("logical snapshot exceeds its column limit")
                row_count = int(
                    conn.execute(
                        f'SELECT COUNT(*) FROM "{escaped_table}"'
                    ).fetchone()[0]
                )
                total_rows += row_count
                if total_rows > maximum_rows:
                    raise RuntimeError("logical snapshot exceeds its row limit")
                table_specs.append((table_name, columns, row_count))

            digest = hashlib.sha256()
            cls._logical_snapshot_hash_frame(
                digest,
                b"V",
                LOGICAL_SNAPSHOT_DIGEST_SCHEMA.encode("ascii"),
            )
            cls._logical_snapshot_hash_frame(
                digest,
                b"A",
                str(application_id).encode("ascii"),
            )
            cls._logical_snapshot_hash_frame(
                digest,
                b"U",
                str(user_version).encode("ascii"),
            )
            cls._logical_snapshot_hash_frame(
                digest,
                b"S",
                _json_dumps(canonical_schema).encode("utf-8"),
            )
            cls._logical_snapshot_hash_frame(
                digest,
                b"T",
                str(len(table_specs)).encode("ascii"),
            )
            total_value_bytes = 0
            for table_name, columns, expected_row_count in table_specs:
                cls._logical_snapshot_hash_frame(
                    digest,
                    b"t",
                    table_name.encode("utf-8"),
                )
                cls._logical_snapshot_hash_frame(
                    digest,
                    b"c",
                    _json_dumps(columns).encode("utf-8"),
                )
                cls._logical_snapshot_hash_frame(
                    digest,
                    b"r",
                    str(expected_row_count).encode("ascii"),
                )
                escaped_table = table_name.replace('"', '""')
                escaped_columns = [
                    str(column[1]).replace('"', '""') for column in columns
                ]
                select_columns = ", ".join(
                    f'"{column}"' for column in escaped_columns
                )
                order_columns = ", ".join(
                    f's2_logical_value_frame("{column}") COLLATE BINARY'
                    for column in escaped_columns
                )
                cursor = conn.execute(
                    f'SELECT {select_columns} FROM "{escaped_table}" '
                    f'ORDER BY {order_columns}'
                )
                streamed_rows = 0
                while True:
                    rows = cursor.fetchmany(512)
                    if not rows:
                        break
                    for row in rows:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("logical snapshot digest timed out")
                        cls._logical_snapshot_hash_frame(digest, b"R", b"")
                        for value in row:
                            value_frame = cls._logical_snapshot_value_frame(value)
                            value_bytes = len(value_frame) - 9
                            if value_bytes > maximum_value_bytes:
                                raise RuntimeError(
                                    "logical snapshot value exceeds its byte limit"
                                )
                            total_value_bytes += value_bytes
                            if total_value_bytes > maximum_total_value_bytes:
                                raise RuntimeError(
                                    "logical snapshot exceeds its total byte limit"
                                )
                            cls._logical_snapshot_hash_frame(
                                digest,
                                b"v",
                                value_frame,
                            )
                        streamed_rows += 1
                if streamed_rows != expected_row_count:
                    raise RuntimeError(
                        "logical snapshot row count changed during its read transaction"
                    )
            return {
                "schema": LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
                "sha256": digest.hexdigest(),
                "schema_sha256": schema_sha256,
                "application_id": application_id,
                "user_version": user_version,
                "table_count": len(table_specs),
                "column_count": total_columns,
                "row_count": total_rows,
                "value_bytes": total_value_bytes,
            }
        finally:
            conn.create_function("s2_logical_value_frame", 1, None)
            if install_progress_handler:
                conn.set_progress_handler(None, 0)

    def recompute_logical_snapshot_digest(
        self,
        path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Read-only exact-state digest for authority/cutover comparisons.

        The live path is read through a WAL-aware transaction.  Non-live
        artifacts must be stable standalone SQLite files and are opened
        immutable only after sidecar ambiguity is excluded.
        """

        live_path = self.db_path.expanduser().absolute()
        candidate = live_path if path is None else Path(path).expanduser().absolute()
        is_live = candidate == live_path
        if not is_live:
            metadata_before = os.lstat(candidate)
            if not stat.S_ISREG(metadata_before.st_mode) or stat.S_ISLNK(
                metadata_before.st_mode
            ):
                raise ValueError("logical snapshot path must be a regular file")
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(str(candidate) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    raise RuntimeError(
                        "logical snapshot artifact has an ambiguous SQLite sidecar"
                    )
            uri = candidate.resolve().as_uri() + "?mode=ro&immutable=1"
            conn = sqlite3.connect(uri, uri=True, isolation_level=None)
        else:
            metadata_before = None
            conn = self._connect_read_only()
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("BEGIN")
            try:
                result = self._canonical_logical_snapshot_digest(conn)
            finally:
                conn.execute("ROLLBACK")
            if self._authority_lease is not None and is_live:
                self._authority_lease.assert_active_for(self.db_path)
        finally:
            conn.close()
        if metadata_before is not None:
            metadata_after = os.lstat(candidate)
            if (
                self._regular_file_identity(metadata_before)
                != self._regular_file_identity(metadata_after)
                or int(metadata_before.st_size) != int(metadata_after.st_size)
                or int(metadata_before.st_mtime_ns) != int(metadata_after.st_mtime_ns)
            ):
                raise RuntimeError(
                    "logical snapshot artifact changed during recomputation"
                )
        return {**result, "path": str(candidate), "verified": True}

    @classmethod
    def _canonical_backup_contract(cls) -> dict[str, Any]:
        """Build the exact code-owned schema/migration allowlist once per process."""

        global _CANONICAL_BACKUP_CONTRACT
        if _CANONICAL_BACKUP_CONTRACT is not None:
            return dict(_CANONICAL_BACKUP_CONTRACT)
        with tempfile.TemporaryDirectory(prefix="synapse-s2-schema-contract-") as raw_root:
            canonical_path = Path(raw_root) / "canonical.sqlite3"
            bootstrap_store = cls(canonical_path)
            bootstrap_store.close()
            authority = CoreAuthorityLease.acquire_core(
                canonical_path,
                timeout_seconds=0.0,
                instance_id="core-schema-contract",
            )
            try:
                canonical_store = cls(canonical_path, authority_lease=authority)
                preclaim = canonical_store.recompute_logical_snapshot_digest()
                canonical_store.claim_core_authority(
                    instance_id=authority.instance_id,
                    config_fingerprint="0" * 64,
                    build_id="schema-contract",
                    protocol_version="synapse-core.v1",
                    expected_store_identity=cls.store_identity_for_path(
                        canonical_path
                    ),
                    request_journal_id="journal-" + ("0" * 24),
                    request_journal_binding_schema=JOURNAL_BINDING_SCHEMA,
                    request_journal_schema_version=JOURNAL_SCHEMA_VERSION,
                    expected_preclaim_logical_snapshot_sha256=str(
                        preclaim["sha256"]
                    ),
                    expected_previous_epoch=0,
                    expected_next_epoch=1,
                    root_generation_id="generation-" + ("0" * 24),
                    embedding_space_identity="0" * 64,
                    attestation_receipt_digest="0" * 64,
                    attestation_expires_at_unix_ms=int(time.time() * 1000) + 60_000,
                )
            finally:
                authority.close()
            with closing(sqlite3.connect(canonical_store.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                schema = cls._sqlite_schema_fingerprint(conn)
                migrations = sorted(
                    str(row[0])
                    for row in conn.execute(
                        "SELECT key FROM store_migrations ORDER BY key"
                    ).fetchall()
                )
                contract = {
                    "schema_sha256": str(schema["sha256"]),
                    "table_count": int(schema["table_count"]),
                    "index_count": int(schema["index_count"]),
                    "migration_set_sha256": hashlib.sha256(
                        _json_dumps(migrations).encode("utf-8")
                    ).hexdigest(),
                    "migration_count": len(migrations),
                    "application_id": int(
                        conn.execute("PRAGMA application_id").fetchone()[0]
                    ),
                    "user_version": int(
                        conn.execute("PRAGMA user_version").fetchone()[0]
                    ),
                }
        _CANONICAL_BACKUP_CONTRACT = dict(contract)
        registered_current = BACKUP_SCHEMA_COMPATIBILITY_REGISTRY.get(
            BACKUP_SCHEMA_CONTRACT_VERSION
        )
        if registered_current != contract:
            raise RuntimeError(
                "code-owned backup schema registry is stale; update it with the migration"
            )
        return dict(contract)

    def _backup_secret_audit(self, conn: sqlite3.Connection) -> dict[str, int]:
        tables = [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        classified = (
            set(LEGACY_SECRET_CONTENT_COLUMNS)
            | set(LEGACY_SECRET_IDENTIFIER_COLUMNS)
            | set(LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS)
        )
        text_columns: set[tuple[str, str]] = set()
        for table_name in tables:
            for row in conn.execute(f'PRAGMA table_xinfo("{table_name}")').fetchall():
                column_type = str(row[2] or "").upper()
                if any(marker in column_type for marker in ("CHAR", "CLOB", "TEXT")):
                    text_columns.add((table_name, str(row[1])))
        unclassified = text_columns - classified
        scan_limit = int(os.getenv("SYNAPSE_S2_BACKUP_SECRET_SCAN_MAX_CELLS", "2000000"))
        scan_byte_limit = int(
            os.getenv("SYNAPSE_S2_BACKUP_SECRET_SCAN_MAX_BYTES", str(2 * 1024**3))
        )
        value_byte_limit = int(
            os.getenv("SYNAPSE_S2_BACKUP_SCAN_MAX_VALUE_BYTES", str(16 * 1024**2))
        )
        if scan_limit <= 0:
            raise ValueError("SYNAPSE_S2_BACKUP_SECRET_SCAN_MAX_CELLS must be positive")
        if scan_byte_limit <= 0 or value_byte_limit <= 0:
            raise ValueError("backup secret scan byte limits must be positive")
        scanned = 0
        scanned_bytes = 0
        distinct_identifier_cells = 0
        redaction_changes = 0
        digest_changes = 0
        derived_identifier_tables = {"memory_spikes", "memory_surface_terms"}
        content_columns = text_columns & set(LEGACY_SECRET_CONTENT_COLUMNS)
        identifier_columns = (
            text_columns
            & (
                set(LEGACY_SECRET_IDENTIFIER_COLUMNS)
                | set(LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS)
            )
        ) - {
            column
            for column in text_columns
            if column[0] in derived_identifier_tables
        }
        for table_name, column_name in sorted(content_columns | identifier_columns):
            is_content = (table_name, column_name) in content_columns
            distinct_sql = "" if is_content else "DISTINCT "
            cursor = conn.execute(
                f'SELECT {distinct_sql}"{column_name}" FROM "{table_name}" '
                f'WHERE "{column_name}" IS NOT NULL'
            )
            for row in cursor:
                scanned += 1
                if not is_content:
                    distinct_identifier_cells += 1
                if scanned > scan_limit:
                    raise RuntimeError("backup secret audit exceeded its bounded scan limit")
                raw_value = str(row[0])
                value_bytes = len(raw_value.encode("utf-8"))
                scanned_bytes += value_bytes
                if value_bytes > value_byte_limit or scanned_bytes > scan_byte_limit:
                    raise RuntimeError("backup secret audit exceeded its bounded byte limit")
                is_json_document = column_name.endswith("_json") or (
                    table_name,
                    column_name,
                ) == ("store_metadata", "value_json")
                if is_json_document:
                    safe_value, _ = self._redact_legacy_json_document(raw_value)
                    digest_safe = safe_value
                else:
                    safe_value, _ = redact_capture_text(raw_value)
                    digest_safe, _ = strip_untrusted_raw_digest_text(safe_value)
                if safe_value != raw_value:
                    redaction_changes += 1
                if digest_safe != safe_value:
                    digest_changes += 1
        return {
            "scanned_cell_count": scanned,
            "scanned_byte_count": scanned_bytes,
            "scanned_distinct_identifier_cell_count": distinct_identifier_cells,
            "derived_identifier_table_count": len(derived_identifier_tables),
            "redaction_changing_cell_count": redaction_changes,
            "raw_digest_changing_cell_count": digest_changes,
            "unclassified_text_column_count": len(unclassified),
        }

    def _secret_content_preclaim_receipt_inventory(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, Any]:
        """Classify content-free action receipts for the offline scrub lane."""

        rows = conn.execute(
            """
            SELECT operation_id, before_revision, after_revision,
                   payload_json, created_at
            FROM store_maintenance_receipts
            WHERE operation_type = 'secret-content-preclaim-repair'
            ORDER BY created_at ASC, operation_id ASC
            """
        ).fetchall()
        pending: list[dict[str, Any]] = []
        verified: list[dict[str, Any]] = []
        invalid_count = 0
        invalid_pending_count = 0
        pending_fields = {
            "protocol_version",
            "content_free",
            "verification_status",
            "reviewed_finding_count",
            "reviewed_redaction_changing_cell_count",
            "reviewed_raw_digest_changing_cell_count",
            "changed_index_row_count",
            "repaired_state_revision",
            "safety_backup_path",
            "safety_backup_sha256",
            "safety_backup_size_bytes",
        }
        verified_fields = pending_fields | {
            "proof_backup_path",
            "proof_backup_sha256",
            "proof_backup_size_bytes",
            "proof_backup_snapshot_revision",
            "proof_backup_restore_eligible",
            "verified_at",
        }
        backup_parent = (self.db_path.parent / "backups").resolve()
        for row in rows:
            payload = _decode_json(str(row["payload_json"]), None)
            status = (
                str(payload.get("verification_status") or "")
                if isinstance(payload, dict)
                else ""
            )
            expected_fields = (
                pending_fields
                if status == "pending"
                else verified_fields
                if status == "verified"
                else set()
            )
            paths = (
                [Path(str(payload.get("safety_backup_path") or ""))]
                if isinstance(payload, dict)
                else []
            )
            if status == "verified" and isinstance(payload, dict):
                paths.append(Path(str(payload.get("proof_backup_path") or "")))
            payload_valid = bool(
                isinstance(payload, dict)
                and set(payload) == expected_fields
                and payload.get("protocol_version")
                == "secret-content-preclaim-repair.v1"
                and payload.get("content_free") is True
                and all(
                    type(payload.get(field)) is int
                    and int(payload[field]) >= 0
                    for field in (
                        "reviewed_finding_count",
                        "reviewed_redaction_changing_cell_count",
                        "reviewed_raw_digest_changing_cell_count",
                        "changed_index_row_count",
                    )
                )
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(payload.get("repaired_state_revision") or ""),
                )
                is not None
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(payload.get("safety_backup_sha256") or ""),
                )
                is not None
                and type(payload.get("safety_backup_size_bytes")) is int
                and int(payload["safety_backup_size_bytes"]) > 0
                and all(
                    path.is_absolute()
                    and path.parent.resolve() == backup_parent
                    and path.name == path.resolve().name
                    for path in paths
                )
                and (
                    status != "verified"
                    or (
                        re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(payload.get("proof_backup_sha256") or ""),
                        )
                        is not None
                        and type(payload.get("proof_backup_size_bytes")) is int
                        and int(payload["proof_backup_size_bytes"]) > 0
                        and re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(
                                payload.get("proof_backup_snapshot_revision")
                                or ""
                            ),
                        )
                        is not None
                        and payload.get("proof_backup_restore_eligible") is True
                        and self._context_delivery_timestamp_is_valid(
                            payload.get("verified_at")
                        )
                    )
                )
            )
            operation_id = str(row["operation_id"])
            before_revision = str(row["before_revision"])
            after_revision = str(row["after_revision"])
            created_at = row["created_at"]
            row_valid = bool(
                re.fullmatch(r"s2maint_[0-9a-f]{32}", operation_id)
                and re.fullmatch(r"[0-9a-f]{64}", before_revision)
                and re.fullmatch(r"[0-9a-f]{64}", after_revision)
                and self._context_delivery_timestamp_is_valid(created_at)
            )
            if not payload_valid or not row_valid:
                invalid_count += 1
                invalid_pending_count += int(status == "pending")
                continue
            record = {
                "operation_id": operation_id,
                "before_revision": before_revision,
                "after_revision": after_revision,
                "payload": dict(payload),
                "payload_sha256": hashlib.sha256(
                    _json_dumps(payload).encode("utf-8")
                ).hexdigest(),
                "created_at": float(created_at),
            }
            (pending if status == "pending" else verified).append(record)
        return {
            "invalid_count": invalid_count,
            "invalid_pending_count": invalid_pending_count,
            "pending": pending,
            "verified": verified,
        }

    def _secret_content_repair_audit(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, Any]:
        """Return an exact content-free review token for offline scrubbing."""

        self._validate_existing_schema_compatibility_markers(conn)
        if int(conn.execute("PRAGMA user_version").fetchone()[0]) != SQLITE_USER_VERSION:
            raise RuntimeError(
                "secret content repair requires the current authoritative schema"
            )
        quick_check_ok = [str(row[0]) for row in conn.execute("PRAGMA quick_check")] == [
            "ok"
        ]
        integrity_check_ok = [
            str(row[0]) for row in conn.execute("PRAGMA integrity_check")
        ] == ["ok"]
        foreign_key_error_count = sum(1 for _ in conn.execute("PRAGMA foreign_key_check"))
        tables = [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        text_columns: set[tuple[str, str]] = set()
        for table_name in tables:
            for row in conn.execute(f'PRAGMA table_xinfo("{table_name}")').fetchall():
                column_type = str(row[2] or "").upper()
                if any(marker in column_type for marker in ("CHAR", "CLOB", "TEXT")):
                    text_columns.add((table_name, str(row[1])))
        classified = (
            set(LEGACY_SECRET_CONTENT_COLUMNS)
            | set(LEGACY_SECRET_IDENTIFIER_COLUMNS)
            | set(LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS)
        )
        unclassified = text_columns - classified
        derived_identifier_tables = {"memory_spikes", "memory_surface_terms"}
        content_columns = text_columns & set(LEGACY_SECRET_CONTENT_COLUMNS)
        identifier_columns = (
            text_columns
            & (
                set(LEGACY_SECRET_IDENTIFIER_COLUMNS)
                | set(LEGACY_OPTIONAL_SECRET_IDENTIFIER_COLUMNS)
            )
        ) - {
            column
            for column in text_columns
            if column[0] in derived_identifier_tables
        }
        scan_limit = int(os.getenv("SYNAPSE_S2_BACKUP_SECRET_SCAN_MAX_CELLS", "2000000"))
        scan_byte_limit = int(
            os.getenv("SYNAPSE_S2_BACKUP_SECRET_SCAN_MAX_BYTES", str(2 * 1024**3))
        )
        value_byte_limit = int(
            os.getenv("SYNAPSE_S2_BACKUP_SCAN_MAX_VALUE_BYTES", str(16 * 1024**2))
        )
        if scan_limit <= 0 or scan_byte_limit <= 0 or value_byte_limit <= 0:
            raise ValueError("secret content repair audit limits must be positive")

        scanned_cell_count = 0
        scanned_byte_count = 0
        content_findings: dict[str, int] = {}
        identifier_findings: dict[str, int] = {}
        redaction_changing_cell_count = 0
        raw_digest_changing_cell_count = 0
        finding_records: list[tuple[str, str, str, str, bool, bool]] = []
        for table_name, column_name in sorted(content_columns | identifier_columns):
            is_content = (table_name, column_name) in content_columns
            if is_content:
                cursor = conn.execute(
                    f'SELECT rowid, "{column_name}" FROM "{table_name}" '
                    f'WHERE "{column_name}" IS NOT NULL ORDER BY rowid'
                )
            else:
                cursor = conn.execute(
                    f'SELECT DISTINCT "{column_name}" FROM "{table_name}" '
                    f'WHERE "{column_name}" IS NOT NULL ORDER BY "{column_name}"'
                )
            for column_ordinal, row in enumerate(cursor, start=1):
                scanned_cell_count += 1
                if scanned_cell_count > scan_limit:
                    raise RuntimeError(
                        "secret content repair audit exceeded its bounded scan limit"
                    )
                cell_identity = (
                    str(row[0]) if is_content else f"distinct-{column_ordinal}"
                )
                raw_value = str(row[1] if is_content else row[0])
                value_bytes = len(raw_value.encode("utf-8"))
                scanned_byte_count += value_bytes
                if value_bytes > value_byte_limit or scanned_byte_count > scan_byte_limit:
                    raise RuntimeError(
                        "secret content repair audit exceeded its bounded byte limit"
                    )
                is_json_document = column_name.endswith("_json") or (
                    table_name,
                    column_name,
                ) == ("store_metadata", "value_json")
                if is_json_document:
                    safe_value, _ = self._redact_legacy_json_document(raw_value)
                    digest_safe = safe_value
                else:
                    safe_value, _ = redact_capture_text(raw_value)
                    digest_safe, _ = strip_untrusted_raw_digest_text(safe_value)
                redaction_changed = safe_value != raw_value
                digest_changed = digest_safe != safe_value
                if not redaction_changed and not digest_changed:
                    continue
                redaction_changing_cell_count += int(redaction_changed)
                raw_digest_changing_cell_count += int(digest_changed)
                column_key = f"{table_name}.{column_name}"
                findings = content_findings if is_content else identifier_findings
                findings[column_key] = findings.get(column_key, 0) + 1
                finding_records.append(
                    (
                        "content" if is_content else "identifier",
                        table_name,
                        column_name,
                        cell_identity,
                        redaction_changed,
                        digest_changed,
                    )
                )
        repair_plan_sha256 = hashlib.sha256(
            _json_dumps(sorted(finding_records)).encode("utf-8")
        ).hexdigest()
        content_finding_count = sum(content_findings.values())
        identifier_finding_count = sum(identifier_findings.values())
        base_blocked = bool(
            not quick_check_ok
            or not integrity_check_ok
            or foreign_key_error_count
            or unclassified
            or identifier_finding_count
        )
        settled_status = (
            "blocked"
            if base_blocked
            else "repairable"
            if content_finding_count
            else "ready"
        )
        settled_revision_seed = {
            "protocol_version": "secret-content-preclaim-repair.v1",
            "status": settled_status,
            "repair_plan_sha256": repair_plan_sha256,
            "content_findings_by_column": content_findings,
            "identifier_findings_by_column": identifier_findings,
            "redaction_changing_cell_count": redaction_changing_cell_count,
            "raw_digest_changing_cell_count": raw_digest_changing_cell_count,
            "unclassified_text_column_count": len(unclassified),
            "quick_check_ok": quick_check_ok,
            "integrity_check_ok": integrity_check_ok,
            "foreign_key_error_count": foreign_key_error_count,
        }
        settled_audit_revision = hashlib.sha256(
            _json_dumps(settled_revision_seed).encode("utf-8")
        ).hexdigest()
        receipt_inventory = self._secret_content_preclaim_receipt_inventory(conn)
        pending_receipts = list(receipt_inventory["pending"])
        receipt_integrity_error_count = int(receipt_inventory["invalid_count"])
        pending_receipt_semantic_error_count = sum(
            1
            for receipt in pending_receipts
            if (
                receipt["after_revision"] != settled_audit_revision
                or receipt["payload"]["repaired_state_revision"]
                != settled_audit_revision
                or int(receipt["payload"]["reviewed_finding_count"]) <= 0
                or settled_status != "ready"
            )
        )
        receipt_binding_error_count = sum(
            1
            for receipt in (
                *pending_receipts,
                *receipt_inventory["verified"],
            )
            if receipt["after_revision"]
            != receipt["payload"]["repaired_state_revision"]
        )
        receipt_semantic_error_count = (
            pending_receipt_semantic_error_count
            + receipt_binding_error_count
        )
        if (
            base_blocked
            or receipt_integrity_error_count
            or receipt_semantic_error_count
            or len(pending_receipts) > 1
        ):
            status = "blocked"
        elif content_finding_count:
            status = "blocked" if pending_receipts else "repairable"
        elif len(pending_receipts) == 1:
            status = "committed_unverified"
        else:
            status = "ready"
        revision_seed = {
            "settled_audit_revision": settled_audit_revision,
            "receipt_integrity_error_count": receipt_integrity_error_count,
            "receipt_semantic_error_count": receipt_semantic_error_count,
            "pending_receipts": [
                {
                    "operation_id": receipt["operation_id"],
                    "before_revision": receipt["before_revision"],
                    "after_revision": receipt["after_revision"],
                    "payload_sha256": receipt["payload_sha256"],
                }
                for receipt in pending_receipts
            ],
        }
        return {
            **settled_revision_seed,
            "status": status,
            "audit_revision": hashlib.sha256(
                _json_dumps(revision_seed).encode("utf-8")
            ).hexdigest(),
            "settled_audit_revision": settled_audit_revision,
            "content_finding_count": content_finding_count,
            "identifier_finding_count": identifier_finding_count,
            "scanned_cell_count": scanned_cell_count,
            "scanned_byte_count": scanned_byte_count,
            "repair_required": status == "repairable",
            "repair_receipt_integrity_error_count": (
                receipt_integrity_error_count
            ),
            "repair_receipt_semantic_error_count": (
                receipt_semantic_error_count
            ),
            "pending_repair_receipt_semantic_error_count": (
                pending_receipt_semantic_error_count
            ),
            "pending_repair_receipt_count": len(pending_receipts),
            "invalid_pending_repair_receipt_count": int(
                receipt_inventory["invalid_pending_count"]
            ),
            "content_free": True,
        }

    def audit_secret_content_preclaim_repair(self) -> dict[str, Any]:
        """Audit secret-bearing residue without exposing any stored value."""

        with closing(self._connect_read_only()) as conn:
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("BEGIN")
            try:
                return self._secret_content_repair_audit(conn)
            finally:
                conn.rollback()

    def _verify_secret_content_safety_backup(
        self,
        backup: dict[str, Any],
    ) -> dict[str, Any]:
        return self._verify_context_delivery_publication_backup(
            {
                "safety_backup_path": backup["backup_path"],
                "safety_backup_sha256": backup["sha256"],
                "safety_backup_size_bytes": int(backup["size_bytes"]),
            }
        )

    def _verify_secret_content_proof_backup(
        self,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        verification = self._verify_secret_content_safety_backup(
            {
                "backup_path": payload["proof_backup_path"],
                "sha256": payload["proof_backup_sha256"],
                "size_bytes": int(payload["proof_backup_size_bytes"]),
            }
        )
        inspection = self._inspect_backup_snapshot(
            Path(str(payload["proof_backup_path"]))
        )
        if (
            inspection["restore_eligible"] is not True
            or str(inspection["snapshot_revision"])
            != str(payload["proof_backup_snapshot_revision"])
            or payload["proof_backup_restore_eligible"] is not True
        ):
            raise RuntimeError(
                "secret content repair proof backup failed restore verification"
            )
        return {
            **verification,
            "snapshot_revision": str(inspection["snapshot_revision"]),
            "snapshot_restore_eligible": True,
        }

    def _prove_secret_content_preclaim_repair_durable(
        self,
        conn: sqlite3.Connection,
        *,
        lease: CoreAuthorityLease,
        receipt: dict[str, Any],
        receipt_status: str,
    ) -> dict[str, Any]:
        if receipt_status not in {"pending", "verified"}:
            raise ValueError("secret content receipt status is invalid")
        checkpoint = conn.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
        if (
            checkpoint is None
            or int(checkpoint[0]) != 0
            or int(checkpoint[1]) != int(checkpoint[2])
        ):
            raise RuntimeError("secret content repair checkpoint was incomplete")
        lease.assert_core_for(self.db_path)
        quick_check = [str(row[0]) for row in conn.execute("PRAGMA quick_check")]
        integrity_check = [
            str(row[0]) for row in conn.execute("PRAGMA integrity_check")
        ]
        foreign_key_error_count = sum(
            1 for _ in conn.execute("PRAGMA foreign_key_check")
        )
        self._run_migrations(conn, allow_mutation=False)
        audit = self._secret_content_repair_audit(conn)
        expected_status = (
            "committed_unverified" if receipt_status == "pending" else "ready"
        )
        inventory = self._secret_content_preclaim_receipt_inventory(conn)
        candidates = inventory[receipt_status]
        matches = [
            candidate
            for candidate in candidates
            if candidate["operation_id"] == receipt["operation_id"]
            and candidate["before_revision"] == receipt["before_revision"]
            and candidate["after_revision"] == receipt["after_revision"]
            and candidate["created_at"] == receipt["created_at"]
            and candidate["payload_sha256"] == receipt["payload_sha256"]
        ]
        if (
            quick_check != ["ok"]
            or integrity_check != ["ok"]
            or foreign_key_error_count != 0
            or audit["status"] != expected_status
            or int(audit["content_finding_count"]) != 0
            or int(audit["identifier_finding_count"]) != 0
            or int(audit["redaction_changing_cell_count"]) != 0
            or int(audit["raw_digest_changing_cell_count"]) != 0
            or inventory["invalid_count"]
            or len(matches) != 1
        ):
            raise RuntimeError(
                "secret content repair durable state failed verification"
            )
        current = matches[0]
        if (
            current["after_revision"] != audit["settled_audit_revision"]
            or current["payload"]["repaired_state_revision"]
            != audit["settled_audit_revision"]
        ):
            raise RuntimeError(
                "secret content repair receipt is not bound to repaired state"
            )
        safety_verification = self._verify_secret_content_safety_backup(
            {
                "backup_path": current["payload"]["safety_backup_path"],
                "sha256": current["payload"]["safety_backup_sha256"],
                "size_bytes": int(
                    current["payload"]["safety_backup_size_bytes"]
                ),
            }
        )
        proof_verification = (
            None
            if receipt_status == "pending"
            else self._verify_secret_content_proof_backup(current["payload"])
        )
        return {
            "audit": audit,
            "receipt": current,
            "checkpoint": [int(value) for value in checkpoint],
            "quick_check": quick_check,
            "integrity_check": integrity_check,
            "foreign_key_error_count": foreign_key_error_count,
            "safety_backup_verification": safety_verification,
            "proof_backup_verification": proof_verification,
        }

    def _verify_pending_secret_content_preclaim_repair(
        self,
        conn: sqlite3.Connection,
        *,
        lease: CoreAuthorityLease,
        receipt: dict[str, Any],
    ) -> dict[str, Any]:
        pending_proof = self._prove_secret_content_preclaim_repair_durable(
            conn,
            lease=lease,
            receipt=receipt,
            receipt_status="pending",
        )
        pending_receipt = pending_proof["receipt"]
        pending_payload = dict(pending_receipt["payload"])
        pending_payload_sha256 = str(pending_receipt["payload_sha256"])

        proof_backup = self._verified_safety_backup(
            conn,
            label="post-secret-content-repair-proof",
        )
        proof_inspection = self._inspect_backup_snapshot(
            Path(str(proof_backup["backup_path"]))
        )
        if proof_inspection["restore_eligible"] is not True:
            raise RuntimeError(
                "secret content repair proof backup is not restore eligible"
            )

        conn.execute("BEGIN EXCLUSIVE")
        try:
            lease.assert_core_for(self.db_path)
            current_audit = self._secret_content_repair_audit(conn)
            if current_audit["status"] != "committed_unverified":
                raise RuntimeError("secret content pending state changed")
            inventory = self._secret_content_preclaim_receipt_inventory(conn)
            matching = [
                candidate
                for candidate in inventory["pending"]
                if candidate["operation_id"] == pending_receipt["operation_id"]
                and candidate["payload_sha256"] == pending_payload_sha256
                and candidate["before_revision"]
                == pending_receipt["before_revision"]
                and candidate["after_revision"]
                == pending_receipt["after_revision"]
                and candidate["created_at"] == pending_receipt["created_at"]
            ]
            if inventory["invalid_count"] or len(matching) != 1:
                raise RuntimeError("secret content pending receipt changed")
            current_receipt = matching[0]
            current_payload = current_receipt["payload"]
            if (
                current_receipt["after_revision"]
                != current_audit["settled_audit_revision"]
                or current_payload["repaired_state_revision"]
                != current_audit["settled_audit_revision"]
            ):
                raise RuntimeError(
                    "secret content pending receipt is not bound to repaired state"
                )
            verified_payload = {
                **current_payload,
                "verification_status": "verified",
                "proof_backup_path": str(proof_backup["backup_path"]),
                "proof_backup_sha256": str(proof_backup["sha256"]),
                "proof_backup_size_bytes": int(proof_backup["size_bytes"]),
                "proof_backup_snapshot_revision": str(
                    proof_inspection["snapshot_revision"]
                ),
                "proof_backup_restore_eligible": True,
                "verified_at": max(
                    time.time(),
                    float(current_receipt["created_at"]),
                ),
            }
            cursor = conn.execute(
                """
                UPDATE store_maintenance_receipts
                SET payload_json = ?
                WHERE operation_id = ?
                  AND before_revision = ?
                  AND after_revision = ?
                  AND created_at = ?
                  AND payload_json = ?
                """,
                (
                    _json_dumps(verified_payload),
                    current_receipt["operation_id"],
                    current_receipt["before_revision"],
                    current_receipt["after_revision"],
                    current_receipt["created_at"],
                    _json_dumps(current_payload),
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("secret content pending receipt changed")
            lease.assert_core_for(self.db_path)
            conn.commit()
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

        inventory = self._secret_content_preclaim_receipt_inventory(conn)
        verified_matches = [
            candidate
            for candidate in inventory["verified"]
            if candidate["operation_id"] == pending_receipt["operation_id"]
        ]
        if inventory["invalid_count"] or len(verified_matches) != 1:
            raise RuntimeError(
                "secret content verified receipt did not persist"
            )
        final_proof = self._prove_secret_content_preclaim_repair_durable(
            conn,
            lease=lease,
            receipt=verified_matches[0],
            receipt_status="verified",
        )
        return {
            **final_proof,
            "pending_checkpoint": pending_proof["checkpoint"],
            "proof_backup": {
                **proof_backup,
                "snapshot_revision": str(
                    proof_inspection["snapshot_revision"]
                ),
                "snapshot_restore_eligible": True,
            },
        }

    def repair_secret_content_preclaim(
        self,
        *,
        expected_revision: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Scrub only reviewed content under an unclaimed offline core lease."""

        if confirm is not True:
            raise ValueError("secret content repair requires confirm=True")
        expected = str(expected_revision or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError("secret content repair requires a reviewed audit revision")
        lease = self._assert_filesystem_authority()
        if lease.role != "core" or lease.durable_epoch is not None:
            raise CoreAuthorityError(
                "secret content repair requires an unclaimed core maintenance lease"
            )

        safety_backup: dict[str, Any] | None = None
        repair_committed = False
        try:
            with closing(self._connect_existing_write()) as conn:
                before_data_version = int(
                    conn.execute("PRAGMA data_version").fetchone()[0]
                )
                before = self._secret_content_repair_audit(conn)
                if before["audit_revision"] != expected:
                    raise RuntimeError(
                        "secret content repair plan is stale; rerun the audit"
                    )
                if before["status"] == "ready":
                    inventory = self._secret_content_preclaim_receipt_inventory(
                        conn
                    )
                    latest_verified = (
                        inventory["verified"][-1]
                        if inventory["verified"]
                        else None
                    )
                    proof = (
                        None
                        if latest_verified is None
                        else self._prove_secret_content_preclaim_repair_durable(
                            conn,
                            lease=lease,
                            receipt=latest_verified,
                            receipt_status="verified",
                        )
                    )
                    if proof is None:
                        checkpoint_row = conn.execute(
                            "PRAGMA wal_checkpoint(FULL)"
                        ).fetchone()
                        if (
                            checkpoint_row is None
                            or int(checkpoint_row[0]) != 0
                            or int(checkpoint_row[1]) != int(checkpoint_row[2])
                        ):
                            raise RuntimeError(
                                "secret content ready checkpoint was incomplete"
                            )
                        lease.assert_core_for(self.db_path)
                        quick_check = [
                            str(row[0])
                            for row in conn.execute("PRAGMA quick_check")
                        ]
                        integrity_check = [
                            str(row[0])
                            for row in conn.execute("PRAGMA integrity_check")
                        ]
                        foreign_key_error_count = sum(
                            1
                            for _ in conn.execute("PRAGMA foreign_key_check")
                        )
                        if (
                            quick_check != ["ok"]
                            or integrity_check != ["ok"]
                            or foreign_key_error_count != 0
                        ):
                            raise RuntimeError(
                                "secret content ready verification failed"
                            )
                    return {
                        "action": "secret-content-preclaim-repair",
                        "status": "ready",
                        "operation_id": (
                            None
                            if latest_verified is None
                            else latest_verified["operation_id"]
                        ),
                        "repair_confirmed": True,
                        "expected_revision": expected,
                        "before": before,
                        "after": before if proof is None else proof["audit"],
                        "safety_backup": None,
                        "proof_backup": None,
                        "checkpoint": (
                            [int(value) for value in checkpoint_row]
                            if proof is None
                            else proof["checkpoint"]
                        ),
                        "quick_check": (
                            quick_check if proof is None else proof["quick_check"]
                        ),
                        "integrity_check": (
                            integrity_check
                            if proof is None
                            else proof["integrity_check"]
                        ),
                        "foreign_key_error_count": (
                            foreign_key_error_count
                            if proof is None
                            else proof["foreign_key_error_count"]
                        ),
                        "action_receipt_verified": bool(proof),
                        "verification_passed": True,
                    }
                if before["status"] == "committed_unverified":
                    inventory = self._secret_content_preclaim_receipt_inventory(
                        conn
                    )
                    if (
                        inventory["invalid_count"]
                        or len(inventory["pending"]) != 1
                    ):
                        raise RuntimeError(
                            "secret content pending receipt is ambiguous"
                        )
                    pending_receipt = inventory["pending"][0]
                    proof = self._verify_pending_secret_content_preclaim_repair(
                        conn,
                        lease=lease,
                        receipt=pending_receipt,
                    )
                    payload = pending_receipt["payload"]
                    return {
                        "action": "secret-content-preclaim-repair",
                        "status": "verified",
                        "operation_id": pending_receipt["operation_id"],
                        "repair_confirmed": True,
                        "expected_revision": expected,
                        "reviewed_finding_count": int(
                            payload["reviewed_finding_count"]
                        ),
                        "changed_index_row_count": int(
                            payload["changed_index_row_count"]
                        ),
                        "safety_backup": {
                            "backup_path": payload["safety_backup_path"],
                            **proof["safety_backup_verification"],
                        },
                        "proof_backup": proof["proof_backup"],
                        "before": before,
                        "after": proof["audit"],
                        "checkpoint": proof["checkpoint"],
                        "quick_check": proof["quick_check"],
                        "integrity_check": proof["integrity_check"],
                        "foreign_key_error_count": proof[
                            "foreign_key_error_count"
                        ],
                        "action_receipt_verified": True,
                        "verification_passed": True,
                    }
                if before["status"] != "repairable":
                    raise RuntimeError(
                        "secret content state is not narrowly repairable"
                    )
                safety_backup = self._verified_safety_backup(
                    conn,
                    label="pre-secret-content-repair",
                )
                if int(conn.execute("PRAGMA data_version").fetchone()[0]) != (
                    before_data_version
                ):
                    raise RuntimeError(
                        "memory store changed during the safety backup; rerun the audit"
                    )

                conn.execute("BEGIN EXCLUSIVE")
                try:
                    lease.assert_core_for(self.db_path)
                    current = self._secret_content_repair_audit(conn)
                    if (
                        current["audit_revision"] != expected
                        or current["status"] != "repairable"
                    ):
                        raise RuntimeError(
                            "secret content repair plan changed before mutation"
                        )
                    changed_index_row_count = self._scrub_legacy_secret_content(conn)
                    after_mutation = self._secret_content_repair_audit(conn)
                    if after_mutation["status"] != "ready":
                        raise RuntimeError(
                            "secret content repair verification failed; transaction "
                            "rolled back "
                            f"(status={after_mutation['status']}, "
                            "content_findings="
                            f"{after_mutation['content_finding_count']}, "
                            "content_columns="
                            f"{after_mutation['content_findings_by_column']}, "
                            "identifier_findings="
                            f"{after_mutation['identifier_finding_count']})"
                        )
                    operation_id = "s2maint_" + uuid.uuid4().hex
                    created_at = time.time()
                    receipt_payload = {
                        "protocol_version": (
                            "secret-content-preclaim-repair.v1"
                        ),
                        "content_free": True,
                        "verification_status": "pending",
                        "reviewed_finding_count": int(
                            current["content_finding_count"]
                        ),
                        "reviewed_redaction_changing_cell_count": int(
                            current["redaction_changing_cell_count"]
                        ),
                        "reviewed_raw_digest_changing_cell_count": int(
                            current["raw_digest_changing_cell_count"]
                        ),
                        "changed_index_row_count": int(
                            changed_index_row_count
                        ),
                        "repaired_state_revision": str(
                            after_mutation["settled_audit_revision"]
                        ),
                        "safety_backup_path": str(
                            safety_backup["backup_path"]
                        ),
                        "safety_backup_sha256": str(safety_backup["sha256"]),
                        "safety_backup_size_bytes": int(
                            safety_backup["size_bytes"]
                        ),
                    }
                    conn.execute(
                        """
                        INSERT INTO store_maintenance_receipts (
                            operation_id, operation_type, context_id,
                            before_revision, after_revision, payload_json,
                            created_at
                        ) VALUES (?, 'secret-content-preclaim-repair', NULL,
                                  ?, ?, ?, ?)
                        """,
                        (
                            operation_id,
                            expected,
                            str(after_mutation["settled_audit_revision"]),
                            _json_dumps(receipt_payload),
                            created_at,
                        ),
                    )
                    lease.assert_core_for(self.db_path)
                    conn.commit()
                    repair_committed = True
                except BaseException:
                    if conn.in_transaction:
                        conn.rollback()
                    raise

                inventory = self._secret_content_preclaim_receipt_inventory(
                    conn
                )
                pending_matches = [
                    receipt
                    for receipt in inventory["pending"]
                    if receipt["operation_id"] == operation_id
                ]
                if inventory["invalid_count"] or len(pending_matches) != 1:
                    raise RuntimeError(
                        "secret content pending receipt did not persist"
                    )
                proof = self._verify_pending_secret_content_preclaim_repair(
                    conn,
                    lease=lease,
                    receipt=pending_matches[0],
                )
                verified = proof["audit"]
            return {
                "action": "secret-content-preclaim-repair",
                "status": "repaired",
                "operation_id": operation_id,
                "repair_confirmed": True,
                "expected_revision": expected,
                "reviewed_finding_count": int(before["content_finding_count"]),
                "changed_index_row_count": int(changed_index_row_count),
                "safety_backup": {
                    **safety_backup,
                    **proof["safety_backup_verification"],
                },
                "proof_backup": proof["proof_backup"],
                "before": before,
                "after": verified,
                "checkpoint": proof["checkpoint"],
                "quick_check": proof["quick_check"],
                "integrity_check": proof["integrity_check"],
                "foreign_key_error_count": proof["foreign_key_error_count"],
                "action_receipt_verified": True,
                "verification_passed": True,
            }
        except Exception:
            if safety_backup is not None and not repair_committed:
                try:
                    self._discard_safety_backup(safety_backup)
                except Exception:
                    LOGGER.exception(
                        "failed to discard unused secret content repair backup"
                    )
            LOGGER.exception("failed to repair secret content preclaim state")
            raise

    def _inspect_backup_snapshot(self, path: Path) -> dict[str, Any]:
        uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            inspection_seconds = float(
                os.getenv("SYNAPSE_S2_BACKUP_INSPECTION_TIMEOUT_SECONDS", "120")
            )
            inspection_steps = int(
                os.getenv("SYNAPSE_S2_BACKUP_INSPECTION_MAX_VM_STEPS", "500000000")
            )
            if (
                not math.isfinite(inspection_seconds)
                or inspection_seconds <= 0
                or inspection_steps <= 0
            ):
                raise ValueError("backup inspection limits must be positive and finite")
            deadline = time.monotonic() + inspection_seconds
            progress_calls = 0
            steps_per_callback = 10_000

            def inspection_progress() -> int:
                nonlocal progress_calls
                progress_calls += 1
                return int(
                    time.monotonic() >= deadline
                    or progress_calls * steps_per_callback > inspection_steps
                )

            conn.set_progress_handler(inspection_progress, steps_per_callback)
            if hasattr(conn, "setlimit") and hasattr(sqlite3, "SQLITE_LIMIT_LENGTH"):
                conn.setlimit(
                    sqlite3.SQLITE_LIMIT_LENGTH,
                    int(
                        os.getenv(
                            "SYNAPSE_S2_BACKUP_SQLITE_MAX_VALUE_BYTES",
                            str(64 * 1024**2),
                        )
                    ),
                )
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA trusted_schema = OFF")
            quick_check = [str(row[0]) for row in conn.execute("PRAGMA quick_check")]
            integrity_check = [str(row[0]) for row in conn.execute("PRAGMA integrity_check")]
            foreign_key_error_count = sum(1 for _ in conn.execute("PRAGMA foreign_key_check"))
            schema = self._sqlite_schema_fingerprint(conn)
            migrations = sorted(
                str(row[0])
                for row in conn.execute(
                    "SELECT key FROM store_migrations ORDER BY key"
                ).fetchall()
            )
            schema_contract = {
                "schema_sha256": str(schema["sha256"]),
                "table_count": int(schema["table_count"]),
                "index_count": int(schema["index_count"]),
                "migration_set_sha256": hashlib.sha256(
                    _json_dumps(migrations).encode("utf-8")
                ).hexdigest(),
                "migration_count": len(migrations),
                "application_id": int(conn.execute("PRAGMA application_id").fetchone()[0]),
                "user_version": int(conn.execute("PRAGMA user_version").fetchone()[0]),
            }
            logical_snapshot = self._canonical_logical_snapshot_digest(
                conn,
                install_progress_handler=False,
            )
            authority_marker = self._core_authority_marker(conn)
            self._validate_core_authority_version_pair(conn, authority_marker)
            if authority_marker is None:
                if int(schema_contract["user_version"]) != 5:
                    raise CoreAuthorityError(
                        "journal-less recovery is supported only for a pre-governed v5 store"
                    )
                authority_binding = {
                    "governance_mode": "pre-governed-v5",
                    "store_generation": "legacy-v5",
                    "authority_epoch_number": None,
                    "store_identity": self.store_identity_for_path(self.db_path),
                    "request_journal_id": None,
                    "schema_identity": (
                        f"sqlite-{int(schema_contract['application_id']):x}-"
                        f"v{int(schema_contract['user_version'])}"
                    ),
                }
            else:
                if int(schema_contract["user_version"]) != SQLITE_USER_VERSION:
                    raise CoreAuthorityError(
                        "governed recovery requires the current authoritative schema"
                    )
                authority_binding = {
                    "governance_mode": "authoritative-v6",
                    "store_generation": f"epoch-{int(authority_marker['epoch'])}",
                    "authority_epoch_number": int(authority_marker["epoch"]),
                    "store_identity": str(authority_marker["store_identity"]),
                    "request_journal_id": str(
                        authority_marker["request_journal_id"]
                    ),
                    "schema_identity": (
                        f"sqlite-{int(schema_contract['application_id']):x}-"
                        f"v{int(schema_contract['user_version'])}"
                    ),
                }
            canonical_contract = self._canonical_backup_contract()
            matching_contract_versions = _matching_backup_schema_contract_versions(
                schema_contract
            )
            schema_contract_error_count = 0 if matching_contract_versions else sum(
                1
                for key, expected_value in canonical_contract.items()
                if schema_contract.get(key) != expected_value
            )
            tables = {
                str(row[0])
                for row in conn.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'"
                ).fetchall()
            }
            counts = {
                table_name: int(conn.execute(f'SELECT COUNT(*) FROM "{table_name}"').fetchone()[0])
                for table_name in sorted(BACKUP_CRITICAL_TABLES & tables)
            }
            json_error_count = 0
            json_scanned_bytes = 0
            json_scan_byte_limit = int(
                os.getenv("SYNAPSE_S2_BACKUP_JSON_SCAN_MAX_BYTES", str(2 * 1024**3))
            )
            json_value_byte_limit = int(
                os.getenv("SYNAPSE_S2_BACKUP_SCAN_MAX_VALUE_BYTES", str(16 * 1024**2))
            )
            if json_scan_byte_limit <= 0 or json_value_byte_limit <= 0:
                raise ValueError("backup JSON scan byte limits must be positive")
            for table_name in sorted(tables):
                if table_name.startswith("sqlite_"):
                    continue
                for row in conn.execute(f'PRAGMA table_xinfo("{table_name}")').fetchall():
                    column_name = str(row[1])
                    if not (column_name.endswith("_json") or (table_name, column_name) == ("store_metadata", "value_json")):
                        continue
                    for value_row in conn.execute(
                        f'SELECT "{column_name}" FROM "{table_name}" WHERE "{column_name}" IS NOT NULL'
                    ):
                        raw_json = str(value_row[0])
                        raw_json_bytes = len(raw_json.encode("utf-8"))
                        json_scanned_bytes += raw_json_bytes
                        if (
                            raw_json_bytes > json_value_byte_limit
                            or json_scanned_bytes > json_scan_byte_limit
                        ):
                            raise RuntimeError(
                                "backup JSON audit exceeded its bounded byte limit"
                            )
                        try:
                            json.loads(raw_json)
                        except (TypeError, ValueError, json.JSONDecodeError):
                            json_error_count += 1
            semantic = self._semantic_index_audit(
                conn,
                context_id=None,
                sample_limit=1,
                include_integrity_checks=False,
            )
            capture_error_count, _ = self._capture_operation_integrity_audit(
                conn, sample_limit=1
            )
            delivery_schema_errors = self._context_delivery_v2_table_errors(conn) + (
                self._context_delivery_v2_index_errors(conn)
            )
            delivery_data_errors = self._context_delivery_data_errors(conn)
            target_error_count, _, _, _ = self._context_event_target_integrity_audit(
                conn, sample_limit=1
            )
            event_error_count, _ = self._context_event_ledger_integrity_audit(
                conn, sample_limit=1
            )
            highwater_error_count, _ = self._context_event_target_highwater_audit(conn)
            secret_audit = self._backup_secret_audit(conn)
            highwaters = {
                "memory_event_id": int(
                    conn.execute("SELECT COALESCE(MAX(event_id), 0) FROM memory_events").fetchone()[0]
                ),
                "context_event_id": int(
                    conn.execute(
                        "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events"
                    ).fetchone()[0]
                ),
                "capture_committed_at_micros": int(
                    float(
                        conn.execute(
                            "SELECT COALESCE(MAX(committed_at), 0) FROM capture_operations"
                        ).fetchone()[0]
                    )
                    * 1_000_000
                ),
            }
        blocking_error_count = sum(
            (
                0 if quick_check == ["ok"] else 1,
                0 if integrity_check == ["ok"] else 1,
                foreign_key_error_count,
                int(schema["missing_critical_table_count"]),
                schema_contract_error_count,
                json_error_count,
                0 if semantic.get("status") == "ready" else 1,
                capture_error_count,
                len(delivery_schema_errors),
                len(delivery_data_errors),
                target_error_count,
                event_error_count,
                highwater_error_count,
                int(secret_audit["redaction_changing_cell_count"]),
                int(secret_audit["raw_digest_changing_cell_count"]),
                int(secret_audit["unclassified_text_column_count"]),
            )
        )
        revision_seed = {
            "schema_sha256": schema["sha256"],
            "critical_counts": counts,
            "highwaters": highwaters,
            "semantic_source_revision": str(semantic.get("source_revision") or ""),
        }
        return {
            "quick_check": quick_check,
            "integrity_check": integrity_check,
            "foreign_key_error_count": foreign_key_error_count,
            "schema": schema,
            "schema_contract": schema_contract,
            "schema_contract_version": (
                matching_contract_versions[-1] if matching_contract_versions else ""
            ),
            "schema_contract_error_count": schema_contract_error_count,
            "authority_binding": authority_binding,
            "logical_snapshot": logical_snapshot,
            "critical_counts": counts,
            "highwaters": highwaters,
            "snapshot_revision": hashlib.sha256(
                _json_dumps(revision_seed).encode("utf-8")
            ).hexdigest(),
            "semantic_index_status": str(semantic.get("status") or "blocked"),
            "semantic_index_revision": str(semantic.get("audit_revision") or ""),
            "semantic_index_mismatch_count": int(
                semantic.get("mismatched_memory_count") or 0
            ),
            "capture_integrity_error_count": capture_error_count,
            "delivery_integrity_error_count": len(delivery_schema_errors)
            + len(delivery_data_errors)
            + target_error_count
            + event_error_count
            + highwater_error_count,
            "canonical_json_error_count": json_error_count,
            "canonical_json_scanned_bytes": json_scanned_bytes,
            "secret_audit": secret_audit,
            "blocking_error_count": int(blocking_error_count),
            "restore_eligible": blocking_error_count == 0,
        }

    def verify_backup(
        self,
        path: str | os.PathLike[str],
        *,
        expected_sha256: str | None = None,
        receipt_path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        reject_sensitive_identifier(path, field="backup_path")
        artifact = Path(path).expanduser().absolute()
        if artifact == self.db_path.expanduser().absolute():
            raise ValueError("backup verification requires a non-live artifact")
        if artifact.is_symlink() or not artifact.is_file():
            raise ValueError("backup_path must be a non-symlink regular file")
        live_metadata = os.lstat(self.db_path)
        artifact_metadata = os.lstat(artifact)
        if (int(live_metadata.st_dev), int(live_metadata.st_ino)) == (
            int(artifact_metadata.st_dev),
            int(artifact_metadata.st_ino),
        ):
            raise ValueError("backup artifact must not alias the live memory database")
        expected = str(expected_sha256 or "").strip().lower()
        expected_was_supplied = bool(expected)
        if expected and not BACKUP_DIGEST_RE.fullmatch(expected):
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
        receipt_file = (
            Path(receipt_path).expanduser().absolute()
            if receipt_path is not None
            else self._backup_receipt_path(artifact)
        )
        receipt: dict[str, Any] | None = None
        receipt_identity_trusted = False
        if receipt_file.exists() or receipt_file.is_symlink():
            if receipt_file.is_symlink():
                raise ValueError("backup receipt must not be a symlink")
            receipt, receipt_identity_trusted = self._read_trusted_backup_receipt(
                receipt_file,
                artifact=artifact,
            )
            receipt_expected = str(receipt["artifact_sha256"])
            if expected and not secrets.compare_digest(expected, receipt_expected):
                raise ValueError("expected SHA-256 does not match the backup receipt")
            expected = receipt_expected
        elif not expected:
            raise ValueError("verification requires a trusted receipt or expected SHA-256")
        if receipt is not None and not receipt_identity_trusted and not expected_was_supplied:
            raise ValueError(
                "backup signer is not trusted locally; provide a reviewed expected SHA-256"
            )
        staging_dir = self._backup_verification_staging_dir()
        temporary = self._unique_private_temp_path(
            staging_dir, prefix=f".{artifact.name}.verify."
        )
        try:
            copied = self._copy_stable_regular_file(artifact, temporary)
            if not secrets.compare_digest(str(copied["sha256"]), expected):
                raise RuntimeError("backup artifact digest verification failed")
            if receipt is not None and int(receipt.get("artifact_size_bytes") or -1) != int(
                copied["size_bytes"]
            ):
                raise RuntimeError("backup artifact size does not match its receipt")
            inspection = self._inspect_backup_snapshot(temporary)
            if not inspection["restore_eligible"]:
                raise RuntimeError("backup artifact failed SYNAPSE recovery invariants")
            if receipt is not None:
                if (
                    receipt.get("schema") == LEGACY_BACKUP_RECEIPT_SCHEMA
                    and inspection["authority_binding"]["governance_mode"]
                    != "pre-governed-v5"
                ):
                    raise RuntimeError(
                        "legacy backup receipts are valid only for pre-governed v5 stores"
                    )
                if str(receipt.get("schema_sha256") or "") != str(
                    inspection["schema"]["sha256"]
                ):
                    raise RuntimeError("backup schema fingerprint does not match its receipt")
                if str(receipt.get("snapshot_revision") or "") != str(
                    inspection["snapshot_revision"]
                ):
                    raise RuntimeError("backup snapshot revision does not match its receipt")
                if receipt.get("critical_counts") != inspection["critical_counts"]:
                    raise RuntimeError("backup critical counts do not match its receipt")
                if receipt.get("highwaters") != inspection["highwaters"]:
                    raise RuntimeError("backup highwaters do not match its receipt")
                if str(receipt.get("semantic_index_revision") or "") != str(
                    inspection["semantic_index_revision"]
                ):
                    raise RuntimeError("backup semantic revision does not match its receipt")
                if str(receipt.get("schema_contract_version") or "") != str(
                    inspection["schema_contract_version"]
                ):
                    raise RuntimeError("backup schema contract version does not match its receipt")
                if receipt.get("schema") == BACKUP_RECEIPT_SCHEMA:
                    logical_snapshot = inspection["logical_snapshot"]
                    logical_mismatches = (
                        receipt.get("logical_snapshot_schema")
                        != logical_snapshot["schema"],
                        not secrets.compare_digest(
                            str(receipt.get("logical_snapshot_sha256") or ""),
                            str(logical_snapshot["sha256"]),
                        ),
                        int(receipt["logical_snapshot_table_count"])
                        != int(logical_snapshot["table_count"]),
                        int(receipt["logical_snapshot_column_count"])
                        != int(logical_snapshot["column_count"]),
                        int(receipt["logical_snapshot_row_count"])
                        != int(logical_snapshot["row_count"]),
                        int(receipt["logical_snapshot_value_bytes"])
                        != int(logical_snapshot["value_bytes"]),
                    )
                    if any(logical_mismatches):
                        raise RuntimeError(
                            "backup logical snapshot digest does not match its receipt"
                        )
            return {
                "action": "verify-backup",
                "backup_path": str(artifact),
                "receipt_path": str(receipt_file) if receipt is not None else None,
                "receipt_verified": receipt is not None,
                "receipt_identity_trusted": receipt_identity_trusted,
                "expected_sha256_verified": expected_was_supplied,
                "sha256": str(copied["sha256"]),
                "size_bytes": int(copied["size_bytes"]),
                "snapshot_revision": str(inspection["snapshot_revision"]),
                "logical_snapshot_schema": str(
                    inspection["logical_snapshot"]["schema"]
                ),
                "logical_snapshot_sha256": str(
                    inspection["logical_snapshot"]["sha256"]
                ),
                "logical_snapshot_table_count": int(
                    inspection["logical_snapshot"]["table_count"]
                ),
                "logical_snapshot_column_count": int(
                    inspection["logical_snapshot"]["column_count"]
                ),
                "logical_snapshot_row_count": int(
                    inspection["logical_snapshot"]["row_count"]
                ),
                "logical_snapshot_value_bytes": int(
                    inspection["logical_snapshot"]["value_bytes"]
                ),
                "schema_sha256": str(inspection["schema"]["sha256"]),
                "schema_contract_version": str(
                    inspection["schema_contract_version"]
                ),
                "governance_mode": str(
                    inspection["authority_binding"]["governance_mode"]
                ),
                "store_generation": str(
                    inspection["authority_binding"]["store_generation"]
                ),
                "authority_epoch_number": inspection["authority_binding"][
                    "authority_epoch_number"
                ],
                "store_identity": inspection["authority_binding"]["store_identity"],
                "request_journal_id": inspection["authority_binding"][
                    "request_journal_id"
                ],
                "schema_identity": str(
                    inspection["authority_binding"]["schema_identity"]
                ),
                "recovery_runtime_id": BACKUP_RECOVERY_RUNTIME_ID,
                "entry_count": int(inspection["critical_counts"].get("memory_entries", 0)),
                "event_count": int(inspection["critical_counts"].get("memory_events", 0)),
                "quick_check": inspection["quick_check"],
                "integrity_check": inspection["integrity_check"],
                "foreign_key_error_count": int(inspection["foreign_key_error_count"]),
                "semantic_index_status": str(inspection["semantic_index_status"]),
                "capture_integrity_error_count": int(
                    inspection["capture_integrity_error_count"]
                ),
                "delivery_integrity_error_count": int(
                    inspection["delivery_integrity_error_count"]
                ),
                "secret_audit": inspection["secret_audit"],
                "restore_eligible": True,
                "verified": True,
                "verified_at": time.time(),
            }
        finally:
            temporary.unlink(missing_ok=True)
            self._fsync_directory(staging_dir)

    def backup(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        purpose: str = "operator",
        pinned: bool = False,
        _paired_recovery: bool = False,
    ) -> dict[str, Any]:
        safe_purpose = re.sub(r"[^a-z0-9_.-]+", "-", str(purpose).lower()).strip("-")
        if not safe_purpose or len(safe_purpose) > 64:
            raise ValueError("backup purpose must contain 1 to 64 safe characters")
        if path is None:
            # Database-only snapshots are intentionally segregated from paired
            # recovery bundles.  Retention and cutover must never mistake an
            # unpaired SQLite file for a complete exactly-once recovery point.
            backup_dir = self.db_path.parent / "backups" / "database-only"
            self._ensure_directory(backup_dir, owned=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            nonce = uuid.uuid4().hex[:12]
            output_path = backup_dir / (
                f"{self.db_path.stem}-{safe_purpose}-{stamp}-{nonce}.sqlite3"
            )
        else:
            reject_sensitive_identifier(path, field="backup_path")
            output_path = Path(path).expanduser().absolute()
        store_root = self.db_path.parent.expanduser().resolve()
        backups_root = store_root / "backups"
        resolved_output_parent = output_path.parent.resolve()
        try:
            backups_relative = resolved_output_parent.relative_to(backups_root)
        except ValueError:
            backups_relative = None
        lane = (
            backups_relative.parts[0]
            if backups_relative is not None and backups_relative.parts
            else ""
        )
        if _paired_recovery:
            if lane == "database-only":
                raise ValueError(
                    "paired recovery bundles must not use the database-only lane"
                )
        elif backups_relative is not None and lane != "database-only":
            raise ValueError(
                "SQLite-only diagnostics must use backups/database-only, not the paired verified recovery lane"
            )
        self._ensure_directory(output_path.parent, owned=False)
        receipt_path = self._backup_receipt_path(output_path)
        if (
            output_path.exists()
            or output_path.is_symlink()
            or receipt_path.exists()
            or receipt_path.is_symlink()
        ):
            raise FileExistsError("backup artifact or receipt already exists; refusing overwrite")
        if output_path == self.db_path.expanduser().absolute():
            raise ValueError("backup_path must not be the live memory database")
        temp_path = self._unique_private_temp_path(
            output_path.parent, prefix=f".{output_path.name}."
        )
        published = False
        receipt_published = False
        try:
            with closing(self._connect()) as source:
                page_count = int(source.execute("PRAGMA page_count").fetchone()[0])
                page_size = int(source.execute("PRAGMA page_size").fetchone()[0])
                estimated_bytes = max(int(self.db_path.stat().st_size), page_count * page_size)
                reserve_bytes = int(
                    os.getenv("SYNAPSE_S2_BACKUP_MIN_FREE_BYTES", str(512 * 1024 * 1024))
                )
                if reserve_bytes < 0:
                    raise ValueError("SYNAPSE_S2_BACKUP_MIN_FREE_BYTES must be non-negative")
                free_bytes = int(shutil.disk_usage(output_path.parent).free)
                if free_bytes < (estimated_bytes * 2) + reserve_bytes:
                    raise OSError("insufficient free space for verified backup")
                with closing(sqlite3.connect(temp_path)) as destination:
                    source.backup(destination)
                    destination.commit()
            self._fsync_file(temp_path)
            inspection = self._inspect_backup_snapshot(temp_path)
            if not inspection["restore_eligible"]:
                raise RuntimeError("backup failed SYNAPSE recovery invariants")
            temp_digest, temp_size, _ = self._hash_stable_regular_file(temp_path)
            os.link(temp_path, output_path, follow_symlinks=False)
            published = True
            temp_metadata = os.lstat(temp_path)
            final_metadata = os.lstat(output_path)
            if self._regular_file_identity(temp_metadata) != self._regular_file_identity(
                final_metadata
            ):
                raise RuntimeError("published backup identity does not match verified snapshot")
            os.chmod(output_path, 0o600, follow_symlinks=False)
            self._fsync_file(output_path)
            temp_metadata = os.lstat(temp_path)
            final_digest, final_size, final_opened = self._hash_stable_regular_file(output_path)
            if (
                self._regular_file_identity(final_opened)
                != self._regular_file_identity(temp_metadata)
                or not secrets.compare_digest(temp_digest, final_digest)
                or temp_size != final_size
            ):
                raise RuntimeError("published backup changed after verification")
            created_at = time.time()
            receipt = {
                "schema": BACKUP_RECEIPT_SCHEMA,
                "artifact_name": output_path.name,
                "artifact_sha256": final_digest,
                "artifact_size_bytes": final_size,
                "schema_sha256": str(inspection["schema"]["sha256"]),
                "schema_contract_version": str(
                    inspection["schema_contract_version"]
                ),
                "recovery_runtime_id": BACKUP_RECOVERY_RUNTIME_ID,
                "snapshot_revision": str(inspection["snapshot_revision"]),
                "logical_snapshot_schema": str(
                    inspection["logical_snapshot"]["schema"]
                ),
                "logical_snapshot_sha256": str(
                    inspection["logical_snapshot"]["sha256"]
                ),
                "logical_snapshot_table_count": int(
                    inspection["logical_snapshot"]["table_count"]
                ),
                "logical_snapshot_column_count": int(
                    inspection["logical_snapshot"]["column_count"]
                ),
                "logical_snapshot_row_count": int(
                    inspection["logical_snapshot"]["row_count"]
                ),
                "logical_snapshot_value_bytes": int(
                    inspection["logical_snapshot"]["value_bytes"]
                ),
                "critical_counts": inspection["critical_counts"],
                "highwaters": inspection["highwaters"],
                "semantic_index_revision": str(inspection["semantic_index_revision"]),
                "purpose": safe_purpose,
                "pinned": bool(pinned),
                "restore_eligible": True,
                "created_at": created_at,
                "source_store_name": self.db_path.name,
            }
            self._authenticate_receipt(receipt)
            self._write_private_json_exclusive(receipt_path, receipt)
            receipt_published = True
            temp_path.unlink()
            self._fsync_directory(output_path.parent)
            verified = self.verify_backup(output_path, receipt_path=receipt_path)
            return {
                **verified,
                "action": "backup-memory",
                "memory_db_path": str(self.db_path),
                "backup_path": str(output_path),
                "receipt_path": str(receipt_path),
                "receipt_schema": BACKUP_RECEIPT_SCHEMA,
                "receipt_digest": str(receipt["receipt_digest"]),
                "purpose": safe_purpose,
                "pinned": bool(pinned),
                "created_at": created_at,
            }
        except BaseException:
            temp_path.unlink(missing_ok=True)
            if receipt_published:
                receipt_path.unlink(missing_ok=True)
            if published:
                output_path.unlink(missing_ok=True)
            try:
                self._fsync_directory(output_path.parent)
            except OSError:
                LOGGER.exception("failed to fsync backup directory after cleanup")
            LOGGER.exception("failed to create verified memory backup")
            raise

    def restore_backup(
        self,
        path: str | os.PathLike[str],
        output_path: str | os.PathLike[str],
        *,
        expected_sha256: str | None = None,
        receipt_path: str | os.PathLike[str] | None = None,
        confirm: bool = False,
        _paired_request_journal_binding: dict[str, Any] | None = None,
        _paired_request_journal_expected_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Materialize a verified backup as an isolated, no-overwrite database.

        Live cutover is intentionally not hidden inside this primitive.  A live
        restore must coordinate the capture transport and runtime drain through
        the governed recovery-bundle workflow; copying over the database alone
        would violate exactly-once capture.
        """

        if not confirm:
            raise ValueError("confirm=true is required to materialize a restore")
        reject_sensitive_identifier(path, field="backup_path")
        reject_sensitive_identifier(output_path, field="restore_path")
        source = Path(path).expanduser().absolute()
        target = Path(output_path).expanduser().absolute()
        live_path = self.db_path.expanduser().absolute()
        if target == live_path:
            raise ValueError(
                "live database restore requires the governed paired recovery workflow"
            )
        if source == target:
            raise ValueError("restore_path must differ from backup_path")
        self._ensure_directory(target.parent, owned=False)
        restore_receipt_path = self._restore_receipt_path(target)
        if (
            target.exists()
            or target.is_symlink()
            or restore_receipt_path.exists()
            or restore_receipt_path.is_symlink()
        ):
            raise FileExistsError("restore artifact or receipt already exists; refusing overwrite")
        verification = self.verify_backup(
            source,
            expected_sha256=expected_sha256,
            receipt_path=receipt_path,
        )
        if not verification.get("receipt_verified"):
            raise ValueError("restore requires a trusted immutable backup receipt")
        if verification.get("governance_mode") == "authoritative-v6":
            binding = _paired_request_journal_binding
            reviewed_journal_sha256 = str(
                _paired_request_journal_expected_sha256 or ""
            ).strip().lower()
            if reviewed_journal_sha256 and not BACKUP_DIGEST_RE.fullmatch(
                reviewed_journal_sha256
            ):
                raise ValueError(
                    "reviewed request-journal digest must be a lowercase SHA-256"
                )
            if (
                not isinstance(binding, dict)
                or binding.get("schema")
                != RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA
                or binding.get("journal_schema_identity")
                != "sqlite-5332524a-v3"
                or CORE_REQUEST_JOURNAL_ID_RE.fullmatch(
                    str(binding.get("request_journal_id") or "")
                )
                is None
            ):
                raise ValueError(
                    "governed v6 restore requires verified paired request-journal evidence"
                )
            digest_fields = (
                "database_sha256",
                "database_snapshot_revision",
                "database_logical_snapshot_sha256",
                "journal_sha256",
                "receipt_digest",
            )
            if any(
                not BACKUP_DIGEST_RE.fullmatch(str(binding.get(field) or ""))
                for field in digest_fields
            ):
                raise ValueError("paired request-journal evidence is invalid")
            if (
                not secrets.compare_digest(
                    str(binding["receipt_digest"]),
                    self._canonical_payload_digest(binding),
                )
            ):
                raise ValueError("paired request-journal evidence digest is invalid")
            binding_identity_trusted = self._verify_receipt_authenticator(binding)
            binding_journal_sha256 = str(binding["journal_sha256"])
            if reviewed_journal_sha256 and not secrets.compare_digest(
                reviewed_journal_sha256,
                binding_journal_sha256,
            ):
                raise ValueError(
                    "reviewed request-journal digest does not match paired evidence"
                )
            if not binding_identity_trusted and not reviewed_journal_sha256:
                raise ValueError(
                    "foreign paired request-journal evidence requires a reviewed SHA-256"
                )
            if (
                not secrets.compare_digest(
                    str(binding["database_sha256"]), str(verification["sha256"])
                )
                or not secrets.compare_digest(
                    str(binding["database_snapshot_revision"]),
                    str(verification["snapshot_revision"]),
                )
                or not secrets.compare_digest(
                    str(binding["database_logical_snapshot_sha256"]),
                    str(verification["logical_snapshot_sha256"]),
                )
                or str(binding["store_generation"])
                != str(verification["store_generation"])
                or str(binding["request_journal_id"])
                != str(verification["request_journal_id"])
            ):
                raise ValueError(
                    "paired request-journal evidence does not match the governed store"
                )
        temporary = self._unique_private_temp_path(
            target.parent, prefix=f".{target.name}.restore."
        )
        published = False
        receipt_published = False
        try:
            copied = self._copy_stable_regular_file(source, temporary)
            if not secrets.compare_digest(
                str(copied["sha256"]), str(verification["sha256"])
            ):
                raise RuntimeError("restore candidate digest changed after verification")
            inspection = self._inspect_backup_snapshot(temporary)
            if (
                not inspection["restore_eligible"]
                or str(inspection["snapshot_revision"])
                != str(verification["snapshot_revision"])
                or not secrets.compare_digest(
                    str(inspection["logical_snapshot"]["sha256"]),
                    str(verification["logical_snapshot_sha256"]),
                )
            ):
                raise RuntimeError("restore candidate failed post-copy verification")
            os.link(temporary, target, follow_symlinks=False)
            published = True
            temporary_metadata = os.lstat(temporary)
            target_metadata = os.lstat(target)
            if self._regular_file_identity(temporary_metadata) != self._regular_file_identity(
                target_metadata
            ):
                raise RuntimeError("restore publication identity mismatch")
            os.chmod(target, 0o600, follow_symlinks=False)
            self._fsync_file(target)
            temporary_metadata = os.lstat(temporary)
            final_digest, final_size, final_metadata = self._hash_stable_regular_file(target)
            if (
                self._regular_file_identity(final_metadata)
                != self._regular_file_identity(temporary_metadata)
                or not secrets.compare_digest(final_digest, str(verification["sha256"]))
            ):
                raise RuntimeError("published restore does not match the verified backup")
            created_at = time.time()
            backup_receipt_file = Path(str(verification["receipt_path"]))
            trusted_backup_receipt, _identity_trusted = self._read_trusted_backup_receipt(
                backup_receipt_file,
                artifact=source,
            )
            restore_receipt = {
                "schema": BACKUP_RESTORE_RECEIPT_SCHEMA,
                "artifact_name": target.name,
                "artifact_sha256": final_digest,
                "artifact_size_bytes": final_size,
                "source_backup_name": source.name,
                "source_backup_receipt_digest": str(
                    trusted_backup_receipt["receipt_digest"]
                ),
                "snapshot_revision": str(inspection["snapshot_revision"]),
                "logical_snapshot_schema": str(
                    inspection["logical_snapshot"]["schema"]
                ),
                "logical_snapshot_sha256": str(
                    inspection["logical_snapshot"]["sha256"]
                ),
                "logical_snapshot_table_count": int(
                    inspection["logical_snapshot"]["table_count"]
                ),
                "logical_snapshot_column_count": int(
                    inspection["logical_snapshot"]["column_count"]
                ),
                "logical_snapshot_row_count": int(
                    inspection["logical_snapshot"]["row_count"]
                ),
                "logical_snapshot_value_bytes": int(
                    inspection["logical_snapshot"]["value_bytes"]
                ),
                "mode": "isolated-candidate",
                "verified": True,
                "created_at": created_at,
            }
            self._authenticate_receipt(restore_receipt)
            self._write_private_json_exclusive(
                restore_receipt_path,
                restore_receipt,
            )
            receipt_published = True
            temporary.unlink()
            self._fsync_directory(target.parent)
            return {
                "action": "restore-backup",
                "mode": "isolated-candidate",
                "backup_path": str(source),
                "restore_path": str(target),
                "restore_receipt_path": str(restore_receipt_path),
                "restore_receipt_schema": BACKUP_RESTORE_RECEIPT_SCHEMA,
                "sha256": final_digest,
                "size_bytes": final_size,
                "snapshot_revision": str(inspection["snapshot_revision"]),
                "logical_snapshot_schema": str(
                    inspection["logical_snapshot"]["schema"]
                ),
                "logical_snapshot_sha256": str(
                    inspection["logical_snapshot"]["sha256"]
                ),
                "quick_check": inspection["quick_check"],
                "integrity_check": inspection["integrity_check"],
                "verified": True,
                "created_at": created_at,
            }
        except BaseException:
            temporary.unlink(missing_ok=True)
            if receipt_published:
                restore_receipt_path.unlink(missing_ok=True)
            if published:
                target.unlink(missing_ok=True)
            try:
                self._fsync_directory(target.parent)
            except OSError:
                LOGGER.exception("failed to fsync restore directory after cleanup")
            LOGGER.exception("failed to materialize verified backup restore")
            raise

    def _row_to_entry(self, row: sqlite3.Row) -> dict[str, Any]:
        safe_metadata = _json_safe(
            _decode_json(str(row["metadata_json"]), {}),
            {},
        )
        return {
            "memory_id": redact_capture_text(str(row["memory_id"]))[0],
            "tag": redact_capture_text(str(row["tag"]))[0],
            "context_id": redact_capture_text(str(row["context_id"]))[0],
            "source_text": redact_capture_text(str(row["source_text"]))[0],
            "metadata": safe_metadata if isinstance(safe_metadata, dict) else {},
            "embedding_dimensions": int(row["embedding_dimensions"]),
            "spike_indices": [
                int(value)
                for value in _decode_json(str(row["spike_indices_json"]), [])
            ],
            "neuron_indices": [
                int(value)
                for value in _decode_json(str(row["neuron_indices_json"]), [])
            ],
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    def _row_to_relationship(self, row: sqlite3.Row) -> dict[str, Any]:
        safe_evidence = _json_safe(
            _decode_json(str(row["evidence_json"]), {}),
            {},
        )
        return {
            "relationship_id": redact_capture_text(str(row["relationship_id"]))[0],
            "context_id": redact_capture_text(str(row["context_id"]))[0],
            "source_memory_id": redact_capture_text(str(row["source_memory_id"]))[0],
            "target_memory_id": redact_capture_text(str(row["target_memory_id"]))[0],
            "source_tag": redact_capture_text(str(row["source_tag"]))[0],
            "target_tag": redact_capture_text(str(row["target_tag"]))[0],
            "relation_type": redact_capture_text(str(row["relation_type"]))[0],
            "weight": round(float(row["weight"]), 6),
            "evidence": safe_evidence if isinstance(safe_evidence, dict) else {},
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    def _row_to_context_link(self, row: sqlite3.Row) -> dict[str, Any]:
        confidence = round(float(row["confidence"]), 6)
        evidence = _json_safe(
            _decode_json(str(row["evidence_json"]), {}),
            {},
        )
        return {
            "context_link_id": redact_capture_text(str(row["context_link_id"]))[0],
            "source_context_id": redact_capture_text(str(row["source_context_id"]))[0],
            "target_context_id": redact_capture_text(str(row["target_context_id"]))[0],
            "relation_type": redact_capture_text(str(row["relation_type"]))[0],
            "direction": redact_capture_text(str(row["direction"]))[0],
            "confidence": confidence,
            "weight": confidence,
            "evidence": evidence if isinstance(evidence, dict) else {},
            "enabled": bool(row["enabled"]),
            "approved": True,
            "approved_by": redact_capture_text(str(row["approved_by"]))[0],
            "approved_at": float(row["approved_at"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "automatic_cross_namespace_write": False,
        }

    def _row_to_context_event(self, row: sqlite3.Row) -> dict[str, Any]:
        safe_payload = _json_safe(
            _decode_json(str(row["payload_json"]), {}),
            {},
        )
        return {
            "event_id": int(row["event_id"]),
            "context_id": redact_capture_text(str(row["context_id"]))[0],
            "source_surface": redact_capture_text(str(row["source_surface"]))[0],
            "event_type": redact_capture_text(str(row["event_type"]))[0],
            "summary": redact_capture_text(str(row["summary"]))[0],
            "payload": safe_payload if isinstance(safe_payload, dict) else {},
            "agent_targets": [
                redact_capture_text(str(value))[0]
                for value in _decode_json(str(row["agent_targets_json"]), [])
            ],
            "created_at": float(row["created_at"]),
        }

    def _context_delivery_payload(
        self,
        delivery_row: sqlite3.Row,
        receipt_row: sqlite3.Row,
        event_row: sqlite3.Row,
        *,
        redelivered: bool,
    ) -> dict[str, Any]:
        return {
            "delivery_id": str(delivery_row["delivery_id"]),
            "receipt_id": str(receipt_row["receipt_id"]),
            # Compatibility alias for clients upgraded from the initial v2
            # prototype. It is an opaque receipt, never a reusable secret.
            "lease_token": str(receipt_row["receipt_id"]),
            "context_id": str(delivery_row["context_id"]),
            "agent_id": str(delivery_row["agent_id"]),
            "consumer_instance_id": str(receipt_row["consumer_instance_id"]),
            "event_id": int(delivery_row["event_id"]),
            "state": str(delivery_row["state"]),
            "attempt_count": int(delivery_row["attempt_count"]),
            "lease_expires_at": float(delivery_row["lease_expires_at"]),
            "redelivered": bool(redelivered),
            "ack_required": str(delivery_row["state"]) == "leased",
            "event": self._row_to_context_event(event_row),
        }

    def _row_to_context_cursor(
        self,
        row: sqlite3.Row,
        *,
        latest_event_id: int,
        latest_eligible_event_id: int | None = None,
        pending_event_count: int,
        acknowledged_delivery_count: int = 0,
        terminal_delivery_count: int = 0,
    ) -> dict[str, Any]:
        keys = set(row.keys())
        last_event_id = int(
            row["last_contiguous_event_id"]
            if "last_contiguous_event_id" in keys
            else row["last_event_id"]
        )
        return {
            "context_id": str(row["context_id"]),
            "agent_id": str(row["agent_id"]),
            "last_event_id": last_event_id,
            "last_contiguous_event_id": last_event_id,
            "latest_event_id": int(latest_event_id),
            "latest_eligible_event_id": int(
                latest_event_id
                if latest_eligible_event_id is None
                else latest_eligible_event_id
            ),
            "pending_event_count": int(pending_event_count),
            "caught_up": int(pending_event_count) == 0,
            "updated_at": float(row["updated_at"]),
            "cursor_basis": (
                "durable-disposition-derived"
                if "last_contiguous_event_id" in keys
                else "legacy-unverified-watermark"
            ),
            "acknowledged_delivery_count": int(acknowledged_delivery_count),
            "has_acknowledged_deliveries": int(acknowledged_delivery_count) > 0,
            "terminal_delivery_count": int(terminal_delivery_count),
        }

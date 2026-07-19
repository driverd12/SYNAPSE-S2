from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import math
import os
import re
import shutil
import sqlite3
import sys
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator


LOGGER = logging.getLogger("synapse_s2.memory_store")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

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

CREATE TABLE IF NOT EXISTS agent_context_cursors (
    context_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    last_event_id INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL,
    PRIMARY KEY (context_id, agent_id)
);

CREATE INDEX IF NOT EXISTS ix_agent_context_cursors_context
ON agent_context_cursors(context_id, updated_at DESC);

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
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return fallback


def _json_dumps(value: Any) -> str:
    return json.dumps(_json_safe(value, {}), sort_keys=True, separators=(",", ":"))


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

    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self.db_path = self._resolve_db_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._protect_path(self.db_path.parent, directory=True)
        self._initialize()

    @classmethod
    def open_existing_for_audit(
        cls,
        db_path: str | os.PathLike[str] | None = None,
    ) -> "DurableMemoryStore":
        """Open an existing store without schema creation, migration, or chmod writes."""

        store = cls.__new__(cls)
        store.db_path = store._resolve_db_path(db_path)
        if not store.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {store.db_path}"
            )
        return store

    def _resolve_db_path(self, db_path: str | os.PathLike[str] | None) -> Path:
        if db_path is not None:
            return Path(db_path).expanduser()
        configured = os.getenv("SYNAPSE_S2_MEMORY_DB")
        if configured:
            return Path(configured).expanduser()
        return Path.cwd() / ".synapse_s2" / "memory.sqlite3"

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._protect_path(self.db_path.parent, directory=True)
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000")
            conn.execute("PRAGMA foreign_keys = ON")
            durability = str(
                os.getenv("SYNAPSE_S2_SQLITE_DURABILITY", "full")
            ).strip().lower()
            if durability not in {"full", "balanced"}:
                raise ValueError(
                    "SYNAPSE_S2_SQLITE_DURABILITY must be full or balanced"
                )
            schema_gate_fd = self._acquire_writer_gate()
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute(
                    "PRAGMA synchronous = FULL"
                    if durability == "full"
                    else "PRAGMA synchronous = NORMAL"
                )
                conn.executescript(SCHEMA_SQL)
                self._protect_path(self.db_path, directory=False)
            finally:
                self._release_file_lock(schema_gate_fd)
            self._run_migrations(conn)
            return conn
        except BaseException:
            conn.close()
            raise

    def _connect_read_only(self) -> sqlite3.Connection:
        if not self.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {self.db_path}"
            )
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
            return conn
        except BaseException:
            conn.close()
            raise

    def _connect_existing_write(self) -> sqlite3.Connection:
        """Open an existing store read/write without implicit schema migration."""

        if not self.db_path.is_file():
            raise FileNotFoundError(
                f"SYNAPSE-S2 memory store does not exist: {self.db_path}"
            )
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
            return conn
        except BaseException:
            conn.close()
            raise

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
                yield
            except BaseException:
                conn.rollback()
                raise
            else:
                conn.commit()
        finally:
            if writer_gate_fd is not None:
                self._release_file_lock(writer_gate_fd)

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        required_migrations = {"memory_spikes_v1", "memory_surface_terms_v1"}
        applied_migrations = {
            str(row["key"])
            for row in conn.execute(
                "SELECT key FROM store_migrations WHERE key IN (?, ?)",
                tuple(sorted(required_migrations)),
            ).fetchall()
        }
        if applied_migrations == required_migrations:
            return

        # Recheck after acquiring the writer lock. Another process may have
        # completed the migration between the optimistic read and this point.
        with self._transaction(conn, immediate=True):
            index_rows_changed = 0
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

    def _protect_path(self, path: Path, *, directory: bool) -> None:
        try:
            if path.exists():
                path.chmod(0o700 if directory else 0o600)
        except PermissionError:
            LOGGER.warning("could not chmod private memory-store path %s", path)

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
        memory_id = self.stable_memory_id(context_id=context_id, tag=tag)
        now = float(registered_at or time.time())
        metadata_json = _json_dumps(metadata or {})
        clean_spike_indices = sorted(set(raw_spike_indices))
        clean_neuron_indices = list(dict.fromkeys(raw_neuron_indices))
        spike_json = _json_list(clean_spike_indices)
        neuron_json = _json_list(clean_neuron_indices)
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
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
                            str(source_text or ""),
                            metadata_json,
                            int(embedding_dimensions),
                            spike_json,
                            neuron_json,
                            now,
                            time.time(),
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
                        source_text=str(source_text or ""),
                        metadata=metadata or {},
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
                                    "embedding_dimensions": int(embedding_dimensions),
                                    "spike_count": len(clean_spike_indices),
                                }
                            ),
                            time.time(),
                        ),
                    )
            entry = self.get_entry(memory_id)
            if entry is None:
                raise RuntimeError(f"memory entry {memory_id} was not readable after upsert")
            return entry
        except Exception:
            LOGGER.exception("failed to upsert memory entry tag=%s context_id=%s", tag, context_id)
            raise

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
    ) -> list[dict[str, Any]]:
        bounded_limit = min(max(int(limit), 1), 10_000)
        try:
            with closing(self._connect()) as conn:
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
    ) -> dict[str, Any]:
        """Read a stable, context-isolated graph snapshot for UI drill-down.

        Rows are selected by primary-key order so repeated calls over unchanged
        data return the same bounded sample. Deleted/pruned rows cannot appear
        because those operations remove the durable rows and cascading edges.
        """
        context = str(context_id or "").strip()
        if not context:
            raise ValueError("context_id is required")
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
                entry_rows = conn.execute(
                    """
                    SELECT *
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
                relationship_rows = conn.execute(
                    """
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
                "entries": [self._row_to_entry(row) for row in entry_rows],
                "relationships": [
                    self._row_to_relationship(row)
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
        bounded_limit = min(max(int(limit), 1), 1000)
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
                    ORDER BY overlap_count DESC, e.updated_at DESC
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
            key=lambda item: (float(item["score"]), float(item["updated_at"])),
            reverse=True,
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
        bounded_limit = min(max(int(limit), 1), 1000)
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
                        ORDER BY overlap_count DESC, term_weight DESC
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
                        e.updated_at DESC
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
        params.append(bounded_limit)
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM context_relationships
                    {where_sql}
                    ORDER BY confidence DESC, updated_at DESC, context_link_id
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()
            return [self._row_to_context_link(row) for row in rows]
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
                    WITH contexts AS (
                        SELECT context_id FROM memory_entries
                        UNION SELECT context_id FROM agent_context_events
                        UNION SELECT source_context_id FROM context_relationships
                        UNION SELECT target_context_id FROM context_relationships
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
                            COALESCE(link_stats.last_link_at, 0.0)
                        ) AS last_activity_at
                    FROM contexts
                    LEFT JOIN entry_stats USING (context_id)
                    LEFT JOIN relationship_stats USING (context_id)
                    LEFT JOIN spike_stats USING (context_id)
                    LEFT JOIN surface_stats USING (context_id)
                    LEFT JOIN event_stats USING (context_id)
                    LEFT JOIN link_stats USING (context_id)
                    ORDER BY entry_count DESC, last_activity_at DESC, contexts.context_id
                    LIMIT ?
                    """,
                    (bounded_limit,),
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
                if float(suggestion["dice_score"]) < float(min_score):
                    continue
                suggestion["already_linked"] = already_linked
                suggestions.append(suggestion)
        suggestions.sort(
            key=lambda item: (
                float(item["dice_score"]),
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
        available_scores: list[tuple[float, float]] = []
        if surface_denominator:
            available_scores.append((surface_dice, 0.7))
        if spike_denominator:
            available_scores.append((spike_dice, 0.3))
        total_weight = sum(weight for _score, weight in available_scores)
        dice_score = (
            sum(score * weight for score, weight in available_scores) / total_weight
            if total_weight
            else 0.0
        )
        bounded_max_delay = min(max(int(max_phase_delay_ticks), 0), 64)
        suggested_phase_delay_ticks = min(
            bounded_max_delay,
            max(0, int(round(bounded_max_delay * (1.0 - dice_score)))),
        )
        pair = sorted((source_context_id, target_context_id))
        suggestion_seed = f"{pair[0]}\x1f{pair[1]}\x1fdensity-dice-v1".encode("utf-8")
        evidence = {
            "method": "density-normalized-dice-v1",
            "surface_dice": round(surface_dice, 6),
            "spike_dice": round(spike_dice, 6),
            "dice_score": round(dice_score, 6),
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
            "score": round(dice_score, 6),
            "weight": round(dice_score, 6),
            "confidence": round(dice_score, 6),
            "dice_score": round(dice_score, 6),
            "surface_dice": round(surface_dice, 6),
            "spike_dice": round(spike_dice, 6),
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
                            str(context_id),
                            str(source_memory_id),
                            str(target_memory_id),
                            str(relation_type),
                            bounded_weight,
                            _json_dumps(evidence or {}),
                            now,
                            now,
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
        except Exception:
            LOGGER.exception(
                "failed to upsert relationship context_id=%s source=%s target=%s",
                context_id,
                source_memory_id,
                target_memory_id,
            )
            raise

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
            with closing(self._connect()) as conn:
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
        targets = [
            str(target).strip()
            for target in (agent_targets or [])
            if str(target).strip()
        ]
        if not targets:
            targets = ["mcp-clients"]
        now = float(created_at or time.time())
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
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
                            str(context_id),
                            str(source_surface or "unknown"),
                            str(event_type or "context-update"),
                            str(summary or ""),
                            _json_dumps(payload or {}),
                            _json_dumps(targets),
                            now,
                        ),
                    )
                    event_id = int(cursor.lastrowid)
                    event_row = conn.execute(
                        "SELECT * FROM agent_context_events WHERE event_id = ?",
                        (event_id,),
                    ).fetchone()
            if event_row is None:
                raise RuntimeError(f"context event {event_id} was not readable after publish")
            return self._row_to_context_event(event_row)
        except Exception:
            LOGGER.exception(
                "failed to publish context event context_id=%s event_type=%s",
                context_id,
                event_type,
            )
            raise

    def list_context_events(
        self,
        *,
        context_id: str | None = None,
        event_id: int | None = None,
        since_event_id: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        if event_id is not None:
            clauses.append("event_id = ?")
            params.append(int(event_id))
        else:
            clauses.append("event_id > ?")
            params.append(max(0, int(since_event_id)))
        where_sql = "WHERE " + " AND ".join(clauses)
        bounded_limit = min(max(int(limit), 1), 1000)
        params.append(bounded_limit)
        try:
            with closing(self._connect()) as conn:
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM (
                        SELECT *
                        FROM agent_context_events
                        {where_sql}
                        ORDER BY event_id DESC
                        LIMIT ?
                    )
                    ORDER BY event_id ASC
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
                        conn.execute(
                            """
                            DELETE FROM agent_context_events
                            WHERE context_id = ? AND event_id = ?
                            """,
                            (str(context_id), bounded_event_id),
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
        except Exception:
            LOGGER.exception(
                "failed to delete context event context_id=%s event_id=%s",
                context_id,
                event_id,
            )
            raise

    def ack_context_events(
        self,
        *,
        context_id: str,
        agent_id: str,
        last_event_id: int,
    ) -> dict[str, Any]:
        context = str(context_id)
        agent = str(agent_id or "").strip() or "unknown-agent"
        requested_event_id = max(0, int(last_event_id))
        try:
            with closing(self._connect()) as conn:
                with self._transaction(conn, immediate=True):
                    latest_event_id = int(
                        conn.execute(
                            """
                            SELECT COALESCE(MAX(event_id), 0)
                            FROM agent_context_events
                            WHERE context_id = ?
                            """,
                            (context,),
                        ).fetchone()[0]
                        or 0
                    )
                    bounded_event_id = min(requested_event_id, latest_event_id)
                    now = time.time()
                    conn.execute(
                        """
                        INSERT INTO agent_context_cursors (
                            context_id,
                            agent_id,
                            last_event_id,
                            updated_at
                        )
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(context_id, agent_id) DO UPDATE SET
                            last_event_id = MAX(
                                agent_context_cursors.last_event_id,
                                excluded.last_event_id
                            ),
                            updated_at = excluded.updated_at
                        """,
                        (context, agent, bounded_event_id, now),
                    )
                    cursor_row = conn.execute(
                        """
                        SELECT *
                        FROM agent_context_cursors
                        WHERE context_id = ? AND agent_id = ?
                        """,
                        (context, agent),
                    ).fetchone()
                    cursor_event_id = int(
                        cursor_row["last_event_id"] if cursor_row is not None else 0
                    )
                    pending_event_count = int(
                        conn.execute(
                            """
                            SELECT COUNT(*)
                            FROM agent_context_events
                            WHERE context_id = ? AND event_id > ?
                            """,
                            (context, cursor_event_id),
                        ).fetchone()[0]
                    )
            if cursor_row is None:
                raise RuntimeError(f"context cursor for {agent} was not readable after ack")
            return self._row_to_context_cursor(
                cursor_row,
                latest_event_id=latest_event_id,
                pending_event_count=pending_event_count,
            )
        except Exception:
            LOGGER.exception(
                "failed to acknowledge context events context_id=%s agent_id=%s",
                context_id,
                agent_id,
            )
            raise

    def list_context_cursors(
        self,
        *,
        context_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if context_id is not None:
            clauses.append("context_id = ?")
            params.append(str(context_id))
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(str(agent_id))
        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        bounded_limit = min(max(int(limit), 1), 1000)
        params.append(bounded_limit)
        try:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN")
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM agent_context_cursors
                    {where_sql}
                    ORDER BY updated_at DESC, context_id ASC, agent_id ASC
                    LIMIT ?
                    """,
                    tuple(params),
                ).fetchall()
                cursors = []
                for row in rows:
                    context = str(row["context_id"])
                    latest_event_id = int(
                        conn.execute(
                            """
                            SELECT COALESCE(MAX(event_id), 0)
                            FROM agent_context_events
                            WHERE context_id = ?
                            """,
                            (context,),
                        ).fetchone()[0]
                        or 0
                    )
                    pending_event_count = int(
                        conn.execute(
                            """
                            SELECT COUNT(*)
                            FROM agent_context_events
                            WHERE context_id = ? AND event_id > ?
                            """,
                            (context, int(row["last_event_id"])),
                        ).fetchone()[0]
                    )
                    cursors.append(
                        self._row_to_context_cursor(
                            row,
                            latest_event_id=latest_event_id,
                            pending_event_count=pending_event_count,
                        )
                    )
                conn.commit()
            return cursors
        except Exception:
            LOGGER.exception("failed to list context cursors")
            raise

    def stats(self, *, context_id: str | None = None) -> dict[str, Any]:
        try:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN")
                journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0])
                synchronous_level = int(
                    conn.execute("PRAGMA synchronous").fetchone()[0]
                )
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
                        "SELECT COUNT(*) FROM agent_context_cursors"
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
                        "SELECT COUNT(*) FROM agent_context_cursors WHERE context_id = ?",
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
                event_count = conn.execute("SELECT COUNT(*) FROM memory_events").fetchone()[0]
                context_rows = conn.execute(
                    """
                    SELECT context_id, COUNT(*) AS count
                    FROM memory_entries
                    GROUP BY context_id
                    ORDER BY context_id
                    """
                ).fetchall()
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
                "context_link_count": int(context_link_count),
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
        backup_dir.mkdir(parents=True, exist_ok=True)
        self._protect_path(backup_dir, directory=True)
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
        try:
            with closing(sqlite3.connect(temp_path)) as destination:
                source.backup(destination)
                destination.commit()
                quick_check = [
                    str(row[0])
                    for row in destination.execute("PRAGMA quick_check").fetchall()
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
                or foreign_key_error_keys != allowed_foreign_key_error_keys
            ):
                raise RuntimeError(
                    "pre-repair safety backup failed SQLite verification"
                )
            with temp_path.open("rb") as handle:
                os.fsync(handle.fileno())
            temp_path.replace(output_path)
            self._protect_path(output_path, directory=False)
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
            for incomplete_path in (temp_path, output_path):
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
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        while True:
            try:
                fcntl.flock(descriptor, mode | fcntl.LOCK_NB)
                os.fchmod(descriptor, 0o600)
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
        lock_dir.mkdir(parents=True, exist_ok=True)
        self._protect_path(lock_dir, directory=True)
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
        payload = {
            "version": 1,
            "exported_at": time.time(),
            "memory_db_path": str(self.db_path),
            "context_id": context_id,
            "stats": self.stats(context_id=context_id),
            "entries": self.list_entries(context_id=context_id, limit=limit),
            "relationships": self.list_relationships(
                context_id=context_id,
                limit=limit,
            ),
            "context_links": self.list_context_links(
                context_id=context_id,
                limit=limit,
            ),
            "context_events": self.list_context_events(
                context_id=context_id,
                limit=limit,
            ),
            "context_cursors": self.list_context_cursors(
                context_id=context_id,
                limit=limit,
            ),
        }
        if path is not None:
            output_path = Path(path).expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            self._protect_path(output_path.parent, directory=True)
            temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    fd = -1
                    handle.write(json.dumps(payload, indent=2, sort_keys=True))
            finally:
                if fd >= 0:
                    os.close(fd)
            temp_path.replace(output_path)
            self._protect_path(output_path, directory=False)
            payload["export_path"] = str(output_path)
        return payload

    def backup(self, path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        if path is None:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            output_path = self.db_path.with_name(f"{self.db_path.stem}-{stamp}.sqlite3")
        else:
            output_path = Path(path).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        self._protect_path(output_path.parent, directory=True)
        try:
            with closing(self._connect()) as source:
                with closing(sqlite3.connect(output_path)) as destination:
                    source.backup(destination)
            self._protect_path(output_path, directory=False)
            stats = self.stats()
            return {
                "backup_path": str(output_path),
                "memory_db_path": str(self.db_path),
                "entry_count": int(stats["entry_count"]),
                "event_count": int(stats["event_count"]),
                "created_at": time.time(),
            }
        except Exception:
            LOGGER.exception("failed to back up memory store from %s to %s", self.db_path, output_path)
            raise

    def _row_to_entry(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "memory_id": str(row["memory_id"]),
            "tag": str(row["tag"]),
            "context_id": str(row["context_id"]),
            "source_text": str(row["source_text"]),
            "metadata": _decode_json(str(row["metadata_json"]), {}),
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
        return {
            "relationship_id": str(row["relationship_id"]),
            "context_id": str(row["context_id"]),
            "source_memory_id": str(row["source_memory_id"]),
            "target_memory_id": str(row["target_memory_id"]),
            "source_tag": str(row["source_tag"]),
            "target_tag": str(row["target_tag"]),
            "relation_type": str(row["relation_type"]),
            "weight": round(float(row["weight"]), 6),
            "evidence": _decode_json(str(row["evidence_json"]), {}),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    def _row_to_context_link(self, row: sqlite3.Row) -> dict[str, Any]:
        confidence = round(float(row["confidence"]), 6)
        evidence = _decode_json(str(row["evidence_json"]), {})
        return {
            "context_link_id": str(row["context_link_id"]),
            "source_context_id": str(row["source_context_id"]),
            "target_context_id": str(row["target_context_id"]),
            "relation_type": str(row["relation_type"]),
            "direction": str(row["direction"]),
            "confidence": confidence,
            "weight": confidence,
            "evidence": evidence if isinstance(evidence, dict) else {},
            "enabled": bool(row["enabled"]),
            "approved": True,
            "approved_by": str(row["approved_by"]),
            "approved_at": float(row["approved_at"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
            "automatic_cross_namespace_write": False,
        }

    def _row_to_context_event(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "event_id": int(row["event_id"]),
            "context_id": str(row["context_id"]),
            "source_surface": str(row["source_surface"]),
            "event_type": str(row["event_type"]),
            "summary": str(row["summary"]),
            "payload": _decode_json(str(row["payload_json"]), {}),
            "agent_targets": [
                str(value)
                for value in _decode_json(str(row["agent_targets_json"]), [])
            ],
            "created_at": float(row["created_at"]),
        }

    def _row_to_context_cursor(
        self,
        row: sqlite3.Row,
        *,
        latest_event_id: int,
        pending_event_count: int,
    ) -> dict[str, Any]:
        last_event_id = int(row["last_event_id"])
        return {
            "context_id": str(row["context_id"]),
            "agent_id": str(row["agent_id"]),
            "last_event_id": last_event_id,
            "latest_event_id": int(latest_event_id),
            "pending_event_count": int(pending_event_count),
            "caught_up": int(pending_event_count) == 0,
            "updated_at": float(row["updated_at"]),
        }

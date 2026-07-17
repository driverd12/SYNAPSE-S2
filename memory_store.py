from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable


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
"""

SURFACE_TERM_RE = re.compile(r"[a-z0-9][a-z0-9_./:-]{1,63}")
MAX_SURFACE_INDEX_SOURCE_CHARS = 4096
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
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(SCHEMA_SQL)
        self._run_migrations(conn)
        self._protect_path(self.db_path, directory=False)
        return conn

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
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
            with conn:
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
                        conn.executemany(
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
            with conn:
                for row in rows:
                    surface_rows = self._surface_term_rows(
                        memory_id=str(row["memory_id"]),
                        context_id=str(row["context_id"]),
                        tag=str(row["tag"]),
                        source_text=str(row["source_text"]),
                        metadata=_decode_json(str(row["metadata_json"]), {}),
                    )
                    if surface_rows:
                        conn.executemany(
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
                conn.execute(
                    """
                    INSERT OR REPLACE INTO store_migrations (key, applied_at)
                    VALUES (?, ?)
                    """,
                    ("memory_surface_terms_v1", time.time()),
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
        memory_id = self.stable_memory_id(context_id=context_id, tag=tag)
        now = float(registered_at or time.time())
        metadata_json = _json_dumps(metadata or {})
        clean_spike_indices = sorted({int(value) for value in spike_indices})
        clean_neuron_indices = [int(value) for value in neuron_indices]
        spike_json = _json_list(clean_spike_indices)
        neuron_json = _json_list(clean_neuron_indices)
        try:
            with closing(self._connect()) as conn:
                with conn:
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
            entry_count = int(row["entry_count"] if row is not None else 0)
            max_updated_at = float(row["max_updated_at"] if row is not None else 0.0)
            max_created_at = float(row["max_created_at"] if row is not None else 0.0)
            revision_seed = (
                f"{context_id or '*'}\x1f{include_global}\x1f"
                f"{','.join(clean_context_ids)}\x1f"
                f"{entry_count}\x1f{max_updated_at:.9f}\x1f{max_created_at:.9f}"
            )
            return {
                "context_id": str(context_id or ""),
                "context_ids": clean_context_ids,
                "include_global": bool(include_global),
                "entry_count": entry_count,
                "max_updated_at": max_updated_at,
                "max_created_at": max_created_at,
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
            links = self.list_context_links(context_link_id=context_link_id, limit=1)
            if not links:
                raise RuntimeError(
                    f"context link {context_link_id} was not readable after upsert"
                )
            return links[0]
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
        links = self.list_context_links(context_link_id=link_id, limit=1)
        link = links[0] if links else None
        if link is None:
            return {"deleted": False, "context_link_id": link_id, "link": None}
        try:
            with closing(self._connect()) as conn:
                conn.execute(
                    "DELETE FROM context_relationships WHERE context_link_id = ?",
                    (link_id,),
                )
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
            relationship = self.get_relationship(relationship_id)
            if relationship is None:
                raise RuntimeError(
                    f"relationship {relationship_id} was not readable after upsert"
                )
            return relationship
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
                row = conn.execute(
                    f"SELECT * FROM memory_entries WHERE {where_sql} LIMIT 1",
                    tuple(params),
                ).fetchone()
                if row is None:
                    return {
                        "deleted": False,
                        "deleted_memory_id": str(memory_id or ""),
                        "deleted_relationship_count": 0,
                        "deleted_memory_event_count": 0,
                        "entry": None,
                    }
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
                conn.execute("DELETE FROM memory_entries WHERE memory_id = ?", (entry_id,))
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
        relationship = self.get_relationship(str(relationship_id))
        if relationship is None or (
            context_id is not None and relationship["context_id"] != str(context_id)
        ):
            return {
                "deleted": False,
                "relationship_id": str(relationship_id),
                "relationship": None,
            }
        try:
            with closing(self._connect()) as conn:
                conn.execute(
                    "DELETE FROM memory_relationships WHERE relationship_id = ?",
                    (str(relationship_id),),
                )
            return {
                "deleted": True,
                "relationship_id": str(relationship_id),
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
            events = self.list_context_events(event_id=event_id, limit=1)
            if not events:
                raise RuntimeError(f"context event {event_id} was not readable after publish")
            return events[0]
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
                row = conn.execute(
                    """
                    SELECT *
                    FROM agent_context_events
                    WHERE context_id = ? AND event_id = ?
                    """,
                    (str(context_id), bounded_event_id),
                ).fetchone()
                if row is None:
                    return {
                        "deleted": False,
                        "event_id": bounded_event_id,
                        "event": None,
                    }
                event = self._row_to_context_event(row)
                conn.execute(
                    """
                    DELETE FROM agent_context_events
                    WHERE context_id = ? AND event_id = ?
                    """,
                    (str(context_id), bounded_event_id),
                )
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
            cursors = self.list_context_cursors(
                context_id=context,
                agent_id=agent,
                limit=1,
            )
            if not cursors:
                raise RuntimeError(f"context cursor for {agent} was not readable after ack")
            return cursors[0]
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
            return cursors
        except Exception:
            LOGGER.exception("failed to list context cursors")
            raise

    def stats(self, *, context_id: str | None = None) -> dict[str, Any]:
        try:
            with closing(self._connect()) as conn:
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
            return {
                "memory_db_path": str(self.db_path),
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

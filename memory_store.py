from __future__ import annotations

import hashlib
import json
import logging
import os
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
"""


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
        conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(SCHEMA_SQL)
        return conn

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
        spike_json = _json_list(spike_indices)
        neuron_json = _json_list(neuron_indices)
        try:
            with closing(self._connect()) as conn:
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

    def recall_candidates(
        self,
        *,
        context_id: str,
        query_spikes: set[int],
        firing_values: list[float],
        limit: int,
    ) -> list[dict[str, Any]]:
        if not query_spikes:
            return []
        candidates: list[dict[str, Any]] = []
        for entry in self.list_entries(
            context_id=context_id,
            include_global=True,
            limit=10_000,
        ):
            trace_spikes = set(int(idx) for idx in entry["spike_indices"])
            if not trace_spikes:
                continue
            overlap = len(query_spikes & trace_spikes)
            union = len(query_spikes | trace_spikes)
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
            candidates.append(candidate)
        candidates.sort(
            key=lambda item: (float(item["score"]), float(item["updated_at"])),
            reverse=True,
        )
        return candidates[: min(max(int(limit), 1), 1000)]

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
                    context_bus_event_count = conn.execute(
                        "SELECT COUNT(*) FROM agent_context_events"
                    ).fetchone()[0]
                    latest_context_event_row = conn.execute(
                        "SELECT COALESCE(MAX(event_id), 0) FROM agent_context_events"
                    ).fetchone()
                else:
                    entry_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_entries WHERE context_id = ?",
                        (context_id,),
                    ).fetchone()[0]
                    relationship_count = conn.execute(
                        "SELECT COUNT(*) FROM memory_relationships WHERE context_id = ?",
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
                "context_bus_event_count": int(context_bus_event_count),
                "context_bus_latest_event_id": int(latest_context_event_row[0] or 0),
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
            "context_events": self.list_context_events(
                context_id=context_id,
                limit=limit,
            ),
        }
        if path is not None:
            output_path = Path(path).expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
            temp_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            temp_path.replace(output_path)
            payload["export_path"] = str(output_path)
        return payload

    def backup(self, path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        if path is None:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            output_path = self.db_path.with_name(f"{self.db_path.stem}-{stamp}.sqlite3")
        else:
            output_path = Path(path).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with closing(self._connect()) as source:
                with closing(sqlite3.connect(output_path)) as destination:
                    source.backup(destination)
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

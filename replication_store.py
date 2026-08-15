from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import math
import os
import secrets
import sqlite3
import stat
import time
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

from core_protocol import canonical_json_bytes
from memory_store import DurableMemoryStore
from replication_protocol import (
    ACK_ID_RE,
    AUTH_FIELDS,
    DIGEST_RE,
    LEDGER_ANCHOR_SCHEMA,
    LINEAGE_ID_RE,
    NODE_ID_RE,
    REPLICATION_PROTOCOL_VERSION,
    ReplicationProtocolError,
    STORE_ID_RE,
    ack_id_for,
    node_id_for_key_id,
    read_private_json,
    sign_payload,
    validate_ledger_anchor,
    validate_checkpoint,
    validate_ack,
    validate_private_directory,
    write_private_json_exclusive,
)


REPLICATION_LEDGER_APPLICATION_ID = 0x53325250
REPLICATION_LEDGER_USER_VERSION = 2
MAX_LEDGER_ANCHORS = 100_000
MAX_REPLICATION_LEDGER_BYTES = 256 * 1024 * 1024
MAX_LEDGER_ROW_COUNTS = {
    "peers": 10_000,
    "checkpoints": 10_000,
    "acknowledgements": 10_000,
    "audit_events": 100_000,
}
STATUS_PEER_PAGE_LIMIT = 128
STATUS_LATEST_CHECKPOINT_LIMIT = 256
REPLICATION_HIGH_WATER_WITNESS_SCHEMA = (
    "synapse-s2.replication-ledger-high-water.v1"
)
REPLICATION_NEUTRAL_HIGH_WATER_METADATA_KEY = (
    "replication_ledger_neutral_high_water.v1"
)
REPLICATION_HIGH_WATER_WITNESS_FIELDS = frozenset(
    {
        "schema",
        "protocol_version",
        "node_id",
        "store_identity",
        "ledger_identity",
        "ledger_path_domain_sha256",
        "anchor_revision",
        "anchor_digest",
        "previous_anchor_digest",
        "witnessed_at",
    }
) | AUTH_FIELDS

SCHEMA_STATEMENTS = (
    """
    CREATE TABLE ledger_meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        anchor_revision INTEGER NOT NULL CHECK(anchor_revision >= 0),
        anchor_digest TEXT NOT NULL,
        previous_anchor_digest TEXT
    ) STRICT
    """,
    """
    CREATE TABLE peers (
        peer_id TEXT PRIMARY KEY,
        lineage_id TEXT NOT NULL,
        direction TEXT NOT NULL CHECK(direction IN ('send', 'receive')),
        signing_key_id TEXT NOT NULL,
        signing_public_key TEXT NOT NULL,
        descriptor_digest TEXT NOT NULL,
        source_store_identity TEXT,
        source_store_generation TEXT,
        source_authority_epoch INTEGER,
        revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
        revoke_reason TEXT,
        paired_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        UNIQUE(lineage_id, direction)
    ) STRICT
    """,
    """
    CREATE TABLE checkpoints (
        checkpoint_digest TEXT PRIMARY KEY,
        checkpoint_id TEXT NOT NULL UNIQUE,
        lineage_id TEXT NOT NULL,
        direction TEXT NOT NULL CHECK(direction IN ('outgoing', 'incoming')),
        peer_id TEXT NOT NULL,
        term INTEGER NOT NULL CHECK(term > 0),
        sequence INTEGER NOT NULL CHECK(sequence > 0),
        parent_checkpoint_digest TEXT,
        bundle_receipt_digest TEXT NOT NULL,
        source_store_identity TEXT NOT NULL,
        store_generation TEXT NOT NULL,
        authority_epoch_number INTEGER NOT NULL CHECK(authority_epoch_number > 0),
        manifest_path TEXT NOT NULL,
        restore_root TEXT,
        state TEXT NOT NULL CHECK(state IN ('exported', 'staged', 'acknowledged', 'rejected')),
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        FOREIGN KEY(peer_id) REFERENCES peers(peer_id),
        UNIQUE(lineage_id, direction, term, sequence)
    ) STRICT
    """,
    """
    CREATE INDEX ix_checkpoints_chain
    ON checkpoints(lineage_id, direction, term, sequence DESC)
    """,
    """
    CREATE INDEX ix_checkpoints_peer_state
    ON checkpoints(peer_id, direction, state)
    """,
    """
    CREATE TABLE acknowledgements (
        ack_digest TEXT PRIMARY KEY,
        ack_id TEXT NOT NULL UNIQUE,
        checkpoint_digest TEXT NOT NULL UNIQUE,
        peer_id TEXT NOT NULL,
        ack_path TEXT NOT NULL,
        created_at REAL NOT NULL,
        FOREIGN KEY(checkpoint_digest) REFERENCES checkpoints(checkpoint_digest),
        FOREIGN KEY(peer_id) REFERENCES peers(peer_id)
    ) STRICT
    """,
    """
    CREATE TABLE audit_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        state TEXT NOT NULL,
        peer_id TEXT,
        lineage_id TEXT,
        checkpoint_digest TEXT,
        detail_code TEXT NOT NULL,
        created_at REAL NOT NULL
    ) STRICT
    """,
    """
    CREATE INDEX ix_audit_events_created
    ON audit_events(created_at DESC, event_id DESC)
    """,
)


def _normalize_sql(value: str) -> str:
    return " ".join(value.strip().split())


EXPECTED_SCHEMA_SQL = frozenset(_normalize_sql(statement) for statement in SCHEMA_STATEMENTS)


class ReplicationLedger:
    """Private exact-schema state for the offline checkpoint protocol."""

    def __init__(self, store: DurableMemoryStore) -> None:
        self.store = store
        self.root = store.db_path.parent.absolute() / "replication"
        if self.root.exists() or self.root.is_symlink():
            validate_private_directory(self.root)
        else:
            store._ensure_directory(self.root, owned=True)
        validate_private_directory(self.root)
        self.path = self.root / "replication.sqlite3"
        self.lock_path = self.root / "manager.lock"
        self.anchor_path = self.root / "ledger-state.receipt.json"
        self.pending_anchor_path = self.root / ".ledger-state.pending.receipt.json"
        self.anchor_history_root = self.root / "anchor-history"
        self.witness_root = store.db_path.parent.absolute() / "core"
        self.witness_path = (
            self.witness_root / "replication-ledger-high-water.receipt.json"
        )
        if self.witness_root.exists() or self.witness_root.is_symlink():
            validate_private_directory(self.witness_root)
        else:
            store._ensure_directory(self.witness_root, owned=True)
        validate_private_directory(self.witness_root)
        if self.anchor_history_root.exists() or self.anchor_history_root.is_symlink():
            validate_private_directory(self.anchor_history_root)
        else:
            store._ensure_directory(self.anchor_history_root, owned=True)
        validate_private_directory(self.anchor_history_root)
        self._ensure_lock_file()
        self._initialize_or_validate()

    @staticmethod
    def _validate_private_regular(path: Path, *, allow_empty: bool = False) -> os.stat_result:
        metadata = os.lstat(path)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or int(metadata.st_nlink) != 1
            or (not allow_empty and metadata.st_size <= 0)
        ):
            raise PermissionError("replication ledger artifact is not a private regular file")
        return metadata

    def _ensure_lock_file(self) -> None:
        if not self.lock_path.exists() and not self.lock_path.is_symlink():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.lock_path, flags, 0o600)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self.store._fsync_directory(self.root)
        self._validate_private_regular(self.lock_path, allow_empty=True)

    @contextmanager
    def manager_lock(self) -> Iterator[None]:
        self._validate_private_regular(self.lock_path, allow_empty=True)
        flags = os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags)
        try:
            metadata = os.fstat(descriptor)
            path_metadata = os.lstat(self.lock_path)
            if (metadata.st_dev, metadata.st_ino) != (
                path_metadata.st_dev,
                path_metadata.st_ino,
            ):
                raise RuntimeError("replication manager lock changed while opening")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _open(self, *, create: bool = False) -> sqlite3.Connection:
        if create:
            conn = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        else:
            self._validate_private_regular(self.path)
            conn = sqlite3.connect(
                self.path.resolve().as_uri() + "?mode=rw",
                uri=True,
                timeout=30.0,
                isolation_level=None,
            )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA trusted_schema = OFF")
        return conn

    def _initialize_or_validate(self) -> None:
        created = not self.path.exists() and not self.path.is_symlink()
        if self.path.is_symlink():
            raise PermissionError("replication ledger must not be a symlink")
        if created:
            with closing(self._open(create=True)) as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute(f"PRAGMA application_id = {REPLICATION_LEDGER_APPLICATION_ID}")
                    conn.execute(f"PRAGMA user_version = {REPLICATION_LEDGER_USER_VERSION}")
                    for statement in SCHEMA_STATEMENTS:
                        conn.execute(statement)
                    conn.execute(
                        "INSERT INTO ledger_meta(singleton, anchor_revision, anchor_digest, previous_anchor_digest) VALUES (1, 0, '', NULL)"
                    )
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
            os.chmod(self.path, 0o600, follow_symlinks=False)
            self.store._fsync_file(self.path)
            self.store._fsync_directory(self.root)
        self._validate_private_regular(self.path)
        with closing(self._open()) as conn:
            self._validate_schema(conn)
            self._initialize_or_recover_anchor(conn)
            self._validate_anchor(conn)

    def _validate_resource_bounds(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, int]:
        metadata = self._validate_private_regular(self.path)
        page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
        if (
            page_size < 512
            or page_size > 65_536
            or page_count < 1
            or page_count > MAX_REPLICATION_LEDGER_BYTES // page_size
            or int(metadata.st_size) > MAX_REPLICATION_LEDGER_BYTES
        ):
            raise RuntimeError("replication ledger exceeds its storage bound")
        counts: dict[str, int] = {}
        for table, maximum in MAX_LEDGER_ROW_COUNTS.items():
            count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            if count < 0 or count > maximum:
                raise RuntimeError(f"replication ledger {table} row bound exceeded")
            counts[table] = count
        return counts

    def _snapshot_digest(self, conn: sqlite3.Connection) -> str:
        expected_counts = self._validate_resource_bounds(conn)
        tables = {
            "peers": "peer_id",
            "checkpoints": "checkpoint_digest",
            "acknowledgements": "ack_digest",
            "audit_events": "event_id",
        }
        digest = hashlib.sha256()
        digest.update(b"synapse-s2.replication-ledger-snapshot.v2\x00")
        for table, ordering in tables.items():
            digest.update(canonical_json_bytes({"table": table}))
            digest.update(b"\x00")
            observed = 0
            cursor = conn.execute(f"SELECT * FROM {table} ORDER BY {ordering}")
            while True:
                rows = cursor.fetchmany(256)
                if not rows:
                    break
                for row in rows:
                    encoded = canonical_json_bytes(dict(row))
                    digest.update(len(encoded).to_bytes(8, "big"))
                    digest.update(encoded)
                    observed += 1
                    if observed > expected_counts[table]:
                        raise RuntimeError(
                            "replication ledger changed during snapshot digest"
                        )
            if observed != expected_counts[table]:
                raise RuntimeError("replication ledger snapshot row count changed")
            digest.update(observed.to_bytes(8, "big"))
        return digest.hexdigest()

    def _local_signing_identity(self) -> tuple[str, str, str]:
        _private, public_bytes, key_id = self.store._backup_receipt_signing_key(
            create=True
        )
        if public_bytes is None or key_id is None:
            raise RuntimeError("replication ledger signing authority is unavailable")
        return (
            node_id_for_key_id(key_id),
            base64.b64encode(public_bytes).decode("ascii"),
            key_id,
        )

    @staticmethod
    def _ledger_is_empty(conn: sqlite3.Connection) -> bool:
        return not any(
            int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "peers",
                "checkpoints",
                "acknowledgements",
                "audit_events",
            )
        )

    def _authoritative_store_identity(self, conn: sqlite3.Connection) -> str:
        marker = self.store._core_authority_marker(conn)
        if marker is None:
            raise RuntimeError(
                "replication high-water witness requires an authoritative memory store"
            )
        store_identity = str(marker["store_identity"])
        if STORE_ID_RE.fullmatch(store_identity) is None:
            raise RuntimeError("replication high-water store identity is invalid")
        return store_identity

    def _ledger_identity_binding(
        self,
        *,
        node_id: str,
        store_identity: str,
    ) -> tuple[str, str]:
        path_domain_sha256 = hashlib.sha256(
            canonical_json_bytes(
                {
                    "memory_store_path": str(self.store.db_path.resolve()),
                    "replication_root": str(self.root.resolve()),
                    "ledger_path": str(self.path.resolve()),
                }
            )
        ).hexdigest()
        ledger_identity = hashlib.sha256(
            canonical_json_bytes(
                {
                    "protocol_version": REPLICATION_PROTOCOL_VERSION,
                    "node_id": node_id,
                    "store_identity": store_identity,
                    "ledger_path_domain_sha256": path_domain_sha256,
                    "application_id": REPLICATION_LEDGER_APPLICATION_ID,
                    "user_version": REPLICATION_LEDGER_USER_VERSION,
                }
            )
        ).hexdigest()
        return ledger_identity, path_domain_sha256

    def _read_high_water_witness_conn(
        self,
        conn: sqlite3.Connection,
    ) -> dict[str, Any] | None:
        if not self.witness_path.exists() and not self.witness_path.is_symlink():
            return None
        self._validate_private_regular(self.witness_path)
        witness = read_private_json(self.witness_path)
        return self._validate_high_water_witness_document(conn, witness)

    def _publish_high_water_witness(self, witness: dict[str, Any]) -> None:
        if self.witness_path.exists() or self.witness_path.is_symlink():
            self._validate_private_regular(self.witness_path)
        temporary = self.store._unique_private_temp_path(
            self.witness_root,
            prefix=".replication-ledger-high-water.",
        )
        try:
            flags = os.O_WRONLY | os.O_TRUNC
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, flags)
            try:
                encoded = canonical_json_bytes(witness) + b"\n"
                offset = 0
                while offset < len(encoded):
                    written = os.write(descriptor, encoded[offset:])
                    if written <= 0:
                        raise OSError(
                            "replication high-water witness write made no progress"
                        )
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, self.witness_path)
            os.chmod(self.witness_path, 0o600, follow_symlinks=False)
            self.store._fsync_file(self.witness_path)
            self.store._fsync_directory(self.witness_root)
        finally:
            temporary.unlink(missing_ok=True)

    def _validate_high_water_witness_document(
        self,
        conn: sqlite3.Connection,
        value: Any,
    ) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != set(
            REPLICATION_HIGH_WATER_WITNESS_FIELDS
        ):
            raise RuntimeError("replication high-water witness contract is invalid")
        node_id, public_key, key_id = self._local_signing_identity()
        store_identity = self._authoritative_store_identity(conn)
        ledger_identity, path_domain_sha256 = self._ledger_identity_binding(
            node_id=node_id,
            store_identity=store_identity,
        )
        revision = value.get("anchor_revision")
        previous = value.get("previous_anchor_digest")
        witnessed_at = value.get("witnessed_at")
        if (
            value.get("schema") != REPLICATION_HIGH_WATER_WITNESS_SCHEMA
            or value.get("protocol_version") != REPLICATION_PROTOCOL_VERSION
            or value.get("node_id") != node_id
            or value.get("store_identity") != store_identity
            or value.get("ledger_identity") != ledger_identity
            or value.get("ledger_path_domain_sha256") != path_domain_sha256
            or type(revision) is not int
            or revision < 0
            or revision > MAX_LEDGER_ANCHORS
            or DIGEST_RE.fullmatch(str(value.get("anchor_digest") or "")) is None
            or (
                revision == 0
                and previous is not None
            )
            or (
                revision > 0
                and DIGEST_RE.fullmatch(str(previous or "")) is None
            )
            or isinstance(witnessed_at, bool)
            or not isinstance(witnessed_at, (int, float))
            or not math.isfinite(float(witnessed_at))
            or float(witnessed_at) <= 0
            or value.get("auth_key_id") != key_id
            or value.get("signing_public_key") != public_key
            or not secrets.compare_digest(
                str(value.get("receipt_digest") or ""),
                self.store._canonical_payload_digest(value),
            )
            or not self.store._verify_receipt_authenticator(value)
        ):
            raise RuntimeError("replication high-water witness verification failed")
        return dict(value)

    def _signed_high_water_witness(
        self,
        conn: sqlite3.Connection,
        anchor: dict[str, Any],
    ) -> dict[str, Any]:
        node_id, _public_key, _key_id = self._local_signing_identity()
        store_identity = self._authoritative_store_identity(conn)
        ledger_identity, path_domain_sha256 = self._ledger_identity_binding(
            node_id=node_id,
            store_identity=store_identity,
        )
        witness = sign_payload(
            self.store,
            {
                "schema": REPLICATION_HIGH_WATER_WITNESS_SCHEMA,
                "protocol_version": REPLICATION_PROTOCOL_VERSION,
                "node_id": node_id,
                "store_identity": store_identity,
                "ledger_identity": ledger_identity,
                "ledger_path_domain_sha256": path_domain_sha256,
                "anchor_revision": int(anchor["revision"]),
                "anchor_digest": str(anchor["receipt_digest"]),
                "previous_anchor_digest": anchor["previous_anchor_digest"],
                "witnessed_at": time.time(),
            },
        )
        return self._validate_high_water_witness_document(conn, witness)

    @staticmethod
    def _read_neutral_high_water_conn(
        conn: sqlite3.Connection,
    ) -> int | None:
        row = conn.execute(
            "SELECT value_json FROM store_metadata WHERE key = ?",
            (REPLICATION_NEUTRAL_HIGH_WATER_METADATA_KEY,),
        ).fetchone()
        if row is None:
            return None
        try:
            revision = json.loads(str(row["value_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "replication neutral high-water revision is malformed"
            ) from exc
        if (
            type(revision) is not int
            or revision < 0
            or revision > MAX_LEDGER_ANCHORS
            or str(row["value_json"]) != str(revision)
        ):
            raise RuntimeError(
                "replication neutral high-water revision is invalid"
            )
        return revision

    def _advance_neutral_high_water(
        self,
        anchor: dict[str, Any],
        *,
        allow_genesis_initialization: bool = False,
    ) -> int:
        target_revision = int(anchor["revision"])
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                current_revision = self._read_neutral_high_water_conn(conn)
                if current_revision is None:
                    if not (
                        allow_genesis_initialization and target_revision == 0
                    ):
                        raise RuntimeError(
                            "replication neutral high-water revision is missing"
                        )
                elif current_revision == target_revision:
                    return current_revision
                elif target_revision != current_revision + 1:
                    raise RuntimeError(
                        "replication neutral high-water cannot skip or roll back"
                    )
                conn.execute(
                    """
                    INSERT INTO store_metadata(key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        REPLICATION_NEUTRAL_HIGH_WATER_METADATA_KEY,
                        str(target_revision),
                        time.time(),
                    ),
                )
                persisted = self._read_neutral_high_water_conn(conn)
                if persisted != target_revision:
                    raise RuntimeError(
                        "replication neutral high-water publication failed"
                    )
                return target_revision

    def _validate_neutral_high_water(
        self,
        conn: sqlite3.Connection,
        anchor: dict[str, Any],
    ) -> int:
        with closing(self.store._connect_read_only()) as witness_conn:
            revision = self._read_neutral_high_water_conn(witness_conn)
        if revision is None:
            if int(anchor["revision"]) != 0 or not self._ledger_is_empty(conn):
                raise RuntimeError(
                    "replication neutral high-water revision is missing"
                )
            revision = self._advance_neutral_high_water(
                anchor,
                allow_genesis_initialization=True,
            )
        if revision != int(anchor["revision"]):
            raise RuntimeError(
                "replication ledger rolled back behind its neutral high-water revision"
            )
        return revision

    def _advance_high_water_witness(
        self,
        anchor: dict[str, Any],
        *,
        allow_genesis_initialization: bool = False,
    ) -> dict[str, Any]:
        target_revision = int(anchor["revision"])
        target_digest = str(anchor["receipt_digest"])
        target_previous = anchor["previous_anchor_digest"]
        with closing(self.store._connect_read_only()) as neutral_conn:
            neutral_revision = self._read_neutral_high_water_conn(neutral_conn)
        if neutral_revision != target_revision:
            raise RuntimeError(
                "signed replication witness cannot advance ahead of neutral high-water"
            )
        with closing(self.store._connect_read_only()) as conn:
            current = self._read_high_water_witness_conn(conn)
            if current is None:
                if not (
                    allow_genesis_initialization
                    and target_revision == 0
                    and target_previous is None
                ):
                    raise RuntimeError("replication high-water witness is missing")
            else:
                current_revision = int(current["anchor_revision"])
                if current_revision == target_revision:
                    if (
                        not secrets.compare_digest(
                            str(current["anchor_digest"]), target_digest
                        )
                        or current["previous_anchor_digest"] != target_previous
                    ):
                        raise RuntimeError(
                            "replication high-water witness conflicts with anchor"
                        )
                    return current
                if (
                    target_revision != current_revision + 1
                    or target_previous != current["anchor_digest"]
                ):
                    raise RuntimeError(
                        "replication high-water witness cannot skip or roll back"
                    )
            witness = self._signed_high_water_witness(conn, anchor)
        self._publish_high_water_witness(witness)
        with closing(self.store._connect_read_only()) as conn:
            persisted = self._read_high_water_witness_conn(conn)
        if (
            persisted is None
            or not secrets.compare_digest(
                str(persisted["receipt_digest"]),
                str(witness["receipt_digest"]),
            )
        ):
            raise RuntimeError("replication high-water witness publication failed")
        return persisted

    def _validate_high_water_witness(
        self,
        conn: sqlite3.Connection,
        anchor: dict[str, Any],
    ) -> dict[str, Any]:
        self._validate_neutral_high_water(conn, anchor)
        with closing(self.store._connect_read_only()) as witness_conn:
            witness = self._read_high_water_witness_conn(witness_conn)
        if witness is None:
            if int(anchor["revision"]) != 0 or not self._ledger_is_empty(conn):
                raise RuntimeError("replication high-water witness is missing")
            witness = self._advance_high_water_witness(
                anchor,
                allow_genesis_initialization=True,
            )
        if (
            int(witness["anchor_revision"]) != int(anchor["revision"])
            or not secrets.compare_digest(
                str(witness["anchor_digest"]), str(anchor["receipt_digest"])
            )
            or witness["previous_anchor_digest"]
            != anchor["previous_anchor_digest"]
        ):
            raise RuntimeError(
                "replication ledger rolled back behind its external high-water witness"
            )
        return witness

    def _signed_anchor(
        self,
        conn: sqlite3.Connection,
        *,
        revision: int,
        previous_digest: str | None,
    ) -> dict[str, Any]:
        node_id, _public, _key_id = self._local_signing_identity()
        return sign_payload(
            self.store,
            {
                "schema": LEDGER_ANCHOR_SCHEMA,
                "protocol_version": REPLICATION_PROTOCOL_VERSION,
                "node_id": node_id,
                "revision": revision,
                "previous_anchor_digest": previous_digest,
                "ledger_snapshot_sha256": self._snapshot_digest(conn),
                "created_at": time.time(),
            },
        )

    def _publish_pending_anchor(self) -> None:
        self._validate_private_regular(self.pending_anchor_path)
        pending = read_private_json(self.pending_anchor_path)
        _node_id, public_key, key_id = self._local_signing_identity()
        validated = validate_ledger_anchor(
            pending,
            expected_public_key=public_key,
            expected_key_id=key_id,
        )
        revision = int(validated["revision"])
        if revision > MAX_LEDGER_ANCHORS:
            raise RuntimeError("replication ledger anchor history exceeds its bound")
        with closing(self.store._connect_read_only()) as witness_conn:
            witness = self._read_high_water_witness_conn(witness_conn)
        if (
            witness is None
            or int(witness["anchor_revision"]) != revision
            or not secrets.compare_digest(
                str(witness["anchor_digest"]), str(validated["receipt_digest"])
            )
            or witness["previous_anchor_digest"]
            != validated["previous_anchor_digest"]
        ):
            raise RuntimeError(
                "replication anchor cannot publish ahead of its high-water witness"
            )
        history_path = self.anchor_history_root / f"anchor-{revision:020d}.receipt.json"
        if history_path.exists() or history_path.is_symlink():
            persisted = validate_ledger_anchor(
                read_private_json(history_path),
                expected_public_key=public_key,
                expected_key_id=key_id,
            )
            if not secrets.compare_digest(
                str(persisted["receipt_digest"]), str(validated["receipt_digest"])
            ):
                raise RuntimeError("replication anchor history conflicts with pending state")
        else:
            write_private_json_exclusive(self.store, history_path, validated)
        if self.anchor_path.exists() or self.anchor_path.is_symlink():
            self._validate_private_regular(self.anchor_path)
        os.replace(self.pending_anchor_path, self.anchor_path)
        os.chmod(self.anchor_path, 0o600, follow_symlinks=False)
        self.store._fsync_file(self.anchor_path)
        self.store._fsync_directory(self.root)

    def _initialize_or_recover_anchor(self, conn: sqlite3.Connection) -> None:
        meta = conn.execute("SELECT * FROM ledger_meta WHERE singleton = 1").fetchone()
        if meta is None:
            raise RuntimeError("replication ledger anchor metadata is missing")
        if self.pending_anchor_path.exists() or self.pending_anchor_path.is_symlink():
            self._validate_private_regular(self.pending_anchor_path)
            pending = read_private_json(self.pending_anchor_path)
            _node_id, public_key, key_id = self._local_signing_identity()
            validated = validate_ledger_anchor(
                pending,
                expected_public_key=public_key,
                expected_key_id=key_id,
            )
            if (
                int(meta["anchor_revision"]) == int(validated["revision"])
                and str(meta["anchor_digest"]) == str(validated["receipt_digest"])
                and meta["previous_anchor_digest"]
                == validated["previous_anchor_digest"]
                and self._snapshot_digest(conn)
                == str(validated["ledger_snapshot_sha256"])
            ):
                self._advance_neutral_high_water(validated)
                self._advance_high_water_witness(validated)
                self._publish_pending_anchor()
            elif self.anchor_path.exists() and not self.anchor_path.is_symlink():
                self.pending_anchor_path.unlink()
                self.store._fsync_directory(self.root)
            else:
                raise RuntimeError("replication ledger has an unrecoverable pending anchor")
        empty_state = self._ledger_is_empty(conn)
        if (
            self.anchor_path.exists()
            and not self.anchor_path.is_symlink()
            and int(meta["anchor_revision"]) == 0
            and not str(meta["anchor_digest"])
            and empty_state
        ):
            _node_id, public_key, key_id = self._local_signing_identity()
            genesis = validate_ledger_anchor(
                read_private_json(self.anchor_path),
                expected_public_key=public_key,
                expected_key_id=key_id,
            )
            if (
                int(genesis["revision"]) != 0
                or genesis["previous_anchor_digest"] is not None
                or genesis["ledger_snapshot_sha256"] != self._snapshot_digest(conn)
            ):
                raise RuntimeError("replication ledger genesis anchor is invalid")
            history = (
                self.anchor_history_root
                / "anchor-00000000000000000000.receipt.json"
            )
            if not history.exists() and not history.is_symlink():
                write_private_json_exclusive(self.store, history, genesis)
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "UPDATE ledger_meta SET anchor_digest = ? WHERE singleton = 1",
                    (str(genesis["receipt_digest"]),),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            meta = conn.execute(
                "SELECT * FROM ledger_meta WHERE singleton = 1"
            ).fetchone()
        if not self.anchor_path.exists() and not self.anchor_path.is_symlink():
            if (
                int(meta["anchor_revision"]) != 0
                or str(meta["anchor_digest"])
                or not empty_state
            ):
                raise RuntimeError("replication ledger anchor is missing")
            anchor = self._signed_anchor(conn, revision=0, previous_digest=None)
            write_private_json_exclusive(self.store, self.anchor_path, anchor)
            write_private_json_exclusive(
                self.store,
                self.anchor_history_root / "anchor-00000000000000000000.receipt.json",
                anchor,
            )
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "UPDATE ledger_meta SET anchor_digest = ? WHERE singleton = 1",
                    (str(anchor["receipt_digest"]),),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _validate_anchor_history(
        self,
        anchor: dict[str, Any],
        *,
        full_chain: bool = False,
        maximum: int = MAX_LEDGER_ANCHORS,
    ) -> None:
        revision = int(anchor["revision"])
        if (
            type(maximum) is not int
            or maximum < 0
            or maximum > MAX_LEDGER_ANCHORS
            or revision > MAX_LEDGER_ANCHORS
        ):
            raise RuntimeError("replication ledger anchor history exceeds its bound")
        _node_id, public_key, key_id = self._local_signing_identity()
        latest_path = self.anchor_history_root / f"anchor-{revision:020d}.receipt.json"
        self._validate_private_regular(latest_path)
        latest = validate_ledger_anchor(
            read_private_json(latest_path),
            expected_public_key=public_key,
            expected_key_id=key_id,
        )
        if not secrets.compare_digest(
            str(latest["receipt_digest"]), str(anchor["receipt_digest"])
        ):
            raise RuntimeError("replication ledger rolled back behind anchor history")
        if not full_chain:
            return
        if revision > maximum:
            raise RuntimeError(
                "replication full anchor-history audit exceeds its requested bound"
            )
        revisions: set[int] = set()
        with os.scandir(self.anchor_history_root) as entries:
            for entry in entries:
                name = entry.name
                if (
                    len(name) != len("anchor-00000000000000000000.receipt.json")
                    or not name.startswith("anchor-")
                    or not name.endswith(".receipt.json")
                ):
                    raise RuntimeError(
                        "replication ledger anchor history contains an invalid entry"
                    )
                number_text = name[len("anchor-") : -len(".receipt.json")]
                if not number_text.isdigit():
                    raise RuntimeError(
                        "replication ledger anchor history contains an invalid entry"
                    )
                number = int(number_text)
                if number > revision or number in revisions:
                    raise RuntimeError("replication ledger anchor history is inconsistent")
                revisions.add(number)
                if (
                    len(revisions) > revision + 1
                    or len(revisions) > MAX_LEDGER_ANCHORS + 1
                ):
                    raise RuntimeError("replication ledger anchor history is unbounded")
        if len(revisions) != revision + 1 or any(
            number not in revisions for number in range(revision + 1)
        ):
            raise RuntimeError("replication ledger anchor history is incomplete")
        previous_digest: str | None = None
        audited_latest: dict[str, Any] | None = None
        for number in range(revision + 1):
            path = self.anchor_history_root / f"anchor-{number:020d}.receipt.json"
            self._validate_private_regular(path)
            current = validate_ledger_anchor(
                read_private_json(path),
                expected_public_key=public_key,
                expected_key_id=key_id,
            )
            if (
                int(current["revision"]) != number
                or current["previous_anchor_digest"] != previous_digest
            ):
                raise RuntimeError("replication ledger anchor history chain is invalid")
            previous_digest = str(current["receipt_digest"])
            audited_latest = current
        if audited_latest is None:
            raise RuntimeError("replication ledger anchor history is missing")
        if not secrets.compare_digest(
            str(audited_latest["receipt_digest"]), str(anchor["receipt_digest"])
        ):
            raise RuntimeError("replication ledger rolled back behind anchor history")

    def audit_anchor_history(
        self,
        *,
        maximum: int = MAX_LEDGER_ANCHORS,
    ) -> dict[str, Any]:
        with self.manager_lock():
            with self._read_transaction() as conn:
                anchor = self._validate_anchor(conn)
                self._validate_anchor_history(
                    anchor,
                    full_chain=True,
                    maximum=maximum,
                )
                return {
                    "schema": "synapse-s2.replication-anchor-history-audit.v1",
                    "revision": int(anchor["revision"]),
                    "anchor_digest": str(anchor["receipt_digest"]),
                    "validated_receipt_count": int(anchor["revision"]) + 1,
                    "full_chain_verified": True,
                }

    def _validate_anchor(self, conn: sqlite3.Connection) -> dict[str, Any]:
        self._validate_private_regular(self.anchor_path)
        meta = conn.execute("SELECT * FROM ledger_meta WHERE singleton = 1").fetchone()
        if meta is None:
            raise RuntimeError("replication ledger anchor metadata is missing")
        _node_id, public_key, key_id = self._local_signing_identity()
        anchor = validate_ledger_anchor(
            read_private_json(self.anchor_path),
            expected_public_key=public_key,
            expected_key_id=key_id,
        )
        if (
            type(meta["anchor_revision"]) is not int
            or int(meta["anchor_revision"]) != int(anchor["revision"])
            or not secrets.compare_digest(
                str(meta["anchor_digest"]), str(anchor["receipt_digest"])
            )
            or meta["previous_anchor_digest"] != anchor["previous_anchor_digest"]
            or not secrets.compare_digest(
                self._snapshot_digest(conn), str(anchor["ledger_snapshot_sha256"])
            )
        ):
            raise RuntimeError("replication ledger state does not match its signed anchor")
        self._validate_anchor_history(anchor)
        self._validate_high_water_witness(conn, anchor)
        return anchor

    def _validate_schema(self, conn: sqlite3.Connection) -> None:
        application_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        integrity = [str(row[0]) for row in conn.execute("PRAGMA integrity_check")]
        foreign_key_failures = list(conn.execute("PRAGMA foreign_key_check"))
        actual = frozenset(
            _normalize_sql(str(row[0]))
            for row in conn.execute(
                """
                SELECT sql
                FROM sqlite_schema
                WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
                ORDER BY type, name
                """
            )
        )
        if (
            application_id != REPLICATION_LEDGER_APPLICATION_ID
            or user_version != REPLICATION_LEDGER_USER_VERSION
            or integrity != ["ok"]
            or foreign_key_failures
            or actual != EXPECTED_SCHEMA_SQL
        ):
            raise RuntimeError("replication ledger schema or integrity is invalid")
        self._validate_resource_bounds(conn)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(self._open()) as conn:
            self._validate_schema(conn)
            self._initialize_or_recover_anchor(conn)
            self._validate_anchor(conn)
            conn.execute("BEGIN IMMEDIATE")
            prepared = False
            try:
                # Revalidate after acquiring the SQLite writer lock so a
                # direct bypass writer cannot race between validation and the
                # authenticated state transition.
                current_anchor = self._validate_anchor(conn)
                if int(current_anchor["revision"]) >= MAX_LEDGER_ANCHORS:
                    raise RuntimeError(
                        "replication ledger anchor revision is exhausted"
                    )
                yield conn
                next_revision = int(current_anchor["revision"]) + 1
                next_anchor = self._signed_anchor(
                    conn,
                    revision=next_revision,
                    previous_digest=str(current_anchor["receipt_digest"]),
                )
                write_private_json_exclusive(
                    self.store, self.pending_anchor_path, next_anchor
                )
                prepared = True
                conn.execute(
                    """
                    UPDATE ledger_meta
                    SET anchor_revision = ?, anchor_digest = ?, previous_anchor_digest = ?
                    WHERE singleton = 1
                    """,
                    (
                        next_revision,
                        str(next_anchor["receipt_digest"]),
                        str(current_anchor["receipt_digest"]),
                    ),
                )
                conn.execute("COMMIT")
                self._advance_neutral_high_water(next_anchor)
                self._advance_high_water_witness(next_anchor)
                self._publish_pending_anchor()
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                if prepared and self.pending_anchor_path.exists():
                    # If COMMIT succeeded, preserve the pending signed anchor so
                    # the next open can reconcile it with the committed DB.
                    meta = conn.execute(
                        "SELECT anchor_revision FROM ledger_meta WHERE singleton = 1"
                    ).fetchone()
                    if meta is not None and int(meta[0]) == int(current_anchor["revision"]):
                        self.pending_anchor_path.unlink(missing_ok=True)
                        self.store._fsync_directory(self.root)
                raise

    def _validate_integrity(self, conn: sqlite3.Connection) -> None:
        self._validate_schema(conn)
        self._initialize_or_recover_anchor(conn)
        self._validate_anchor(conn)

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        with closing(self._open()) as conn:
            self._validate_schema(conn)
            self._initialize_or_recover_anchor(conn)
            conn.execute("BEGIN")
            try:
                self._validate_schema(conn)
                self._validate_anchor(conn)
                yield conn
            finally:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return None if row is None else dict(row)

    def peer(self, peer_id: str) -> dict[str, Any] | None:
        with self._read_transaction() as conn:
            return self._row(
                conn.execute(
                    "SELECT * FROM peers WHERE peer_id = ?", (peer_id,)
                ).fetchone()
            )

    def peers_for_integrity(self, *, maximum: int = 10_000) -> list[dict[str, Any]]:
        if type(maximum) is not int or maximum < 1 or maximum > 10_000:
            raise ReplicationProtocolError("peer integrity bound is invalid")
        with self._read_transaction() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0])
            if count > maximum:
                raise RuntimeError("replication peer integrity scan exceeds its bound")
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM peers ORDER BY paired_at, peer_id"
                )
            ]

    def pair_peer(
        self,
        *,
        peer_id: str,
        lineage_id: str,
        direction: str,
        signing_key_id: str,
        signing_public_key: str,
        descriptor_digest: str,
        now: float,
        audit: bool = False,
    ) -> dict[str, Any]:
        if (
            NODE_ID_RE.fullmatch(peer_id) is None
            or LINEAGE_ID_RE.fullmatch(lineage_id) is None
        ):
            raise ReplicationProtocolError("peer identity is invalid")
        if direction not in {"send", "receive"}:
            raise ReplicationProtocolError("peer direction is invalid")
        if (
            DIGEST_RE.fullmatch(signing_key_id) is None
            or DIGEST_RE.fullmatch(descriptor_digest) is None
        ):
            raise ReplicationProtocolError("peer key or descriptor digest is invalid")
        try:
            decoded_public = base64.b64decode(signing_public_key, validate=True)
        except (TypeError, ValueError) as exc:
            raise ReplicationProtocolError("peer signing key encoding is invalid") from exc
        if len(decoded_public) != 32:
            raise ReplicationProtocolError("peer signing key is invalid")
        with self._transaction() as conn:
            existing = self._row(
                conn.execute("SELECT * FROM peers WHERE peer_id = ?", (peer_id,)).fetchone()
            )
            lineage_owner = self._row(
                conn.execute(
                    "SELECT * FROM peers WHERE lineage_id = ? AND direction = ?",
                    (lineage_id, direction),
                ).fetchone()
            )
            if existing is not None:
                immutable = (
                    existing["lineage_id"],
                    existing["direction"],
                    existing["signing_key_id"],
                    existing["signing_public_key"],
                    existing["descriptor_digest"],
                )
                proposed = (
                    lineage_id,
                    direction,
                    signing_key_id,
                    signing_public_key,
                    descriptor_digest,
                )
                if immutable != proposed:
                    raise ReplicationProtocolError("peer identity conflicts with its pinned record")
                if audit:
                    self._insert_audit_conn(
                        conn,
                        action="pair-peer",
                        state="accepted",
                        peer_id=peer_id,
                        lineage_id=lineage_id,
                        checkpoint_digest=None,
                        detail_code="idempotent-pinned-descriptor",
                        now=now,
                    )
                return existing
            if lineage_owner is not None:
                raise ReplicationProtocolError("replication lineage is already paired")
            conn.execute(
                """
                INSERT INTO peers(
                    peer_id, lineage_id, direction, signing_key_id,
                    signing_public_key, descriptor_digest, revoked,
                    revoke_reason, paired_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)
                """,
                (
                    peer_id,
                    lineage_id,
                    direction,
                    signing_key_id,
                    signing_public_key,
                    descriptor_digest,
                    now,
                    now,
                ),
            )
            record = dict(
                conn.execute(
                    "SELECT * FROM peers WHERE peer_id = ?", (peer_id,)
                ).fetchone()
            )
            if audit:
                self._insert_audit_conn(
                    conn,
                    action="pair-peer",
                    state="accepted",
                    peer_id=peer_id,
                    lineage_id=lineage_id,
                    checkpoint_digest=None,
                    detail_code="descriptor-key-pinned",
                    now=now,
                )
            return record

    def update_peer_descriptor(
        self,
        peer_id: str,
        *,
        previous_descriptor_digest: str,
        descriptor_digest: str,
        signing_key_id: str,
        signing_public_key: str,
        now: float,
        audit: bool = False,
    ) -> dict[str, Any]:
        """Compare-and-swap a peer's pinned descriptor digest, audited.

        A capability upgrade re-pins a newer descriptor signed by the exact
        same peer key. Identity, lineage, direction, and signing key remain
        immutable; only the reviewed descriptor digest advances, and only
        when the caller names the currently pinned digest.
        """

        if NODE_ID_RE.fullmatch(peer_id) is None:
            raise ReplicationProtocolError("peer identity is invalid")
        if (
            DIGEST_RE.fullmatch(previous_descriptor_digest) is None
            or DIGEST_RE.fullmatch(descriptor_digest) is None
            or DIGEST_RE.fullmatch(signing_key_id) is None
        ):
            raise ReplicationProtocolError("peer descriptor digest is invalid")
        if previous_descriptor_digest == descriptor_digest:
            raise ReplicationProtocolError(
                "peer descriptor upgrade requires a new descriptor digest"
            )
        with self._transaction() as conn:
            existing = self._row(
                conn.execute(
                    "SELECT * FROM peers WHERE peer_id = ?", (peer_id,)
                ).fetchone()
            )
            if existing is None:
                raise ReplicationProtocolError("replication peer is unknown")
            if bool(existing["revoked"]):
                raise ReplicationProtocolError("replication peer is revoked")
            if (
                existing["descriptor_digest"] != previous_descriptor_digest
                or existing["signing_key_id"] != signing_key_id
                or existing["signing_public_key"] != signing_public_key
            ):
                raise ReplicationProtocolError(
                    "peer descriptor upgrade does not match the pinned record"
                )
            updated = conn.execute(
                """
                UPDATE peers SET descriptor_digest = ?, updated_at = ?
                WHERE peer_id = ? AND descriptor_digest = ? AND revoked = 0
                """,
                (descriptor_digest, float(now), peer_id, previous_descriptor_digest),
            )
            if updated.rowcount != 1:
                raise ReplicationProtocolError(
                    "peer descriptor upgrade lost its compare-and-swap race"
                )
            record = dict(
                conn.execute(
                    "SELECT * FROM peers WHERE peer_id = ?", (peer_id,)
                ).fetchone()
            )
            if audit:
                # Action-specific meaning: for upgrade-peer-descriptor audit
                # rows the checkpoint_digest column records the reviewed
                # PREVIOUS descriptor digest the compare-and-swap replaced.
                # The row is written in the same transaction as the CAS and
                # is covered by the anchored snapshot digest, so it is the
                # authenticated predecessor record replays and integrity
                # checks must bind to.
                self._insert_audit_conn(
                    conn,
                    action="upgrade-peer-descriptor",
                    state="accepted",
                    peer_id=peer_id,
                    lineage_id=str(existing["lineage_id"]),
                    checkpoint_digest=previous_descriptor_digest,
                    detail_code="capability-descriptor-upgraded",
                    now=now,
                )
            return record

    def peer_descriptor_predecessor(self, peer_id: str) -> str | None:
        """Return the anchored predecessor digest of a peer's descriptor CAS.

        The predecessor is recorded in the upgrade-peer-descriptor audit row
        written in the same transaction as the compare-and-swap (see
        update_peer_descriptor); None means the pinned descriptor was never
        upgraded. The protocol upgrades a pin baseline->full at most once, so
        the latest accepted row maps unambiguously to the current pin.
        """

        if NODE_ID_RE.fullmatch(peer_id) is None:
            raise ReplicationProtocolError("peer identity is invalid")
        with self._read_transaction() as conn:
            row = conn.execute(
                """
                SELECT checkpoint_digest FROM audit_events
                WHERE action = 'upgrade-peer-descriptor'
                    AND state = 'accepted' AND peer_id = ?
                ORDER BY event_id DESC LIMIT 1
                """,
                (peer_id,),
            ).fetchone()
        if row is None:
            return None
        previous = str(row[0] or "")
        if DIGEST_RE.fullmatch(previous) is None:
            raise ReplicationProtocolError(
                "peer descriptor upgrade audit predecessor is invalid"
            )
        return previous

    def revoke_peer(
        self,
        peer_id: str,
        *,
        reason: str,
        now: float,
        audit_action: str | None = None,
        audit_detail_code: str | None = None,
        checkpoint_digest: str | None = None,
    ) -> dict[str, Any]:
        if not reason or len(reason.encode("utf-8")) > 128:
            raise ReplicationProtocolError("revocation reason is invalid")
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM peers WHERE peer_id = ?", (peer_id,)).fetchone()
            if row is None:
                raise ReplicationProtocolError("replication peer is unknown")
            conn.execute(
                "UPDATE peers SET revoked = 1, revoke_reason = ?, updated_at = ? WHERE peer_id = ?",
                (reason, now, peer_id),
            )
            record = dict(
                conn.execute(
                    "SELECT * FROM peers WHERE peer_id = ?", (peer_id,)
                ).fetchone()
            )
            if audit_action is not None:
                self._insert_audit_conn(
                    conn,
                    action=audit_action,
                    state="revoked",
                    peer_id=peer_id,
                    lineage_id=str(record["lineage_id"]),
                    checkpoint_digest=checkpoint_digest,
                    detail_code=(audit_detail_code or "peer-revoked"),
                    now=now,
                )
            return record

    def latest_checkpoint(self, *, lineage_id: str, direction: str) -> dict[str, Any] | None:
        with self._read_transaction() as conn:
            return self._row(
                conn.execute(
                    """
                    SELECT * FROM checkpoints
                    WHERE lineage_id = ? AND direction = ?
                    ORDER BY term DESC, sequence DESC
                    LIMIT 1
                    """,
                    (lineage_id, direction),
                ).fetchone()
            )

    def checkpoint_at(
        self, *, lineage_id: str, direction: str, term: int, sequence: int
    ) -> dict[str, Any] | None:
        with self._read_transaction() as conn:
            return self._row(
                conn.execute(
                    """
                    SELECT * FROM checkpoints
                    WHERE lineage_id = ? AND direction = ? AND term = ? AND sequence = ?
                    """,
                    (lineage_id, direction, term, sequence),
                ).fetchone()
            )

    def checkpoint(self, checkpoint_digest: str) -> dict[str, Any] | None:
        with self._read_transaction() as conn:
            return self._row(
                conn.execute(
                    "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                    (checkpoint_digest,),
                ).fetchone()
            )

    def checkpoints_for_integrity(self, *, maximum: int = 10_000) -> list[dict[str, Any]]:
        if type(maximum) is not int or maximum < 1 or maximum > 10_000:
            raise ReplicationProtocolError("checkpoint integrity bound is invalid")
        with self._read_transaction() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0])
            if count > maximum:
                raise RuntimeError("replication checkpoint integrity scan exceeds its bound")
            records = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT * FROM checkpoints
                    ORDER BY lineage_id, direction, term, sequence
                    """
                )
            ]
            for record in records:
                self._validate_checkpoint_row_manifest(conn, record, initial=False)
            return records

    def _validate_checkpoint_row_manifest(
        self,
        conn: sqlite3.Connection,
        row: dict[str, Any],
        *,
        initial: bool,
        peer: sqlite3.Row | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if peer is None:
            peer = conn.execute(
                "SELECT * FROM peers WHERE peer_id = ?",
                (str(row.get("peer_id") or ""),),
            ).fetchone()
        if peer is None:
            raise ReplicationProtocolError("checkpoint peer is unknown")
        direction = str(row.get("direction") or "")
        lineage_id = str(row.get("lineage_id") or "")
        checkpoint_id = str(row.get("checkpoint_id") or "")
        if direction not in {"outgoing", "incoming"}:
            raise ReplicationProtocolError("checkpoint direction is invalid")
        local_node_id, local_public_key, local_key_id = (
            self._local_signing_identity()
        )
        if direction == "outgoing":
            expected_source = local_node_id
            expected_target = str(peer["peer_id"])
            expected_public_key = local_public_key
            expected_key_id = local_key_id
            checkpoint_root = (
                self.root / "outgoing" / lineage_id / checkpoint_id
            )
            expected_restore_root: str | None = None
            allowed_states = {"exported", "acknowledged", "rejected"}
            initial_state = "exported"
        else:
            expected_source = str(peer["peer_id"])
            expected_target = local_node_id
            expected_public_key = str(peer["signing_public_key"])
            expected_key_id = str(peer["signing_key_id"])
            checkpoint_root = (
                self.root / "incoming" / lineage_id / checkpoint_id
            )
            expected_restore_root = str(
                self.root / "staged" / lineage_id / checkpoint_id
            )
            allowed_states = {"staged", "rejected"}
            initial_state = "staged"
        manifest_path = checkpoint_root / "checkpoint.manifest.json"
        self._validate_private_regular(manifest_path)
        manifest = validate_checkpoint(
            read_private_json(manifest_path),
            expected_public_key=expected_public_key,
            expected_key_id=expected_key_id,
        )
        state = str(row.get("state") or "")
        if (
            str(row.get("manifest_path") or "") != str(manifest_path)
            or row.get("restore_root") != expected_restore_root
            or state not in allowed_states
            or (initial and state != initial_state)
            or str(peer["lineage_id"]) != lineage_id
            or str(peer["direction"])
            != ("send" if direction == "outgoing" else "receive")
            or manifest.get("receipt_digest") != row.get("checkpoint_digest")
            or manifest.get("checkpoint_id") != checkpoint_id
            or manifest.get("lineage_id") != lineage_id
            or manifest.get("source_node_id") != expected_source
            or manifest.get("target_node_id") != expected_target
            or int(manifest.get("term", -1)) != int(row.get("term", -2))
            or int(manifest.get("sequence", -1)) != int(row.get("sequence", -2))
            or manifest.get("parent_checkpoint_digest")
            != row.get("parent_checkpoint_digest")
            or manifest.get("bundle_receipt_digest")
            != row.get("bundle_receipt_digest")
            or manifest.get("source_store_identity")
            != row.get("source_store_identity")
            or manifest.get("store_generation") != row.get("store_generation")
            or int(manifest.get("authority_epoch_number", -1))
            != int(row.get("authority_epoch_number", -2))
        ):
            raise ReplicationProtocolError(
                "checkpoint ledger row does not match its signed manifest"
            )
        return manifest

    def record_checkpoint(
        self,
        *,
        checkpoint_digest: str,
        checkpoint_id: str,
        lineage_id: str,
        direction: str,
        peer_id: str,
        term: int,
        sequence: int,
        parent_checkpoint_digest: str | None,
        bundle_receipt_digest: str,
        source_store_identity: str,
        store_generation: str,
        authority_epoch_number: int,
        manifest_path: str,
        restore_root: str | None,
        state: str,
        now: float,
        audit_action: str | None = None,
        audit_detail_code: str | None = None,
    ) -> dict[str, Any]:
        with self._transaction() as conn:
            peer = conn.execute(
                "SELECT * FROM peers WHERE peer_id = ?", (peer_id,)
            ).fetchone()
            if peer is None or str(peer["lineage_id"]) != lineage_id:
                raise ReplicationProtocolError("checkpoint peer lineage is not pinned")
            proposed_record = {
                "checkpoint_digest": checkpoint_digest,
                "checkpoint_id": checkpoint_id,
                "lineage_id": lineage_id,
                "direction": direction,
                "peer_id": peer_id,
                "term": term,
                "sequence": sequence,
                "parent_checkpoint_digest": parent_checkpoint_digest,
                "bundle_receipt_digest": bundle_receipt_digest,
                "source_store_identity": source_store_identity,
                "store_generation": store_generation,
                "authority_epoch_number": authority_epoch_number,
                "manifest_path": manifest_path,
                "restore_root": restore_root,
                "state": state,
            }
            self._validate_checkpoint_row_manifest(
                conn,
                proposed_record,
                initial=True,
            )
            if (
                not source_store_identity
                or not store_generation
                or type(authority_epoch_number) is not int
                or authority_epoch_number < 1
                or store_generation != f"epoch-{authority_epoch_number}"
            ):
                raise ReplicationProtocolError("checkpoint source lineage is invalid")
            pinned_identity = peer["source_store_identity"]
            pinned_epoch = peer["source_authority_epoch"]
            if pinned_identity is None:
                conn.execute(
                    """
                    UPDATE peers
                    SET source_store_identity = ?, source_store_generation = ?,
                        source_authority_epoch = ?, updated_at = ?
                    WHERE peer_id = ?
                    """,
                    (
                        source_store_identity,
                        store_generation,
                        authority_epoch_number,
                        now,
                        peer_id,
                    ),
                )
            elif (
                str(pinned_identity) != source_store_identity
                or type(pinned_epoch) is not int
                or authority_epoch_number < int(pinned_epoch)
            ):
                raise ReplicationProtocolError(
                    "checkpoint source identity or authority epoch rolled back"
                )
            elif authority_epoch_number > int(pinned_epoch):
                conn.execute(
                    """
                    UPDATE peers
                    SET source_store_generation = ?, source_authority_epoch = ?, updated_at = ?
                    WHERE peer_id = ?
                    """,
                    (store_generation, authority_epoch_number, now, peer_id),
                )
            existing = self._row(
                conn.execute(
                    "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                    (checkpoint_digest,),
                ).fetchone()
            )
            if existing is not None:
                immutable = (
                    existing["checkpoint_id"],
                    existing["lineage_id"],
                    existing["direction"],
                    existing["peer_id"],
                    int(existing["term"]),
                    int(existing["sequence"]),
                    existing["parent_checkpoint_digest"],
                    existing["bundle_receipt_digest"],
                    existing["source_store_identity"],
                    existing["store_generation"],
                    int(existing["authority_epoch_number"]),
                )
                proposed = (
                    checkpoint_id,
                    lineage_id,
                    direction,
                    peer_id,
                    term,
                    sequence,
                    parent_checkpoint_digest,
                    bundle_receipt_digest,
                    source_store_identity,
                    store_generation,
                    authority_epoch_number,
                )
                if immutable != proposed:
                    raise ReplicationProtocolError("checkpoint digest conflicts with ledger state")
                if audit_action is not None and audit_detail_code is not None:
                    self._insert_audit_conn(
                        conn,
                        action=audit_action,
                        state=state,
                        peer_id=peer_id,
                        lineage_id=lineage_id,
                        checkpoint_digest=checkpoint_digest,
                        detail_code=audit_detail_code,
                        now=now,
                    )
                return existing
            conn.execute(
                """
                INSERT INTO checkpoints(
                    checkpoint_digest, checkpoint_id, lineage_id, direction,
                    peer_id, term, sequence, parent_checkpoint_digest,
                    bundle_receipt_digest, source_store_identity,
                    store_generation, authority_epoch_number,
                    manifest_path, restore_root, state,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint_digest,
                    checkpoint_id,
                    lineage_id,
                    direction,
                    peer_id,
                    term,
                    sequence,
                    parent_checkpoint_digest,
                    bundle_receipt_digest,
                    source_store_identity,
                    store_generation,
                    authority_epoch_number,
                    manifest_path,
                    restore_root,
                    state,
                    now,
                    now,
                ),
            )
            record = dict(
                conn.execute(
                    "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                    (checkpoint_digest,),
                ).fetchone()
            )
            if audit_action is not None and audit_detail_code is not None:
                self._insert_audit_conn(
                    conn,
                    action=audit_action,
                    state=state,
                    peer_id=peer_id,
                    lineage_id=lineage_id,
                    checkpoint_digest=checkpoint_digest,
                    detail_code=audit_detail_code,
                    now=now,
                )
            return record

    def set_checkpoint_state(
        self,
        checkpoint_digest: str,
        *,
        state: str,
        restore_root: str | None = None,
        now: float,
    ) -> dict[str, Any]:
        if state not in {"exported", "staged", "acknowledged", "rejected"}:
            raise ReplicationProtocolError("checkpoint state is invalid")
        with self._transaction() as conn:
            current = conn.execute(
                "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                (checkpoint_digest,),
            ).fetchone()
            if current is None:
                raise ReplicationProtocolError("checkpoint is unknown")
            self._validate_checkpoint_row_manifest(
                conn,
                dict(current),
                initial=False,
            )
            current_state = str(current["state"])
            direction = str(current["direction"])
            allowed_transitions = (
                {
                    "exported": {"exported", "acknowledged", "rejected"},
                    "acknowledged": {"acknowledged"},
                    "rejected": {"rejected"},
                }
                if direction == "outgoing"
                else {
                    "staged": {"staged", "rejected"},
                    "rejected": {"rejected"},
                }
            )
            if state not in allowed_transitions.get(current_state, set()):
                raise ReplicationProtocolError(
                    "checkpoint state transition is invalid"
                )
            conn.execute(
                """
                UPDATE checkpoints
                SET state = ?, restore_root = COALESCE(?, restore_root), updated_at = ?
                WHERE checkpoint_digest = ?
                """,
                (state, restore_root, now, checkpoint_digest),
            )
            updated = dict(
                conn.execute(
                    "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                    (checkpoint_digest,),
                ).fetchone()
            )
            self._validate_checkpoint_row_manifest(
                conn,
                updated,
                initial=False,
            )
            return updated

    def acknowledgement_for_checkpoint(self, checkpoint_digest: str) -> dict[str, Any] | None:
        with self._read_transaction() as conn:
            return self._row(
                conn.execute(
                    "SELECT * FROM acknowledgements WHERE checkpoint_digest = ?",
                    (checkpoint_digest,),
                ).fetchone()
            )

    def _validate_ack_row_document(
        self,
        conn: sqlite3.Connection,
        row: dict[str, Any],
        *,
        checkpoint: sqlite3.Row | dict[str, Any] | None = None,
        peer: sqlite3.Row | dict[str, Any] | None = None,
        resulting_checkpoint_state: str | None = None,
    ) -> dict[str, Any]:
        checkpoint_digest = str(row.get("checkpoint_digest") or "")
        if checkpoint is None:
            checkpoint = conn.execute(
                "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                (checkpoint_digest,),
            ).fetchone()
        if checkpoint is None:
            raise ReplicationProtocolError("checkpoint is unknown")
        if peer is None:
            peer = conn.execute(
                "SELECT * FROM peers WHERE peer_id = ?",
                (str(checkpoint["peer_id"]),),
            ).fetchone()
        if peer is None:
            raise ReplicationProtocolError("checkpoint peer is unknown")
        local_node_id, local_public_key, local_key_id = (
            self._local_signing_identity()
        )
        outgoing = str(checkpoint["direction"]) == "outgoing"
        receiver_node_id = str(peer["peer_id"]) if outgoing else local_node_id
        source_node_id = local_node_id if outgoing else str(peer["peer_id"])
        expected_ack_id = ack_id_for(
            checkpoint_digest=checkpoint_digest,
            receiver_node_id=receiver_node_id,
        )
        expected_path = (
            self.root
            / "acks"
            / str(checkpoint["lineage_id"])
            / (
                f"received-{expected_ack_id}.json"
                if outgoing
                else f"{expected_ack_id}.json"
            )
        )
        self._validate_private_regular(expected_path)
        ack = validate_ack(
            read_private_json(expected_path),
            expected_public_key=(
                str(peer["signing_public_key"])
                if outgoing
                else local_public_key
            ),
            expected_key_id=(
                str(peer["signing_key_id"])
                if outgoing
                else local_key_id
            ),
        )
        state = (
            str(resulting_checkpoint_state)
            if resulting_checkpoint_state is not None
            else str(checkpoint["state"])
        )
        if (
            row.get("ack_id") != expected_ack_id
            or row.get("ack_id") != ack.get("ack_id")
            or row.get("ack_digest") != ack.get("receipt_digest")
            or row.get("checkpoint_digest") != checkpoint["checkpoint_digest"]
            or row.get("peer_id") != checkpoint["peer_id"]
            or row.get("ack_path") != str(expected_path)
            or float(row.get("created_at", -1.0))
            != float(ack.get("acked_at", -2.0))
            or ack.get("checkpoint_id") != checkpoint["checkpoint_id"]
            or ack.get("lineage_id") != checkpoint["lineage_id"]
            or int(ack.get("term", -1)) != int(checkpoint["term"])
            or int(ack.get("sequence", -1)) != int(checkpoint["sequence"])
            or ack.get("source_node_id") != source_node_id
            or ack.get("receiver_node_id") != receiver_node_id
            or ack.get("bundle_receipt_digest")
            != checkpoint["bundle_receipt_digest"]
            or ack.get("memory_recovery_cutover_ready") is not True
            or (outgoing and state != "acknowledged")
            or (not outgoing and state not in {"staged", "acknowledged"})
        ):
            raise ReplicationProtocolError(
                "acknowledgement ledger row does not match its signed document"
            )
        return ack

    def record_acknowledgement(
        self,
        *,
        ack_digest: str,
        ack_id: str,
        checkpoint_digest: str,
        peer_id: str,
        ack_path: str,
        now: float,
        checkpoint_state: str | None = None,
        audit_action: str | None = None,
        audit_detail_code: str | None = None,
    ) -> dict[str, Any]:
        with self._transaction() as conn:
            checkpoint = conn.execute(
                "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                (checkpoint_digest,),
            ).fetchone()
            if checkpoint is None:
                raise ReplicationProtocolError("checkpoint is unknown")
            if str(checkpoint["peer_id"]) != peer_id:
                raise ReplicationProtocolError(
                    "checkpoint acknowledgement peer does not match its checkpoint"
                )
            local_node_id, _public_key, _key_id = self._local_signing_identity()
            receiver_node_id = (
                peer_id
                if str(checkpoint["direction"]) == "outgoing"
                else local_node_id
            )
            expected_ack_id = ack_id_for(
                checkpoint_digest=checkpoint_digest,
                receiver_node_id=receiver_node_id,
            )
            if (
                DIGEST_RE.fullmatch(ack_digest) is None
                or DIGEST_RE.fullmatch(checkpoint_digest) is None
                or ACK_ID_RE.fullmatch(ack_id) is None
                or ack_id != expected_ack_id
                or not ack_path
                or isinstance(now, bool)
                or not isinstance(now, (int, float))
                or not math.isfinite(float(now))
                or float(now) <= 0
            ):
                raise ReplicationProtocolError(
                    "checkpoint acknowledgement contract is invalid"
                )
            resulting_state = (
                checkpoint_state
                if checkpoint_state is not None
                else str(checkpoint["state"])
            )
            if (
                str(checkpoint["direction"]) == "outgoing"
                and resulting_state != "acknowledged"
            ) or (
                str(checkpoint["direction"]) == "incoming"
                and resulting_state not in {"staged", "acknowledged"}
            ):
                raise ReplicationProtocolError(
                    "checkpoint acknowledgement state is inconsistent"
                )
            proposed_ack = {
                "ack_digest": ack_digest,
                "ack_id": ack_id,
                "checkpoint_digest": checkpoint_digest,
                "peer_id": peer_id,
                "ack_path": ack_path,
                "created_at": float(now),
            }
            self._validate_ack_row_document(
                conn,
                proposed_ack,
                checkpoint=checkpoint,
                resulting_checkpoint_state=resulting_state,
            )
            existing = self._row(
                conn.execute(
                    "SELECT * FROM acknowledgements WHERE checkpoint_digest = ?",
                    (checkpoint_digest,),
                ).fetchone()
            )
            if existing is not None:
                if (
                    existing["ack_digest"] != ack_digest
                    or existing["ack_id"] != ack_id
                    or existing["peer_id"] != peer_id
                    or existing["ack_path"] != ack_path
                    or float(existing["created_at"]) != float(now)
                ):
                    raise ReplicationProtocolError(
                        "checkpoint acknowledgement conflicts with ledger state"
                    )
                record = existing
            else:
                conn.execute(
                    """
                    INSERT INTO acknowledgements(
                        ack_digest, ack_id, checkpoint_digest, peer_id, ack_path, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (ack_digest, ack_id, checkpoint_digest, peer_id, ack_path, now),
                )
                record = dict(
                    conn.execute(
                        "SELECT * FROM acknowledgements WHERE checkpoint_digest = ?",
                        (checkpoint_digest,),
                    ).fetchone()
                )
            if checkpoint_state is not None:
                if checkpoint_state not in {"exported", "staged", "acknowledged", "rejected"}:
                    raise ReplicationProtocolError("checkpoint state is invalid")
                changed = conn.execute(
                    "UPDATE checkpoints SET state = ?, updated_at = ? WHERE checkpoint_digest = ?",
                    (checkpoint_state, now, checkpoint_digest),
                ).rowcount
                if changed != 1:
                    raise ReplicationProtocolError("checkpoint is unknown")
                checkpoint = conn.execute(
                    "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                    (checkpoint_digest,),
                ).fetchone()
                if checkpoint is None:
                    raise ReplicationProtocolError("checkpoint is unknown")
                self._validate_checkpoint_row_manifest(
                    conn,
                    dict(checkpoint),
                    initial=False,
                )
            persisted_checkpoint = conn.execute(
                "SELECT * FROM checkpoints WHERE checkpoint_digest = ?",
                (checkpoint_digest,),
            ).fetchone()
            if persisted_checkpoint is None:
                raise ReplicationProtocolError("checkpoint is unknown")
            self._validate_ack_row_document(
                conn,
                record,
                checkpoint=persisted_checkpoint,
            )
            if audit_action is not None and audit_detail_code is not None:
                self._insert_audit_conn(
                    conn,
                    action=audit_action,
                    state=(checkpoint_state or "staged"),
                    peer_id=peer_id,
                    lineage_id=str(checkpoint["lineage_id"]),
                    checkpoint_digest=checkpoint_digest,
                    detail_code=audit_detail_code,
                    now=now,
                )
            return record

    def audit(
        self,
        *,
        action: str,
        state: str,
        detail_code: str,
        peer_id: str | None = None,
        lineage_id: str | None = None,
        checkpoint_digest: str | None = None,
        now: float | None = None,
    ) -> None:
        with self._transaction() as conn:
            self._insert_audit_conn(
                conn,
                action=action,
                state=state,
                detail_code=detail_code,
                peer_id=peer_id,
                lineage_id=lineage_id,
                checkpoint_digest=checkpoint_digest,
                now=float(now if now is not None else time.time()),
            )

    @staticmethod
    def _insert_audit_conn(
        conn: sqlite3.Connection,
        *,
        action: str,
        state: str,
        detail_code: str,
        peer_id: str | None,
        lineage_id: str | None,
        checkpoint_digest: str | None,
        now: float,
    ) -> None:
        for label, value in (("action", action), ("state", state), ("detail", detail_code)):
            if not value or len(value.encode("utf-8")) > 64:
                raise ReplicationProtocolError(f"audit {label} is invalid")
        conn.execute(
            """
            INSERT INTO audit_events(
                action, state, peer_id, lineage_id, checkpoint_digest,
                detail_code, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action,
                state,
                peer_id,
                lineage_id,
                checkpoint_digest,
                detail_code,
                float(now),
            ),
        )

    def integrity_snapshot(self) -> dict[str, Any]:
        with self._read_transaction() as conn:
            peer_rows = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM peers ORDER BY paired_at, peer_id"
                )
            ]
            checkpoint_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT * FROM checkpoints
                    ORDER BY lineage_id, direction, term, sequence
                    """
                )
            ]
            acknowledgement_rows = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM acknowledgements ORDER BY ack_digest"
                )
            ]
            # For upgrade-peer-descriptor audit rows the checkpoint_digest
            # column carries the reviewed PREVIOUS descriptor digest the CAS
            # replaced (see update_peer_descriptor). One pin upgrades
            # baseline->full at most once, so the latest accepted row maps
            # unambiguously to the current pin.
            descriptor_upgrade_predecessors: dict[str, str] = {}
            for peer_id, previous in conn.execute(
                """
                SELECT peer_id, checkpoint_digest FROM audit_events
                WHERE action = 'upgrade-peer-descriptor'
                    AND state = 'accepted' AND peer_id IS NOT NULL
                ORDER BY event_id
                """
            ):
                if DIGEST_RE.fullmatch(str(previous or "")) is None:
                    raise ReplicationProtocolError(
                        "peer descriptor upgrade audit predecessor is invalid"
                    )
                descriptor_upgrade_predecessors[str(peer_id)] = str(previous)
            checkpoints_by_digest = {
                str(record["checkpoint_digest"]): record
                for record in checkpoint_rows
            }
            peers_by_id = {
                str(record["peer_id"]): record for record in peer_rows
            }
            for record in checkpoint_rows:
                self._validate_checkpoint_row_manifest(
                    conn,
                    record,
                    initial=False,
                    peer=peers_by_id.get(str(record["peer_id"])),
                )
            for record in acknowledgement_rows:
                checkpoint = checkpoints_by_digest.get(
                    str(record["checkpoint_digest"])
                )
                if checkpoint is None:
                    raise ReplicationProtocolError(
                        "acknowledgement references an unknown checkpoint"
                    )
                self._validate_ack_row_document(
                    conn,
                    record,
                    checkpoint=checkpoint,
                    peer=peers_by_id.get(str(checkpoint["peer_id"])),
                )
            audit_count = int(
                conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            )
        peer_count = len(peer_rows)
        peer_page_rows = peer_rows[:STATUS_PEER_PAGE_LIMIT]
        peers = [
                {
                    "peer_id": str(row["peer_id"]),
                    "lineage_id": str(row["lineage_id"]),
                    "direction": str(row["direction"]),
                    "revoked": bool(row["revoked"]),
                    "paired_at": float(row["paired_at"]),
                }
                for row in peer_page_rows
            ]
        checkpoint_counts: dict[str, int] = {}
        latest_by_lineage: dict[tuple[str, str], dict[str, Any]] = {}
        for row in checkpoint_rows:
            count_key = f"{row['direction']}:{row['state']}"
            checkpoint_counts[count_key] = checkpoint_counts.get(count_key, 0) + 1
            lineage_key = (str(row["lineage_id"]), str(row["direction"]))
            current = latest_by_lineage.get(lineage_key)
            if current is None or (int(row["term"]), int(row["sequence"])) > (
                int(current["term"]),
                int(current["sequence"]),
            ):
                latest_by_lineage[lineage_key] = row
        latest_checkpoint_count = len(latest_by_lineage)
        latest_rows = [
            latest_by_lineage[key]
            for key in sorted(latest_by_lineage)
        ][:STATUS_LATEST_CHECKPOINT_LIMIT]
        latest = [
                {
                    "lineage_id": str(row["lineage_id"]),
                    "direction": str(row["direction"]),
                    "term": int(row["term"]),
                    "sequence": int(row["sequence"]),
                    "checkpoint_digest": str(row["checkpoint_digest"]),
                    "state": str(row["state"]),
                }
                for row in latest_rows
            ]
        status = {
            "schema": "synapse-s2.replication-status.v1",
            "mode": "offline-single-writer-checkpoint",
            "transport": "operator-mediated-directory",
            "live_overwrite_supported": False,
            "peer_count": peer_count,
            "peer_returned_count": len(peers),
            "peers_truncated": peer_count > len(peers),
            "peer_pagination": {
                "limit": STATUS_PEER_PAGE_LIMIT,
                "returned": len(peers),
                "total": peer_count,
                "truncated": peer_count > len(peers),
                "next_cursor": (
                    {
                        "paired_at": float(peers[-1]["paired_at"]),
                        "peer_id": str(peers[-1]["peer_id"]),
                    }
                    if peer_count > len(peers) and peers
                    else None
                ),
            },
            "peers": peers,
            "checkpoint_counts": checkpoint_counts,
            "latest_checkpoints": latest,
            "latest_checkpoint_count": latest_checkpoint_count,
            "latest_checkpoint_returned_count": len(latest),
            "latest_checkpoints_truncated": latest_checkpoint_count > len(latest),
            "latest_checkpoint_projection": {
                "limit": STATUS_LATEST_CHECKPOINT_LIMIT,
                "returned": len(latest),
                "total": latest_checkpoint_count,
                "truncated": latest_checkpoint_count > len(latest),
                "pagination_supported": False,
            },
            "acknowledgement_count": len(acknowledgement_rows),
            "audit_event_count": audit_count,
            "anchor_history_validation": "current-receipt-and-external-witness",
            "full_anchor_history_audit_on_demand": True,
        }
        return {
            "schema": "synapse-s2.replication-integrity-snapshot.v1",
            "status": status,
            "peers": peer_rows,
            "checkpoints": checkpoint_rows,
            "acknowledgements": acknowledgement_rows,
            "descriptor_upgrade_predecessors": descriptor_upgrade_predecessors,
        }

    def status(self) -> dict[str, Any]:
        return dict(self.integrity_snapshot()["status"])

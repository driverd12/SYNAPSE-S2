from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Collection, Literal

from core_authority import CoreAuthorityError, CoreAuthorityLease


JOURNAL_APPLICATION_ID = 0x5332524A  # "S2RJ"
JOURNAL_SCHEMA_VERSION = 3
JOURNAL_SCHEMA_IDENTITY = (
    f"sqlite-{JOURNAL_APPLICATION_ID:x}-v{JOURNAL_SCHEMA_VERSION}"
)
JOURNAL_BINDING_SCHEMA = "synapse-s2.request-journal-binding.v1"
DEFAULT_MAX_ROWS = 16_384
DEFAULT_MAX_ACCEPTED_ROWS = 4_096
DEFAULT_RETENTION_SECONDS = 30 * 24 * 60 * 60
HEALTH_CACHE_SECONDS = 2.0
MAX_STATUS_AGE_MS = 9_007_199_254_740_991
PRECLAIM_REPAIR_SCHEMA = "synapse-s2.empty-preclaim-journal-repair.v1"
PRECLAIM_VERIFY_SCHEMA = "synapse-s2.empty-preclaim-journal-verification.v1"
MAX_PRECLAIM_REPAIR_ARCHIVES = 8
MAX_PRECLAIM_VERIFY_DIRS = 8
MAX_PRECLAIM_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_PRECLAIM_SIDECAR_BYTES = 4 * 1024 * 1024
MAX_PRECLAIM_RECEIPT_BYTES = 64 * 1024
MAX_PRECLAIM_RECEIPT_TEMPS = 32

_IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_FINGERPRINT_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_STORE_IDENTITY_RE = re.compile(r"\Astore-[0-9a-f]{24}\Z")
_JOURNAL_ID_RE = re.compile(r"\Ajournal-[0-9a-f]{24}\Z")
_PRECLAIM_RECEIPT_NAME_RE = re.compile(
    r"\Arequests\.sqlite3\.preclaim-repair-([0-9a-f]{24})\.json\Z"
)
_PRECLAIM_RECEIPT_TEMP_RE = re.compile(
    r"\A\.requests\.sqlite3\.preclaim-repair-([0-9a-f]{24})\.json"
    r"\.tmp(?:-[0-9]+-[0-9a-f]{12})?\Z"
)
_PRECLAIM_VERIFY_DIR_RE = re.compile(
    r"\A\.requests\.sqlite3\.preclaim-verify-([0-9a-f]{24})\Z"
)
_SECRET_PATTERNS = (
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bBearer[A-Za-z0-9._~+:/=-]{12,}\b", re.IGNORECASE),
)
_TERMINAL_STATES = ("completed", "failed")
SAFE_ERROR_CODES = frozenset(
    {
        "authentication_failed",
        "deadline_exceeded",
        "invalid_request",
        "operation_failed",
        "operation_unavailable",
        "outcome_unknown",
        "path_not_authorized",
        "protocol_violation",
        "request_conflict",
        "service_unavailable",
    }
)
_SAFE_ERROR_CODES = SAFE_ERROR_CODES

_REQUEST_JOURNAL_TABLE_SQL = """
CREATE TABLE request_journal (
    caller TEXT NOT NULL CHECK(length(caller) BETWEEN 1 AND 128),
    request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 1 AND 128),
    operation TEXT NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint) = 64),
    authority_epoch TEXT NOT NULL CHECK(length(authority_epoch) BETWEEN 1 AND 128),
    state TEXT NOT NULL CHECK(state IN ('accepted','completed','failed','ambiguous')),
    result_kind TEXT CHECK(result_kind IN ('null','boolean','integer','number','string','array','object')),
    safe_error_code TEXT CHECK(safe_error_code IS NULL OR length(safe_error_code) BETWEEN 1 AND 64),
    accepted_at_unix_ms INTEGER NOT NULL CHECK(accepted_at_unix_ms > 0),
    finished_at_unix_ms INTEGER CHECK(finished_at_unix_ms IS NULL OR finished_at_unix_ms >= accepted_at_unix_ms),
    PRIMARY KEY (caller, request_id)
) WITHOUT ROWID
"""
_REQUEST_JOURNAL_METADATA_TABLE_SQL = """
CREATE TABLE request_journal_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID
"""
_REQUEST_JOURNAL_INDEX_SQL = (
    "CREATE INDEX request_journal_terminal_age "
    "ON request_journal(state, finished_at_unix_ms)"
)


def _normalized_schema_sql(value: str) -> str:
    return " ".join(str(value).split())


def _assert_exact_current_schema(db: sqlite3.Connection) -> None:
    expected_objects = {
        (
            "table",
            "request_journal",
            "request_journal",
            _normalized_schema_sql(_REQUEST_JOURNAL_TABLE_SQL),
        ),
        (
            "table",
            "request_journal_metadata",
            "request_journal_metadata",
            _normalized_schema_sql(_REQUEST_JOURNAL_METADATA_TABLE_SQL),
        ),
        (
            "index",
            "request_journal_terminal_age",
            "request_journal",
            _normalized_schema_sql(_REQUEST_JOURNAL_INDEX_SQL),
        ),
    }
    observed_objects = {
        (
            str(row[0]),
            str(row[1]),
            str(row[2]),
            _normalized_schema_sql(str(row[3] or "")),
        )
        for row in db.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall()
    }
    request_xinfo = tuple(
        tuple(row) for row in db.execute("PRAGMA table_xinfo(request_journal)")
    )
    metadata_xinfo = tuple(
        tuple(row)
        for row in db.execute("PRAGMA table_xinfo(request_journal_metadata)")
    )
    index_xinfo = tuple(
        tuple(row)
        for row in db.execute(
            "PRAGMA index_xinfo(request_journal_terminal_age)"
        )
    )
    index_list = {
        (str(row[1]), int(row[2]), str(row[3]), int(row[4]))
        for row in db.execute("PRAGMA index_list(request_journal)")
    }
    if (
        observed_objects != expected_objects
        or request_xinfo
        != (
            (0, "caller", "TEXT", 1, None, 1, 0),
            (1, "request_id", "TEXT", 1, None, 2, 0),
            (2, "operation", "TEXT", 1, None, 0, 0),
            (3, "request_fingerprint", "TEXT", 1, None, 0, 0),
            (4, "authority_epoch", "TEXT", 1, None, 0, 0),
            (5, "state", "TEXT", 1, None, 0, 0),
            (6, "result_kind", "TEXT", 0, None, 0, 0),
            (7, "safe_error_code", "TEXT", 0, None, 0, 0),
            (8, "accepted_at_unix_ms", "INTEGER", 1, None, 0, 0),
            (9, "finished_at_unix_ms", "INTEGER", 0, None, 0, 0),
        )
        or metadata_xinfo
        != (
            (0, "key", "TEXT", 1, None, 1, 0),
            (1, "value", "TEXT", 1, None, 0, 0),
        )
        or index_xinfo
        != (
            (0, 5, "state", 0, "BINARY", 1),
            (1, 9, "finished_at_unix_ms", 0, "BINARY", 1),
            (2, 0, "caller", 0, "BINARY", 0),
            (3, 1, "request_id", 0, "BINARY", 0),
        )
        or index_list
        != {
            ("request_journal_terminal_age", 0, "c", 0),
            ("sqlite_autoindex_request_journal_1", 1, "pk", 0),
        }
    ):
        raise CoreRequestJournalError()


class CoreRequestJournalError(RuntimeError):
    """Content-free durable request-journal failure."""

    def __init__(self, code: str = "service_unavailable") -> None:
        super().__init__(code)
        self.code = code


class CoreRequestJournalCapacityError(CoreRequestJournalError):
    """The ambiguity-preserving journal cannot accept another mutation."""


@dataclass(frozen=True)
class JournalDecision:
    disposition: Literal["accepted", "existing", "conflict"]
    state: str | None = None


def _validate_identifier(value: str) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_RE.fullmatch(value) is None
        or any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS)
    ):
        raise CoreRequestJournalError()
    return value


def _validate_fingerprint(value: str) -> str:
    if not isinstance(value, str) or _FINGERPRINT_RE.fullmatch(value) is None:
        raise CoreRequestJournalError()
    return value


def _validate_private_directory(path: Path) -> os.stat_result:
    if not path.is_absolute() or ".." in path.parts:
        raise CoreRequestJournalError()
    try:
        observed = path.lstat()
    except FileNotFoundError as exc:
        raise CoreRequestJournalError() from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISDIR(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise CoreRequestJournalError()
    return observed


def _open_private_regular_file(
    path: Path,
    *,
    create: bool = True,
) -> tuple[int, tuple[int, int]]:
    base_flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    base_flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    for _attempt in range(2):
        try:
            before = path.lstat()
        except FileNotFoundError:
            if not create:
                raise CoreRequestJournalError()
            try:
                descriptor = os.open(path, base_flags | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                continue
            except OSError as exc:
                raise CoreRequestJournalError() from exc
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise CoreRequestJournalError()
        try:
            descriptor = os.open(path, base_flags)
            break
        except OSError as exc:
            raise CoreRequestJournalError() from exc
    if descriptor is None:
        raise CoreRequestJournalError()
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != os.getuid()
            or observed.st_nlink != 1
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise CoreRequestJournalError()
        visible = path.lstat()
        if (
            stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or visible.st_uid != os.getuid()
            or visible.st_nlink != 1
            or stat.S_IMODE(visible.st_mode) != 0o600
            or (visible.st_dev, visible.st_ino)
            != (observed.st_dev, observed.st_ino)
        ):
            raise CoreRequestJournalError()
        return descriptor, (int(observed.st_dev), int(observed.st_ino))
    except BaseException:
        os.close(descriptor)
        raise


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CoreRequestJournalError() from exc


def _result_kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise CoreRequestJournalError()


def _bounded_age_ms(now_unix_ms: int, timestamp_unix_ms: int | None) -> int | None:
    if timestamp_unix_ms is None:
        return None
    return min(MAX_STATUS_AGE_MS, max(0, now_unix_ms - int(timestamp_unix_ms)))


class CoreRequestJournal:
    """Private, bounded acceptance journal for authoritative-core mutations.

    This deliberately stores no arguments or response content. A durable row
    proves only that a mutation may have run. The service may replay an exact
    response from its process-local cache, but a later process must surface
    ``outcome_unknown`` instead of dispatching the mutation again.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        authority_epoch: str,
        max_rows: int = DEFAULT_MAX_ROWS,
        max_accepted_rows: int = DEFAULT_MAX_ACCEPTED_ROWS,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        require_existing: bool = False,
        prune_on_open: bool = True,
        allow_migration: bool = True,
        store_identity: str | None = None,
        expected_journal_id: str | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self.authority_epoch = _validate_identifier(authority_epoch)
        if (
            not self.path.is_absolute()
            or ".." in self.path.parts
            or self.path.name != "requests.sqlite3"
        ):
            raise CoreRequestJournalError()
        if not isinstance(max_rows, int) or isinstance(max_rows, bool) or max_rows < 1:
            raise CoreRequestJournalError()
        if (
            not isinstance(max_accepted_rows, int)
            or isinstance(max_accepted_rows, bool)
            or max_accepted_rows < 1
            or max_accepted_rows > max_rows
        ):
            raise CoreRequestJournalError()
        if (
            not isinstance(retention_seconds, int)
            or isinstance(retention_seconds, bool)
            or retention_seconds < 0
        ):
            raise CoreRequestJournalError()
        if type(require_existing) is not bool:
            raise CoreRequestJournalError()
        if type(prune_on_open) is not bool:
            raise CoreRequestJournalError()
        if type(allow_migration) is not bool:
            raise CoreRequestJournalError()
        if store_identity is not None and (
            not isinstance(store_identity, str)
            or _STORE_IDENTITY_RE.fullmatch(store_identity) is None
        ):
            raise CoreRequestJournalError()
        if expected_journal_id is not None and (
            not isinstance(expected_journal_id, str)
            or _JOURNAL_ID_RE.fullmatch(expected_journal_id) is None
        ):
            raise CoreRequestJournalError()
        self.max_rows = max_rows
        self.max_accepted_rows = max_accepted_rows
        self.retention_seconds = retention_seconds
        self.require_existing = require_existing
        self.prune_on_open = prune_on_open
        self.allow_migration = allow_migration
        self.store_identity = store_identity
        self.expected_journal_id = expected_journal_id
        self.journal_id: str | None = None
        self._mutex = threading.RLock()
        self._closed = False
        self._health_cache: tuple[float, frozenset[tuple[str, str]], dict[str, Any]] | None = None
        self._last_prune_unix_ms = 0
        self._connection: sqlite3.Connection | None = None
        self._lock_descriptor: int | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._file_identity: tuple[int, int] | None = None
        self._sidecar_identities: dict[str, tuple[int, int]] = {}
        self._bind_sidecar_identities = False

        _validate_private_directory(self.path.parent)
        if self.require_existing:
            # Reject before creating even the coordination lock. A durable-v6
            # restart must never turn missing dedup evidence into an empty,
            # apparently healthy journal.
            try:
                existing = self.path.lstat()
            except FileNotFoundError as exc:
                raise CoreRequestJournalError() from exc
            if (
                stat.S_ISLNK(existing.st_mode)
                or not stat.S_ISREG(existing.st_mode)
                or existing.st_uid != os.getuid()
                or existing.st_nlink != 1
                or stat.S_IMODE(existing.st_mode) != 0o600
                or existing.st_size <= 0
            ):
                raise CoreRequestJournalError()
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        lock_descriptor, lock_identity = _open_private_regular_file(lock_path)
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(lock_descriptor)
            raise CoreRequestJournalError() from exc
        self._lock_descriptor = lock_descriptor
        self._lock_identity = lock_identity

        journal_descriptor: int | None = None
        previous_umask = os.umask(0o077)
        try:
            journal_descriptor, file_identity = _open_private_regular_file(
                self.path,
                create=not self.require_existing,
            )
            self._file_identity = file_identity
            os.fsync(journal_descriptor)
            os.close(journal_descriptor)
            journal_descriptor = None
            _fsync_directory(self.path.parent)
            # Refuse hostile pre-existing SQLite sidecars before sqlite3 has
            # any opportunity to open or replace them. Re-checking after
            # every transaction still protects against later substitution.
            self._secure_sidecars()
            connection = sqlite3.connect(
                self.path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection = connection
            self._assert_identity()
            connection.execute("PRAGMA busy_timeout = 5000")
            if str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower() != "wal":
                raise CoreRequestJournalError()
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("PRAGMA temp_store = MEMORY")
            connection.execute("PRAGMA wal_autocheckpoint = 128")
            self._bind_sidecar_identities = True
            self._secure_sidecars()
            self._migrate()
            self._secure_sidecars()
            if self.prune_on_open:
                self.prune()
        except BaseException:
            if journal_descriptor is not None:
                os.close(journal_descriptor)
            self.close()
            raise
        finally:
            os.umask(previous_umask)

    def _assert_identity(self) -> None:
        if self._closed or self._connection is None or self._file_identity is None:
            raise CoreRequestJournalError()
        _validate_private_directory(self.path.parent)
        try:
            visible = self.path.lstat()
        except FileNotFoundError as exc:
            raise CoreRequestJournalError() from exc
        if (
            stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or visible.st_uid != os.getuid()
            or visible.st_nlink != 1
            or stat.S_IMODE(visible.st_mode) != 0o600
            or (int(visible.st_dev), int(visible.st_ino)) != self._file_identity
        ):
            raise CoreRequestJournalError()
        self._secure_sidecars()
        if self._lock_descriptor is None or self._lock_identity is None:
            raise CoreRequestJournalError()
        lock_stat = os.fstat(self._lock_descriptor)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        try:
            lock_visible = lock_path.lstat()
        except FileNotFoundError as exc:
            raise CoreRequestJournalError() from exc
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != os.getuid()
            or lock_stat.st_nlink != 1
            or stat.S_ISLNK(lock_visible.st_mode)
            or not stat.S_ISREG(lock_visible.st_mode)
            or lock_visible.st_uid != os.getuid()
            or lock_visible.st_nlink != 1
            or stat.S_IMODE(lock_visible.st_mode) != 0o600
            or (int(lock_stat.st_dev), int(lock_stat.st_ino)) != self._lock_identity
            or (int(lock_visible.st_dev), int(lock_visible.st_ino)) != self._lock_identity
        ):
            raise CoreRequestJournalError()

    @property
    def _db(self) -> sqlite3.Connection:
        self._assert_identity()
        assert self._connection is not None
        return self._connection

    def _commit_checked(self, db: sqlite3.Connection) -> None:
        """Commit only while every journal path still names the opened files."""

        self._assert_identity()
        db.execute("COMMIT")
        self._assert_identity()

    def _secure_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            try:
                observed = sidecar.lstat()
            except FileNotFoundError:
                if suffix in self._sidecar_identities:
                    raise CoreRequestJournalError()
                continue
            if (
                stat.S_ISLNK(observed.st_mode)
                or not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.getuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != 0o600
            ):
                raise CoreRequestJournalError()
            identity = (int(observed.st_dev), int(observed.st_ino))
            expected = self._sidecar_identities.get(suffix)
            if expected is not None and identity != expected:
                raise CoreRequestJournalError()
            if expected is None and self._bind_sidecar_identities:
                self._sidecar_identities[suffix] = identity

    def _migrate(self) -> None:
        db = self._db
        application_id = int(db.execute("PRAGMA application_id").fetchone()[0])
        version = int(db.execute("PRAGMA user_version").fetchone()[0])
        if version < 0 or version > JOURNAL_SCHEMA_VERSION:
            raise CoreRequestJournalError()
        if version != JOURNAL_SCHEMA_VERSION and not self.allow_migration:
            raise CoreRequestJournalError()
        if version == 0 and application_id not in (0, JOURNAL_APPLICATION_ID):
            raise CoreRequestJournalError()
        if version > 0 and application_id != JOURNAL_APPLICATION_ID:
            raise CoreRequestJournalError()
        def create_current_table() -> None:
            # Preserve the historical sqlite_schema SQL bytes: recovery bundle
            # verification intentionally fingerprints this durable contract.
            db.execute(
                """
                CREATE TABLE request_journal (
                    caller TEXT NOT NULL CHECK(length(caller) BETWEEN 1 AND 128),
                    request_id TEXT NOT NULL CHECK(length(request_id) BETWEEN 1 AND 128),
                    operation TEXT NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
                    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint) = 64),
                    authority_epoch TEXT NOT NULL CHECK(length(authority_epoch) BETWEEN 1 AND 128),
                    state TEXT NOT NULL CHECK(state IN ('accepted','completed','failed','ambiguous')),
                    result_kind TEXT CHECK(result_kind IN ('null','boolean','integer','number','string','array','object')),
                    safe_error_code TEXT CHECK(safe_error_code IS NULL OR length(safe_error_code) BETWEEN 1 AND 64),
                    accepted_at_unix_ms INTEGER NOT NULL CHECK(accepted_at_unix_ms > 0),
                    finished_at_unix_ms INTEGER CHECK(finished_at_unix_ms IS NULL OR finished_at_unix_ms >= accepted_at_unix_ms),
                    PRIMARY KEY (caller, request_id)
                ) WITHOUT ROWID
                """
            )
            db.execute(
                "CREATE INDEX request_journal_terminal_age "
                "ON request_journal(state, finished_at_unix_ms)"
            )

        def create_binding_table() -> None:
            journal_id = "journal-" + secrets.token_hex(12)
            bound_store_identity = self.store_identity or "unbound"
            db.execute(
                """
                CREATE TABLE request_journal_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID
                """
            )
            db.executemany(
                "INSERT INTO request_journal_metadata (key, value) VALUES (?, ?)",
                (
                    ("binding_schema", JOURNAL_BINDING_SCHEMA),
                    ("journal_id", journal_id),
                    ("store_identity", bound_store_identity),
                ),
            )

        if version == 0:
            if self.require_existing:
                raise CoreRequestJournalError()
            db.execute("BEGIN IMMEDIATE")
            try:
                create_current_table()
                create_binding_table()
                db.execute(f"PRAGMA application_id = {JOURNAL_APPLICATION_ID}")
                db.execute(f"PRAGMA user_version = {JOURNAL_SCHEMA_VERSION}")
                self._commit_checked(db)
            except BaseException:
                db.execute("ROLLBACK")
                raise
        elif version == 1:
            old_columns = tuple(
                row[1]
                for row in db.execute("PRAGMA table_info(request_journal)").fetchall()
            )
            if old_columns != (
                "caller",
                "request_id",
                "operation",
                "request_fingerprint",
                "authority_epoch",
                "state",
                "result_kind",
                "response_sha256",
                "response_bytes",
                "safe_error_code",
                "accepted_at_unix_ms",
                "finished_at_unix_ms",
            ):
                raise CoreRequestJournalError()
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DROP INDEX request_journal_terminal_age")
                db.execute("ALTER TABLE request_journal RENAME TO request_journal_v1")
                create_current_table()
                db.execute(
                    "INSERT INTO request_journal ("
                    "caller, request_id, operation, request_fingerprint, authority_epoch, "
                    "state, result_kind, safe_error_code, accepted_at_unix_ms, finished_at_unix_ms"
                    ") SELECT caller, request_id, operation, request_fingerprint, authority_epoch, "
                    "state, result_kind, safe_error_code, accepted_at_unix_ms, finished_at_unix_ms "
                    "FROM request_journal_v1"
                )
                db.execute("DROP TABLE request_journal_v1")
                create_binding_table()
                db.execute(f"PRAGMA user_version = {JOURNAL_SCHEMA_VERSION}")
                self._commit_checked(db)
            except BaseException:
                db.execute("ROLLBACK")
                raise
        elif version == 2:
            db.execute("BEGIN IMMEDIATE")
            try:
                create_binding_table()
                db.execute(f"PRAGMA user_version = {JOURNAL_SCHEMA_VERSION}")
                self._commit_checked(db)
            except BaseException:
                db.execute("ROLLBACK")
                raise
        _assert_exact_current_schema(db)
        metadata = {
            str(row[0]): str(row[1])
            for row in db.execute(
                "SELECT key, value FROM request_journal_metadata ORDER BY key"
            ).fetchall()
        }
        if set(metadata) != {"binding_schema", "journal_id", "store_identity"}:
            raise CoreRequestJournalError()
        journal_id = metadata["journal_id"]
        bound_store_identity = metadata["store_identity"]
        if (
            metadata["binding_schema"] != JOURNAL_BINDING_SCHEMA
            or _JOURNAL_ID_RE.fullmatch(journal_id) is None
            or (
                bound_store_identity != "unbound"
                and _STORE_IDENTITY_RE.fullmatch(bound_store_identity) is None
            )
            or (
                self.store_identity is not None
                and bound_store_identity != self.store_identity
            )
            or (
                self.expected_journal_id is not None
                and journal_id != self.expected_journal_id
            )
        ):
            raise CoreRequestJournalError()
        self.journal_id = journal_id
        self.store_identity = (
            None if bound_store_identity == "unbound" else bound_store_identity
        )

    def binding(self) -> dict[str, Any]:
        """Return the immutable, content-free journal/store association."""

        self._assert_identity()
        if self.journal_id is None:
            raise CoreRequestJournalError()
        return {
            "schema": JOURNAL_BINDING_SCHEMA,
            "journal_id": self.journal_id,
            "store_identity": self.store_identity,
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "journal_schema_identity": JOURNAL_SCHEMA_IDENTITY,
        }

    def accept(
        self,
        *,
        caller: str,
        request_id: str,
        operation: str,
        request_fingerprint: str,
    ) -> JournalDecision:
        caller = _validate_identifier(caller)
        request_id = _validate_identifier(request_id)
        operation = _validate_identifier(operation)
        request_fingerprint = _validate_fingerprint(request_fingerprint)
        now_ms = int(time.time() * 1000)
        # Reclaim only rows that have completed their full configured dedup
        # horizon. Capacity must never shorten that horizon.
        self.prune(now_unix_ms=now_ms)
        with self._mutex:
            db = self._db
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute(
                    "SELECT operation, request_fingerprint, state "
                    "FROM request_journal WHERE caller = ? AND request_id = ?",
                    (caller, request_id),
                ).fetchone()
                if existing is not None:
                    self._commit_checked(db)
                    if existing[0] != operation or existing[1] != request_fingerprint:
                        return JournalDecision("conflict", str(existing[2]))
                    return JournalDecision("existing", str(existing[2]))
                accepted_count = int(
                    db.execute(
                        "SELECT count(*) FROM request_journal "
                        "WHERE state IN ('accepted','ambiguous')"
                    ).fetchone()[0]
                )
                if accepted_count >= self.max_accepted_rows:
                    raise CoreRequestJournalCapacityError()
                total = int(
                    db.execute("SELECT count(*) FROM request_journal").fetchone()[0]
                )
                if total >= self.max_rows:
                    raise CoreRequestJournalCapacityError()
                db.execute(
                    "INSERT INTO request_journal ("
                    "caller, request_id, operation, request_fingerprint, authority_epoch, "
                    "state, accepted_at_unix_ms"
                    ") VALUES (?, ?, ?, ?, ?, 'accepted', ?)",
                    (
                        caller,
                        request_id,
                        operation,
                        request_fingerprint,
                        self.authority_epoch,
                        now_ms,
                    ),
                )
                self._commit_checked(db)
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            self._health_cache = None
            self._secure_sidecars()
            return JournalDecision("accepted", "accepted")

    def finish(
        self,
        *,
        caller: str,
        request_id: str,
        operation: str,
        request_fingerprint: str,
        result: Any,
        safe_error_code: str | None,
    ) -> None:
        caller = _validate_identifier(caller)
        request_id = _validate_identifier(request_id)
        operation = _validate_identifier(operation)
        request_fingerprint = _validate_fingerprint(request_fingerprint)
        if safe_error_code is not None and safe_error_code not in _SAFE_ERROR_CODES:
            raise CoreRequestJournalError()
        state = (
            "completed"
            if safe_error_code is None
            else "ambiguous"
            if safe_error_code == "outcome_unknown"
            else "failed"
        )
        kind = _result_kind(result) if safe_error_code is None else None
        now_ms = int(time.time() * 1000)
        with self._mutex:
            db = self._db
            db.execute("BEGIN IMMEDIATE")
            try:
                changed = db.execute(
                    "UPDATE request_journal SET state = ?, result_kind = ?, "
                    "safe_error_code = ?, "
                    "finished_at_unix_ms = MAX(?, accepted_at_unix_ms) "
                    "WHERE caller = ? AND request_id = ? "
                    "AND operation = ? AND request_fingerprint = ? AND state = 'accepted'",
                    (
                        state,
                        kind,
                        safe_error_code,
                        now_ms,
                        caller,
                        request_id,
                        operation,
                        request_fingerprint,
                    ),
                ).rowcount
                if changed != 1:
                    raise CoreRequestJournalError()
                self._commit_checked(db)
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            self._health_cache = None
            self._secure_sidecars()
            self.prune()

    def request_status(self, *, caller: str, request_id: str) -> dict[str, Any]:
        """Return a fixed, content-free reconciliation projection for one request."""

        caller = _validate_identifier(caller)
        request_id = _validate_identifier(request_id)
        now_ms = int(time.time() * 1000)
        with self._mutex:
            row = self._db.execute(
                "SELECT operation, authority_epoch, state, result_kind, "
                "safe_error_code, accepted_at_unix_ms, finished_at_unix_ms "
                "FROM request_journal WHERE caller = ? AND request_id = ?",
                (caller, request_id),
            ).fetchone()
            if row is None:
                return {
                    "known": False,
                    "caller": caller,
                    "request_id": request_id,
                    "state": "not_found",
                    "operation": None,
                    "safe_error_code": None,
                    "result_kind": None,
                    "authority_epoch": None,
                    "accepted_age_ms": None,
                    "finished_age_ms": None,
                    "replay_safe": False,
                    "retention_expiry_possible": True,
                }
            return {
                "known": True,
                "caller": caller,
                "request_id": request_id,
                "state": str(row[2]),
                "operation": str(row[0]),
                "safe_error_code": None if row[4] is None else str(row[4]),
                "result_kind": None if row[3] is None else str(row[3]),
                "authority_epoch": str(row[1]),
                "accepted_age_ms": _bounded_age_ms(now_ms, row[5]),
                "finished_age_ms": _bounded_age_ms(now_ms, row[6]),
                "replay_safe": False,
                "retention_expiry_possible": False,
            }

    def prune(self, *, now_unix_ms: int | None = None) -> int:
        now_ms = int(time.time() * 1000) if now_unix_ms is None else int(now_unix_ms)
        cutoff = now_ms - (self.retention_seconds * 1000)
        with self._mutex:
            db = self._db
            db.execute("BEGIN IMMEDIATE")
            try:
                removed = db.execute(
                    "DELETE FROM request_journal WHERE state IN ('completed','failed') "
                    "AND finished_at_unix_ms < ?",
                    (cutoff,),
                ).rowcount
                self._commit_checked(db)
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            self._last_prune_unix_ms = now_ms
            self._health_cache = None
            self._secure_sidecars()
            return int(removed)

    def health(
        self,
        *,
        exact_response_keys: Collection[tuple[str, str]] = (),
    ) -> dict[str, Any]:
        known = frozenset(exact_response_keys)
        now = time.monotonic()
        with self._mutex:
            cached = self._health_cache
            if cached is not None and cached[1] == known and now - cached[0] < HEALTH_CACHE_SECONDS:
                return dict(cached[2])
            rows = self._db.execute(
                "SELECT caller, request_id, state FROM request_journal"
            ).fetchall()
            counts = {"accepted": 0, "completed": 0, "failed": 0, "ambiguous": 0}
            ambiguous = 0
            for caller, request_id, state in rows:
                counts[str(state)] += 1
                if str(state) in {"accepted", "ambiguous"} or (
                    str(caller), str(request_id)
                ) not in known:
                    ambiguous += 1
            last_prune_age_ms = (
                None
                if self._last_prune_unix_ms <= 0
                else max(0, int(time.time() * 1000) - self._last_prune_unix_ms)
            )
            used_rows = len(rows)
            nonprunable_count = counts["accepted"] + counts["ambiguous"]
            remaining_rows = max(0, self.max_rows - used_rows)
            accepted_remaining = max(0, self.max_accepted_rows - nonprunable_count)
            accepting_mutations = remaining_rows > 0 and accepted_remaining > 0
            result = {
                "ready": accepting_mutations,
                "accepted_count": counts["accepted"],
                "completed_count": counts["completed"],
                "failed_count": counts["failed"],
                "explicit_ambiguous_count": counts["ambiguous"],
                "ambiguous_count": ambiguous,
                "last_prune_age_ms": last_prune_age_ms,
                "max_rows": self.max_rows,
                "used_rows": used_rows,
                "remaining_rows": remaining_rows,
                "max_accepted_rows": self.max_accepted_rows,
                "accepted_capacity_remaining": accepted_remaining,
                "accepting_mutations": accepting_mutations,
                "blocker": None if accepting_mutations else "request_journal_capacity",
            }
            self._health_cache = (now, known, result)
            return dict(result)

    def close(self) -> None:
        with self._mutex:
            if self._closed:
                return
            self._closed = True
            connection = self._connection
            self._connection = None
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            descriptor = self._lock_descriptor
            self._lock_descriptor = None
            if descriptor is not None:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)

    def __enter__(self) -> "CoreRequestJournal":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()


def _canonical_private_json(value: dict[str, Any]) -> bytes:
    try:
        return (
            json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CoreRequestJournalError() from exc


def _read_private_artifact(
    path: Path,
    *,
    maximum_bytes: int,
) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size < 0
        or before.st_size > maximum_bytes
    ):
        raise CoreRequestJournalError()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(65_536, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise CoreRequestJournalError()
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    visible = path.lstat()
    identity = lambda item: (
        int(item.st_dev),
        int(item.st_ino),
        int(item.st_size),
        int(item.st_mtime_ns),
        int(item.st_ctime_ns),
        int(item.st_uid),
        int(item.st_nlink),
        stat.S_IMODE(item.st_mode),
    )
    if (
        len({identity(item) for item in (before, opened, finished, visible)}) != 1
        or total != int(before.st_size)
    ):
        raise CoreRequestJournalError()
    return b"".join(chunks), visible


def _atomic_private_json(
    path: Path,
    payload: dict[str, Any],
    *,
    expected_existing: bytes | None,
) -> bytes:
    encoded = _canonical_private_json(payload)
    if len(encoded) > MAX_PRECLAIM_RECEIPT_BYTES:
        raise CoreRequestJournalError()
    existing_stat: os.stat_result | None = None
    if expected_existing is None:
        if path.exists() or path.is_symlink():
            raise CoreRequestJournalError()
    else:
        observed, existing_stat = _read_private_artifact(
            path,
            maximum_bytes=MAX_PRECLAIM_RECEIPT_BYTES,
        )
        if not secrets.compare_digest(observed, expected_existing):
            raise CoreRequestJournalError()
    # One deterministic temp per immutable repair receipt bounds crash residue.
    # The recovery entrypoint validates and removes an interrupted temp before
    # retrying the same state transition.
    temporary = path.with_name(f".{path.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CoreRequestJournalError()
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        if expected_existing is None:
            if path.exists() or path.is_symlink():
                raise CoreRequestJournalError()
        else:
            current = path.lstat()
            assert existing_stat is not None
            if (
                int(current.st_dev),
                int(current.st_ino),
                int(current.st_size),
                int(current.st_mtime_ns),
                int(current.st_ctime_ns),
            ) != (
                int(existing_stat.st_dev),
                int(existing_stat.st_ino),
                int(existing_stat.st_size),
                int(existing_stat.st_mtime_ns),
                int(existing_stat.st_ctime_ns),
            ):
                raise CoreRequestJournalError()
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return encoded


def _preclaim_repair_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": PRECLAIM_REPAIR_SCHEMA,
        "repair_id": payload["repair_id"],
        "store_identity": payload["store_identity"],
        "journal_id": payload["journal_id"],
        "journal_schema_identity": payload["journal_schema_identity"],
        "authority_epoch": payload["authority_epoch"],
        "request_row_count": payload["request_row_count"],
        "artifacts": payload["artifacts"],
        "created_at": payload["created_at"],
    }


def _validate_preclaim_repair_receipt_raw(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise CoreRequestJournalError() from exc
    expected_fields = {
        "schema",
        "status",
        "repair_id",
        "store_identity",
        "journal_id",
        "journal_schema_identity",
        "authority_epoch",
        "request_row_count",
        "artifacts",
        "evidence_sha256",
        "created_at",
        "completed_at",
        "updated_at",
    }
    artifacts = payload.get("artifacts") if isinstance(payload, dict) else None
    status_value = payload.get("status") if isinstance(payload, dict) else None
    created_at = payload.get("created_at") if isinstance(payload, dict) else None
    completed_at = (
        payload.get("completed_at") if isinstance(payload, dict) else None
    )
    updated_at = payload.get("updated_at") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or set(payload) != expected_fields
        or payload.get("schema") != PRECLAIM_REPAIR_SCHEMA
        or status_value not in {"pending", "complete", "retiring"}
        or re.fullmatch(r"[0-9a-f]{24}", str(payload.get("repair_id") or ""))
        is None
        or _STORE_IDENTITY_RE.fullmatch(
            str(payload.get("store_identity") or "")
        )
        is None
        or _JOURNAL_ID_RE.fullmatch(str(payload.get("journal_id") or ""))
        is None
        or payload.get("journal_schema_identity") != JOURNAL_SCHEMA_IDENTITY
        or payload.get("authority_epoch") != "epoch-1"
        or payload.get("request_row_count") != 0
        or not isinstance(artifacts, list)
        or not 2 <= len(artifacts) <= 4
        or type(created_at) not in {int, float}
        or not math.isfinite(float(created_at))
        or float(created_at) <= 0.0
        or type(updated_at) not in {int, float}
        or not math.isfinite(float(updated_at))
        or float(updated_at) < float(created_at)
        or (
            status_value == "pending"
            and (
                completed_at is not None
                or float(updated_at) != float(created_at)
            )
        )
        or (
            status_value == "complete"
            and (
                type(completed_at) not in {int, float}
                or not math.isfinite(float(completed_at))
                or float(completed_at) != float(updated_at)
            )
        )
        or (
            status_value == "retiring"
            and (
                type(completed_at) not in {int, float}
                or not math.isfinite(float(completed_at))
                or not float(created_at)
                <= float(completed_at)
                <= float(updated_at)
            )
        )
    ):
        raise CoreRequestJournalError()
    seen_sources: set[str] = set()
    allowed_sources = {
        "requests.sqlite3": MAX_PRECLAIM_JOURNAL_BYTES,
        "requests.sqlite3.lock": 64 * 1024,
        "requests.sqlite3-wal": MAX_PRECLAIM_SIDECAR_BYTES,
        "requests.sqlite3-shm": MAX_PRECLAIM_SIDECAR_BYTES,
    }
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "source_name",
            "archive_name",
            "device",
            "inode",
            "size_bytes",
            "sha256",
        }:
            raise CoreRequestJournalError()
        source_name = artifact.get("source_name")
        expected_archive = (
            f".{source_name}.preclaim-{payload['repair_id']}.archive"
            if isinstance(source_name, str)
            else ""
        )
        maximum = allowed_sources.get(str(source_name))
        if (
            maximum is None
            or source_name in seen_sources
            or artifact.get("archive_name") != expected_archive
            or type(artifact.get("device")) is not int
            or int(artifact["device"]) < 0
            or type(artifact.get("inode")) is not int
            or int(artifact["inode"]) <= 0
            or type(artifact.get("size_bytes")) is not int
            or not 0 <= int(artifact["size_bytes"]) <= maximum
            or re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256") or ""))
            is None
            or (
                source_name == "requests.sqlite3.lock"
                and (
                    artifact.get("size_bytes") != 0
                    or artifact.get("sha256")
                    != hashlib.sha256(b"").hexdigest()
                )
            )
        ):
            raise CoreRequestJournalError()
        seen_sources.add(str(source_name))
    if not {"requests.sqlite3", "requests.sqlite3.lock"}.issubset(seen_sources):
        raise CoreRequestJournalError()
    evidence_sha256 = hashlib.sha256(
        json.dumps(
            _preclaim_repair_evidence(payload),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if not secrets.compare_digest(
        str(payload.get("evidence_sha256") or ""),
        evidence_sha256,
    ):
        raise CoreRequestJournalError()
    if raw != _canonical_private_json(payload):
        raise CoreRequestJournalError()
    return dict(payload)


def _validate_preclaim_repair_receipt(
    path: Path,
) -> tuple[dict[str, Any], bytes]:
    raw, _observed = _read_private_artifact(
        path,
        maximum_bytes=MAX_PRECLAIM_RECEIPT_BYTES,
    )
    return _validate_preclaim_repair_receipt_raw(raw), raw


def _assert_no_unsealed_sqlite_transients(
    parent: Path,
    *,
    allowed_names: Collection[str] = (),
) -> frozenset[str]:
    """Refuse SQLite recovery files that were not sealed in a receipt.

    In particular, opening a database beside an attacker-controlled rollback
    journal, WAL, or SHM file can consume or delete that evidence.  This scan is
    intentionally broader than the three common suffixes so super-journals and
    future SQLite transient names fail closed too.
    """

    allowed = frozenset(allowed_names)
    try:
        observed = {
            entry.name
            for entry in os.scandir(parent)
            if entry.name.startswith("requests.sqlite3-")
        }
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    if not observed.issubset(allowed):
        raise CoreRequestJournalError()
    return frozenset(observed)


def _cleanup_preclaim_receipt_temps(
    parent: Path,
    *,
    expected_store_identity: str,
    assert_preclaim_authority: Callable[[], None],
) -> None:
    """Remove only authenticated, bounded residue from interrupted receipt writes."""

    try:
        names = sorted(
            entry.name
            for entry in os.scandir(parent)
            if entry.name.startswith(".requests.sqlite3.preclaim-repair-")
            and ".json.tmp" in entry.name
        )
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    if len(names) > MAX_PRECLAIM_RECEIPT_TEMPS:
        raise CoreRequestJournalError()
    for name in names:
        match = _PRECLAIM_RECEIPT_TEMP_RE.fullmatch(name)
        if match is None:
            raise CoreRequestJournalError()
        repair_id = match.group(1)
        temporary = parent / name
        raw, _observed = _read_private_artifact(
            temporary,
            maximum_bytes=MAX_PRECLAIM_RECEIPT_BYTES,
        )
        receipt = _validate_preclaim_repair_receipt_raw(raw)
        if (
            receipt["repair_id"] != repair_id
            or receipt["store_identity"] != expected_store_identity
        ):
            raise CoreRequestJournalError()
        final_path = parent / (
            f"requests.sqlite3.preclaim-repair-{repair_id}.json"
        )
        if final_path.exists() or final_path.is_symlink():
            final, _final_raw = _validate_preclaim_repair_receipt(final_path)
            valid_transition = {
                "pending": {"pending", "complete"},
                "complete": {"complete", "retiring"},
                "retiring": {"retiring"},
            }
            if (
                final["store_identity"] != expected_store_identity
                or final["repair_id"] != repair_id
                or _preclaim_repair_evidence(final)
                != _preclaim_repair_evidence(receipt)
                or receipt["status"]
                not in valid_transition[str(final["status"])]
            ):
                raise CoreRequestJournalError()
        else:
            # A temp without a final receipt can only precede the first pending
            # publication.  No rename can have started yet, so require its
            # exact main+lock(+WAL/+SHM) sources before rebuilding that intent.
            source_names = {
                str(item["source_name"])
                for item in receipt["artifacts"]
            }
            permitted_source_sets = {
                frozenset({"requests.sqlite3", "requests.sqlite3.lock"}),
                frozenset(
                    {
                        "requests.sqlite3",
                        "requests.sqlite3.lock",
                        "requests.sqlite3-wal",
                    }
                ),
                frozenset(
                    {
                        "requests.sqlite3",
                        "requests.sqlite3.lock",
                        "requests.sqlite3-wal",
                        "requests.sqlite3-shm",
                    }
                ),
            }
            if (
                receipt["status"] != "pending"
                or frozenset(source_names) not in permitted_source_sets
            ):
                raise CoreRequestJournalError()
            sealed_transients = {
                name for name in source_names if name.startswith("requests.sqlite3-")
            }
            if _assert_no_unsealed_sqlite_transients(
                parent,
                allowed_names=sealed_transients,
            ) != frozenset(sealed_transients):
                raise CoreRequestJournalError()
            for artifact in receipt["artifacts"]:
                source = parent / str(artifact["source_name"])
                archive = parent / str(artifact["archive_name"])
                if not (source.exists() or source.is_symlink()) or (
                    archive.exists() or archive.is_symlink()
                ):
                    raise CoreRequestJournalError()
                _assert_artifact_matches(source, artifact)
            lock_artifact = next(
                item
                for item in receipt["artifacts"]
                if item["source_name"] == "requests.sqlite3.lock"
            )
            if lock_artifact["size_bytes"] != 0:
                raise CoreRequestJournalError()
        lock_descriptor = _acquire_receipt_bound_lock(parent, receipt)
        try:
            assert_preclaim_authority()
            _assert_receipt_bound_lock(parent, receipt, lock_descriptor)
            _unlink_exact_private_artifact(temporary, expected_raw=raw)
            _fsync_directory(parent)
            _assert_receipt_bound_lock(parent, receipt, lock_descriptor)
            assert_preclaim_authority()
        finally:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_descriptor)


def _artifact_descriptor(
    path: Path,
    *,
    source_name: str,
    archive_name: str,
    maximum_bytes: int,
) -> dict[str, Any]:
    content, observed = _read_private_artifact(
        path,
        maximum_bytes=maximum_bytes,
    )
    return {
        "source_name": source_name,
        "archive_name": archive_name,
        "device": int(observed.st_dev),
        "inode": int(observed.st_ino),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _assert_artifact_matches(path: Path, artifact: dict[str, Any]) -> None:
    maximum = (
        MAX_PRECLAIM_JOURNAL_BYTES
        if artifact["source_name"] == "requests.sqlite3"
        else 64 * 1024
        if artifact["source_name"] == "requests.sqlite3.lock"
        else MAX_PRECLAIM_SIDECAR_BYTES
    )
    content, observed = _read_private_artifact(path, maximum_bytes=maximum)
    if (
        int(observed.st_dev) != artifact["device"]
        or int(observed.st_ino) != artifact["inode"]
        or len(content) != artifact["size_bytes"]
        or not secrets.compare_digest(
            hashlib.sha256(content).hexdigest(), artifact["sha256"]
        )
    ):
        raise CoreRequestJournalError()


def _cleanup_preclaim_verify_dirs(
    parent: Path,
    *,
    assert_preclaim_authority: Callable[[], None],
) -> None:
    """Bound and remove only strict private scratch directories from verification."""

    try:
        names = sorted(
            entry.name
            for entry in os.scandir(parent)
            if entry.name.startswith(".requests.sqlite3.preclaim-verify-")
        )
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    if len(names) > MAX_PRECLAIM_VERIFY_DIRS:
        raise CoreRequestJournalError()
    maximum_by_name = {
        "manifest.json": MAX_PRECLAIM_RECEIPT_BYTES,
        "manifest.json.tmp": MAX_PRECLAIM_RECEIPT_BYTES,
        # Isolated WAL replay may grow the disposable main file by up to the
        # sealed WAL bound even though each canonical source was independently
        # within its limit.
        "requests.sqlite3": (
            MAX_PRECLAIM_JOURNAL_BYTES + MAX_PRECLAIM_SIDECAR_BYTES
        ),
        "requests.sqlite3-wal": MAX_PRECLAIM_SIDECAR_BYTES,
        "requests.sqlite3-shm": MAX_PRECLAIM_SIDECAR_BYTES,
        "requests.sqlite3-journal": MAX_PRECLAIM_SIDECAR_BYTES,
    }
    for name in names:
        if _PRECLAIM_VERIFY_DIR_RE.fullmatch(name) is None:
            raise CoreRequestJournalError()
        directory = parent / name
        try:
            before = directory.lstat()
        except OSError as exc:
            raise CoreRequestJournalError() from exc
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o700
        ):
            raise CoreRequestJournalError()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise CoreRequestJournalError() from exc
        if len(entries) > len(maximum_by_name):
            raise CoreRequestJournalError()
        for entry in entries:
            maximum = maximum_by_name.get(entry.name)
            if maximum is None:
                raise CoreRequestJournalError()
            _read_private_artifact(directory / entry.name, maximum_bytes=maximum)
        assert_preclaim_authority()
        for entry in entries:
            maximum = maximum_by_name[entry.name]
            raw, _observed = _read_private_artifact(
                directory / entry.name,
                maximum_bytes=maximum,
            )
            _unlink_exact_private_artifact(
                directory / entry.name,
                expected_raw=raw,
            )
        _fsync_directory(directory)
        visible = directory.lstat()
        if (
            int(visible.st_dev),
            int(visible.st_ino),
            int(visible.st_uid),
            stat.S_IMODE(visible.st_mode),
        ) != (
            int(before.st_dev),
            int(before.st_ino),
            int(before.st_uid),
            stat.S_IMODE(before.st_mode),
        ):
            raise CoreRequestJournalError()
        directory.rmdir()
        _fsync_directory(parent)
        assert_preclaim_authority()


def _write_new_private_file(path: Path, content: bytes, *, maximum: int) -> None:
    if len(content) > maximum or path.exists() or path.is_symlink():
        raise CoreRequestJournalError()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CoreRequestJournalError()
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_sealed_preclaim_journal_copy(
    parent: Path,
    *,
    expected_store_identity: str,
    preliminaries: list[tuple[str, int, bytes, os.stat_result]],
    assert_preclaim_authority: Callable[[], None],
) -> dict[str, Any]:
    """Replay WAL, if present, only in a disposable isolated copy."""

    sealed_sources = [
        {
            "source_name": source_name,
            "device": int(observed.st_dev),
            "inode": int(observed.st_ino),
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for source_name, _maximum, content, observed in preliminaries
    ]
    verify_seed = {
        "schema": PRECLAIM_VERIFY_SCHEMA,
        "store_identity": expected_store_identity,
        "sources": sealed_sources,
    }
    verify_id = hashlib.sha256(
        json.dumps(
            verify_seed,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()[:24]
    directory = parent / f".requests.sqlite3.preclaim-verify-{verify_id}"
    assert_preclaim_authority()
    try:
        os.mkdir(directory, 0o700)
        _fsync_directory(parent)
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    try:
        manifest = {
            **verify_seed,
            "verify_id": verify_id,
        }
        _write_new_private_file(
            directory / "manifest.json",
            _canonical_private_json(manifest),
            maximum=MAX_PRECLAIM_RECEIPT_BYTES,
        )
        for source_name, maximum, content, _observed in preliminaries:
            if source_name not in {"requests.sqlite3", "requests.sqlite3-wal"}:
                continue
            _write_new_private_file(
                directory / source_name,
                content,
                maximum=maximum,
            )
        _fsync_directory(directory)
        assert_preclaim_authority()
        isolated_path = directory / "requests.sqlite3"
        try:
            connection = sqlite3.connect(
                isolated_path,
                timeout=1.0,
                isolation_level=None,
            )
            has_sealed_wal = any(
                item[0] == "requests.sqlite3-wal" for item in preliminaries
            )
            if has_sealed_wal:
                checkpoint = connection.execute(
                    "PRAGMA wal_checkpoint(PASSIVE)"
                ).fetchone()
                if (
                    checkpoint is None
                    or int(checkpoint[0]) != 0
                    or int(checkpoint[1]) <= 0
                    or int(checkpoint[2]) != int(checkpoint[1])
                ):
                    raise CoreRequestJournalError()
            connection.execute("PRAGMA query_only = ON")
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            user_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if (
                application_id != JOURNAL_APPLICATION_ID
                or user_version != JOURNAL_SCHEMA_VERSION
            ):
                raise CoreRequestJournalError()
            _assert_exact_current_schema(connection)
            if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise CoreRequestJournalError()
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise CoreRequestJournalError()
            request_row_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM request_journal"
                ).fetchone()[0]
            )
            if request_row_count != 0:
                raise CoreRequestJournalError()
            metadata = {
                str(row[0]): str(row[1])
                for row in connection.execute(
                    "SELECT key, value FROM request_journal_metadata ORDER BY key"
                ).fetchall()
            }
        except sqlite3.Error as exc:
            raise CoreRequestJournalError() from exc
        finally:
            if "connection" in locals():
                connection.close()
        if set(metadata) != {"binding_schema", "journal_id", "store_identity"}:
            raise CoreRequestJournalError()
        journal_id = metadata["journal_id"]
        if (
            metadata["binding_schema"] != JOURNAL_BINDING_SCHEMA
            or metadata["store_identity"] != expected_store_identity
            or _JOURNAL_ID_RE.fullmatch(journal_id) is None
        ):
            raise CoreRequestJournalError()
        assert_preclaim_authority()
        return {
            "schema": JOURNAL_BINDING_SCHEMA,
            "journal_id": journal_id,
            "store_identity": expected_store_identity,
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "journal_schema_identity": JOURNAL_SCHEMA_IDENTITY,
        }
    finally:
        # The isolated copy is the only SQLite surface that may be replayed or
        # checkpointed.  Its strict scratch directory is removed before any
        # canonical artifact is renamed.
        _cleanup_preclaim_verify_dirs(
            parent,
            assert_preclaim_authority=assert_preclaim_authority,
        )


def _acquire_receipt_bound_lock(
    parent: Path,
    receipt: dict[str, Any],
) -> int:
    artifact = next(
        (
            item
            for item in receipt["artifacts"]
            if item["source_name"] == "requests.sqlite3.lock"
        ),
        None,
    )
    if artifact is None or artifact["size_bytes"] != 0:
        raise CoreRequestJournalError()
    source = parent / str(artifact["source_name"])
    archive = parent / str(artifact["archive_name"])
    source_present = source.exists() or source.is_symlink()
    archive_present = archive.exists() or archive.is_symlink()
    if source_present == archive_present:
        raise CoreRequestJournalError()
    lock_path = source if source_present else archive
    _assert_artifact_matches(lock_path, artifact)
    descriptor, identity = _open_private_regular_file(lock_path, create=False)
    try:
        if identity != (int(artifact["device"]), int(artifact["inode"])):
            raise CoreRequestJournalError()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise CoreRequestJournalError() from exc
        _assert_receipt_bound_lock(parent, receipt, descriptor)
        return descriptor
    except BaseException:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(descriptor)
        raise


def _assert_receipt_bound_lock(
    parent: Path,
    receipt: dict[str, Any],
    descriptor: int,
) -> None:
    artifact = next(
        (
            item
            for item in receipt["artifacts"]
            if item["source_name"] == "requests.sqlite3.lock"
        ),
        None,
    )
    if artifact is None or artifact["size_bytes"] != 0:
        raise CoreRequestJournalError()
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != os.getuid()
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_size != 0
        or (int(opened.st_dev), int(opened.st_ino))
        != (int(artifact["device"]), int(artifact["inode"]))
    ):
        raise CoreRequestJournalError()
    source = parent / str(artifact["source_name"])
    archive = parent / str(artifact["archive_name"])
    source_present = source.exists() or source.is_symlink()
    archive_present = archive.exists() or archive.is_symlink()
    if source_present == archive_present:
        raise CoreRequestJournalError()
    visible = source if source_present else archive
    _assert_artifact_matches(visible, artifact)


def _finish_preclaim_repair(
    parent: Path,
    receipt_path: Path,
    receipt: dict[str, Any],
    receipt_raw: bytes,
    *,
    assert_preclaim_authority: Callable[[], None],
    assert_receipt_lock: Callable[[], None],
) -> dict[str, Any]:
    assert_preclaim_authority()
    assert_receipt_lock()
    for artifact in receipt["artifacts"]:
        assert_preclaim_authority()
        assert_receipt_lock()
        source = parent / artifact["source_name"]
        archive = parent / artifact["archive_name"]
        source_present = source.exists() or source.is_symlink()
        archive_present = archive.exists() or archive.is_symlink()
        if source_present == archive_present:
            raise CoreRequestJournalError()
        current = source if source_present else archive
        _assert_artifact_matches(current, artifact)
        if source_present:
            os.rename(source, archive)
            _assert_artifact_matches(archive, artifact)
        assert_receipt_lock()
        assert_preclaim_authority()
    _fsync_directory(parent)
    assert_preclaim_authority()
    assert_receipt_lock()
    now = max(
        time.time(),
        float(receipt["created_at"]),
        float(receipt["updated_at"]),
        float(receipt["completed_at"] or 0.0),
    )
    completed = {
        **receipt,
        "status": "complete",
        "completed_at": now,
        "updated_at": now,
    }
    _atomic_private_json(
        receipt_path,
        completed,
        expected_existing=receipt_raw,
    )
    assert_receipt_lock()
    assert_preclaim_authority()
    return completed


def _unlink_exact_private_artifact(
    path: Path,
    *,
    artifact: dict[str, Any] | None = None,
    expected_raw: bytes | None = None,
) -> None:
    maximum = (
        MAX_PRECLAIM_RECEIPT_BYTES
        if artifact is None
        else MAX_PRECLAIM_JOURNAL_BYTES
        if artifact["source_name"] == "requests.sqlite3"
        else MAX_PRECLAIM_SIDECAR_BYTES
    )
    raw, observed = _read_private_artifact(path, maximum_bytes=maximum)
    if artifact is not None:
        _assert_artifact_matches(path, artifact)
    if expected_raw is not None and not secrets.compare_digest(raw, expected_raw):
        raise CoreRequestJournalError()
    visible = path.lstat()
    if (
        int(visible.st_dev),
        int(visible.st_ino),
        int(visible.st_size),
        int(visible.st_mtime_ns),
        int(visible.st_ctime_ns),
    ) != (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_size),
        int(observed.st_mtime_ns),
        int(observed.st_ctime_ns),
    ):
        raise CoreRequestJournalError()
    path.unlink()


def _retire_preclaim_repair(
    parent: Path,
    receipt_path: Path,
    receipt: dict[str, Any],
    receipt_raw: bytes,
    *,
    assert_preclaim_authority: Callable[[], None],
) -> None:
    if receipt["status"] == "complete":
        assert_preclaim_authority()
        now = max(
            time.time(),
            float(receipt["created_at"]),
            float(receipt["updated_at"]),
            float(receipt["completed_at"] or 0.0),
        )
        retiring = {
            **receipt,
            "status": "retiring",
            "updated_at": now,
        }
        receipt_raw = _atomic_private_json(
            receipt_path,
            retiring,
            expected_existing=receipt_raw,
        )
        receipt = retiring
        assert_preclaim_authority()
    if receipt["status"] != "retiring":
        raise CoreRequestJournalError()
    for artifact in receipt["artifacts"]:
        assert_preclaim_authority()
        archive = parent / artifact["archive_name"]
        if archive.exists() or archive.is_symlink():
            _unlink_exact_private_artifact(archive, artifact=artifact)
        assert_preclaim_authority()
    _fsync_directory(parent)
    assert_preclaim_authority()
    _unlink_exact_private_artifact(
        receipt_path,
        expected_raw=receipt_raw,
    )
    _fsync_directory(parent)
    assert_preclaim_authority()


def _assert_v5_preclaim_authority(
    *,
    memory_db_path: Path,
    authority_lease: CoreAuthorityLease,
) -> None:
    try:
        authority_lease.assert_core_for(memory_db_path)
    except CoreAuthorityError as exc:
        raise CoreRequestJournalError() from exc
    if authority_lease.durable_epoch is not None:
        raise CoreRequestJournalError()
    try:
        observed = memory_db_path.lstat()
    except OSError as exc:
        raise CoreRequestJournalError() from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise CoreRequestJournalError()
    uri = memory_db_path.resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        connection.execute("PRAGMA query_only = ON")
        application_id = int(
            connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        metadata_table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?",
            ("store_metadata",),
        ).fetchone()
        marker = (
            None
            if metadata_table is None
            else connection.execute(
                "SELECT 1 FROM store_metadata WHERE key = ?",
                ("core_authority",),
            ).fetchone()
        )
    except sqlite3.Error as exc:
        raise CoreRequestJournalError() from exc
    finally:
        if "connection" in locals():
            connection.close()
    if application_id != 0x53324442 or user_version != 5 or marker is not None:
        raise CoreRequestJournalError()
    try:
        authority_lease.assert_core_for(memory_db_path)
    except CoreAuthorityError as exc:
        raise CoreRequestJournalError() from exc


def repair_empty_preclaim_journal_residue(
    path: str | os.PathLike[str],
    *,
    expected_store_identity: str,
    memory_db_path: str | os.PathLike[str],
    authority_lease: CoreAuthorityLease,
) -> dict[str, Any] | None:
    """Archive only a proven-empty v5 preclaim journal, with crash receipts.

    The caller must hold the exact unbound core lease for the v5 database.
    That database precondition is rechecked around every irreversible step;
    the function never accepts a journal containing even one request row.
    """

    journal_path = Path(path).expanduser()
    if (
        not journal_path.is_absolute()
        or journal_path.name != "requests.sqlite3"
        or _STORE_IDENTITY_RE.fullmatch(expected_store_identity) is None
    ):
        raise CoreRequestJournalError()
    parent = journal_path.parent
    _validate_private_directory(parent)
    memory_db = Path(memory_db_path).expanduser().resolve()

    def assert_preclaim_authority() -> None:
        _assert_v5_preclaim_authority(
            memory_db_path=memory_db,
            authority_lease=authority_lease,
        )

    assert_preclaim_authority()
    binding_receipt = parent / "requests.sqlite3.binding.receipt.json"
    if binding_receipt.exists() or binding_receipt.is_symlink():
        raise CoreRequestJournalError()
    _cleanup_preclaim_receipt_temps(
        parent,
        expected_store_identity=expected_store_identity,
        assert_preclaim_authority=assert_preclaim_authority,
    )
    _cleanup_preclaim_verify_dirs(
        parent,
        assert_preclaim_authority=assert_preclaim_authority,
    )

    receipt_paths = sorted(
        parent.glob("requests.sqlite3.preclaim-repair-*.json")
    )
    if len(receipt_paths) > MAX_PRECLAIM_REPAIR_ARCHIVES:
        raise CoreRequestJournalError()
    receipts: list[tuple[Path, dict[str, Any], bytes]] = []
    referenced_archives: set[str] = set()
    for receipt_path in receipt_paths:
        receipt, raw = _validate_preclaim_repair_receipt(receipt_path)
        if (
            receipt["store_identity"] != expected_store_identity
            or receipt_path.name
            != f"requests.sqlite3.preclaim-repair-{receipt['repair_id']}.json"
        ):
            raise CoreRequestJournalError()
        for artifact in receipt["artifacts"]:
            archive_name = str(artifact["archive_name"])
            if archive_name in referenced_archives:
                raise CoreRequestJournalError()
            referenced_archives.add(archive_name)
            archive_path = parent / archive_name
            if receipt["status"] == "complete":
                if not (archive_path.exists() or archive_path.is_symlink()):
                    raise CoreRequestJournalError()
                _assert_artifact_matches(archive_path, artifact)
            elif archive_path.exists() or archive_path.is_symlink():
                _assert_artifact_matches(archive_path, artifact)
        receipts.append((receipt_path, receipt, raw))
    observed_archives = {
        candidate.name for candidate in parent.glob(".*.preclaim-*.archive")
    }
    if not observed_archives.issubset(referenced_archives):
        raise CoreRequestJournalError()
    observed_transients = _assert_no_unsealed_sqlite_transients(
        parent,
        allowed_names={"requests.sqlite3-wal", "requests.sqlite3-shm"},
    )
    retiring = [item for item in receipts if item[1]["status"] == "retiring"]
    if retiring:
        for receipt_path, receipt, raw in sorted(
            retiring,
            key=lambda item: (float(item[1]["created_at"]), item[0].name),
        ):
            _retire_preclaim_repair(
                parent,
                receipt_path,
                receipt,
                raw,
                assert_preclaim_authority=assert_preclaim_authority,
            )
        return repair_empty_preclaim_journal_residue(
            journal_path,
            expected_store_identity=expected_store_identity,
            memory_db_path=memory_db,
            authority_lease=authority_lease,
        )
    pending = [item for item in receipts if item[1]["status"] == "pending"]
    if len(pending) > 1:
        raise CoreRequestJournalError()
    if pending:
        receipt_path, receipt, raw = pending[0]
        sealed_transients = {
            str(artifact["source_name"])
            for artifact in receipt["artifacts"]
            if str(artifact["source_name"]).startswith("requests.sqlite3-")
        }
        if not observed_transients.issubset(sealed_transients):
            raise CoreRequestJournalError()
        lock_descriptor = _acquire_receipt_bound_lock(parent, receipt)
        try:
            result = _finish_preclaim_repair(
                parent,
                receipt_path,
                receipt,
                raw,
                assert_preclaim_authority=assert_preclaim_authority,
                assert_receipt_lock=lambda: _assert_receipt_bound_lock(
                    parent,
                    receipt,
                    lock_descriptor,
                ),
            )
        finally:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(lock_descriptor)
        # No canonical artifact may remain after a completed repair.
        for name in (
            "requests.sqlite3",
            "requests.sqlite3.lock",
            "requests.sqlite3-wal",
            "requests.sqlite3-shm",
        ):
            if (parent / name).exists() or (parent / name).is_symlink():
                raise CoreRequestJournalError()
        return result

    canonical_artifacts = tuple(
        parent / name
        for name in (
            "requests.sqlite3",
            "requests.sqlite3.lock",
            "requests.sqlite3-wal",
            "requests.sqlite3-shm",
        )
    )
    if not (journal_path.exists() or journal_path.is_symlink()):
        if any(path.exists() or path.is_symlink() for path in canonical_artifacts[1:]):
            raise CoreRequestJournalError()
        return None
    if len(receipts) >= MAX_PRECLAIM_REPAIR_ARCHIVES:
        completed = sorted(
            (item for item in receipts if item[1]["status"] == "complete"),
            key=lambda item: (float(item[1]["created_at"]), item[0].name),
        )
        if not completed:
            raise CoreRequestJournalError()
        receipt_path, receipt, raw = completed[0]
        _retire_preclaim_repair(
            parent,
            receipt_path,
            receipt,
            raw,
            assert_preclaim_authority=assert_preclaim_authority,
        )
        return repair_empty_preclaim_journal_residue(
            journal_path,
            expected_store_identity=expected_store_identity,
            memory_db_path=memory_db,
            authority_lease=authority_lease,
        )

    journal_lock_path = parent / "requests.sqlite3.lock"
    if not (journal_lock_path.exists() or journal_lock_path.is_symlink()):
        raise CoreRequestJournalError()

    if "requests.sqlite3-shm" in observed_transients and (
        "requests.sqlite3-wal" not in observed_transients
    ):
        raise CoreRequestJournalError()
    lock_descriptor, _lock_identity = _open_private_regular_file(
        journal_lock_path,
        create=False,
    )
    try:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise CoreRequestJournalError() from exc
        source_specs = (
            ("requests.sqlite3", MAX_PRECLAIM_JOURNAL_BYTES),
            ("requests.sqlite3.lock", 64 * 1024),
            ("requests.sqlite3-wal", MAX_PRECLAIM_SIDECAR_BYTES),
            ("requests.sqlite3-shm", MAX_PRECLAIM_SIDECAR_BYTES),
        )
        preliminaries: list[tuple[str, int, bytes, os.stat_result]] = []
        for source_name, maximum in source_specs:
            source = parent / source_name
            if not (source.exists() or source.is_symlink()):
                continue
            content, observed = _read_private_artifact(
                source,
                maximum_bytes=maximum,
            )
            preliminaries.append((source_name, maximum, content, observed))
        present_names = {item[0] for item in preliminaries}
        required_names = {"requests.sqlite3", "requests.sqlite3.lock"}
        if not required_names.issubset(present_names):
            raise CoreRequestJournalError()
        lock_content = next(
            item[2]
            for item in preliminaries
            if item[0] == "requests.sqlite3.lock"
        )
        if lock_content != b"":
            raise CoreRequestJournalError()
        binding = _verify_sealed_preclaim_journal_copy(
            parent,
            expected_store_identity=expected_store_identity,
            preliminaries=preliminaries,
            assert_preclaim_authority=assert_preclaim_authority,
        )
        # Re-read every untouched canonical source after isolated replay.  No
        # receipt may authorize a rename if any inode or byte changed.
        for source_name, _maximum, content, observed in preliminaries:
            source = parent / source_name
            current, visible = _read_private_artifact(
                source,
                maximum_bytes=(
                    MAX_PRECLAIM_JOURNAL_BYTES
                    if source_name == "requests.sqlite3"
                    else 64 * 1024
                    if source_name == "requests.sqlite3.lock"
                    else MAX_PRECLAIM_SIDECAR_BYTES
                ),
            )
            if (
                not secrets.compare_digest(current, content)
                or (int(visible.st_dev), int(visible.st_ino))
                != (int(observed.st_dev), int(observed.st_ino))
            ):
                raise CoreRequestJournalError()
        if _assert_no_unsealed_sqlite_transients(
            parent,
            allowed_names={"requests.sqlite3-wal", "requests.sqlite3-shm"},
        ) != observed_transients:
            raise CoreRequestJournalError()
        repair_seed = {
            "store_identity": expected_store_identity,
            "journal_id": binding["journal_id"],
            "sources": [
                {
                    "source_name": item[0],
                    "device": int(item[3].st_dev),
                    "inode": int(item[3].st_ino),
                    "size_bytes": len(item[2]),
                    "sha256": hashlib.sha256(item[2]).hexdigest(),
                }
                for item in preliminaries
            ],
        }
        repair_id = hashlib.sha256(
            json.dumps(
                repair_seed,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()[:24]
        receipt_path = parent / (
            f"requests.sqlite3.preclaim-repair-{repair_id}.json"
        )
        if receipt_path.exists() or receipt_path.is_symlink():
            raise CoreRequestJournalError()
        artifacts = [
            _artifact_descriptor(
                parent / source_name,
                source_name=source_name,
                archive_name=f".{source_name}.preclaim-{repair_id}.archive",
                maximum_bytes=maximum,
            )
            for source_name, maximum, _content, _observed in preliminaries
        ]
        now = time.time()
        pending_receipt: dict[str, Any] = {
            "schema": PRECLAIM_REPAIR_SCHEMA,
            "status": "pending",
            "repair_id": repair_id,
            "store_identity": expected_store_identity,
            "journal_id": binding["journal_id"],
            "journal_schema_identity": JOURNAL_SCHEMA_IDENTITY,
            "authority_epoch": "epoch-1",
            "request_row_count": 0,
            "artifacts": artifacts,
            "evidence_sha256": "",
            "created_at": now,
            "completed_at": None,
            "updated_at": now,
        }
        pending_receipt["evidence_sha256"] = hashlib.sha256(
            json.dumps(
                _preclaim_repair_evidence(pending_receipt),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        assert_preclaim_authority()
        pending_raw = _atomic_private_json(
            receipt_path,
            pending_receipt,
            expected_existing=None,
        )
        assert_preclaim_authority()
        return _finish_preclaim_repair(
            parent,
            receipt_path,
            pending_receipt,
            pending_raw,
            assert_preclaim_authority=assert_preclaim_authority,
            assert_receipt_lock=lambda: _assert_receipt_bound_lock(
                parent,
                pending_receipt,
                lock_descriptor,
            ),
        )
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_descriptor)

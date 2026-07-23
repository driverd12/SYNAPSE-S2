#!/usr/bin/env python3
"""Repair only the exact SYNAPSE-S2 v6-without-authority-marker torn state.

This utility is deliberately narrower than a general schema repair command.  It
accepts a database only when its schema and migration set are the registered v5
contract, its header says v6, and neither the durable authority marker nor the
v6 migration exists.  A private, integrity-checked pre-repair SQLite backup and
its expected SHA-256 digest are mandatory before the one-field repair.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_store import (  # noqa: E402
    DurableMemoryStore,
    _matching_backup_schema_contract_versions,
)
from core_authority import CoreAuthorityError, CoreAuthorityLease  # noqa: E402


TORN_USER_VERSION = 6
REPAIRED_USER_VERSION = 5
AUTHORITY_METADATA_KEY = "core_authority"
AUTHORITY_MIGRATION_KEY = "authoritative_core_v1"
SHA256_LENGTH = 64


class TornAdoptionRepairError(RuntimeError):
    """A content-free refusal to repair an unrecognized database state."""


def _absolute_private_file(raw_path: str | os.PathLike[str], *, label: str) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise TornAdoptionRepairError(f"{label} must be an absolute normalized path")
    try:
        observed = path.lstat()
        parent = path.parent.lstat()
    except FileNotFoundError as exc:
        raise TornAdoptionRepairError(f"{label} does not exist") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or stat.S_IMODE(observed.st_mode) != 0o600
    ):
        raise TornAdoptionRepairError(f"{label} must be a private owned regular file")
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise TornAdoptionRepairError(f"{label} parent must be a private owned directory")
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        visible = path.lstat()
        if (
            opened.st_dev != visible.st_dev
            or opened.st_ino != visible.st_ino
            or opened.st_nlink != 1
        ):
            raise TornAdoptionRepairError("backup identity changed during verification")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _migration_digest(migrations: list[str]) -> str:
    payload = json.dumps(
        migrations,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _inspect_connection(connection: sqlite3.Connection) -> dict[str, Any]:
    connection.row_factory = sqlite3.Row
    integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
    integrity = [str(row[0]) for row in integrity_rows]
    if integrity != ["ok"]:
        raise TornAdoptionRepairError("database integrity check failed")
    schema = DurableMemoryStore._sqlite_schema_fingerprint(connection)
    logical_snapshot = DurableMemoryStore._canonical_logical_snapshot_digest(
        connection
    )
    migrations = sorted(
        str(row[0])
        for row in connection.execute(
            "SELECT key FROM store_migrations ORDER BY key"
        ).fetchall()
    )
    marker = connection.execute(
        "SELECT value_json FROM store_metadata WHERE key = ?",
        (AUTHORITY_METADATA_KEY,),
    ).fetchone()
    authority_migration = connection.execute(
        "SELECT 1 FROM store_migrations WHERE key = ?",
        (AUTHORITY_MIGRATION_KEY,),
    ).fetchone()
    table_names = sorted(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    )
    counts: dict[str, int] = {}
    for table_name in table_names:
        quoted_name = table_name.replace('"', '""')
        counts[table_name] = int(
            connection.execute(
                f'SELECT COUNT(*) FROM "{quoted_name}"'
            ).fetchone()[0]
        )
    return {
        "application_id": int(connection.execute("PRAGMA application_id").fetchone()[0]),
        "user_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
        "schema_sha256": str(schema["sha256"]),
        "table_count": int(schema["table_count"]),
        "index_count": int(schema["index_count"]),
        "missing_critical_table_count": int(schema["missing_critical_table_count"]),
        "migration_count": len(migrations),
        "migration_set_sha256": _migration_digest(migrations),
        "authority_marker_present": marker is not None,
        "authority_migration_present": authority_migration is not None,
        "logical_snapshot": logical_snapshot,
        "counts": counts,
    }


def _open_database(path: Path, *, writable: bool) -> sqlite3.Connection:
    mode = "rw" if writable else "ro"
    connection = sqlite3.connect(
        path.resolve().as_uri() + f"?mode={mode}",
        uri=True,
        timeout=30.0,
        isolation_level=None,
    )
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def _assert_v5_contract(snapshot: dict[str, Any]) -> None:
    schema_contract = {
        key: snapshot[key]
        for key in (
            "application_id",
            "user_version",
            "schema_sha256",
            "table_count",
            "index_count",
            "migration_count",
            "migration_set_sha256",
        )
    }
    schema_contract["user_version"] = REPAIRED_USER_VERSION
    if not _matching_backup_schema_contract_versions(schema_contract):
        raise TornAdoptionRepairError("database does not match a registered v5 contract")
    if snapshot["missing_critical_table_count"] != 0:
        raise TornAdoptionRepairError("database is missing a critical table")
    if snapshot["authority_marker_present"] or snapshot["authority_migration_present"]:
        raise TornAdoptionRepairError("database contains authoritative-core adoption state")


def inspect_database(path: Path) -> dict[str, Any]:
    with closing(_open_database(path, writable=False)) as connection:
        return _inspect_connection(connection)


def _logical_snapshot_for_backup_comparison(
    connection: sqlite3.Connection,
    snapshot: dict[str, Any],
    *,
    backup_user_version: int,
) -> dict[str, Any]:
    """Return a logical digest normalized only across the repaired header bit.

    The canonical logical digest intentionally includes ``user_version``.  An
    idempotent repair therefore has a v5 live header while its mandatory
    pre-repair backup has a v6 header.  Normalize that one registered repair
    field inside a savepoint so all schema and row content is still compared
    by the canonical digest without changing the durable live header.
    """

    live_user_version = int(snapshot["user_version"])
    if live_user_version == int(backup_user_version):
        return dict(snapshot["logical_snapshot"])
    if (
        live_user_version != REPAIRED_USER_VERSION
        or int(backup_user_version) != TORN_USER_VERSION
    ):
        raise TornAdoptionRepairError("database header state cannot be normalized")
    savepoint = "s2_torn_adoption_header_comparison"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        connection.execute(f"PRAGMA user_version = {TORN_USER_VERSION}")
        return DurableMemoryStore._canonical_logical_snapshot_digest(connection)
    finally:
        connection.execute(f"ROLLBACK TO {savepoint}")
        connection.execute(f"RELEASE {savepoint}")


def repair_torn_adoption(
    database_path: str | os.PathLike[str],
    *,
    backup_path: str | os.PathLike[str],
    expected_backup_sha256: str,
    confirm: bool,
) -> dict[str, Any]:
    if confirm is not True:
        raise TornAdoptionRepairError("repair requires explicit confirmation")
    database = _absolute_private_file(database_path, label="database")
    backup = _absolute_private_file(backup_path, label="backup")
    if database == backup:
        raise TornAdoptionRepairError("backup must be separate from the database")
    expected_digest = str(expected_backup_sha256 or "").strip().lower()
    if (
        len(expected_digest) != SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        raise TornAdoptionRepairError("expected backup digest is invalid")
    observed_digest = _sha256_file(backup)
    if not hmac.compare_digest(observed_digest, expected_digest):
        raise TornAdoptionRepairError("backup digest does not match")

    backup_snapshot = inspect_database(backup)
    _assert_v5_contract(backup_snapshot)
    if backup_snapshot["user_version"] != TORN_USER_VERSION:
        raise TornAdoptionRepairError("backup is not the expected torn-adoption snapshot")

    try:
        authority = CoreAuthorityLease.acquire_core(
            database,
            timeout_seconds=0.0,
            instance_id="maintenance-repair-torn-core-adoption",
        )
    except CoreAuthorityError as exc:
        raise TornAdoptionRepairError(
            "exclusive authoritative-core maintenance lease is unavailable"
        ) from exc

    try:
        with authority, closing(_open_database(database, writable=True)) as connection:
            authority.assert_core_for(database)
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN EXCLUSIVE")
            try:
                before = _inspect_connection(connection)
                _assert_v5_contract(before)
                comparable_before = _logical_snapshot_for_backup_comparison(
                    connection,
                    before,
                    backup_user_version=int(backup_snapshot["user_version"]),
                )
                if not hmac.compare_digest(
                    str(comparable_before["sha256"]),
                    str(backup_snapshot["logical_snapshot"]["sha256"]),
                ):
                    raise TornAdoptionRepairError(
                        "database changed after the required pre-repair backup"
                    )
                if before["user_version"] == REPAIRED_USER_VERSION:
                    connection.rollback()
                    authority.assert_core_for(database)
                    return {
                        "action": "repair-torn-core-adoption",
                        "status": "already-repaired",
                        "database": str(database),
                        "backup_sha256": observed_digest,
                        "before": before,
                        "after": before,
                    }
                if before["user_version"] != TORN_USER_VERSION:
                    raise TornAdoptionRepairError(
                        "database is not in the exact torn-adoption state"
                    )
                connection.execute(f"PRAGMA user_version = {REPAIRED_USER_VERSION}")
                expected_after = _inspect_connection(connection)
                connection.commit()
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            checkpoint = connection.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
            after = _inspect_connection(connection)
            _assert_v5_contract(after)
            if after["user_version"] != REPAIRED_USER_VERSION:
                raise TornAdoptionRepairError("database header repair did not persist")
            if not hmac.compare_digest(
                str(after["logical_snapshot"]["sha256"]),
                str(expected_after["logical_snapshot"]["sha256"]),
            ):
                raise TornAdoptionRepairError(
                    "database content changed during header repair"
                )
            authority.assert_core_for(database)
            return {
                "action": "repair-torn-core-adoption",
                "status": "repaired",
                "database": str(database),
                "backup_sha256": observed_digest,
                "checkpoint": [int(value) for value in checkpoint] if checkpoint else None,
                "before": before,
                "after": after,
            }
    except CoreAuthorityError as exc:
        raise TornAdoptionRepairError(
            "exclusive authoritative-core maintenance lease became invalid"
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repair only an exact v6-without-core-marker torn adoption."
    )
    parser.add_argument("--database", required=True)
    parser.add_argument("--backup", required=True)
    parser.add_argument("--expected-backup-sha256", required=True)
    parser.add_argument("--confirm", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = repair_torn_adoption(
            args.database,
            backup_path=args.backup,
            expected_backup_sha256=args.expected_backup_sha256,
            confirm=bool(args.confirm),
        )
    except TornAdoptionRepairError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

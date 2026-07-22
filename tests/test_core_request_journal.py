from __future__ import annotations

import json
import fcntl
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from core_request_journal import (
    JOURNAL_APPLICATION_ID,
    JOURNAL_SCHEMA_VERSION,
    CoreRequestJournal,
    CoreRequestJournalCapacityError,
    CoreRequestJournalError,
    MAX_PRECLAIM_REPAIR_ARCHIVES,
    repair_empty_preclaim_journal_residue,
)
from core_authority import CoreAuthorityError, CoreAuthorityLease
from core_client import (
    CoreClient,
    CoreOutcomeUnknown,
    CoreRemoteError,
    CoreUnavailable,
    _CorePreconnectUnavailable,
    outcome_unknown_projection,
)
from core_protocol import (
    CoreProtocolError,
    build_request,
    receive_frame,
    send_frame,
    validate_response,
)
from core_service import (
    CORE_OPERATION_CONTRACTS,
    AuthoritativeCoreService,
    CoreConfig,
    CoreServiceError,
)
from memory_store import DurableMemoryStore


class CoreRequestJournalTests(unittest.TestCase):
    def private_root(self, temporary: str) -> Path:
        root = Path(temporary) / "core"
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        return root

    @staticmethod
    def accept(
        journal: CoreRequestJournal,
        request_id: str,
        *,
        fingerprint: str | None = None,
        operation: str = "set_enabled",
    ):
        return journal.accept(
            caller="test-client",
            request_id=request_id,
            operation=operation,
            request_fingerprint=fingerprint or ("a" * 64),
        )

    @staticmethod
    def finish(
        journal: CoreRequestJournal,
        request_id: str,
        *,
        result: object = None,
        error: str | None = None,
    ) -> None:
        journal.finish(
            caller="test-client",
            request_id=request_id,
            operation="set_enabled",
            request_fingerprint="a" * 64,
            result=result,
            safe_error_code=error,
        )

    def test_private_full_durability_schema_and_identity(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            journal = CoreRequestJournal(path, authority_epoch="epoch-1")
            self.addCleanup(journal.close)
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
            self.assertEqual(path.lstat().st_nlink, 1)
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(
                    int(connection.execute("PRAGMA application_id").fetchone()[0]),
                    JOURNAL_APPLICATION_ID,
                )
                self.assertEqual(
                    int(connection.execute("PRAGMA user_version").fetchone()[0]),
                    JOURNAL_SCHEMA_VERSION,
                )
                self.assertEqual(
                    str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                    "wal",
                )
            finally:
                connection.close()

    def test_require_existing_refuses_missing_or_blank_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            with self.assertRaises(CoreRequestJournalError):
                CoreRequestJournal(
                    path,
                    authority_epoch="epoch-required",
                    require_existing=True,
                )
            self.assertFalse(path.exists())
            self.assertFalse(path.with_suffix(".sqlite3.lock").exists())

            path.touch(mode=0o600)
            os.chmod(path, 0o600)
            with self.assertRaises(CoreRequestJournalError):
                CoreRequestJournal(
                    path,
                    authority_epoch="epoch-required",
                    require_existing=True,
                )
            self.assertEqual(path.stat().st_size, 0)

    def test_require_existing_opens_a_valid_durable_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            first = CoreRequestJournal(path, authority_epoch="epoch-1")
            self.accept(first, "req-existing")
            first.close()

            second = CoreRequestJournal(
                path,
                authority_epoch="epoch-2",
                require_existing=True,
            )
            self.addCleanup(second.close)
            decision = self.accept(second, "req-existing")
            self.assertEqual(decision.disposition, "existing")

    def test_finish_clamps_backward_wall_clock_to_persisted_acceptance(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            journal = CoreRequestJournal(path, authority_epoch="epoch-1")
            self.addCleanup(journal.close)
            with mock.patch("core_request_journal.time.time", return_value=2_000.0):
                self.assertEqual(
                    self.accept(journal, "req-clock-rollback").disposition,
                    "accepted",
                )
            with mock.patch("core_request_journal.time.time", return_value=1_000.0):
                self.finish(journal, "req-clock-rollback", result={"ok": True})
            row = journal._db.execute(
                "SELECT state, accepted_at_unix_ms, finished_at_unix_ms "
                "FROM request_journal WHERE caller = ? AND request_id = ?",
                ("test-client", "req-clock-rollback"),
            ).fetchone()
            self.assertEqual(row[0], "completed")
            self.assertEqual(row[2], row[1])

    def test_preclaim_open_can_defer_retention_mutation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            first = CoreRequestJournal(path, authority_epoch="epoch-1")
            self.accept(first, "req-expired")
            self.finish(first, "req-expired", result={"enabled": True})
            first.close()
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE request_journal "
                    "SET accepted_at_unix_ms = 1, finished_at_unix_ms = 1 "
                    "WHERE caller = ? AND request_id = ?",
                    ("test-client", "req-expired"),
                )
                connection.commit()
            finally:
                connection.close()

            second = CoreRequestJournal(
                path,
                authority_epoch="epoch-2",
                retention_seconds=0,
                require_existing=True,
                prune_on_open=False,
            )
            self.addCleanup(second.close)
            before = second.request_status(
                caller="test-client",
                request_id="req-expired",
            )
            self.assertTrue(before["known"])
            self.assertEqual(second.prune(), 1)
            after = second.request_status(
                caller="test-client",
                request_id="req-expired",
            )
            self.assertFalse(after["known"])

    def test_v1_schema_migrates_without_response_derived_metadata(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "CREATE TABLE request_journal ("
                    "caller TEXT NOT NULL, request_id TEXT NOT NULL, operation TEXT NOT NULL, "
                    "request_fingerprint TEXT NOT NULL, authority_epoch TEXT NOT NULL, "
                    "state TEXT NOT NULL, result_kind TEXT, response_sha256 TEXT, "
                    "response_bytes INTEGER, safe_error_code TEXT, "
                    "accepted_at_unix_ms INTEGER NOT NULL, finished_at_unix_ms INTEGER, "
                    "PRIMARY KEY (caller, request_id)) WITHOUT ROWID"
                )
                connection.execute(
                    "CREATE INDEX request_journal_terminal_age "
                    "ON request_journal(state, finished_at_unix_ms)"
                )
                connection.execute(f"PRAGMA application_id = {JOURNAL_APPLICATION_ID}")
                connection.execute("PRAGMA user_version = 1")
                connection.commit()
            finally:
                connection.close()
            os.chmod(path, 0o600)

            journal = CoreRequestJournal(path, authority_epoch="epoch-migrated")
            self.addCleanup(journal.close)
            columns = tuple(
                row[1]
                for row in journal._db.execute(
                    "PRAGMA table_info(request_journal)"
                ).fetchall()
            )
            self.assertNotIn("response_sha256", columns)
            self.assertNotIn("response_bytes", columns)
            self.assertEqual(
                int(journal._db.execute("PRAGMA user_version").fetchone()[0]),
                JOURNAL_SCHEMA_VERSION,
            )

    def test_preclaim_existing_open_refuses_schema_migration(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "CREATE TABLE request_journal ("
                    "caller TEXT NOT NULL, request_id TEXT NOT NULL, operation TEXT NOT NULL, "
                    "request_fingerprint TEXT NOT NULL, authority_epoch TEXT NOT NULL, "
                    "state TEXT NOT NULL, result_kind TEXT, response_sha256 TEXT, "
                    "response_bytes INTEGER, safe_error_code TEXT, "
                    "accepted_at_unix_ms INTEGER NOT NULL, finished_at_unix_ms INTEGER, "
                    "PRIMARY KEY (caller, request_id)) WITHOUT ROWID"
                )
                connection.execute(
                    "CREATE INDEX request_journal_terminal_age "
                    "ON request_journal(state, finished_at_unix_ms)"
                )
                connection.execute(
                    f"PRAGMA application_id = {JOURNAL_APPLICATION_ID}"
                )
                connection.execute("PRAGMA user_version = 1")
                connection.commit()
            finally:
                connection.close()
            os.chmod(path, 0o600)

            with self.assertRaises(CoreRequestJournalError):
                CoreRequestJournal(
                    path,
                    authority_epoch="epoch-2",
                    require_existing=True,
                    prune_on_open=False,
                    allow_migration=False,
                )
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(
                    int(connection.execute("PRAGMA user_version").fetchone()[0]),
                    1,
                )
            finally:
                connection.close()

    def test_accept_duplicate_conflict_and_restart_are_non_replayable(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            first = CoreRequestJournal(path, authority_epoch="epoch-1")
            self.assertEqual(self.accept(first, "req-1").disposition, "accepted")
            self.assertEqual(self.accept(first, "req-1").disposition, "existing")
            self.assertEqual(
                self.accept(first, "req-1", fingerprint="b" * 64).disposition,
                "conflict",
            )
            self.finish(first, "req-1", result={"enabled": True})
            self.assertEqual(self.accept(first, "req-1").disposition, "existing")
            first.close()

            second = CoreRequestJournal(path, authority_epoch="epoch-2")
            self.addCleanup(second.close)
            decision = self.accept(second, "req-1")
            self.assertEqual(decision.disposition, "existing")
            self.assertEqual(decision.state, "completed")

    def test_only_request_fingerprint_and_content_free_metadata_are_persisted(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            path = root / "requests.sqlite3"
            canary = "sk-secret-canary-12345678901234567890"
            journal = CoreRequestJournal(path, authority_epoch="epoch-1")
            self.accept(journal, "req-secret")
            self.finish(
                journal,
                "req-secret",
                result=canary,
            )
            health = journal.health(exact_response_keys={("test-client", "req-secret")})
            status = journal.request_status(
                caller="test-client",
                request_id="req-secret",
            )
            columns = {
                row[1]
                for row in journal._db.execute(
                    "PRAGMA table_info(request_journal)"
                ).fetchall()
            }
            self.assertNotIn("response_sha256", columns)
            self.assertNotIn("response_bytes", columns)
            self.assertEqual(health["completed_count"], 1)
            self.assertEqual(health["ambiguous_count"], 0)
            journal.close()
            rendered_health = repr(health).encode("utf-8")
            rendered_status = repr(status).encode("utf-8")
            database_bytes = path.read_bytes()
            wal_path = Path(f"{path}-wal")
            wal_bytes = wal_path.read_bytes() if wal_path.exists() else b""
            self.assertNotIn(canary.encode("utf-8"), database_bytes + wal_bytes)
            self.assertNotIn(canary.encode("utf-8"), rendered_health + rendered_status)

    def test_reconciliation_status_is_fixed_content_free_and_stable(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            journal = CoreRequestJournal(
                root / "requests.sqlite3",
                authority_epoch="epoch-status",
            )
            self.addCleanup(journal.close)
            expected_fields = {
                "known",
                "caller",
                "request_id",
                "state",
                "operation",
                "safe_error_code",
                "result_kind",
                "authority_epoch",
                "accepted_age_ms",
                "finished_age_ms",
                "replay_safe",
                "retention_expiry_possible",
            }
            not_found = journal.request_status(
                caller="test-client",
                request_id="req-missing",
            )
            self.assertEqual(frozenset(not_found), expected_fields)
            self.assertFalse(not_found["known"])
            self.assertEqual(not_found["state"], "not_found")
            self.assertFalse(not_found["replay_safe"])
            self.assertTrue(not_found["retention_expiry_possible"])

            self.accept(journal, "req-accepted")
            accepted = journal.request_status(
                caller="test-client",
                request_id="req-accepted",
            )
            self.assertTrue(accepted["known"])
            self.assertEqual(accepted["state"], "accepted")
            self.assertEqual(accepted["operation"], "set_enabled")
            self.assertEqual(accepted["authority_epoch"], "epoch-status")
            self.assertIsInstance(accepted["accepted_age_ms"], int)
            self.assertIsNone(accepted["finished_age_ms"])
            self.assertFalse(accepted["replay_safe"])
            self.assertFalse(accepted["retention_expiry_possible"])

            self.finish(journal, "req-accepted", result={"enabled": True})
            completed = journal.request_status(
                caller="test-client",
                request_id="req-accepted",
            )
            self.assertEqual(completed["state"], "completed")
            self.assertEqual(completed["result_kind"], "object")
            self.assertIsNone(completed["safe_error_code"])
            self.assertIsInstance(completed["finished_age_ms"], int)

            self.accept(journal, "req-failed")
            self.finish(journal, "req-failed", error="operation_failed")
            failed = journal.request_status(
                caller="test-client",
                request_id="req-failed",
            )
            self.assertEqual(failed["state"], "failed")
            self.assertEqual(failed["safe_error_code"], "operation_failed")
            self.assertIsNone(failed["result_kind"])
            forbidden = {
                "arguments",
                "request_fingerprint",
                "response",
                "response_bytes",
                "response_sha256",
                "digest",
                "text",
                "embedding",
                "embeddings",
            }
            for projection in (not_found, accepted, completed, failed):
                self.assertEqual(frozenset(projection), expected_fields)
                self.assertTrue(forbidden.isdisjoint(projection))

    def test_request_status_contract_is_retry_safe_service_control(self) -> None:
        contract = CORE_OPERATION_CONTRACTS["request_status"]
        self.assertFalse(contract.mutation)
        self.assertTrue(contract.retry_safe)
        self.assertEqual(contract.allowed_arguments, {"caller", "request_id"})
        self.assertEqual(contract.required_arguments, {"caller", "request_id"})

    def test_refuses_unsafe_parent_symlink_hardlink_and_replacement(self) -> None:
        with TemporaryDirectory() as temporary:
            base = Path(temporary)
            unsafe = base / "unsafe"
            unsafe.mkdir(mode=0o755)
            os.chmod(unsafe, 0o755)
            with self.assertRaises(CoreRequestJournalError):
                CoreRequestJournal(unsafe / "requests.sqlite3", authority_epoch="epoch-1")

            root = self.private_root(temporary)
            target = root / "target.sqlite3"
            target.write_bytes(b"")
            os.chmod(target, 0o600)
            link = root / "requests.sqlite3"
            link.symlink_to(target)
            with self.assertRaises(CoreRequestJournalError):
                CoreRequestJournal(link, authority_epoch="epoch-1")
            link.unlink()

            hardlink = root / "requests.sqlite3"
            os.link(target, hardlink)
            with self.assertRaises(CoreRequestJournalError):
                CoreRequestJournal(hardlink, authority_epoch="epoch-1")
            hardlink.unlink()
            target.unlink()

            unsafe_mode = root / "requests.sqlite3"
            unsafe_mode.write_bytes(b"")
            os.chmod(unsafe_mode, 0o644)
            with self.assertRaises(CoreRequestJournalError):
                CoreRequestJournal(unsafe_mode, authority_epoch="epoch-1")
            unsafe_mode.unlink()

            journal = CoreRequestJournal(unsafe_mode, authority_epoch="epoch-1")
            moved = root / "moved.sqlite3"
            unsafe_mode.rename(moved)
            unsafe_mode.write_bytes(b"")
            os.chmod(unsafe_mode, 0o600)
            with self.assertRaises(CoreRequestJournalError):
                self.accept(journal, "req-replaced")
            journal.close()
            self.assertTrue(unsafe_mode.exists())

    def test_refuses_unsafe_sqlite_sidecars_before_open(self) -> None:
        for suffix in ("-wal", "-shm"):
            with self.subTest(suffix=suffix), TemporaryDirectory() as temporary:
                root = self.private_root(temporary)
                target = root / "sidecar-target"
                target.write_bytes(b"unchanged")
                os.chmod(target, 0o600)
                sidecar = Path(f"{root / 'requests.sqlite3'}{suffix}")
                sidecar.symlink_to(target)

                with self.assertRaises(CoreRequestJournalError):
                    CoreRequestJournal(
                        root / "requests.sqlite3",
                        authority_epoch="epoch-1",
                    )

                self.assertTrue(sidecar.is_symlink())
                self.assertEqual(target.read_bytes(), b"unchanged")

    def test_mid_transaction_path_substitution_fails_before_accept_returns(self) -> None:
        for target_kind in ("main", "lock", "-wal", "-shm"):
            with self.subTest(target_kind=target_kind), TemporaryDirectory() as temporary:
                root = self.private_root(temporary)
                path = root / "requests.sqlite3"
                journal = CoreRequestJournal(path, authority_epoch="epoch-1")
                target = (
                    path
                    if target_kind == "main"
                    else path.with_suffix(path.suffix + ".lock")
                    if target_kind == "lock"
                    else Path(f"{path}{target_kind}")
                )
                self.assertTrue(target.exists(), target_kind)
                replacement = root / f"replacement-{target_kind.lstrip('-')}"
                replacement.write_bytes(b"replacement")
                os.chmod(replacement, 0o600)
                replaced = False

                def replace_during_insert(statement: str) -> None:
                    nonlocal replaced
                    if replaced or not statement.startswith("INSERT INTO request_journal"):
                        return
                    replaced = True
                    os.replace(replacement, target)

                assert journal._connection is not None
                journal._connection.set_trace_callback(replace_during_insert)
                try:
                    with self.assertRaises(CoreRequestJournalError):
                        self.accept(journal, f"req-replaced-{target_kind.lstrip('-')}")
                    self.assertTrue(replaced)
                finally:
                    journal.close()

    def test_retention_is_bounded_without_deleting_accepted_rows(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self.private_root(temporary)
            journal = CoreRequestJournal(
                root / "requests.sqlite3",
                authority_epoch="epoch-1",
                max_rows=3,
                max_accepted_rows=2,
                retention_seconds=60,
            )
            self.addCleanup(journal.close)
            for index in range(3):
                request_id = f"req-{index}"
                self.assertEqual(self.accept(journal, request_id).disposition, "accepted")
                self.finish(journal, request_id)
            with self.assertRaises(CoreRequestJournalCapacityError):
                self.accept(journal, "req-within-horizon")
            health = journal.health()
            self.assertEqual(
                health["accepted_count"]
                + health["completed_count"]
                + health["failed_count"],
                3,
            )
            self.assertFalse(health["ready"])
            self.assertFalse(health["accepting_mutations"])
            self.assertEqual(health["remaining_rows"], 0)
            self.assertEqual(health["blocker"], "request_journal_capacity")

            removed = journal.prune(
                now_unix_ms=int(time.time() * 1000) + 61_000
            )
            self.assertEqual(removed, 3)
            self.assertEqual(
                self.accept(journal, "req-after-horizon").disposition,
                "accepted",
            )
            health = journal.health()
            self.assertTrue(health["accepting_mutations"])
            self.assertEqual(health["accepted_count"], 1)


class EmptyPreclaimJournalRepairTests(unittest.TestCase):
    def fixture(
        self,
        temporary: str,
    ) -> tuple[Path, Path, str, CoreAuthorityLease]:
        root = Path(temporary).resolve()
        database = root / "memory.sqlite3"
        bootstrap = DurableMemoryStore(database)
        store_identity = bootstrap.store_identity_for_path(database)
        bootstrap.close()
        lease = CoreAuthorityLease.acquire_core(
            database,
            timeout_seconds=0.0,
            instance_id="preclaim-repair-test",
        )
        return root, database, store_identity, lease

    @staticmethod
    def create_empty_journal(root: Path, store_identity: str) -> str:
        journal = CoreRequestJournal(
            root / "core" / "requests.sqlite3",
            authority_epoch="epoch-1",
            prune_on_open=False,
            store_identity=store_identity,
        )
        try:
            return str(journal.binding()["journal_id"])
        finally:
            journal.close()

    def repair(
        self,
        root: Path,
        database: Path,
        store_identity: str,
        lease: CoreAuthorityLease,
    ) -> dict[str, object] | None:
        return repair_empty_preclaim_journal_residue(
            root / "core" / "requests.sqlite3",
            expected_store_identity=store_identity,
            memory_db_path=database,
            authority_lease=lease,
        )

    def test_empty_residue_is_archived_with_replayable_receipt(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            journal_id = self.create_empty_journal(root, store_identity)
            receipt = self.repair(root, database, store_identity, lease)
            assert receipt is not None
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(receipt["journal_id"], journal_id)
            self.assertEqual(receipt["request_row_count"], 0)
            self.assertFalse((root / "core" / "requests.sqlite3").exists())
            self.assertIsNone(self.repair(root, database, store_identity, lease))

    def test_nonempty_residue_is_never_archived(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            journal_path = root / "core" / "requests.sqlite3"
            journal = CoreRequestJournal(
                journal_path,
                authority_epoch="epoch-1",
                prune_on_open=False,
                store_identity=store_identity,
            )
            journal.accept(
                caller="repair-test",
                request_id="accepted-before-cutover",
                operation="set_enabled",
                request_fingerprint="a" * 64,
            )
            journal.close()
            with self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)
            self.assertTrue(journal_path.exists())
            self.assertFalse(
                tuple((root / "core").glob("*.preclaim-repair-*.json"))
            )

    def test_missing_lock_with_sidecar_is_rejected_without_recreation(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            self.create_empty_journal(root, store_identity)
            journal_path = root / "core" / "requests.sqlite3"
            lock_path = root / "core" / "requests.sqlite3.lock"
            lock_path.unlink()
            wal_path = Path(f"{journal_path}-wal")
            wal_path.write_bytes(b"")
            wal_path.chmod(0o600)
            with self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)
            self.assertFalse(lock_path.exists())
            self.assertTrue(journal_path.exists())

    def test_rollback_and_unknown_sqlite_transients_are_preserved(self) -> None:
        for suffix in ("-journal", "-mj deadbeef"):
            with self.subTest(suffix=suffix), TemporaryDirectory() as temporary:
                root, database, store_identity, lease = self.fixture(temporary)
                try:
                    self.create_empty_journal(root, store_identity)
                    core = root / "core"
                    journal_path = core / "requests.sqlite3"
                    transient = Path(f"{journal_path}{suffix}")
                    transient.write_bytes(b"unsealed sqlite recovery evidence")
                    transient.chmod(0o600)
                    before = transient.lstat()
                    before_main = journal_path.read_bytes()
                    with self.assertRaises(CoreRequestJournalError):
                        self.repair(root, database, store_identity, lease)
                    after = transient.lstat()
                    self.assertEqual(
                        (before.st_dev, before.st_ino, before.st_size),
                        (after.st_dev, after.st_ino, after.st_size),
                    )
                    self.assertEqual(
                        transient.read_bytes(),
                        b"unsealed sqlite recovery evidence",
                    )
                    self.assertEqual(journal_path.read_bytes(), before_main)
                    self.assertFalse(
                        tuple(core.glob("requests.sqlite3.preclaim-repair-*.json"))
                    )
                    self.assertFalse(tuple(core.glob(".*.preclaim-*.archive")))
                finally:
                    lease.close()

    def test_fake_wal_and_shm_are_verified_only_on_copy_and_preserved(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            self.create_empty_journal(root, store_identity)
            core = root / "core"
            journal_path = core / "requests.sqlite3"
            wal = Path(f"{journal_path}-wal")
            shm = Path(f"{journal_path}-shm")
            wal.write_bytes(b"fake-wal-canary")
            shm.write_bytes(b"fake-shm-canary")
            wal.chmod(0o600)
            shm.chmod(0o600)
            before = {
                path: (path.read_bytes(), path.lstat()) for path in (wal, shm)
            }
            with self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)
            for path, (content, observed) in before.items():
                visible = path.lstat()
                self.assertEqual(path.read_bytes(), content)
                self.assertEqual(
                    (visible.st_dev, visible.st_ino, visible.st_size),
                    (observed.st_dev, observed.st_ino, observed.st_size),
                )
            self.assertFalse(
                tuple(core.glob("requests.sqlite3.preclaim-repair-*.json"))
            )
            self.assertFalse(tuple(core.glob(".*.preclaim-*.archive")))
            self.assertFalse(
                tuple(core.glob(".requests.sqlite3.preclaim-verify-*"))
            )

    def test_nonempty_protocol_lock_is_never_repaired_or_rotated(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            self.create_empty_journal(root, store_identity)
            core = root / "core"
            lock_path = core / "requests.sqlite3.lock"
            lock_path.write_bytes(b"not protocol lock content")
            lock_path.chmod(0o600)
            before = lock_path.lstat()
            with self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)
            after = lock_path.lstat()
            self.assertEqual(lock_path.read_bytes(), b"not protocol lock content")
            self.assertEqual(
                (before.st_dev, before.st_ino, before.st_size),
                (after.st_dev, after.st_ino, after.st_size),
            )
            self.assertFalse(
                tuple(core.glob("requests.sqlite3.preclaim-repair-*.json"))
            )
            self.assertFalse(tuple(core.glob(".*.preclaim-*.archive")))

    def test_exact_schema_tampering_is_never_archived(self) -> None:
        cases = ("hidden-column", "wrong-index", "weakened-check")
        for case in cases:
            with self.subTest(case=case), TemporaryDirectory() as temporary:
                root, database, store_identity, lease = self.fixture(temporary)
                try:
                    self.create_empty_journal(root, store_identity)
                    core = root / "core"
                    journal_path = core / "requests.sqlite3"
                    with closing(sqlite3.connect(journal_path)) as connection:
                        if case == "hidden-column":
                            connection.execute(
                                "ALTER TABLE request_journal ADD COLUMN hidden_x "
                                "TEXT GENERATED ALWAYS AS ('x') VIRTUAL"
                            )
                        elif case == "wrong-index":
                            connection.execute(
                                "DROP INDEX request_journal_terminal_age"
                            )
                            connection.execute(
                                "CREATE INDEX request_journal_terminal_age "
                                "ON request_journal(finished_at_unix_ms, state)"
                            )
                        else:
                            schema_version = int(
                                connection.execute(
                                    "PRAGMA schema_version"
                                ).fetchone()[0]
                            )
                            connection.execute("PRAGMA writable_schema = ON")
                            connection.execute(
                                "UPDATE sqlite_schema SET sql = replace(sql, "
                                "'accepted_at_unix_ms > 0', "
                                "'accepted_at_unix_ms >= 0') "
                                "WHERE type = 'table' AND name = 'request_journal'"
                            )
                            connection.execute(
                                f"PRAGMA schema_version = {schema_version + 1}"
                            )
                            connection.execute("PRAGMA writable_schema = OFF")
                        connection.commit()
                    before = journal_path.read_bytes()
                    with self.assertRaises(CoreRequestJournalError):
                        self.repair(root, database, store_identity, lease)
                    self.assertEqual(journal_path.read_bytes(), before)
                    self.assertFalse(
                        tuple(core.glob("requests.sqlite3.preclaim-repair-*.json"))
                    )
                    self.assertFalse(tuple(core.glob(".*.preclaim-*.archive")))
                finally:
                    lease.close()

    def test_completed_archive_tamper_and_orphan_archive_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            self.create_empty_journal(root, store_identity)
            receipt = self.repair(root, database, store_identity, lease)
            assert receipt is not None
            main = next(
                item
                for item in receipt["artifacts"]
                if item["source_name"] == "requests.sqlite3"
            )
            archive = root / "core" / main["archive_name"]
            archive.write_bytes(b"tampered")
            archive.chmod(0o600)
            with self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)

    def test_destructive_repair_refuses_wrong_binding_and_unsafe_identities(
        self,
    ) -> None:
        canonical_cases = (
            "wrong-store-binding",
            "journal-symlink",
            "journal-mode-0644",
        )
        for case in canonical_cases:
            with self.subTest(case=case), TemporaryDirectory() as temporary:
                root, database, store_identity, lease = self.fixture(temporary)
                try:
                    core = root / "core"
                    journal_path = core / "requests.sqlite3"
                    bound_identity = (
                        "store-" + "f" * 24
                        if case == "wrong-store-binding"
                        else store_identity
                    )
                    self.create_empty_journal(root, bound_identity)
                    expected_source = journal_path
                    if case == "journal-symlink":
                        target = core / "journal-target.sqlite3"
                        journal_path.rename(target)
                        journal_path.symlink_to(target)
                        expected_source = target
                    elif case == "journal-mode-0644":
                        journal_path.chmod(0o644)
                    before = expected_source.lstat()
                    with self.assertRaises(CoreRequestJournalError):
                        self.repair(root, database, store_identity, lease)
                    after = expected_source.lstat()
                    self.assertEqual(
                        (before.st_dev, before.st_ino, before.st_size),
                        (after.st_dev, after.st_ino, after.st_size),
                    )
                    self.assertFalse(
                        tuple(core.glob("requests.sqlite3.preclaim-repair-*.json"))
                    )
                    self.assertFalse(
                        tuple(core.glob(".*.preclaim-*.archive"))
                    )
                finally:
                    lease.close()

        published_cases = (
            "receipt-symlink",
            "receipt-mode-0644",
            "archive-symlink",
            "archive-mode-0644",
        )
        for case in published_cases:
            with self.subTest(case=case), TemporaryDirectory() as temporary:
                root, database, store_identity, lease = self.fixture(temporary)
                try:
                    core = root / "core"
                    self.create_empty_journal(root, store_identity)
                    receipt = self.repair(root, database, store_identity, lease)
                    assert receipt is not None
                    receipt_path = next(
                        core.glob("requests.sqlite3.preclaim-repair-*.json")
                    )
                    main = next(
                        item
                        for item in receipt["artifacts"]
                        if item["source_name"] == "requests.sqlite3"
                    )
                    archive_path = core / main["archive_name"]
                    if case == "receipt-symlink":
                        target = core / "receipt-target.json"
                        receipt_path.rename(target)
                        receipt_path.symlink_to(target)
                    elif case == "receipt-mode-0644":
                        receipt_path.chmod(0o644)
                    elif case == "archive-symlink":
                        target = core / "archive-target.sqlite3"
                        archive_path.rename(target)
                        archive_path.symlink_to(target)
                    else:
                        archive_path.chmod(0o644)
                    with self.assertRaises(CoreRequestJournalError):
                        self.repair(root, database, store_identity, lease)
                    self.assertFalse((core / "requests.sqlite3").exists())
                    self.assertEqual(
                        len(tuple(core.glob("requests.sqlite3.preclaim-repair-*.json"))),
                        1,
                    )
                finally:
                    lease.close()

        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            orphan = root / "core" / ".requests.sqlite3.preclaim-deadbeef.archive"
            orphan.write_bytes(b"")
            orphan.chmod(0o600)
            with self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)

    def test_verified_rotation_keeps_retry_available_at_archive_cap(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            for _index in range(MAX_PRECLAIM_REPAIR_ARCHIVES + 1):
                self.create_empty_journal(root, store_identity)
                receipt = self.repair(root, database, store_identity, lease)
                assert receipt is not None
                self.assertEqual(receipt["status"], "complete")
            core = root / "core"
            self.assertEqual(
                len(tuple(core.glob("requests.sqlite3.preclaim-repair-*.json"))),
                MAX_PRECLAIM_REPAIR_ARCHIVES,
            )

    def test_pending_receipt_resumes_after_one_of_multiple_renames(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            self.create_empty_journal(root, store_identity)
            original_rename = os.rename
            rename_count = 0

            def fail_after_first_rename(source, target):
                nonlocal rename_count
                rename_count += 1
                if rename_count == 2:
                    raise OSError("injected rename interruption")
                return original_rename(source, target)

            with mock.patch(
                "core_request_journal.os.rename",
                side_effect=fail_after_first_rename,
            ), self.assertRaises(OSError):
                self.repair(root, database, store_identity, lease)
            self.assertEqual(rename_count, 2)
            receipt_path = next(
                (root / "core").glob(
                    "requests.sqlite3.preclaim-repair-*.json"
                )
            )
            pending = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(pending["status"], "pending")
            self.assertEqual(pending["request_row_count"], 0)
            self.assertTrue(
                (root / "core" / pending["artifacts"][0]["archive_name"]).exists()
            )
            self.assertTrue((root / "core" / "requests.sqlite3.lock").exists())

            completed = self.repair(root, database, store_identity, lease)
            assert completed is not None
            self.assertEqual(completed["status"], "complete")
            for name in (
                "requests.sqlite3",
                "requests.sqlite3.lock",
                "requests.sqlite3-wal",
                "requests.sqlite3-shm",
            ):
                self.assertFalse((root / "core" / name).exists())
            main = next(
                item
                for item in completed["artifacts"]
                if item["source_name"] == "requests.sqlite3"
            )
            with closing(
                sqlite3.connect(root / "core" / main["archive_name"])
            ) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM request_journal"
                    ).fetchone()[0],
                    0,
                )

    def test_pending_resume_refuses_a_held_receipt_bound_lock(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            self.create_empty_journal(root, store_identity)
            core = root / "core"
            with mock.patch(
                "core_request_journal.os.rename",
                side_effect=OSError("injected pre-rename interruption"),
            ), self.assertRaises(OSError):
                self.repair(root, database, store_identity, lease)
            receipt_path = next(
                core.glob("requests.sqlite3.preclaim-repair-*.json")
            )
            self.assertEqual(
                json.loads(receipt_path.read_text(encoding="utf-8"))["status"],
                "pending",
            )
            lock_path = core / "requests.sqlite3.lock"
            descriptor = os.open(lock_path, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(CoreRequestJournalError):
                    self.repair(root, database, store_identity, lease)
                self.assertTrue(lock_path.exists())
                self.assertEqual(
                    json.loads(
                        receipt_path.read_text(encoding="utf-8")
                    )["status"],
                    "pending",
                )
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            completed = self.repair(root, database, store_identity, lease)
            assert completed is not None
            self.assertEqual(completed["status"], "complete")

    def test_pending_resume_detects_lock_path_replacement_during_rename(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            self.create_empty_journal(root, store_identity)
            core = root / "core"
            with mock.patch(
                "core_request_journal.os.rename",
                side_effect=OSError("injected pre-rename interruption"),
            ), self.assertRaises(OSError):
                self.repair(root, database, store_identity, lease)
            receipt_path = next(
                core.glob("requests.sqlite3.preclaim-repair-*.json")
            )
            receipt_raw = receipt_path.read_bytes()
            lock_path = core / "requests.sqlite3.lock"
            saved_lock = core / "requests.sqlite3.lock.saved-for-race"
            lock_before = lock_path.lstat()
            original_rename = os.rename
            replaced = False

            def replace_lock_during_first_rename(source, target):
                nonlocal replaced
                if not replaced:
                    replaced = True
                    original_rename(lock_path, saved_lock)
                    lock_path.write_bytes(b"")
                    lock_path.chmod(0o600)
                return original_rename(source, target)

            with mock.patch(
                "core_request_journal.os.rename",
                side_effect=replace_lock_during_first_rename,
            ), self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)
            self.assertTrue(replaced)
            self.assertEqual(receipt_path.read_bytes(), receipt_raw)
            saved_stat = saved_lock.lstat()
            self.assertEqual(saved_lock.read_bytes(), b"")
            self.assertEqual(
                (saved_stat.st_dev, saved_stat.st_ino, saved_stat.st_size),
                (lock_before.st_dev, lock_before.st_ino, lock_before.st_size),
            )
            lock_path.unlink()
            saved_lock.rename(lock_path)
            completed = self.repair(root, database, store_identity, lease)
            assert completed is not None
            self.assertEqual(completed["status"], "complete")

    def test_hard_crash_wal_receipt_temp_is_bounded_and_recoverable(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            core = root / "core"
            journal_path = core / "requests.sqlite3"
            repository = Path(__file__).resolve().parents[1]
            create_code = """
import os
import sys
from pathlib import Path
from core_request_journal import CoreRequestJournal
journal = CoreRequestJournal(
    Path(sys.argv[1]),
    authority_epoch="epoch-1",
    prune_on_open=False,
    store_identity=sys.argv[2],
)
os._exit(0)
"""
            created = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    create_code,
                    str(journal_path),
                    store_identity,
                ],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            wal = Path(f"{journal_path}-wal")
            shm = Path(f"{journal_path}-shm")
            self.assertTrue(wal.exists())
            self.assertTrue(shm.exists())
            sealed = {
                path.name: (path.read_bytes(), path.lstat())
                for path in (journal_path, core / "requests.sqlite3.lock", wal, shm)
            }
            lease.close()
            crash_code = """
import os
import sys
from pathlib import Path
import core_request_journal as journal_module
from core_authority import CoreAuthorityLease
original_replace = journal_module.os.replace
def crash_before_receipt_publish(source, target):
    if (
        Path(source).name.endswith(".json.tmp")
        and ".preclaim-repair-" in Path(target).name
    ):
        os._exit(93)
    return original_replace(source, target)
journal_module.os.replace = crash_before_receipt_publish
lease = CoreAuthorityLease.acquire_core(
    Path(sys.argv[2]), timeout_seconds=0.0, instance_id="temp-crash-child"
)
journal_module.repair_empty_preclaim_journal_residue(
    Path(sys.argv[1]),
    expected_store_identity=sys.argv[3],
    memory_db_path=Path(sys.argv[2]),
    authority_lease=lease,
)
"""
            for _attempt in range(3):
                crashed = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        crash_code,
                        str(journal_path),
                        str(database),
                        store_identity,
                    ],
                    cwd=repository,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(crashed.returncode, 93, crashed.stderr)
                self.assertEqual(
                    len(
                        tuple(
                            core.glob(
                                ".requests.sqlite3.preclaim-repair-*.json.tmp"
                            )
                        )
                    ),
                    1,
                )
                if _attempt == 0:
                    held_lease = CoreAuthorityLease.acquire_core(
                        database,
                        timeout_seconds=0.0,
                        instance_id="temp-crash-held-lock",
                    )
                    descriptor = os.open(
                        core / "requests.sqlite3.lock",
                        os.O_RDWR,
                    )
                    temp_path = next(
                        core.glob(
                            ".requests.sqlite3.preclaim-repair-*.json.tmp"
                        )
                    )
                    temp_raw = temp_path.read_bytes()
                    try:
                        fcntl.flock(
                            descriptor,
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
                        with self.assertRaises(CoreRequestJournalError):
                            self.repair(
                                root,
                                database,
                                store_identity,
                                held_lease,
                            )
                        self.assertEqual(temp_path.read_bytes(), temp_raw)
                    finally:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                        os.close(descriptor)
                        held_lease.close()
                for name, (content, observed) in sealed.items():
                    path = core / name
                    visible = path.lstat()
                    self.assertEqual(path.read_bytes(), content)
                    self.assertEqual(
                        (visible.st_dev, visible.st_ino, visible.st_size),
                        (observed.st_dev, observed.st_ino, observed.st_size),
                    )
            final_lease = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="temp-crash-final",
            )
            self.addCleanup(final_lease.close)
            completed = self.repair(
                root,
                database,
                store_identity,
                final_lease,
            )
            assert completed is not None
            self.assertEqual(completed["status"], "complete")
            self.assertEqual(
                {
                    item["source_name"]
                    for item in completed["artifacts"]
                },
                {
                    "requests.sqlite3",
                    "requests.sqlite3.lock",
                    "requests.sqlite3-wal",
                    "requests.sqlite3-shm",
                },
            )
            for artifact in completed["artifacts"]:
                content, _observed = sealed[artifact["source_name"]]
                self.assertEqual(
                    artifact["sha256"],
                    __import__("hashlib").sha256(content).hexdigest(),
                )
                self.assertEqual(
                    (core / artifact["archive_name"]).read_bytes(),
                    content,
                )
            self.assertFalse(
                tuple(core.glob(".requests.sqlite3.preclaim-repair-*.json.tmp"))
            )
            self.assertFalse(
                tuple(core.glob(".requests.sqlite3.preclaim-verify-*"))
            )

    def test_retiring_receipt_resumes_after_clock_rollback_and_partial_delete(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            core = root / "core"
            for _index in range(MAX_PRECLAIM_REPAIR_ARCHIVES):
                self.create_empty_journal(root, store_identity)
                self.repair(root, database, store_identity, lease)
            self.create_empty_journal(root, store_identity)
            import core_request_journal as journal_module

            original_unlink = journal_module._unlink_exact_private_artifact
            archive_unlink_count = 0

            def interrupt_retirement(path, **kwargs):
                nonlocal archive_unlink_count
                if kwargs.get("artifact") is not None:
                    archive_unlink_count += 1
                    if archive_unlink_count == 2:
                        raise OSError("injected retirement interruption")
                return original_unlink(path, **kwargs)

            with mock.patch(
                "core_request_journal._unlink_exact_private_artifact",
                side_effect=interrupt_retirement,
            ), mock.patch(
                "core_request_journal.time.time",
                return_value=1.0,
            ), self.assertRaises(OSError):
                self.repair(root, database, store_identity, lease)
            self.assertEqual(archive_unlink_count, 2)
            receipts = tuple(
                (root / "core").glob(
                    "requests.sqlite3.preclaim-repair-*.json"
                )
            )
            retiring = [
                (path, json.loads(path.read_text(encoding="utf-8")))
                for path in receipts
                if json.loads(path.read_text(encoding="utf-8"))["status"]
                == "retiring"
            ]
            self.assertEqual(len(retiring), 1)
            self.assertEqual(retiring[0][1]["request_row_count"], 0)

            completed = self.repair(root, database, store_identity, lease)
            assert completed is not None
            self.assertEqual(completed["status"], "complete")
            final_receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "core").glob(
                    "requests.sqlite3.preclaim-repair-*.json"
                )
            ]
            self.assertEqual(
                len(final_receipts),
                MAX_PRECLAIM_REPAIR_ARCHIVES,
            )
            self.assertTrue(
                all(receipt["status"] == "complete" for receipt in final_receipts)
            )
            self.assertFalse((root / "core" / "requests.sqlite3").exists())
            for receipt in final_receipts:
                self.assertEqual(receipt["request_row_count"], 0)
                main = next(
                    item
                    for item in receipt["artifacts"]
                    if item["source_name"] == "requests.sqlite3"
                )
                with closing(
                    sqlite3.connect(root / "core" / main["archive_name"])
                ) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM request_journal"
                        ).fetchone()[0],
                        0,
                    )
            self.assertEqual(
                len(tuple(core.glob(".requests.sqlite3.preclaim-*.archive"))),
                MAX_PRECLAIM_REPAIR_ARCHIVES,
            )

    def test_v6_transition_before_rename_never_archives_live_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            root, database, store_identity, lease = self.fixture(temporary)
            self.addCleanup(lease.close)
            journal_path = root / "core" / "requests.sqlite3"
            journal = CoreRequestJournal(
                journal_path,
                authority_epoch="epoch-1",
                prune_on_open=False,
                store_identity=store_identity,
            )
            binding = journal.binding()
            journal.close()
            store = DurableMemoryStore(database, authority_lease=lease)
            inspection = store.inspect_core_authority_preclaim()
            original_atomic = __import__(
                "core_request_journal"
            )._atomic_private_json
            transitioned = False

            def transition_then_publish(*args, **kwargs):
                nonlocal transitioned
                if not transitioned:
                    transitioned = True
                    store.claim_core_authority(
                        instance_id=lease.instance_id,
                        config_fingerprint="a" * 64,
                        build_id="build-v6-race-test",
                        protocol_version="1.0",
                        expected_store_identity=store_identity,
                        request_journal_id=str(binding["journal_id"]),
                        request_journal_binding_schema=str(binding["schema"]),
                        request_journal_schema_version=int(
                            binding["journal_schema_version"]
                        ),
                        expected_preclaim_logical_snapshot_sha256=str(
                            inspection["logical_snapshot"]["sha256"]
                        ),
                        expected_previous_epoch=0,
                        expected_next_epoch=1,
                        root_generation_id="generation-" + "b" * 24,
                        embedding_space_identity="c" * 64,
                        attestation_receipt_digest="d" * 64,
                        attestation_expires_at_unix_ms=(
                            int(time.time() * 1000) + 60_000
                        ),
                    )
                return original_atomic(*args, **kwargs)

            with mock.patch(
                "core_request_journal._atomic_private_json",
                side_effect=transition_then_publish,
            ), self.assertRaises(CoreRequestJournalError):
                self.repair(root, database, store_identity, lease)
            self.assertTrue(transitioned)
            self.assertTrue(journal_path.exists())
            self.assertFalse(
                tuple((root / "core").glob(".requests.sqlite3.preclaim-*.archive"))
            )
            store.close()


class _SharedMutationBackend:
    def __init__(
        self,
        effects: list[dict[str, object]],
        memory_store: DurableMemoryStore,
    ) -> None:
        self.effects = effects
        self.memory_store = memory_store

    def set_enabled(
        self,
        enabled: bool,
        *,
        context_id: str | None = None,
    ) -> dict[str, object]:
        result = {"enabled": bool(enabled), "context_id": context_id}
        self.effects.append(result)
        if context_id == "fail":
            raise RuntimeError("simulated post-effect backend failure")
        return result

    def close(self) -> None:
        self.memory_store.close()

    def _runtime_state_path(self) -> Path:
        return self.memory_store.db_path.parent / "runtime_state.json"

    def assert_runtime_state_authority_marker(self, marker: dict[str, object]) -> None:
        payload = json.loads(self._runtime_state_path().read_text(encoding="utf-8"))
        if payload.get("authority_binding") != (
            self.memory_store.runtime_state_authority_binding_for_marker(marker)
        ):
            raise CoreAuthorityError("runtime state binding changed")

    def publish_runtime_state_authority_binding(self) -> None:
        binding = self.memory_store.runtime_state_authority_binding()
        if binding is None:
            raise CoreAuthorityError("runtime state authority unavailable")
        path = self._runtime_state_path()
        path.write_text(
            json.dumps(
                {
                    "version": 3,
                    "global_enabled": True,
                    "context_overrides": {},
                    "cortex_sessions": {},
                    "runtime_state_repair": {},
                    "memory_db_path": str(self.memory_store.db_path),
                    "updated_at": time.time(),
                    "authority_binding": binding,
                },
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)


class DurableMutationServiceTests(unittest.TestCase):
    CONTRACTS = {
        "health": CORE_OPERATION_CONTRACTS["health"],
        "request_status": CORE_OPERATION_CONTRACTS["request_status"],
        "set_enabled": CORE_OPERATION_CONTRACTS["set_enabled"],
    }

    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        state_root = Path(self.temporary.name) / "state"
        state_root.mkdir(mode=0o700)
        os.chmod(state_root, 0o700)
        self.config = CoreConfig(
            socket_path=state_root / "core" / "service.sock",
            state_path=state_root / "runtime_state.json",
            memory_path=state_root / "memory.sqlite3",
            dimension=8,
            num_neurons=8,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )
        self.effects: list[dict[str, object]] = []
        self.services: list[tuple[AuthoritativeCoreService, threading.Thread]] = []

    def tearDown(self) -> None:
        for service, thread in reversed(self.services):
            service.close()
            thread.join(timeout=3.0)

    def start_service(self) -> AuthoritativeCoreService:
        def backend_factory(lease: CoreAuthorityLease) -> _SharedMutationBackend:
            return _SharedMutationBackend(
                self.effects,
                DurableMemoryStore(
                    self.config.memory_path,
                    authority_lease=lease,
                ),
            )

        service = AuthoritativeCoreService(
            self.config,
            backend_factory=backend_factory,
            operation_contracts=self.CONTRACTS,
            operation_handlers_factory=lambda value: {
                "set_enabled": value.set_enabled,
            },
        )
        failures: list[BaseException] = []

        def run() -> None:
            try:
                service.serve_forever()
            except BaseException as exc:
                failures.append(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not self.config.socket_path.exists():
            if failures:
                raise failures[0]
            time.sleep(0.01)
        if failures:
            raise failures[0]
        self.assertTrue(self.config.socket_path.exists())
        self.assertTrue(self.config.memory_path.is_file())
        self.services.append((service, thread))
        return service

    def stop_service(self, service: AuthoritativeCoreService) -> None:
        for index, (candidate, thread) in enumerate(self.services):
            if candidate is service:
                service.close()
                thread.join(timeout=3.0)
                self.services.pop(index)
                return
        raise AssertionError("service not registered")

    def key(self) -> bytes:
        return bytes.fromhex(
            self.config.socket_path.with_suffix(".sock.token").read_text("ascii")
        )

    def request(
        self,
        request_id: str,
        *,
        enabled: bool = True,
        context_id: str = "default",
    ) -> dict[str, object]:
        return build_request(
            request_id=request_id,
            caller="durable-test-client",
            deadline_unix_ms=int((time.time() + 30.0) * 1000),
            operation="set_enabled",
            arguments={"enabled": enabled, "context_id": context_id},
            authentication_key=self.key(),
        )

    def send(self, request: dict[str, object]) -> dict[str, object]:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(3.0)
        try:
            connection.connect(str(self.config.socket_path))
            send_frame(connection, request)
            response = receive_frame(connection)
        finally:
            connection.close()
        return validate_response(response, expected_request=request)

    def seed_accept(
        self,
        service: AuthoritativeCoreService,
        request: dict[str, object],
    ) -> None:
        journal = service._request_journal
        assert journal is not None
        decision = journal.accept(
            caller=str(request["caller"]),
            request_id=str(request["request_id"]),
            operation=str(request["operation"]),
            request_fingerprint=str(request["request_fingerprint"]),
        )
        self.assertEqual(decision.disposition, "accepted")

    def test_same_process_duplicate_executes_once_and_health_is_content_free(self) -> None:
        service = self.start_service()
        request = self.request("req-same-process")
        first = self.send(request)
        second = self.send(request)
        self.assertTrue(first["ok"])
        self.assertEqual(first, second)
        self.assertEqual(len(self.effects), 1)
        health = CoreClient(socket_path=self.config.socket_path).health()
        self.assertTrue(health["request_journal"]["ready"])
        self.assertEqual(health["request_journal"]["completed_count"], 1)
        self.assertEqual(health["request_journal"]["ambiguous_count"], 0)
        self.assertTrue(service.identity["neural_epoch"])
        status = CoreClient(
            socket_path=self.config.socket_path,
            caller="status-reader",
        ).request_status(
            caller="durable-test-client",
            request_id="req-same-process",
        )
        self.assertTrue(status["known"])
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["result_kind"], "object")

    def test_restart_after_completed_returns_outcome_unknown_without_replay(self) -> None:
        first_service = self.start_service()
        request = self.request("req-completed-restart")
        self.assertTrue(self.send(request)["ok"])
        self.assertEqual(len(self.effects), 1)
        self.stop_service(first_service)
        self.start_service()
        status = CoreClient(
            socket_path=self.config.socket_path,
            caller="restart-reconciler",
        ).request_status(
            caller="durable-test-client",
            request_id="req-completed-restart",
        )
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["operation"], "set_enabled")
        response = self.send(request)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], {"code": "outcome_unknown", "retryable": False})
        self.assertEqual(len(self.effects), 1)
        health = CoreClient(socket_path=self.config.socket_path).health()
        self.assertEqual(health["request_journal"]["ambiguous_count"], 1)

    def test_restart_after_accept_before_handler_never_dispatches(self) -> None:
        first_service = self.start_service()
        request = self.request("req-before-handler")
        self.seed_accept(first_service, request)
        self.stop_service(first_service)
        self.start_service()
        status = CoreClient(
            socket_path=self.config.socket_path,
            caller="accepted-reconciler",
        ).request_status(
            caller="durable-test-client",
            request_id="req-before-handler",
        )
        self.assertEqual(status["state"], "accepted")
        response = self.send(request)
        self.assertEqual(response["error"]["code"], "outcome_unknown")
        self.assertEqual(self.effects, [])

    def test_restart_after_domain_commit_before_finish_never_duplicates(self) -> None:
        first_service = self.start_service()
        request = self.request("req-after-commit")
        self.seed_accept(first_service, request)
        self.effects.append({"enabled": True, "context_id": "default"})
        self.stop_service(first_service)
        self.start_service()
        response = self.send(request)
        self.assertEqual(response["error"]["code"], "outcome_unknown")
        self.assertEqual(len(self.effects), 1)

    def test_request_id_fingerprint_conflict_is_rejected(self) -> None:
        service = self.start_service()
        first = self.request("req-conflict", enabled=True)
        self.seed_accept(service, first)
        conflicting = self.request("req-conflict", enabled=False)
        response = self.send(conflicting)
        self.assertEqual(response["error"]["code"], "request_conflict")
        self.assertEqual(self.effects, [])

    def test_ambiguous_and_not_found_statuses_are_stable_across_restart(self) -> None:
        first_service = self.start_service()
        failed_request = self.request("req-failed-status", context_id="fail")
        response = self.send(failed_request)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "outcome_unknown")
        self.assertEqual(len(self.effects), 1)
        repeated = self.send(failed_request)
        self.assertEqual(repeated, response)
        self.assertEqual(len(self.effects), 1)
        self.stop_service(first_service)
        self.start_service()
        client = CoreClient(
            socket_path=self.config.socket_path,
            caller="failure-reconciler",
        )
        failed = client.request_status(
            caller="durable-test-client",
            request_id="req-failed-status",
        )
        self.assertEqual(failed["state"], "ambiguous")
        self.assertEqual(failed["safe_error_code"], "outcome_unknown")
        after_restart = self.send(failed_request)
        self.assertEqual(after_restart["error"]["code"], "outcome_unknown")
        self.assertEqual(len(self.effects), 1)
        missing = client.request_status(
            caller="durable-test-client",
            request_id="req-never-seen",
        )
        self.assertFalse(missing["known"])
        self.assertEqual(missing["state"], "not_found")
        self.assertFalse(missing["replay_safe"])
        self.assertTrue(missing["retention_expiry_possible"])

    def test_secret_canary_absent_from_journal_and_health(self) -> None:
        self.start_service()
        canary = "sk-secret-canary-12345678901234567890"
        response = self.send(self.request("req-secret", context_id=canary))
        self.assertTrue(response["ok"])
        status = CoreClient(
            socket_path=self.config.socket_path,
            caller="secret-checker",
        ).request_status(
            caller="durable-test-client",
            request_id="req-secret",
        )
        health = CoreClient(socket_path=self.config.socket_path).health()
        rendered = (repr(health) + repr(status)).encode("utf-8")
        journal_path = self.config.socket_path.parent / "requests.sqlite3"
        database_bytes = journal_path.read_bytes()
        wal_path = Path(f"{journal_path}-wal")
        wal_bytes = wal_path.read_bytes() if wal_path.exists() else b""
        self.assertNotIn(canary.encode("utf-8"), rendered + database_bytes + wal_bytes)

    def test_secret_shaped_status_target_is_rejected_without_reflection(self) -> None:
        self.start_service()
        canary = "sk-secret-status-target-12345678901234567890"
        client = CoreClient(
            socket_path=self.config.socket_path,
            caller="status-secret-checker",
        )
        with self.assertRaises(CoreRemoteError) as raised:
            client.request_status(caller=canary, request_id="req-secret-target")
        self.assertEqual(raised.exception.code, "service_unavailable")
        self.assertNotIn(canary, str(raised.exception))
        self.assertNotIn(canary, repr(raised.exception))

    def test_unsafe_journal_without_database_fails_closed_and_never_listens(self) -> None:
        core = self.config.socket_path.parent
        core.mkdir(mode=0o700, exist_ok=True)
        os.chmod(core, 0o700)
        target = core / "unsafe-target"
        target.write_bytes(b"")
        os.chmod(target, 0o600)
        (core / "requests.sqlite3").symlink_to(target)
        def backend_factory(lease: CoreAuthorityLease) -> _SharedMutationBackend:
            return _SharedMutationBackend(
                self.effects,
                DurableMemoryStore(
                    self.config.memory_path,
                    authority_lease=lease,
                ),
            )

        service = AuthoritativeCoreService(
            self.config,
            backend_factory=backend_factory,
            operation_contracts=self.CONTRACTS,
            operation_handlers_factory=lambda value: {"set_enabled": value.set_enabled},
        )
        with self.assertRaises(CoreServiceError):
            service.start()
        self.assertFalse(self.config.socket_path.exists())
        lease = CoreAuthorityLease.acquire_core(
            self.config.memory_path,
            timeout_seconds=0.0,
        )
        lease.close()


class CoreClientMutationTransportTests(unittest.TestCase):
    def private_client(self, root: Path) -> CoreClient:
        core = root / "core"
        core.mkdir(mode=0o700)
        os.chmod(core, 0o700)
        socket_path = core / "service.sock"
        token = socket_path.with_suffix(".sock.token")
        token.write_text(bytes(range(32)).hex(), encoding="ascii")
        os.chmod(token, 0o600)
        return CoreClient(
            socket_path=socket_path,
            caller="transport-test",
            default_timeout_seconds=1.0,
        )

    def test_mutation_preconnect_failure_is_unavailable(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self.private_client(Path(temporary))
            with self.assertRaises(CoreUnavailable):
                client.set_enabled(True)

    def test_mutation_preconnect_failure_retries_same_request_once(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self.private_client(Path(temporary))
            observed_request_ids: list[str] = []

            def fail_then_respond(
                request: dict[str, object],
                *,
                timeout_seconds: float,
            ) -> dict[str, object]:
                _ = timeout_seconds
                observed_request_ids.append(str(request["request_id"]))
                if len(observed_request_ids) == 1:
                    raise _CorePreconnectUnavailable()
                return {
                    "protocol_version": "synapse-core.v1",
                    "request_id": request["request_id"],
                    "caller": request["caller"],
                    "operation": request["operation"],
                    "request_fingerprint": request["request_fingerprint"],
                    "operation_sequence": 1,
                    "server_time_unix_ms": int(time.time() * 1000),
                    "identity": {
                        "authority_id": "core-test",
                        "neural_epoch": "epoch-1",
                        "config_fingerprint": "a" * 64,
                        "build_id": "build-test",
                        "store_identity": "store-test",
                        "schema_identity": "sqlite-test-v6",
                    },
                    "ok": True,
                    "result": {"effective_enabled": True},
                    "error": None,
                }

            client._exchange = fail_then_respond  # type: ignore[method-assign]
            result = client.call(
                "set_enabled",
                {"enabled": True},
                request_id="req-preconnect-retry",
            )

        self.assertTrue(result["effective_enabled"])
        self.assertEqual(
            observed_request_ids,
            ["req-preconnect-retry", "req-preconnect-retry"],
        )

    def test_mutation_disconnect_after_send_is_outcome_unknown(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self.private_client(Path(temporary))
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(client.socket_path))
            os.chmod(client.socket_path, 0o600)
            listener.listen(1)

            def consume_then_close() -> None:
                connection, _address = listener.accept()
                try:
                    connection.recv(65_536)
                finally:
                    connection.close()
                    listener.close()

            thread = threading.Thread(target=consume_then_close, daemon=True)
            thread.start()
            with self.assertRaises(CoreOutcomeUnknown) as raised:
                client.call(
                    "set_enabled",
                    {"enabled": True},
                    request_id="req-disconnect",
                )
            self.assertEqual(raised.exception.caller, "transport-test")
            self.assertEqual(raised.exception.request_id, "req-disconnect")
            self.assertEqual(raised.exception.operation, "set_enabled")
            self.assertEqual(str(raised.exception), "outcome_unknown")
            self.assertNotIn("enabled", repr(raised.exception))
            projection = outcome_unknown_projection(raised.exception)
            self.assertEqual(
                projection,
                {
                    "code": "outcome_unknown",
                    "caller": "transport-test",
                    "request_id": "req-disconnect",
                    "operation": "set_enabled",
                    "replay_safe": False,
                },
            )
            self.assertNotIn("arguments", projection)
            self.assertNotIn("request_fingerprint", projection)
            thread.join(timeout=2.0)

    def test_reconciliation_projection_rejects_secret_shaped_identifiers(self) -> None:
        canary = "sk-reconciliation-secret-12345678901234567890"
        with self.assertRaises(CoreProtocolError) as raised:
            CoreOutcomeUnknown(
                caller="transport-test",
                request_id=canary,
                operation="set_enabled",
            )
        self.assertNotIn(canary, str(raised.exception))

    def test_explicit_server_ambiguity_maps_to_distinct_client_exception(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self.private_client(Path(temporary))

            def ambiguous_response(
                request: dict[str, object],
                *,
                timeout_seconds: float,
            ) -> dict[str, object]:
                _ = timeout_seconds
                return {
                    "protocol_version": "synapse-core.v1",
                    "request_id": request["request_id"],
                    "caller": request["caller"],
                    "operation": request["operation"],
                    "request_fingerprint": request["request_fingerprint"],
                    "operation_sequence": 1,
                    "server_time_unix_ms": int(time.time() * 1000),
                    "identity": {
                        "authority_id": "core-test",
                        "neural_epoch": "epoch-1",
                        "config_fingerprint": "a" * 64,
                        "build_id": "build-test",
                        "store_identity": "store-test",
                        "schema_identity": "sqlite-test-v6",
                    },
                    "ok": False,
                    "result": None,
                    "error": {"code": "outcome_unknown", "retryable": False},
                }

            client._exchange = ambiguous_response  # type: ignore[method-assign]
            with self.assertRaises(CoreOutcomeUnknown) as raised:
                client.call(
                    "set_enabled",
                    {"enabled": True},
                    request_id="req-explicit-ambiguity",
                )
            self.assertFalse(raised.exception.retryable)
            self.assertEqual(raised.exception.caller, "transport-test")
            self.assertEqual(
                raised.exception.request_id,
                "req-explicit-ambiguity",
            )
            self.assertEqual(raised.exception.operation, "set_enabled")

    def test_secret_shaped_caller_is_rejected_without_reflection(self) -> None:
        canary = "sk-secret-caller-12345678901234567890"
        with TemporaryDirectory() as temporary:
            with self.assertRaises(CoreUnavailable) as raised:
                CoreClient(
                    socket_path=Path(temporary) / "core" / "service.sock",
                    caller=canary,
                )
        self.assertNotIn(canary, str(raised.exception))
        self.assertNotIn(canary, repr(raised.exception))


if __name__ == "__main__":
    unittest.main()

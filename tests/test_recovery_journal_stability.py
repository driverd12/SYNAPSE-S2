"""Real, synthetic journal snapshots: drift must never become recovery evidence."""
import hashlib
import inspect
import os
import sqlite3
from contextlib import closing
from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from core_request_journal import CoreRequestJournal, request_journal_entry_revision
from memory_store import DurableMemoryStore
from recovery_manager import ImmutableJournalInspectionDrift, VerifiedRecoveryManager


class RecoveryJournalStabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = DurableMemoryStore(self.root / "memory.sqlite3")
        self.addCleanup(self.store.close)
        self.path = self.root / "requests.sqlite3"
        journal = CoreRequestJournal(
            self.path, authority_epoch="epoch-1", store_identity="store-" + "1" * 24,
        )
        self.journal_id = journal.binding()["journal_id"]
        journal.accept(
            caller="synthetic-test", request_id="retained-request",
            operation="capture_session", request_fingerprint="a" * 64,
        )
        journal.accept(
            caller="synthetic-test", request_id="ambiguous-request",
            operation="capture_session", request_fingerprint="b" * 64,
        )
        journal.finish(
            caller="synthetic-test", request_id="ambiguous-request",
            operation="capture_session", request_fingerprint="b" * 64,
            result=None, safe_error_code="outcome_unknown",
        )
        journal.close()
        self.expected = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.manager = VerifiedRecoveryManager(self.store, capture_root=self.root)
        self.inspected = []

    def _verify_with_mutation(self, mutate, *, reconciliation_targets=(), late=False):
        inspector = self.manager.inspect_request_journal_snapshot
        logical = self.store._canonical_logical_snapshot_digest
        lstat = os.lstat
        observations = {}

        def record_inspection(path, **kwargs):
            if self.inspected:
                self.assertFalse(self.inspected[-1].exists(), "failed copy was reused")
            self.inspected.append(path)
            return inspector(path, **kwargs)

        def inspect_then_mutate(conn, **kwargs):
            result = logical(conn, **kwargs)
            if not late:
                mutate(self.inspected[-1], len(self.inspected))
            return result

        def observe(path, *args, **kwargs):
            caller = inspect.currentframe().f_back
            if late and caller.f_code is inspector.__func__.__code__ and Path(path) in self.inspected:
                observations[path] = observations.get(path, 0) + 1
                if observations[path] == 2:
                    replacement = mutate(Path(path), len(self.inspected))
                    if replacement is not None:
                        return replacement
            return lstat(path, *args, **kwargs)

        # Wrap the real function in a plain function: a Mock would insert its
        # own frame between the observer and the inspector's final lstat.
        with mock.patch.object(self.manager, "inspect_request_journal_snapshot", side_effect=record_inspection), mock.patch.object(self.store, "_canonical_logical_snapshot_digest", side_effect=inspect_then_mutate), mock.patch("recovery_manager.os.lstat", new=observe):
            return self.manager._verify_request_journal_artifact(
                self.path, expected_sha256=self.expected,
                maximum_authority_epoch=1, reconciliation_targets=reconciliation_targets,
            )

    def _touch_ctime(self, path):
        before = path.stat()
        for _ in range(32):
            os.chmod(path, 0o600)
            after = path.stat()
            if after.st_ctime_ns != before.st_ctime_ns:
                break
        self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_uid", "st_nlink", "st_mode"):
            self.assertEqual(getattr(before, field), getattr(after, field))

    def test_one_ctime_only_change_uses_a_fresh_signed_snapshot(self):
        result = self._verify_with_mutation(
            lambda path, attempt: self._touch_ctime(path) if attempt == 1 else None,
        )
        self.assertEqual(len(self.inspected), 2)
        self.assertNotEqual(*self.inspected)
        self.assertTrue(all(not path.exists() for path in self.inspected))
        self.assertEqual(result["sha256"], self.expected)
        self.assertEqual(result["journal_id"], self.journal_id)
        self.assertEqual(result["state_counts"]["accepted"], 1)
        self.assertFalse(any("retry" in field for field in result))
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), self.expected)

    def test_unchanged_snapshot_is_inspected_once(self):
        self._verify_with_mutation(lambda _path, _attempt: None)
        self.assertEqual(len(self.inspected), 1)

    def test_repeated_ctime_drift_fails_after_two_fresh_attempts(self):
        with self.assertRaises(ImmutableJournalInspectionDrift) as raised:
            self._verify_with_mutation(lambda path, _attempt: self._touch_ctime(path))
        self.assertEqual(raised.exception.changed_fields, ("ctime_ns",))
        self.assertEqual(len(self.inspected), 2)
        self.assertTrue(all(not path.exists() for path in self.inspected))
        self.assertNotIn(str(self.root), str(raised.exception))

    @staticmethod
    def _rewrite_same_size_restore_mtime(path):
        before = path.stat()
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))

    def test_copy_rewrite_with_restored_mtime_fails_digest_gate(self):
        with self.assertRaises(ImmutableJournalInspectionDrift) as raised:
            self._verify_with_mutation(
                lambda path, _attempt: self._rewrite_same_size_restore_mtime(path), late=True,
            )
        self.assertEqual(raised.exception.changed_fields, ("ctime_ns",))
        self.assertEqual(len(self.inspected), 1)

    def test_source_corruption_between_attempts_is_not_retried(self):
        def mutate(path, _attempt):
            self._touch_ctime(path)
            self._rewrite_same_size_restore_mtime(self.path)
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            self._verify_with_mutation(mutate)
        self.assertEqual(len(self.inspected), 1)

    def test_same_digest_source_replacement_during_retry_copy_is_rejected(self):
        stable_copy = self.store._copy_stable_regular_file
        copies = []
        original = self.path.stat()

        def replace_before_copy(source, destination):
            copies.append(destination)
            if len(copies) == 2:
                replacement = self.root / "replacement.sqlite3"
                replacement.write_bytes(source.read_bytes())
                replacement.chmod(0o600)
                os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
                os.replace(replacement, source)
            return stable_copy(source, destination)

        with mock.patch.object(self.store, "_copy_stable_regular_file", side_effect=replace_before_copy):
            with self.assertRaisesRegex(RuntimeError, "source changed during inspection retry"):
                self._verify_with_mutation(
                    lambda path, attempt: self._touch_ctime(path) if attempt == 1 else None,
                )
        self.assertEqual(len(copies), 2)
        self.assertEqual(len(self.inspected), 1)
        self.assertNotEqual(self.path.stat().st_ino, original.st_ino)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), self.expected)
        self.assertTrue(all(not path.exists() for path in copies))

    def test_original_expected_digest_is_not_replaced_by_copied_digest(self):
        self._rewrite_same_size_restore_mtime(self.path)
        with self.assertRaisesRegex(RuntimeError, "digest verification failed"):
            self._verify_with_mutation(lambda _path, _attempt: None)
        self.assertEqual(self.inspected, [])

    def test_other_metadata_changes_fail_without_retry(self):
        def inode(path):
            before = path.stat()
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.replace(replacement, path)
        def owner(path):
            value = path.stat()
            attributes = {name:getattr(value, name) for name in dir(value) if name.startswith("st_")}
            attributes["st_uid"] += 1
            return SimpleNamespace(**attributes)
        changes = {
            "inode": inode,
            "mode": lambda path: path.chmod(0o640),
            "nlink": lambda path: os.link(path, path.with_suffix(".extra-link")),
            "mtime_ns": lambda path: os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000)),
            "uid": owner,
        }
        for expected_field, mutate in changes.items():
            with self.subTest(field=expected_field):
                self.inspected.clear()
                with self.assertRaises(ImmutableJournalInspectionDrift) as raised:
                    self._verify_with_mutation(lambda path, _attempt: mutate(path), late=True)
                self.assertIn(expected_field, raised.exception.changed_fields)
                self.assertEqual(len(self.inspected), 1)

    def test_sidecar_change_is_not_hidden_by_ctime_drift(self):
        def mutate(path, _attempt):
            self._touch_ctime(path)
            for suffix, size in (("-wal", 0), ("-shm", 32768)):
                sidecar = Path(str(path) + suffix)
                sidecar.write_bytes(b"\0" * size)
                sidecar.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "sidecar changed") as raised:
            self._verify_with_mutation(mutate, late=True)
        self.assertNotIsInstance(raised.exception, ImmutableJournalInspectionDrift)
        self.assertEqual(len(self.inspected), 1)

    def test_drift_before_independent_hash_is_not_retried(self):
        stable_hash = self.store._hash_stable_regular_file
        def changed_before_hash(path):
            self._touch_ctime(path)
            return stable_hash(path)
        with mock.patch.object(self.store, "_hash_stable_regular_file", side_effect=changed_before_hash):
            with self.assertRaises(ImmutableJournalInspectionDrift):
                self._verify_with_mutation(lambda path, _attempt: self._touch_ctime(path))
        self.assertEqual(len(self.inspected), 1)

    def test_change_after_independent_hash_is_not_retried(self):
        stable_hash = self.store._hash_stable_regular_file
        def changed_after_hash(path):
            result = stable_hash(path)
            self._touch_ctime(path)
            return result
        with mock.patch.object(self.store, "_hash_stable_regular_file", side_effect=changed_after_hash):
            with self.assertRaises(ImmutableJournalInspectionDrift):
                self._verify_with_mutation(lambda path, _attempt: self._touch_ctime(path))
        self.assertEqual(len(self.inspected), 1)

    def test_sidecar_change_after_hash_is_not_retried(self):
        stable_hash = self.store._hash_stable_regular_file
        def changed_after_hash(path):
            result = stable_hash(path)
            for suffix, size in (("-wal", 0), ("-shm", 32768)):
                sidecar = Path(str(path) + suffix)
                sidecar.write_bytes(b"\0" * size)
                sidecar.chmod(0o600)
            return result
        with mock.patch.object(self.store, "_hash_stable_regular_file", side_effect=changed_after_hash):
            with self.assertRaises(ImmutableJournalInspectionDrift):
                self._verify_with_mutation(lambda path, _attempt: self._touch_ctime(path))
        self.assertEqual(len(self.inspected), 1)

    def test_logical_rejection_cannot_use_metadata_retry(self):
        with closing(sqlite3.connect(self.path)) as conn:
            conn.execute("PRAGMA ignore_check_constraints=ON")
            conn.execute("UPDATE request_journal SET state='invalid' WHERE request_id='retained-request'")
            conn.commit()
        self.expected = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(RuntimeError) as raised:
            self._verify_with_mutation(lambda path, _attempt: self._touch_ctime(path))
        self.assertNotIsInstance(raised.exception, ImmutableJournalInspectionDrift)
        self.assertEqual(len(self.inspected), 1)

    def test_direct_inspection_keeps_strict_metadata_rejection(self):
        logical = self.store._canonical_logical_snapshot_digest
        def mutate(conn, **kwargs):
            result = logical(conn, **kwargs)
            self._touch_ctime(self.path)
            return result
        with mock.patch.object(self.store, "_canonical_logical_snapshot_digest", side_effect=mutate):
            with self.assertRaises(ImmutableJournalInspectionDrift) as raised:
                self.manager.inspect_request_journal_snapshot(self.path, maximum_authority_epoch=1)
        self.assertEqual(raised.exception.changed_fields, ("ctime_ns",))

    def test_one_shot_reconciliation_targets_are_checked_again(self):
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro&immutable=1", uri=True)) as conn:
            row = conn.execute(
                "SELECT caller, request_id, operation, request_fingerprint, authority_epoch, "
                "state, result_kind, safe_error_code, accepted_at_unix_ms, finished_at_unix_ms "
                "FROM request_journal WHERE request_id='ambiguous-request'",
            ).fetchone()
        target = {
            "request_journal_id":self.journal_id, "store_identity":"store-" + "1" * 24,
            "target_caller":row[0], "target_request_id":row[1], "target_operation":row[2],
            "target_authority_epoch":row[4], "target_original_state":row[5],
            "target_entry_revision":request_journal_entry_revision(
                journal_id=self.journal_id, store_identity="store-" + "1" * 24, row=row,
            ),
        }
        def mutate(path, attempt):
            if attempt == 1:
                self._touch_ctime(path)
                target["target_entry_revision"] = "f" * 64
        result = self._verify_with_mutation(
            mutate,
            reconciliation_targets=(item for item in (target,)),
        )
        self.assertEqual(len(self.inspected), 2)
        self.assertEqual(result["reconciliation_receipts"]["count"], 1)
        self.assertEqual(result["reconciliation_receipts"]["ambiguous_count"], 1)


if __name__ == "__main__":
    unittest.main()

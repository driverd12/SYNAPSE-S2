from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core_authority import CoreAuthorityError, CoreAuthorityLease
from memory_store import DurableMemoryStore
from scripts import repair_torn_core_adoption as repair_module
from scripts.repair_torn_core_adoption import (
    TornAdoptionRepairError,
    inspect_database,
    repair_torn_adoption,
)


class TornCoreAdoptionRepairTests(unittest.TestCase):
    def _private_root(self, temporary: str) -> Path:
        root = Path(temporary)
        os.chmod(root, 0o700)
        return root

    def _torn_database(self, root: Path) -> Path:
        database = root / "memory.sqlite3"
        store = DurableMemoryStore(database)
        store.upsert_entry(
            tag="repair-proof",
            context_id="default",
            source_text="nonsensitive proof",
            metadata={},
            embedding_dimensions=8,
            spike_indices=[1, 2],
            neuron_indices=[1],
        )
        store.close()
        connection = sqlite3.connect(database)
        try:
            connection.execute("PRAGMA user_version = 6")
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)
        return database

    def _backup(self, database: Path, root: Path) -> tuple[Path, str]:
        backup_root = root / "backup"
        backup_root.mkdir(mode=0o700)
        backup = backup_root / "memory.sqlite3"
        source = sqlite3.connect(database)
        destination = sqlite3.connect(backup)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        os.chmod(backup, 0o600)
        return backup, hashlib.sha256(backup.read_bytes()).hexdigest()

    def test_exact_torn_state_repairs_only_header_and_is_idempotent(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, digest = self._backup(database, root)
            before = inspect_database(database)
            result = repair_torn_adoption(
                database,
                backup_path=backup,
                expected_backup_sha256=digest,
                confirm=True,
            )
            repeated = repair_torn_adoption(
                database,
                backup_path=backup,
                expected_backup_sha256=digest,
                confirm=True,
            )
            after = inspect_database(database)

        self.assertEqual(result["status"], "repaired")
        self.assertEqual(repeated["status"], "already-repaired")
        self.assertEqual(before["user_version"], 6)
        self.assertEqual(after["user_version"], 5)
        self.assertEqual(before["counts"], after["counts"])
        self.assertEqual(before["schema_sha256"], after["schema_sha256"])
        self.assertFalse(after["authority_marker_present"])

    def test_holds_exclusive_authority_through_post_verification(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, digest = self._backup(database, root)
            original_inspect = repair_module._inspect_connection
            observed_live_inspections: list[tuple[int, bool]] = []

            def inspect_while_fenced(
                connection: sqlite3.Connection,
            ) -> dict[str, object]:
                snapshot = original_inspect(connection)
                database_row = connection.execute("PRAGMA database_list").fetchone()
                if Path(str(database_row[2])).resolve() == database.resolve():
                    observed_live_inspections.append(
                        (int(snapshot["user_version"]), connection.in_transaction)
                    )
                    with self.assertRaises(CoreAuthorityError):
                        CoreAuthorityLease.acquire_local(database)
                return snapshot

            with patch.object(
                repair_module,
                "_inspect_connection",
                side_effect=inspect_while_fenced,
            ):
                result = repair_torn_adoption(
                    database,
                    backup_path=backup,
                    expected_backup_sha256=digest,
                    confirm=True,
                )

        self.assertEqual(result["status"], "repaired")
        self.assertIn((5, False), observed_live_inspections)

    def test_refuses_repair_while_an_authority_lease_is_active(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, digest = self._backup(database, root)
            with CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="test-active-core",
            ):
                with self.assertRaisesRegex(
                    TornAdoptionRepairError,
                    "maintenance lease is unavailable",
                ):
                    repair_torn_adoption(
                        database,
                        backup_path=backup,
                        expected_backup_sha256=digest,
                        confirm=True,
                    )

    def test_refuses_bad_digest_unconfirmed_and_nonprivate_backup(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, digest = self._backup(database, root)
            with self.assertRaises(TornAdoptionRepairError):
                repair_torn_adoption(
                    database,
                    backup_path=backup,
                    expected_backup_sha256=digest,
                    confirm=False,
                )
            with self.assertRaises(TornAdoptionRepairError):
                repair_torn_adoption(
                    database,
                    backup_path=backup,
                    expected_backup_sha256="0" * 64,
                    confirm=True,
                )
            os.chmod(backup, 0o644)
            with self.assertRaises(TornAdoptionRepairError):
                repair_torn_adoption(
                    database,
                    backup_path=backup,
                    expected_backup_sha256=digest,
                    confirm=True,
                )

    def test_refuses_claimed_or_schema_changed_database(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, digest = self._backup(database, root)
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE unexpected_table(value TEXT)")
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(TornAdoptionRepairError):
                repair_torn_adoption(
                    database,
                    backup_path=backup,
                    expected_backup_sha256=digest,
                    confirm=True,
                )

    def test_refuses_backup_from_a_different_snapshot(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, _digest = self._backup(database, root)
            other_root = root / "other"
            other_root.mkdir(mode=0o700)
            other = self._torn_database(other_root)
            other_backup = root / "backup" / "other.sqlite3"
            shutil.copy2(other, other_backup)
            os.chmod(other_backup, stat.S_IRUSR | stat.S_IWUSR)
            digest = hashlib.sha256(other_backup.read_bytes()).hexdigest()
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "INSERT INTO memory_events(memory_id, event_type, payload_json, created_at) "
                    "SELECT memory_id, 'extra', '{}', 1.0 FROM memory_entries LIMIT 1"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(TornAdoptionRepairError):
                repair_torn_adoption(
                    database,
                    backup_path=other_backup,
                    expected_backup_sha256=digest,
                    confirm=True,
                )

    def test_refuses_same_count_content_change_after_backup(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, digest = self._backup(database, root)
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "UPDATE memory_entries SET source_text = ? WHERE tag = ?",
                    ("changed proof text", "repair-proof"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(
                TornAdoptionRepairError,
                "changed after the required pre-repair backup",
            ):
                repair_torn_adoption(
                    database,
                    backup_path=backup,
                    expected_backup_sha256=digest,
                    confirm=True,
                )

    def test_already_repaired_rechecks_logical_equality_with_backup(self) -> None:
        with TemporaryDirectory() as temporary:
            root = self._private_root(temporary)
            database = self._torn_database(root)
            backup, digest = self._backup(database, root)
            repaired = repair_torn_adoption(
                database,
                backup_path=backup,
                expected_backup_sha256=digest,
                confirm=True,
            )
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    "UPDATE memory_entries SET source_text = ? WHERE tag = ?",
                    ("changed after successful repair", "repair-proof"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(
                TornAdoptionRepairError,
                "changed after the required pre-repair backup",
            ):
                repair_torn_adoption(
                    database,
                    backup_path=backup,
                    expected_backup_sha256=digest,
                    confirm=True,
                )

        self.assertEqual(repaired["status"], "repaired")


if __name__ == "__main__":
    unittest.main()

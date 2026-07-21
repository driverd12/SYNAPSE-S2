from __future__ import annotations

import json
import os
import sqlite3
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core_authority import CoreAuthorityError, CoreAuthorityLease
from memory_store import DurableMemoryStore


class CoreAuthorityLeaseTests(unittest.TestCase):
    @staticmethod
    def _claim(
        store: DurableMemoryStore,
        lease: CoreAuthorityLease,
        *,
        attestation_expires_at_unix_ms: int | None = None,
    ) -> dict:
        inspection = store.inspect_core_authority_preclaim()
        preclaim = inspection["logical_snapshot"]
        previous_epoch = int(inspection["previous_epoch"])
        return store.claim_core_authority(
            instance_id=lease.instance_id,
            config_fingerprint="a" * 64,
            build_id="test-build",
            protocol_version="synapse-core.v1",
            expected_store_identity=str(inspection["store_identity"]),
            request_journal_id="journal-" + ("a" * 24),
            request_journal_binding_schema="synapse-s2.request-journal-binding.v1",
            request_journal_schema_version=3,
            expected_preclaim_logical_snapshot_sha256=str(preclaim["sha256"]),
            expected_previous_epoch=previous_epoch,
            expected_next_epoch=previous_epoch + 1,
            root_generation_id="generation-" + ("a" * 24),
            embedding_space_identity="a" * 64,
            attestation_receipt_digest="b" * 64,
            attestation_expires_at_unix_ms=(
                int(time.time() * 1000) + 60_000
                if attestation_expires_at_unix_ms is None
                else attestation_expires_at_unix_ms
            ),
        )

    def test_local_backends_share_authority_until_core_cutover(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            first = CoreAuthorityLease.acquire_local(database)
            second = CoreAuthorityLease.acquire_local(database)
            self.addCleanup(first.close)
            self.addCleanup(second.close)

            with self.assertRaisesRegex(CoreAuthorityError, "active local backend"):
                CoreAuthorityLease.acquire_core(database, timeout_seconds=0.0)

            first.close()
            second.close()
            core = CoreAuthorityLease.acquire_core(database, timeout_seconds=0.0)
            self.addCleanup(core.close)
            self.assertTrue(core.active)

    def test_lock_generation_changes_when_the_visible_lock_inode_is_replaced(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            first = CoreAuthorityLease.acquire_core(database, timeout_seconds=0.0)
            generation = first.lock_generation_id
            lock_path = first.lock_path
            displaced = lock_path.with_name("authority.lock.displaced")
            os.replace(lock_path, displaced)
            lock_path.touch(mode=0o600)
            os.chmod(lock_path, 0o600)

            with self.assertRaisesRegex(CoreAuthorityError, "lock path was replaced"):
                first.assert_active_for(database)
            first.close()

            replacement = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
            )
            self.addCleanup(replacement.close)
            self.assertNotEqual(replacement.lock_generation_id, generation)

    def test_core_exclusive_lease_rejects_new_local_backend(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            core = CoreAuthorityLease.acquire_core(database, timeout_seconds=0.0)
            self.addCleanup(core.close)

            with self.assertRaisesRegex(CoreAuthorityError, "route through the core client"):
                CoreAuthorityLease.acquire_local(database)

    def test_store_lifetime_holds_local_fence_and_core_can_take_over_after_close(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            store = DurableMemoryStore(database)
            with self.assertRaises(CoreAuthorityError):
                CoreAuthorityLease.acquire_core(database, timeout_seconds=0.0)

            store.close()
            core = CoreAuthorityLease.acquire_core(database, timeout_seconds=0.0)
            self.addCleanup(core.close)
            core_store = DurableMemoryStore(database, authority_lease=core)
            self.addCleanup(core_store.close)
            self.assertEqual(core_store.list_entries(limit=1), [])

    def test_core_lease_cannot_be_reused_for_another_store(self) -> None:
        with TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.sqlite3"
            second = Path(temporary) / "second.sqlite3"
            core = CoreAuthorityLease.acquire_core(first, timeout_seconds=0.0)
            self.addCleanup(core.close)

            with self.assertRaisesRegex(CoreAuthorityError, "does not match"):
                DurableMemoryStore(second, authority_lease=core)

    def test_authority_does_not_create_a_missing_database_parent(self) -> None:
        with TemporaryDirectory() as temporary:
            missing_parent = Path(temporary) / "missing"
            with self.assertRaisesRegex(CoreAuthorityError, "parent must exist"):
                CoreAuthorityLease.acquire_local(missing_parent / "memory.sqlite3")
            self.assertFalse(missing_parent.exists())

    def test_existing_unsafe_authority_lock_fails_closed_without_repair(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            core_dir = database.parent / "core"
            core_dir.mkdir(mode=0o700)
            lock_path = core_dir / "authority.lock"
            lock_path.write_text("unexpected", encoding="utf-8")
            os.chmod(lock_path, 0o644)

            with self.assertRaisesRegex(CoreAuthorityError, "mode 0600"):
                CoreAuthorityLease.acquire_local(database)

            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(lock_path.read_text(encoding="utf-8"), "unexpected")

    def test_authority_lock_symlink_fails_with_a_safe_domain_error(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            core_dir = database.parent / "core"
            core_dir.mkdir(mode=0o700)
            target = database.parent / "unrelated"
            target.write_text("preserve", encoding="utf-8")
            (core_dir / "authority.lock").symlink_to(target)

            with self.assertRaisesRegex(CoreAuthorityError, "opened safely"):
                CoreAuthorityLease.acquire_local(database)

            self.assertEqual(target.read_text(encoding="utf-8"), "preserve")

    def test_unbound_lease_rejects_database_that_appears_before_creation(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-create-race",
            )
            self.addCleanup(core.close)
            self.assertIsNone(core.database_inode)
            with closing(sqlite3.connect(database)):
                pass

            with self.assertRaisesRegex(
                CoreAuthorityError,
                "appeared during secure creation",
            ):
                DurableMemoryStore(database, authority_lease=core)

    def test_fresh_v5_creation_binds_private_database_identity(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            store = DurableMemoryStore(database)
            try:
                lease = store._authority_lease
                self.assertIsNotNone(lease)
                assert lease is not None
                observed = database.stat()
                self.assertEqual(lease.database_device, observed.st_dev)
                self.assertEqual(lease.database_inode, observed.st_ino)
                self.assertEqual(observed.st_mode & 0o777, 0o600)
                with closing(sqlite3.connect(database)) as connection:
                    self.assertEqual(
                        connection.execute("PRAGMA user_version").fetchone()[0],
                        5,
                    )
            finally:
                store.close()

    def test_local_open_preserves_v5_without_service_marker(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            store = DurableMemoryStore(database)
            store.close()
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNone(
                    conn.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_migrations WHERE key = ?",
                        ("authoritative_core_v1",),
                    ).fetchone()[0],
                    0,
                )

    def test_explicit_claim_atomically_publishes_v6_and_permanent_marker(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            local = DurableMemoryStore(database)
            local.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-test-instance",
            )
            core_store = DurableMemoryStore(database, authority_lease=core)
            claim = self._claim(core_store, core)
            self.assertEqual(claim["authority_epoch"], "epoch-1")
            self.assertEqual(claim["authority_epoch_number"], 1)
            self.assertEqual(core.durable_epoch, 1)
            with closing(sqlite3.connect(database)) as conn:
                conn.row_factory = sqlite3.Row
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 6)
                marker = json.loads(
                    str(
                        conn.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_authority",),
                        ).fetchone()[0]
                    )
                )
                self.assertTrue(marker["service_required"])
                self.assertEqual(marker["epoch"], 1)
                self.assertEqual(marker["instance_id"], "core-test-instance")
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_migrations WHERE key = ?",
                        ("authoritative_core_v1",),
                    ).fetchone()[0],
                    1,
                )
            core_store.close()
            core.close()

            with self.assertRaisesRegex(CoreAuthorityError, "requires the authoritative"):
                DurableMemoryStore(database)
            audit = DurableMemoryStore.open_existing_for_audit(database)
            self.assertEqual(audit.audit_semantic_indexes()["status"], "ready")

    def test_runtime_publication_completion_survives_wall_clock_rollback(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-runtime-clock-rollback",
            )
            store = DurableMemoryStore(database, authority_lease=core)
            self._claim(store, core)
            try:
                with closing(sqlite3.connect(database)) as connection:
                    pending = json.loads(
                        str(
                            connection.execute(
                                "SELECT value_json FROM store_metadata WHERE key = ?",
                                ("core_runtime_state_publication",),
                            ).fetchone()[0]
                        )
                    )
                self.assertEqual(pending["status"], "pending")

                with patch("memory_store.time.time", return_value=1.0):
                    completed = store.complete_runtime_state_authority_publication(
                        runtime_state_path=database.parent / "runtime_state.json",
                    )

                self.assertEqual(completed["status"], "complete")
                self.assertGreaterEqual(
                    completed["completed_at"],
                    pending["started_at"],
                )
                self.assertEqual(
                    completed["completed_at"],
                    completed["updated_at"],
                )
                with closing(sqlite3.connect(database)) as connection:
                    persisted = json.loads(
                        str(
                            connection.execute(
                                "SELECT value_json FROM store_metadata WHERE key = ?",
                                ("core_runtime_state_publication",),
                            ).fetchone()[0]
                        )
                    )
                self.assertEqual(persisted, completed)
            finally:
                store.close()
                core.close()

    def test_authority_epoch_increments_across_core_restarts(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            first = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-first",
            )
            first_store = DurableMemoryStore(database, authority_lease=first)
            self.assertEqual(self._claim(first_store, first)["authority_epoch"], "epoch-1")
            first.close()

            second = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-second",
            )
            second_store = DurableMemoryStore(database, authority_lease=second)
            self.assertEqual(
                self._claim(second_store, second)["authority_epoch"],
                "epoch-2",
            )
            second.close()

    def test_stale_store_cannot_write_after_lease_close(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            store = DurableMemoryStore(database)
            store.close()
            with self.assertRaisesRegex(CoreAuthorityError, "not active"):
                store.upsert_entry(
                    tag="stale-write",
                    context_id="default",
                    source_text="must not commit",
                    metadata={},
                    embedding_dimensions=4,
                    spike_indices=[1],
                    neuron_indices=[1],
                )
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0],
                    0,
                )

    @unittest.skipUnless(hasattr(os, "fork"), "fork is not available")
    def test_forked_child_cannot_reuse_parent_authority(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            lease = CoreAuthorityLease.acquire_local(database)
            read_fd, write_fd = os.pipe()
            child_pid = os.fork()
            if child_pid == 0:  # pragma: no cover - asserted through pipe
                os.close(read_fd)
                try:
                    lease.assert_active_for(database)
                except CoreAuthorityError:
                    os.write(write_fd, b"fenced")
                    os._exit(0)
                os.write(write_fd, b"unsafe")
                os._exit(1)
            os.close(write_fd)
            result = os.read(read_fd, 32)
            os.close(read_fd)
            _, status = os.waitpid(child_pid, 0)
            lease.close()
            self.assertEqual(result, b"fenced")
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_replaced_lock_path_invalidates_old_lease_and_blocks_claim(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-replaced-lock",
            )
            core_store = DurableMemoryStore(database, authority_lease=core)
            core.lock_path.unlink()
            replacement = os.open(core.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            os.close(replacement)
            with self.assertRaisesRegex(
                CoreAuthorityError,
                "lock identity is invalid|lock path was replaced",
            ):
                self._claim(core_store, core)
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNone(
                    conn.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()
                )
            core.close()

    def test_claim_reasserts_lock_identity_immediately_before_commit(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-claim-commit-fence",
            )
            store = DurableMemoryStore(database, authority_lease=core)
            original_marker = store._core_authority_marker
            marker_reads = 0

            def replace_lock_after_persisted_marker(conn: sqlite3.Connection):
                nonlocal marker_reads
                marker_reads += 1
                marker = original_marker(conn)
                if marker_reads == 3:
                    core.lock_path.unlink()
                    replacement = os.open(
                        core.lock_path,
                        os.O_RDWR | os.O_CREAT,
                        0o600,
                    )
                    os.close(replacement)
                return marker

            store._core_authority_marker = replace_lock_after_persisted_marker
            try:
                with self.assertRaisesRegex(
                    CoreAuthorityError,
                    "lock identity is invalid|lock path was replaced",
                ):
                    self._claim(store, core)
                with closing(sqlite3.connect(database)) as conn:
                    self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 5)
                    self.assertIsNone(
                        conn.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_authority",),
                        ).fetchone()
                    )
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM store_migrations WHERE key = ?",
                            ("authoritative_core_v1",),
                        ).fetchone()[0],
                        0,
                    )
            finally:
                core.close()

    def test_replacement_lock_cannot_create_a_successor_authority(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            first = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-old-inode",
            )
            first_store = DurableMemoryStore(database, authority_lease=first)
            self.assertEqual(self._claim(first_store, first)["authority_epoch"], "epoch-1")

            first.lock_path.unlink()
            second = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-new-inode",
            )
            second_store = DurableMemoryStore(database, authority_lease=second)
            with self.assertRaisesRegex(
                CoreAuthorityError,
                "lock generation changed without restored-target adoption",
            ):
                self._claim(second_store, second)
            with closing(sqlite3.connect(database)) as conn:
                count_before = conn.execute(
                    "SELECT COUNT(*) FROM memory_entries"
                ).fetchone()[0]
            with self.assertRaisesRegex(
                CoreAuthorityError,
                "lock identity is invalid|lock path was replaced",
            ):
                first_store.upsert_entry(
                    tag="stale-core-write",
                    context_id="default",
                    source_text="must not commit",
                    metadata={},
                    embedding_dimensions=4,
                    spike_indices=[1],
                    neuron_indices=[1],
                )
            with closing(sqlite3.connect(database)) as conn:
                count_after = conn.execute(
                    "SELECT COUNT(*) FROM memory_entries"
                ).fetchone()[0]
                marker = json.loads(
                    str(
                        conn.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_authority",),
                        ).fetchone()[0]
                    )
                )
            self.assertEqual(count_after, count_before)
            self.assertEqual(marker["epoch"], 1)
            self.assertEqual(marker["instance_id"], "core-old-inode")
            first.close()
            second.close()

    def test_write_transaction_reasserts_exact_durable_epoch_tuple(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-transaction-check",
            )
            store = DurableMemoryStore(database, authority_lease=core)
            self._claim(store, core)
            connection = store._connect()
            try:
                with closing(sqlite3.connect(database)) as tamper:
                    row = tamper.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()
                    marker = json.loads(str(row[0]))
                    marker["epoch"] = 2
                    marker["instance_id"] = "core-unexpected"
                    marker["updated_at"] = marker["updated_at"] + 1.0
                    tamper.execute(
                        """
                        UPDATE store_metadata
                        SET value_json = ?, updated_at = ?
                        WHERE key = ?
                        """,
                        (
                            json.dumps(marker, sort_keys=True, separators=(",", ":")),
                            marker["updated_at"],
                            "core_authority",
                        ),
                    )
                    tamper.commit()
                with self.assertRaisesRegex(CoreAuthorityError, "epoch does not match"):
                    with store._transaction(connection, immediate=True):
                        connection.execute(
                            "INSERT INTO store_metadata (key, value_json, updated_at) "
                            "VALUES ('must-not-commit', '{}', 1.0)"
                        )
                with closing(sqlite3.connect(database)) as verify:
                    self.assertIsNone(
                        verify.execute(
                            "SELECT 1 FROM store_metadata WHERE key = 'must-not-commit'"
                        ).fetchone()
                    )
            finally:
                connection.close()
                core.close()

    def test_write_transaction_reasserts_lock_identity_before_commit(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-commit-fence",
            )
            store = DurableMemoryStore(database, authority_lease=core)
            self._claim(store, core)
            connection = store._connect()
            try:
                with self.assertRaisesRegex(
                    CoreAuthorityError,
                    "lock identity is invalid|lock path was replaced",
                ):
                    with store._transaction(connection, immediate=True):
                        connection.execute(
                            "INSERT INTO store_metadata (key, value_json, updated_at) "
                            "VALUES ('must-not-cross-handoff', '{}', 1.0)"
                        )
                        core.lock_path.unlink()
                        replacement = os.open(
                            core.lock_path,
                            os.O_RDWR | os.O_CREAT,
                            0o600,
                        )
                        os.close(replacement)
                with closing(sqlite3.connect(database)) as verify:
                    self.assertIsNone(
                        verify.execute(
                            "SELECT 1 FROM store_metadata "
                            "WHERE key = 'must-not-cross-handoff'"
                        ).fetchone()
                    )
            finally:
                connection.close()
                core.close()

    def test_v5_schema_repair_has_no_effect_after_authority_replacement(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            missing_index = "ix_memory_entries_context_updated"
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(f"DROP INDEX {missing_index}")
                conn.commit()

            original_preflight = DurableMemoryStore._preflight_durable_authority
            preflight_calls = 0

            def replace_lock_after_preflight(
                store: DurableMemoryStore,
                conn: sqlite3.Connection,
            ) -> None:
                nonlocal preflight_calls
                original_preflight(store, conn)
                preflight_calls += 1
                if preflight_calls == 1:
                    assert store._authority_lease is not None
                    store._authority_lease.lock_path.unlink()
                    replacement = os.open(
                        store._authority_lease.lock_path,
                        os.O_RDWR | os.O_CREAT,
                        0o600,
                    )
                    os.close(replacement)

            with patch.object(
                DurableMemoryStore,
                "_preflight_durable_authority",
                replace_lock_after_preflight,
            ):
                with self.assertRaisesRegex(
                    CoreAuthorityError,
                    "lock identity is invalid|lock path was replaced",
                ):
                    DurableMemoryStore(database)

            with closing(sqlite3.connect(database)) as conn:
                self.assertIsNone(
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?",
                        (missing_index,),
                    ).fetchone()
                )

    def test_atomic_database_replacement_invalidates_bound_core(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            replacement = root / "replacement.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-database-replacement",
            )
            store = DurableMemoryStore(database, authority_lease=core)
            self._claim(store, core)
            original_identity = (core.database_device, core.database_inode)
            with closing(sqlite3.connect(database)) as source, closing(
                sqlite3.connect(replacement)
            ) as destination:
                source.backup(destination)
            os.replace(replacement, database)
            self.assertNotEqual(
                original_identity,
                (database.stat().st_dev, database.stat().st_ino),
            )

            with self.assertRaisesRegex(CoreAuthorityError, "database path was replaced"):
                store.upsert_entry(
                    tag="must-not-write-after-database-replacement",
                    context_id="default",
                    source_text="must not commit",
                    metadata={},
                    embedding_dimensions=4,
                    spike_indices=[1],
                    neuron_indices=[1],
                )
            with closing(sqlite3.connect(database)) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_entries WHERE tag = ?",
                        ("must-not-write-after-database-replacement",),
                    ).fetchone()[0],
                    0,
                )
            core.close()

    def test_database_replacement_during_transaction_rolls_back_old_inode(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "memory.sqlite3"
            replacement = root / "replacement.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-database-precommit",
            )
            store = DurableMemoryStore(database, authority_lease=core)
            self._claim(store, core)
            with closing(sqlite3.connect(database)) as source, closing(
                sqlite3.connect(replacement)
            ) as destination:
                source.backup(destination)
            connection = store._connect()
            try:
                with self.assertRaisesRegex(
                    CoreAuthorityError,
                    "database path was replaced",
                ):
                    with store._transaction(connection, immediate=True):
                        connection.execute(
                            "INSERT INTO store_metadata (key, value_json, updated_at) "
                            "VALUES ('must-not-cross-database-swap', '{}', 1.0)"
                        )
                        os.replace(replacement, database)
                with closing(sqlite3.connect(database)) as verify:
                    self.assertIsNone(
                        verify.execute(
                            "SELECT 1 FROM store_metadata "
                            "WHERE key = 'must-not-cross-database-swap'"
                        ).fetchone()
                    )
            finally:
                connection.close()
                core.close()

    def test_v5_disabled_core_marker_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            now = 1_800_000_000.0
            marker = {
                "schema_version": 1,
                "service_required": False,
                "epoch": 1,
                "instance_id": "core-disabled-v5",
                "config_fingerprint": "b" * 64,
                "build_id": "test-build",
                "protocol_version": "synapse-core.v1",
                "claimed_at": now,
                "updated_at": now,
            }
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(
                    "INSERT INTO store_metadata (key, value_json, updated_at) "
                    "VALUES (?, ?, ?)",
                    (
                        "core_authority",
                        json.dumps(marker, sort_keys=True, separators=(",", ":")),
                        now,
                    ),
                )
                conn.commit()
            with self.assertRaisesRegex(CoreAuthorityError, "marker is invalid"):
                DurableMemoryStore(database)

    def test_v5_core_adoption_migration_without_marker_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(
                    "INSERT INTO store_migrations (key, applied_at) VALUES (?, ?)",
                    ("authoritative_core_v1", 1_800_000_000.0),
                )
                conn.commit()
            with self.assertRaisesRegex(CoreAuthorityError, "invalid|inconsistent"):
                DurableMemoryStore(database)

    def test_v6_without_required_marker_fails_closed_but_audit_opens(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            with closing(sqlite3.connect(database)) as conn:
                conn.execute("PRAGMA user_version = 6")
                conn.commit()
            with self.assertRaisesRegex(CoreAuthorityError, "invalid|inconsistent"):
                DurableMemoryStore(database)
            audit = DurableMemoryStore.open_existing_for_audit(database)
            with closing(audit._connect_read_only()) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0], 0)

    def test_v6_with_disabled_service_marker_fails_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            now = 1_800_000_000.0
            disabled_marker = {
                "schema_version": 1,
                "service_required": False,
                "epoch": 1,
                "instance_id": "core-disabled",
                "config_fingerprint": "b" * 64,
                "build_id": "test-build",
                "protocol_version": "synapse-core.v1",
                "claimed_at": now,
                "updated_at": now,
            }
            with closing(sqlite3.connect(database)) as conn:
                conn.execute(
                    """
                    INSERT INTO store_metadata (key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        "core_authority",
                        json.dumps(disabled_marker, sort_keys=True, separators=(",", ":")),
                        now,
                    ),
                )
                conn.execute("PRAGMA user_version = 6")
                conn.commit()
            with self.assertRaisesRegex(CoreAuthorityError, "invalid|inconsistent"):
                DurableMemoryStore(database)

    def test_expired_attestation_cannot_cross_the_final_claim_commit(self) -> None:
        with TemporaryDirectory() as temporary:
            database = Path(temporary) / "memory.sqlite3"
            bootstrap = DurableMemoryStore(database)
            bootstrap.close()
            core = CoreAuthorityLease.acquire_core(
                database,
                timeout_seconds=0.0,
                instance_id="core-expired-attestation",
            )
            try:
                store = DurableMemoryStore(database, authority_lease=core)
                with self.assertRaisesRegex(CoreAuthorityError, "expired"):
                    self._claim(
                        store,
                        core,
                        attestation_expires_at_unix_ms=(
                            int(time.time() * 1000) + 500
                        ),
                    )
            finally:
                core.close()
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(
                    int(connection.execute("PRAGMA user_version").fetchone()[0]),
                    5,
                )
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                )


if __name__ == "__main__":
    unittest.main()

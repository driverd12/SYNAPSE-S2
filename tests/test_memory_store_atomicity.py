import hashlib
import json
import sqlite3
import subprocess
import sys
import threading
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from memory_store import DurableMemoryStore


class DurableMemoryStoreAtomicityTests(unittest.TestCase):
    def test_audit_and_repair_normalize_malformed_reserved_schema(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="malformed-schema",
                context_id="demo",
                source_text="Malformed derived schema must not masquerade as healthy.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[1],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.executescript(
                    """
                    DROP INDEX ix_memory_spikes_context_spike;
                    CREATE INDEX ix_memory_spikes_context_spike
                    ON memory_spikes(memory_id);
                    DROP TABLE store_maintenance_receipts;
                    CREATE TABLE store_maintenance_receipts (bogus TEXT);
                    CREATE INDEX ix_store_maintenance_receipts_type_created
                    ON store_maintenance_receipts(bogus);
                    """
                )
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = 2",
                    (entry["memory_id"],),
                )
                conn.commit()

            report = store.audit_semantic_indexes(context_id="demo")
            self.assertEqual(report["status"], "degraded")
            self.assertTrue(report["repairable"])
            self.assertIn(
                "ix_memory_spikes_context_spike",
                report["invalid_schema_object_names"],
            )
            self.assertIn(
                "store_maintenance_receipts",
                report["invalid_schema_object_names"],
            )
            repair = store.repair_semantic_indexes(
                context_id="demo",
                confirm=True,
                expected_revision=report["audit_revision"],
            )
            verified = store.audit_semantic_indexes(context_id="demo")

            self.assertEqual(repair["status"], "ready")
            self.assertEqual(verified["status"], "ready")
            self.assertIn(
                "store_maintenance_receipts",
                repair["normalized_schema_objects"],
            )
            self.assertTrue(repair["quarantined_schema_objects"])
            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    [
                        row[2]
                        for row in conn.execute(
                            "PRAGMA index_info(ix_memory_spikes_context_spike)"
                        ).fetchall()
                    ],
                    ["context_id", "spike_index", "memory_id"],
                )
                receipt_columns = {
                    row[1]
                    for row in conn.execute(
                        "PRAGMA table_info(store_maintenance_receipts)"
                    ).fetchall()
                }
                self.assertIn("operation_type", receipt_columns)
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_maintenance_receipts"
                    ).fetchone()[0],
                    1,
                )

    def test_repair_accepts_only_known_derived_orphan_foreign_key_errors(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
                conn.execute(
                    "INSERT INTO memory_spikes (memory_id, context_id, spike_index) VALUES (?, ?, ?)",
                    ("orphan-memory", "demo", 7),
                )
                conn.execute(
                    "INSERT INTO memory_surface_terms (memory_id, context_id, term, weight) VALUES (?, ?, ?, ?)",
                    ("orphan-memory", "demo", "orphan", 1.0),
                )
                conn.commit()

            report = store.audit_semantic_indexes(context_id="demo")
            self.assertEqual(report["status"], "degraded")
            self.assertTrue(report["repairable"])
            self.assertEqual(report["foreign_key_error_count"], 2)
            self.assertEqual(report["repairable_foreign_key_error_count"], 2)
            self.assertEqual(report["blocking_foreign_key_error_count"], 0)
            repair = store.repair_semantic_indexes(
                context_id="demo",
                confirm=True,
                expected_revision=report["audit_revision"],
            )
            verified = store.audit_semantic_indexes(context_id="demo")

            self.assertEqual(repair["orphan_spikes_removed"], 1)
            self.assertEqual(repair["orphan_surface_terms_removed"], 1)
            self.assertEqual(
                repair["safety_backup"]["allowed_foreign_key_error_count"],
                2,
            )
            self.assertEqual(verified["status"], "ready")
            self.assertEqual(verified["foreign_key_error_count"], 0)

    def test_audit_blocks_non_derived_foreign_key_errors(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute("PRAGMA foreign_keys = OFF")
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
                    """,
                    (
                        "invalid-relationship",
                        "demo",
                        "missing-source",
                        "missing-target",
                        "related",
                        1.0,
                        "{}",
                        1.0,
                        1.0,
                    ),
                )
                conn.commit()

            report = store.audit_semantic_indexes(context_id="demo")
            self.assertEqual(report["status"], "blocked")
            self.assertFalse(report["repairable"])
            self.assertEqual(report["repairable_foreign_key_error_count"], 0)
            self.assertEqual(report["blocking_foreign_key_error_count"], 2)

    def test_maintenance_gate_precedes_persistent_journal_mode_change(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    str(conn.execute("PRAGMA journal_mode = DELETE").fetchone()[0]),
                    "delete",
                )
            descriptors = store._acquire_maintenance_lock("journal-mode-regression")
            attempted = threading.Event()
            completed = threading.Event()
            errors: list[BaseException] = []
            original_acquire = DurableMemoryStore._acquire_file_lock

            def instrumented(path, *, mode, timeout_seconds):
                if (
                    threading.current_thread().name == "journal-mode-writer"
                    and path.name == "writer-turnstile.lock"
                ):
                    attempted.set()
                return original_acquire(
                    path,
                    mode=mode,
                    timeout_seconds=timeout_seconds,
                )

            def connect_writer() -> None:
                try:
                    with closing(store._connect()):
                        pass
                except BaseException as exc:  # pragma: no cover - diagnostic path
                    errors.append(exc)
                finally:
                    completed.set()

            worker = threading.Thread(
                target=connect_writer,
                name="journal-mode-writer",
            )
            try:
                with mock.patch.object(
                    DurableMemoryStore,
                    "_acquire_file_lock",
                    new=staticmethod(instrumented),
                ):
                    worker.start()
                    self.assertTrue(attempted.wait(timeout=5.0))
                    with closing(sqlite3.connect(db_path)) as observer:
                        self.assertEqual(
                            str(observer.execute("PRAGMA journal_mode").fetchone()[0]),
                            "delete",
                        )
                    self.assertFalse(completed.is_set())
                    store._release_maintenance_lock(descriptors)
                    descriptors = None
                    self.assertTrue(completed.wait(timeout=5.0))
            finally:
                if descriptors is not None:
                    store._release_maintenance_lock(descriptors)
                worker.join(timeout=5.0)
            self.assertFalse(errors)
            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    str(conn.execute("PRAGMA journal_mode").fetchone()[0]),
                    "wal",
                )

    def test_verified_backup_removes_final_file_after_post_rename_failure(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            store.upsert_entry(
                tag="backup-cleanup",
                context_id="demo",
                source_text="Post-rename failures must not leak full backups.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[1],
            )
            with closing(store._connect_existing_write()) as conn:
                with mock.patch(
                    "memory_store.hashlib.sha256",
                    side_effect=RuntimeError("injected digest failure"),
                ):
                    with self.assertRaisesRegex(RuntimeError, "digest failure"):
                        store._verified_safety_backup(
                            conn,
                            label="digest-failure",
                        )
            backup_dir = db_path.parent / "backups"
            self.assertEqual(list(backup_dir.glob("*.sqlite3")), [])
            self.assertEqual(list(backup_dir.glob("*.tmp")), [])

    def test_audit_retries_when_database_changes_during_snapshot(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            store.upsert_entry(
                tag="audit-retry",
                context_id="demo",
                source_text="Audits must not cache a snapshot invalidated during scanning.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[1],
            )
            original_audit = store._semantic_index_audit
            calls = 0

            def audit_then_write(conn, **kwargs):
                nonlocal calls
                calls += 1
                payload = original_audit(conn, **kwargs)
                if calls == 1:
                    with closing(sqlite3.connect(db_path, timeout=10.0)) as writer:
                        writer.execute(
                            "INSERT INTO store_metadata (key, value_json, updated_at) VALUES (?, ?, ?)",
                            ("audit-concurrent-write", "true", 1.0),
                        )
                        writer.commit()
                return payload

            with mock.patch.object(
                store,
                "_semantic_index_audit",
                side_effect=audit_then_write,
            ):
                report = store.audit_semantic_indexes(context_id="demo")

            self.assertEqual(calls, 2)
            self.assertTrue(report["snapshot_stable"])
            self.assertEqual(report["snapshot_attempts"], 2)
            self.assertEqual(report["status"], "ready")

    def test_maintenance_gate_drains_writer_and_blocks_new_writer(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)

            first_writer_entered = threading.Event()
            release_first_writer = threading.Event()
            maintenance_turnstile_acquired = threading.Event()
            maintenance_entered = threading.Event()
            release_maintenance = threading.Event()
            second_writer_attempted = threading.Event()
            second_writer_entered = threading.Event()
            order: list[str] = []
            order_lock = threading.Lock()
            worker_errors: list[BaseException] = []
            original_acquire_file_lock = DurableMemoryStore._acquire_file_lock

            def append_order(value: str) -> None:
                with order_lock:
                    order.append(value)

            def instrumented_acquire_file_lock(
                path: Path,
                *,
                mode: int,
                timeout_seconds: float,
            ) -> int:
                thread_name = threading.current_thread().name
                if (
                    path.name == "writer-turnstile.lock"
                    and thread_name == "writer-after-maintenance"
                ):
                    second_writer_attempted.set()
                descriptor = original_acquire_file_lock(
                    path,
                    mode=mode,
                    timeout_seconds=timeout_seconds,
                )
                if (
                    path.name == "writer-turnstile.lock"
                    and thread_name == "maintenance"
                ):
                    maintenance_turnstile_acquired.set()
                return descriptor

            def first_writer() -> None:
                try:
                    with closing(store._connect_existing_write()) as conn:
                        with store._transaction(conn, immediate=True):
                            append_order("writer-1")
                            first_writer_entered.set()
                            if not release_first_writer.wait(5.0):
                                raise TimeoutError("first writer was not released")
                except BaseException as exc:  # pragma: no cover - diagnostic path
                    worker_errors.append(exc)
                    first_writer_entered.set()

            def maintenance() -> None:
                descriptors: tuple[int, int, int] | None = None
                try:
                    descriptors = store._acquire_maintenance_lock(
                        "writer-drain-regression"
                    )
                    append_order("maintenance")
                    maintenance_entered.set()
                    if not release_maintenance.wait(5.0):
                        raise TimeoutError("maintenance gate was not released")
                except BaseException as exc:  # pragma: no cover - diagnostic path
                    worker_errors.append(exc)
                    maintenance_entered.set()
                finally:
                    if descriptors is not None:
                        store._release_maintenance_lock(descriptors)

            def second_writer() -> None:
                try:
                    with closing(store._connect_existing_write()) as conn:
                        with store._transaction(conn, immediate=True):
                            append_order("writer-2")
                            second_writer_entered.set()
                except BaseException as exc:  # pragma: no cover - diagnostic path
                    worker_errors.append(exc)
                    second_writer_entered.set()

            threads: list[threading.Thread] = []
            with mock.patch.object(
                DurableMemoryStore,
                "_acquire_file_lock",
                new=staticmethod(instrumented_acquire_file_lock),
            ):
                try:
                    threads.append(
                        threading.Thread(target=first_writer, name="writer-in-flight")
                    )
                    threads[-1].start()
                    self.assertTrue(
                        first_writer_entered.wait(5.0),
                        "the first writer never entered its transaction",
                    )
                    self.assertFalse(worker_errors)

                    threads.append(
                        threading.Thread(target=maintenance, name="maintenance")
                    )
                    threads[-1].start()
                    self.assertTrue(
                        maintenance_turnstile_acquired.wait(5.0),
                        "maintenance never closed the writer turnstile",
                    )
                    self.assertFalse(
                        maintenance_entered.is_set(),
                        "maintenance bypassed the in-flight writer",
                    )

                    threads.append(
                        threading.Thread(
                            target=second_writer,
                            name="writer-after-maintenance",
                        )
                    )
                    threads[-1].start()
                    self.assertTrue(
                        second_writer_attempted.wait(5.0),
                        "the second writer never attempted the turnstile",
                    )

                    release_first_writer.set()
                    self.assertTrue(
                        maintenance_entered.wait(5.0),
                        "maintenance did not enter after the first writer drained",
                    )
                    self.assertFalse(worker_errors)
                    self.assertFalse(
                        second_writer_entered.is_set(),
                        "a new cooperating writer entered while maintenance held the gate",
                    )

                    release_maintenance.set()
                    self.assertTrue(
                        second_writer_entered.wait(5.0),
                        "the second writer did not resume after maintenance released the gate",
                    )
                finally:
                    release_first_writer.set()
                    release_maintenance.set()
                    for thread in threads:
                        thread.join(5.0)

            self.assertFalse(worker_errors)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(order, ["writer-1", "maintenance", "writer-2"])

    def test_abrupt_process_exit_rolls_back_transaction_and_releases_writer_gate(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="process-rollback",
                context_id="demo",
                source_text="committed source",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[2],
            )
            child_code = """
import os
import sys
from contextlib import closing
from pathlib import Path

from memory_store import DurableMemoryStore

store = DurableMemoryStore(Path(sys.argv[1]))
with closing(store._connect_existing_write()) as conn:
    with store._transaction(conn, immediate=True):
        conn.execute(
            "UPDATE memory_entries SET source_text = ? WHERE memory_id = ?",
            ("uncommitted child source", sys.argv[2]),
        )
        print("READY", flush=True)
        sys.stdin.readline()
        os._exit(73)
"""
            process = subprocess.Popen(
                [sys.executable, "-c", child_code, str(db_path), entry["memory_id"]],
                cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = process.communicate(input="exit\n", timeout=10.0)
            except BaseException:
                process.kill()
                process.wait(timeout=5.0)
                raise

            self.assertEqual(process.returncode, 73, stderr)
            self.assertEqual(stdout.strip(), "READY")
            with closing(sqlite3.connect(db_path)) as conn:
                source_text = conn.execute(
                    "SELECT source_text FROM memory_entries WHERE memory_id = ?",
                    (entry["memory_id"],),
                ).fetchone()[0]
            self.assertEqual(source_text, "committed source")

            replacement = store.upsert_entry(
                tag="process-rollback",
                context_id="demo",
                source_text="replacement after abrupt exit",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[3],
                neuron_indices=[4],
            )
            self.assertEqual(replacement["memory_id"], entry["memory_id"])
            self.assertEqual(replacement["source_text"], "replacement after abrupt exit")

    def test_upsert_rejects_noncanonical_indices_before_opening_transaction(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            invalid_cases = (
                {"embedding_dimensions": 0, "spike_indices": [], "neuron_indices": []},
                {"embedding_dimensions": 8, "spike_indices": [True], "neuron_indices": []},
                {"embedding_dimensions": 8, "spike_indices": [-1], "neuron_indices": []},
                {"embedding_dimensions": 8, "spike_indices": [8], "neuron_indices": []},
                {"embedding_dimensions": 8, "spike_indices": [1], "neuron_indices": [False]},
                {"embedding_dimensions": 8, "spike_indices": [1], "neuron_indices": [-1]},
            )
            for index, case in enumerate(invalid_cases):
                with self.subTest(case=case):
                    with self.assertRaises(ValueError):
                        store.upsert_entry(
                            tag=f"invalid-{index}",
                            context_id="demo",
                            source_text="Invalid canonical input.",
                            metadata={},
                            **case,
                        )
            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0],
                    0,
                )

    def test_upsert_rolls_back_entry_and_indexes_when_final_event_write_fails(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            original = store.upsert_entry(
                tag="atomic-upsert",
                context_id="demo",
                source_text="Original durable memory about cortex safety.",
                metadata={"version": 1, "semantic_facets": ["cortex safety"]},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[3, 4],
            )

            with closing(sqlite3.connect(db_path)) as conn:
                original_spikes = conn.execute(
                    """
                    SELECT spike_index
                    FROM memory_spikes
                    WHERE memory_id = ?
                    ORDER BY spike_index
                    """,
                    (original["memory_id"],),
                ).fetchall()
                original_terms = conn.execute(
                    """
                    SELECT term, weight
                    FROM memory_surface_terms
                    WHERE memory_id = ?
                    ORDER BY term
                    """,
                    (original["memory_id"],),
                ).fetchall()
                original_event_count = conn.execute(
                    "SELECT COUNT(*) FROM memory_events WHERE memory_id = ?",
                    (original["memory_id"],),
                ).fetchone()[0]
                conn.executescript(
                    """
                    CREATE TRIGGER inject_upsert_event_failure
                    BEFORE INSERT ON memory_events
                    WHEN NEW.event_type = 'upsert'
                    BEGIN
                        SELECT RAISE(ABORT, 'injected upsert event failure');
                    END;
                    """
                )

            with self.assertLogs("synapse_s2.memory_store", level="ERROR") as logs:
                with self.assertRaises(sqlite3.IntegrityError):
                    store.upsert_entry(
                        tag="atomic-upsert",
                        context_id="demo",
                        source_text="Replacement text must not survive a partial write.",
                        metadata={"version": 2, "semantic_facets": ["replacement only"]},
                        embedding_dimensions=16,
                        spike_indices=[7, 8, 9],
                        neuron_indices=[10, 11],
                    )
            self.assertIn("injected upsert event failure", "\n".join(logs.output))

            with closing(sqlite3.connect(db_path)) as conn:
                conn.row_factory = sqlite3.Row
                restored = conn.execute(
                    "SELECT * FROM memory_entries WHERE memory_id = ?",
                    (original["memory_id"],),
                ).fetchone()
                restored_spikes = conn.execute(
                    """
                    SELECT spike_index
                    FROM memory_spikes
                    WHERE memory_id = ?
                    ORDER BY spike_index
                    """,
                    (original["memory_id"],),
                ).fetchall()
                restored_terms = conn.execute(
                    """
                    SELECT term, weight
                    FROM memory_surface_terms
                    WHERE memory_id = ?
                    ORDER BY term
                    """,
                    (original["memory_id"],),
                ).fetchall()
                restored_event_count = conn.execute(
                    "SELECT COUNT(*) FROM memory_events WHERE memory_id = ?",
                    (original["memory_id"],),
                ).fetchone()[0]

            self.assertIsNotNone(restored)
            self.assertEqual(restored["source_text"], original["source_text"])
            self.assertEqual(json.loads(restored["metadata_json"]), original["metadata"])
            self.assertEqual(restored["embedding_dimensions"], 8)
            self.assertEqual(json.loads(restored["spike_indices_json"]), [1, 2])
            self.assertEqual(json.loads(restored["neuron_indices_json"]), [3, 4])
            self.assertEqual(
                [tuple(row) for row in restored_spikes],
                [tuple(row) for row in original_spikes],
            )
            self.assertEqual(
                [tuple(row) for row in restored_terms],
                [tuple(row) for row in original_terms],
            )
            self.assertEqual(restored_event_count, original_event_count)

    def test_mode_relationship_delete_rolls_back_when_second_delete_fails(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entries = [
                store.upsert_entry(
                    tag=f"relationship-node-{index}",
                    context_id="demo",
                    source_text=f"Relationship node {index}.",
                    metadata={},
                    embedding_dimensions=8,
                    spike_indices=[index],
                    neuron_indices=[index],
                )
                for index in range(1, 4)
            ]
            first = store.upsert_relationship(
                context_id="demo",
                source_memory_id=entries[0]["memory_id"],
                target_memory_id=entries[1]["memory_id"],
                relation_type="temporal_next",
                weight=0.9,
            )
            second = store.upsert_relationship(
                context_id="demo",
                source_memory_id=entries[1]["memory_id"],
                target_memory_id=entries[2]["memory_id"],
                relation_type="temporal_next",
                weight=0.8,
            )

            with closing(sqlite3.connect(db_path)) as conn:
                # The implementation deletes newest-first. Make that order
                # deterministic, then fail the older relationship so one DELETE
                # has already executed when the trigger aborts the second.
                conn.execute(
                    "UPDATE memory_relationships SET updated_at = ? WHERE relationship_id = ?",
                    (1.0, first["relationship_id"]),
                )
                conn.execute(
                    "UPDATE memory_relationships SET updated_at = ? WHERE relationship_id = ?",
                    (2.0, second["relationship_id"]),
                )
                conn.execute(
                    f"""
                    CREATE TRIGGER inject_second_relationship_delete_failure
                    BEFORE DELETE ON memory_relationships
                    WHEN OLD.relationship_id = '{first["relationship_id"]}'
                    BEGIN
                        SELECT RAISE(ABORT, 'injected second relationship delete failure');
                    END
                    """
                )
                conn.commit()

            with self.assertLogs("synapse_s2.memory_store", level="ERROR") as logs:
                with self.assertRaises(sqlite3.IntegrityError):
                    store.delete_relationships_by_mode(
                        context_id="demo",
                        mode="temporal",
                    )
            self.assertIn(
                "injected second relationship delete failure",
                "\n".join(logs.output),
            )

            with closing(sqlite3.connect(db_path)) as conn:
                remaining_ids = [
                    str(row[0])
                    for row in conn.execute(
                        """
                        SELECT relationship_id
                        FROM memory_relationships
                        WHERE context_id = ?
                        ORDER BY relationship_id
                        """,
                        ("demo",),
                    ).fetchall()
                ]

            self.assertEqual(
                remaining_ids,
                sorted([first["relationship_id"], second["relationship_id"]]),
            )

    def test_semantic_index_repair_refuses_stale_revision_without_mutation(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="stale-repair-plan",
                context_id="demo",
                source_text="Stale repair plans must never mutate memory indexes.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2, 3],
                neuron_indices=[1, 2],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = ?",
                    (entry["memory_id"], 2),
                )
                conn.commit()

            reviewed = store.audit_semantic_indexes(context_id="demo", sample_limit=10)

            # Change the repair target after the operator-reviewed audit. This
            # simulates a concurrent writer and invalidates the reviewed plan.
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = ?",
                    (entry["memory_id"], 3),
                )
                conn.commit()
                before_spikes = conn.execute(
                    """
                    SELECT spike_index
                    FROM memory_spikes
                    WHERE memory_id = ?
                    ORDER BY spike_index
                    """,
                    (entry["memory_id"],),
                ).fetchall()
                before_generation = conn.execute(
                    "SELECT value_json FROM store_metadata WHERE key = ?",
                    ("semantic_index_generation",),
                ).fetchone()
                before_receipt_count = conn.execute(
                    "SELECT COUNT(*) FROM store_maintenance_receipts"
                ).fetchone()[0]

            with self.assertLogs("synapse_s2.memory_store", level="ERROR") as logs:
                with self.assertRaisesRegex(RuntimeError, "repair plan is stale"):
                    store.repair_semantic_indexes(
                        context_id="demo",
                        confirm=True,
                        expected_revision=reviewed["audit_revision"],
                        sample_limit=10,
                    )
            self.assertIn("repair plan is stale", "\n".join(logs.output))

            with closing(sqlite3.connect(db_path)) as conn:
                after_spikes = conn.execute(
                    """
                    SELECT spike_index
                    FROM memory_spikes
                    WHERE memory_id = ?
                    ORDER BY spike_index
                    """,
                    (entry["memory_id"],),
                ).fetchall()
                after_generation = conn.execute(
                    "SELECT value_json FROM store_metadata WHERE key = ?",
                    ("semantic_index_generation",),
                ).fetchone()
                after_receipt_count = conn.execute(
                    "SELECT COUNT(*) FROM store_maintenance_receipts"
                ).fetchone()[0]

            self.assertEqual(after_spikes, before_spikes)
            self.assertEqual(after_generation, before_generation)
            self.assertEqual(after_receipt_count, before_receipt_count)
            backup_dir = db_path.parent / "backups"
            self.assertFalse(backup_dir.exists())

    def test_read_only_audit_and_rejected_repairs_do_not_run_migrations(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="no-implicit-repair",
                context_id="demo",
                source_text="Audit authorization must not mutate indexes.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[1],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = 2",
                    (entry["memory_id"],),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'memory_spikes_v1'"
                )
                conn.commit()

            audit_store = DurableMemoryStore.open_existing_for_audit(db_path)
            report = audit_store.audit_semantic_indexes(context_id="demo")
            self.assertEqual(report["status"], "degraded")
            with self.assertRaises(ValueError):
                audit_store.repair_semantic_indexes(
                    context_id="demo",
                    confirm=False,
                    expected_revision=report["audit_revision"],
                )
            with self.assertLogs("synapse_s2.memory_store", level="ERROR"):
                with self.assertRaisesRegex(RuntimeError, "repair plan is stale"):
                    audit_store.repair_semantic_indexes(
                        context_id="demo",
                        confirm=True,
                        expected_revision="stale-revision",
                    )

            with closing(sqlite3.connect(db_path)) as conn:
                spikes = conn.execute(
                    "SELECT spike_index FROM memory_spikes WHERE memory_id = ? ORDER BY 1",
                    (entry["memory_id"],),
                ).fetchall()
                marker = conn.execute(
                    "SELECT 1 FROM store_migrations WHERE key = 'memory_spikes_v1'"
                ).fetchone()
                receipt_count = conn.execute(
                    "SELECT COUNT(*) FROM store_maintenance_receipts"
                ).fetchone()[0]
            self.assertEqual(spikes, [(1,)])
            self.assertIsNone(marker)
            self.assertEqual(receipt_count, 0)
            self.assertFalse((db_path.parent / "backups").exists())

    def test_receipt_failure_rolls_back_repair_and_discards_attempt_backup(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="receipt-rollback",
                context_id="demo",
                source_text="Receipt persistence is part of the repair commit.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2, 3],
                neuron_indices=[1],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = 2",
                    (entry["memory_id"],),
                )
                conn.executescript(
                    """
                    CREATE TRIGGER inject_receipt_failure
                    BEFORE INSERT ON store_maintenance_receipts
                    BEGIN
                        SELECT RAISE(ABORT, 'injected receipt failure');
                    END;
                    """
                )
            report = store.audit_semantic_indexes(context_id="demo")
            with self.assertLogs("synapse_s2.memory_store", level="ERROR"):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "receipt failure"):
                    store.repair_semantic_indexes(
                        context_id="demo",
                        confirm=True,
                        expected_revision=report["audit_revision"],
                    )
            with closing(sqlite3.connect(db_path)) as conn:
                spikes = conn.execute(
                    "SELECT spike_index FROM memory_spikes WHERE memory_id = ? ORDER BY 1",
                    (entry["memory_id"],),
                ).fetchall()
                generation = conn.execute(
                    "SELECT value_json FROM store_metadata WHERE key = 'semantic_index_generation'"
                ).fetchone()
                receipts = conn.execute(
                    "SELECT COUNT(*) FROM store_maintenance_receipts"
                ).fetchone()[0]
            self.assertEqual(spikes, [(1,), (3,)])
            self.assertIsNone(generation)
            self.assertEqual(receipts, 0)
            backup_dir = db_path.parent / "backups"
            self.assertEqual(list(backup_dir.glob("*.sqlite3")), [])
            self.assertEqual(list(backup_dir.glob("*.tmp")), [])

    def test_backup_failure_leaves_repair_targets_untouched(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="backup-failure",
                context_id="demo",
                source_text="Repair must stop when its safety backup fails.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[1],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = 2",
                    (entry["memory_id"],),
                )
                conn.commit()
            report = store.audit_semantic_indexes(context_id="demo")
            with mock.patch.object(
                store,
                "_verified_safety_backup",
                side_effect=OSError("injected backup failure"),
            ):
                with self.assertLogs("synapse_s2.memory_store", level="ERROR"):
                    with self.assertRaisesRegex(OSError, "backup failure"):
                        store.repair_semantic_indexes(
                            context_id="demo",
                            confirm=True,
                            expected_revision=report["audit_revision"],
                        )
            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT spike_index FROM memory_spikes WHERE memory_id = ? ORDER BY 1",
                        (entry["memory_id"],),
                    ).fetchall(),
                    [(1,)],
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_maintenance_receipts"
                    ).fetchone()[0],
                    0,
                )

    def test_concurrent_writer_invalidates_plan_and_attempt_backup_is_removed(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="concurrent-repair",
                context_id="demo",
                source_text="Concurrent changes invalidate repair planning.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[1],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = 2",
                    (entry["memory_id"],),
                )
                conn.commit()
            report = store.audit_semantic_indexes(context_id="demo")
            original_backup = store._verified_safety_backup

            def backup_then_external_write(
                conn,
                *,
                label,
                allowed_foreign_key_errors=(),
            ):
                payload = original_backup(
                    conn,
                    label=label,
                    allowed_foreign_key_errors=allowed_foreign_key_errors,
                )
                with closing(sqlite3.connect(db_path, timeout=10.0)) as external:
                    external.execute(
                        "INSERT INTO store_metadata (key, value_json, updated_at) VALUES (?, ?, ?)",
                        ("concurrent-test", "true", 1.0),
                    )
                    external.commit()
                return payload

            with mock.patch.object(
                store,
                "_verified_safety_backup",
                side_effect=backup_then_external_write,
            ):
                with self.assertLogs("synapse_s2.memory_store", level="ERROR"):
                    with self.assertRaisesRegex(RuntimeError, "changed during safety backup"):
                        store.repair_semantic_indexes(
                            context_id="demo",
                            confirm=True,
                            expected_revision=report["audit_revision"],
                        )
            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT spike_index FROM memory_spikes WHERE memory_id = ? ORDER BY 1",
                        (entry["memory_id"],),
                    ).fetchall(),
                    [(1,)],
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_maintenance_receipts"
                    ).fetchone()[0],
                    0,
                )
            self.assertEqual(
                list((db_path.parent / "backups").glob("*.sqlite3")),
                [],
            )

    def test_confirmed_repair_creates_missing_derived_schema_transactionally(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entry = store.upsert_entry(
                tag="legacy-schema",
                context_id="demo",
                source_text="Legacy stores need an explicit derived-schema repair.",
                metadata={"display_label": "Legacy schema"},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[1],
            )
            with closing(sqlite3.connect(db_path)) as conn:
                conn.executescript(
                    """
                    DROP TABLE memory_spikes;
                    DROP TABLE memory_surface_terms;
                    DROP TABLE store_maintenance_receipts;
                    DROP TABLE store_metadata;
                    """
                )
            audit_store = DurableMemoryStore.open_existing_for_audit(db_path)
            report = audit_store.audit_semantic_indexes(context_id="demo")
            self.assertEqual(report["status"], "degraded")
            self.assertTrue(report["repairable"])
            self.assertIn("memory_spikes", report["missing_schema_objects"])
            self.assertIn("store_metadata", report["missing_schema_objects"])
            repair = audit_store.repair_semantic_indexes(
                context_id="demo",
                confirm=True,
                expected_revision=report["audit_revision"],
            )
            verified = audit_store.audit_semantic_indexes(context_id="demo")
            self.assertEqual(repair["status"], "ready")
            self.assertTrue(repair["schema_objects_created"])
            self.assertEqual(verified["status"], "ready")
            with closing(sqlite3.connect(db_path)) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT spike_index FROM memory_spikes WHERE memory_id = ? ORDER BY 1",
                        (entry["memory_id"],),
                    ).fetchall(),
                    [(1,), (2,)],
                )
                self.assertGreater(
                    conn.execute(
                        "SELECT COUNT(*) FROM memory_surface_terms WHERE memory_id = ?",
                        (entry["memory_id"],),
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM store_maintenance_receipts"
                    ).fetchone()[0],
                    1,
                )

    def test_repair_generation_invalidates_other_store_revision_cache_key(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            writer = DurableMemoryStore(db_path)
            reader = DurableMemoryStore(db_path)
            entry = writer.upsert_entry(
                tag="cross-process-generation",
                context_id="demo",
                source_text="Generation changes invalidate semantic cache keys.",
                metadata={},
                embedding_dimensions=8,
                spike_indices=[1, 2],
                neuron_indices=[1],
            )
            revision_before = reader.entries_revision(context_id="demo")
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = 2",
                    (entry["memory_id"],),
                )
                conn.commit()
            report = writer.audit_semantic_indexes(context_id="demo")
            writer.repair_semantic_indexes(
                context_id="demo",
                confirm=True,
                expected_revision=report["audit_revision"],
            )
            revision_after = reader.entries_revision(context_id="demo")
            self.assertNotEqual(
                revision_before["semantic_index_generation"],
                revision_after["semantic_index_generation"],
            )
            self.assertNotEqual(
                revision_before["revision"],
                revision_after["revision"],
            )

    def test_semantic_index_audit_blocks_noncanonical_spike_sources(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            entries = [
                store.upsert_entry(
                    tag=tag,
                    context_id="demo",
                    source_text=f"Canonical validation case {tag}.",
                    metadata={},
                    embedding_dimensions=8,
                    spike_indices=[1, 2],
                    neuron_indices=[1, 2],
                )
                for tag in ("boolean-spike", "out-of-range-spike", "unsorted-spikes")
            ]
            invalid_sources = {
                entries[0]["memory_id"]: "[true]",
                entries[1]["memory_id"]: "[8]",
                entries[2]["memory_id"]: "[2,1]",
            }
            with closing(sqlite3.connect(db_path)) as conn:
                conn.executemany(
                    "UPDATE memory_entries SET spike_indices_json = ? WHERE memory_id = ?",
                    [
                        (raw_json, memory_id)
                        for memory_id, raw_json in invalid_sources.items()
                    ],
                )
                conn.commit()

            report = store.audit_semantic_indexes(context_id="demo", sample_limit=10)

            self.assertEqual(report["status"], "blocked")
            self.assertFalse(report["repairable"])
            self.assertEqual(report["source_error_count"], 3)
            self.assertEqual(report["spike_mismatch_count"], 3)
            self.assertEqual(
                {sample["memory_id"] for sample in report["source_error_samples"]},
                set(invalid_sources),
            )
            self.assertTrue(
                all(
                    "invalid spike_indices_json" in sample["error"]
                    for sample in report["source_error_samples"]
                )
            )

    def test_semantic_index_audit_detects_and_repairs_partial_indexes(self):
        with TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synapse-memory.sqlite3"
            store = DurableMemoryStore(db_path)
            spike_entry = store.upsert_entry(
                tag="partial-spike-index",
                context_id="demo",
                source_text="Camera control bridge evidence.",
                metadata={"display_label": "Camera bridge"},
                embedding_dimensions=8,
                spike_indices=[1, 2, 3],
                neuron_indices=[1, 2],
            )
            term_entry = store.upsert_entry(
                tag="partial-term-index",
                context_id="demo",
                source_text="Operator cortex safety evidence.",
                metadata={"display_label": "Operator cortex"},
                embedding_dimensions=8,
                spike_indices=[5, 6],
                neuron_indices=[5, 6],
            )

            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = ?",
                    (spike_entry["memory_id"], 2),
                )
                conn.execute(
                    "DELETE FROM memory_surface_terms WHERE memory_id = ? AND term = ?",
                    (term_entry["memory_id"], "operator"),
                )
                conn.commit()

            report = store.audit_semantic_indexes(context_id="demo", sample_limit=10)

            self.assertEqual(report["status"], "degraded")
            self.assertEqual(report["mismatched_memory_count"], 2)
            self.assertEqual(report["spike_mismatch_count"], 1)
            self.assertEqual(report["surface_term_mismatch_count"], 1)
            self.assertNotEqual(
                report["expected_spike_index_count"],
                report["actual_spike_index_count"],
            )
            self.assertNotEqual(
                report["expected_surface_term_count"],
                report["actual_surface_term_count"],
            )
            samples = {
                sample["memory_id"]: sample for sample in report["mismatch_samples"]
            }
            self.assertTrue(samples[spike_entry["memory_id"]]["spike_mismatch"])
            self.assertFalse(samples[spike_entry["memory_id"]]["surface_term_mismatch"])
            self.assertFalse(samples[term_entry["memory_id"]]["spike_mismatch"])
            self.assertTrue(samples[term_entry["memory_id"]]["surface_term_mismatch"])

            with self.assertRaises(ValueError):
                store.repair_semantic_indexes(
                    context_id="demo",
                    confirm=False,
                    sample_limit=10,
                )
            with self.assertRaises(ValueError):
                store.repair_semantic_indexes(
                    context_id="demo",
                    confirm="false",  # type: ignore[arg-type]
                    sample_limit=10,
                )

            repair = store.repair_semantic_indexes(
                context_id="demo",
                confirm=True,
                expected_revision=report["audit_revision"],
                sample_limit=10,
            )
            repaired = store.audit_semantic_indexes(context_id="demo", sample_limit=10)

            self.assertEqual(repaired["status"], "ready")
            self.assertEqual(repaired["mismatched_memory_count"], 0)
            self.assertEqual(repaired["spike_mismatch_count"], 0)
            self.assertEqual(repaired["surface_term_mismatch_count"], 0)
            self.assertEqual(
                repaired["expected_spike_index_count"],
                repaired["actual_spike_index_count"],
            )
            self.assertEqual(
                repaired["expected_surface_term_count"],
                repaired["actual_surface_term_count"],
            )
            self.assertTrue(repair["verification_passed"])
            self.assertEqual(
                repair["semantic_index_generation_after"],
                repair["semantic_index_generation_before"] + 1,
            )
            self.assertEqual(
                repaired["semantic_index_generation"],
                repair["semantic_index_generation_after"],
            )
            backup = repair["safety_backup"]
            self.assertIsNotNone(backup)
            backup_path = Path(backup["backup_path"])
            self.assertTrue(backup["verified"])
            self.assertEqual(backup["quick_check"], ["ok"])
            self.assertEqual(backup["foreign_key_error_count"], 0)
            self.assertTrue(backup_path.is_file())
            self.assertEqual(backup_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                hashlib.sha256(backup_path.read_bytes()).hexdigest(),
                backup["sha256"],
            )

            with closing(sqlite3.connect(db_path)) as conn:
                receipts = conn.execute(
                    """
                    SELECT
                        operation_id,
                        operation_type,
                        context_id,
                        before_revision,
                        after_revision,
                        payload_json
                    FROM store_maintenance_receipts
                    """
                ).fetchall()
            self.assertEqual(len(receipts), 1)
            receipt = receipts[0]
            receipt_payload = json.loads(receipt[5])
            self.assertEqual(receipt[0], repair["operation_id"])
            self.assertEqual(receipt[1], "semantic-index-repair")
            self.assertEqual(receipt[2], "demo")
            self.assertEqual(
                receipt_payload["full_before_revision"],
                report["audit_revision"],
            )
            self.assertEqual(receipt_payload["revision_scope"], "repair-targets")
            self.assertEqual(receipt_payload["repair_target_count"], 2)
            self.assertEqual(
                receipt_payload["repair_target_sha256"],
                hashlib.sha256(
                    "\n".join(
                        sorted(
                            [
                                spike_entry["memory_id"],
                                term_entry["memory_id"],
                            ]
                        )
                    ).encode("utf-8")
                ).hexdigest(),
            )
            self.assertNotEqual(receipt[3], receipt[4])
            self.assertEqual(
                receipt_payload["semantic_index_generation_before"],
                repair["semantic_index_generation_before"],
            )
            self.assertEqual(
                receipt_payload["semantic_index_generation_after"],
                repair["semantic_index_generation_after"],
            )
            self.assertEqual(receipt_payload["safety_backup_path"], str(backup_path))
            self.assertEqual(receipt_payload["safety_backup_sha256"], backup["sha256"])


if __name__ == "__main__":
    unittest.main()

import json
import shutil
import sqlite3
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from capture_daemon import CaptureInboxDaemon, write_capture_drop
from mlx_backend import SpikingAttentionBackend
from recovery_manager import VerifiedRecoveryManager


class CaptureLedgerReconciliationTests(unittest.TestCase):
    @staticmethod
    def _remove_capture_identity(value):
        if isinstance(value, dict):
            return {
                key: CaptureLedgerReconciliationTests._remove_capture_identity(item)
                for key, item in value.items()
                if key not in {"capture_id", "protocol"}
            }
        if isinstance(value, list):
            return [
                CaptureLedgerReconciliationTests._remove_capture_identity(item)
                for item in value
            ]
        return value

    @classmethod
    def _seed_legacy_gap(cls, root: Path):
        capture_id = "s2cap_71717171717171717171717171717171"
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=root / "runtime-state.json",
            memory_path=root / "memory.sqlite3",
        )
        write_capture_drop(
            root=root,
            context_id="legacy-repair",
            source_tag="legacy-cutover",
            speaker="codex",
            text=(
                "A bounded hot-runtime cutover wrote this durable event graph so "
                "the governed repair must add only its missing ledger receipt."
            ),
            metadata={"fixture": "legacy-ledger-reconciliation"},
            capture_id=capture_id,
        )
        daemon = CaptureInboxDaemon(root=root, backend=backend)
        processed = daemon.process_once()
        if processed["processed_file_count"] != 1:
            raise AssertionError("capture fixture did not process")
        processed_path = next(
            path
            for path in (root / "capture_processed").glob("*.json")
            if json.loads(path.read_text(encoding="utf-8")).get("capture_id")
            == capture_id
        )
        receipt_path = root / "capture_receipts" / f"{capture_id}.json"
        transport_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

        with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
            conn.row_factory = sqlite3.Row
            original = conn.execute(
                "SELECT * FROM capture_operations WHERE capture_id = ?",
                (capture_id,),
            ).fetchone()
            if original is None:
                raise AssertionError("capture fixture has no ledger row")
            original_row = dict(original)
            deployment = conn.execute(
                "SELECT * FROM agent_context_events WHERE event_id = ?",
                (int(original["deployment_event_id"]),),
            ).fetchone()
            if deployment is None:
                raise AssertionError("capture fixture has no deployment event")
            payload = cls._remove_capture_identity(
                json.loads(str(deployment["payload_json"]))
            )
            conn.execute(
                "UPDATE agent_context_events SET payload_json = ? WHERE event_id = ?",
                (
                    json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    int(original["deployment_event_id"]),
                ),
            )
            entry_rows = conn.execute(
                "SELECT memory_id, metadata_json FROM memory_entries WHERE instr(metadata_json, ?) > 0",
                (capture_id,),
            ).fetchall()
            for entry in entry_rows:
                metadata = json.loads(str(entry["metadata_json"]))
                metadata.pop("capture_id", None)
                metadata.pop("capture_protocol", None)
                if metadata.get("event_segment") is True:
                    metadata["capture_file"] = processed_path.name
                conn.execute(
                    "UPDATE memory_entries SET metadata_json = ? WHERE memory_id = ?",
                    (
                        json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                        str(entry["memory_id"]),
                    ),
                )
            graph_counts = {
                "entries": conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0],
                "relationships": conn.execute(
                    "SELECT COUNT(*) FROM memory_relationships"
                ).fetchone()[0],
                "deployments": conn.execute(
                    "SELECT COUNT(*) FROM agent_context_events"
                ).fetchone()[0],
            }
            conn.execute(
                "DELETE FROM capture_operations WHERE capture_id = ?",
                (capture_id,),
            )
            conn.commit()
        receipt_path.unlink()
        manager = VerifiedRecoveryManager(backend.memory_store, capture_root=root)
        return {
            "backend": backend,
            "capture_id": capture_id,
            "manager": manager,
            "original_row": original_row,
            "processed_path": processed_path,
            "receipt_path": receipt_path,
            "transport_fingerprint": transport_receipt["request_fingerprint"],
            "graph_counts": graph_counts,
        }

    @staticmethod
    def _ledger_row(root: Path, capture_id: str):
        with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM capture_operations WHERE capture_id = ?",
                (capture_id,),
            ).fetchone()
            return None if row is None else dict(row)

    @staticmethod
    def _seed_exact_capture(root: Path):
        capture_id = "s2cap_81818181818181818181818181818181"
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=root / "runtime-state.json",
            memory_path=root / "memory.sqlite3",
        )
        write_capture_drop(
            root=root,
            context_id="exact-ledger",
            source_tag="exact-ledger-test",
            speaker="codex",
            text="This exact capture must remain bound to its authoritative ledger row.",
            metadata={"fixture": "exact-ledger"},
            capture_id=capture_id,
        )
        daemon = CaptureInboxDaemon(root=root, backend=backend)
        result = daemon.process_once()
        if result["processed_file_count"] != 1:
            raise AssertionError("exact capture fixture did not process")
        processed_path = next(
            path
            for path in (root / "capture_processed").glob("*.json")
            if json.loads(path.read_text(encoding="utf-8")).get("capture_id")
            == capture_id
        )
        return {
            "backend": backend,
            "capture_id": capture_id,
            "daemon": daemon,
            "manager": VerifiedRecoveryManager(
                backend.memory_store,
                capture_root=root,
            ),
            "processed_path": processed_path,
        }

    def test_governed_repair_projects_ledger_identity_without_replaying_graph(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            manager = fixture["manager"]
            audit = manager.audit_capture_ledger()
            repaired = manager.repair_capture_ledger(
                confirm=True,
                expected_revision=audit["audit_revision"],
            )
            row = self._ledger_row(root, fixture["capture_id"])
            retried = manager.repair_capture_ledger(
                confirm=True,
                expected_revision=audit["audit_revision"],
            )
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                graph_counts = {
                    "entries": conn.execute(
                        "SELECT COUNT(*) FROM memory_entries"
                    ).fetchone()[0],
                    "relationships": conn.execute(
                        "SELECT COUNT(*) FROM memory_relationships"
                    ).fetchone()[0],
                    "deployments": conn.execute(
                        "SELECT COUNT(*) FROM agent_context_events"
                    ).fetchone()[0],
                }
                maintenance_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM store_maintenance_receipts
                    WHERE operation_type = 'capture-ledger-reconciliation'
                    """
                ).fetchone()[0]

        self.assertEqual(audit["status"], "degraded")
        self.assertTrue(audit["repairable"])
        self.assertEqual(repaired["state"], "completed")
        self.assertTrue(repaired["verification_passed"])
        self.assertIsNotNone(row)
        assert row is not None
        for field in (
            "capture_id",
            "protocol",
            "request_fingerprint",
            "context_id",
            "source_tag",
            "speaker",
            "deployment_event_id",
            "entry_count",
            "relationship_count",
        ):
            self.assertEqual(row[field], fixture["original_row"][field])
        self.assertNotEqual(
            row["request_fingerprint"],
            fixture["transport_fingerprint"],
        )
        self.assertEqual(graph_counts, fixture["graph_counts"])
        self.assertFalse(fixture["receipt_path"].exists())
        self.assertEqual(retried["state"], "already-completed")
        self.assertEqual(maintenance_count, 1)

    def test_concurrent_managers_serialize_repair_audit_and_retry(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            primary = fixture["manager"]
            retrying = VerifiedRecoveryManager(
                fixture["backend"].memory_store,
                capture_root=root,
            )
            observing = VerifiedRecoveryManager(
                fixture["backend"].memory_store,
                capture_root=root,
            )
            audit = primary.audit_capture_ledger()
            first_reached_ledger = threading.Event()
            release_first = threading.Event()
            retry_invoked = threading.Event()
            audit_invoked = threading.Event()
            outcomes = {}
            failures = {}

            def hold_first_repair(stage):
                if stage == "after_ledger_1":
                    first_reached_ledger.set()
                    if not release_first.wait(5.0):
                        raise RuntimeError("concurrency test release timed out")

            def run(name, operation, invoked=None):
                if invoked is not None:
                    invoked.set()
                try:
                    outcomes[name] = operation()
                except BaseException as exc:  # pragma: no cover - asserted below
                    failures[name] = exc

            first_thread = threading.Thread(
                target=run,
                args=(
                    "first",
                    lambda: primary.repair_capture_ledger(
                        confirm=True,
                        expected_revision=audit["audit_revision"],
                        fault_hook=hold_first_repair,
                    ),
                ),
                daemon=True,
            )
            retry_thread = threading.Thread(
                target=run,
                args=(
                    "retry",
                    lambda: retrying.repair_capture_ledger(
                        confirm=True,
                        expected_revision=audit["audit_revision"],
                    ),
                    retry_invoked,
                ),
                daemon=True,
            )
            audit_thread = threading.Thread(
                target=run,
                args=("audit", observing.audit_capture_ledger, audit_invoked),
                daemon=True,
            )
            threads = [first_thread, retry_thread, audit_thread]
            first_thread.start()
            try:
                self.assertTrue(first_reached_ledger.wait(5.0))
                retry_thread.start()
                audit_thread.start()
                self.assertTrue(retry_invoked.wait(2.0))
                self.assertTrue(audit_invoked.wait(2.0))
                time.sleep(0.05)
                self.assertTrue(retry_thread.is_alive())
                self.assertTrue(audit_thread.is_alive())
            finally:
                release_first.set()
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(10.0)

            self.assertFalse([thread.name for thread in threads if thread.is_alive()])
            self.assertFalse(failures)
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                ledger_count = conn.execute(
                    "SELECT COUNT(*) FROM capture_operations WHERE capture_id = ?",
                    (fixture["capture_id"],),
                ).fetchone()[0]
                maintenance_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM store_maintenance_receipts
                    WHERE operation_type = 'capture-ledger-reconciliation'
                    """
                ).fetchone()[0]

        self.assertEqual(outcomes["first"]["state"], "completed")
        self.assertEqual(outcomes["retry"]["state"], "already-completed")
        self.assertEqual(
            outcomes["retry"]["operation_id"],
            outcomes["first"]["operation_id"],
        )
        self.assertEqual(outcomes["audit"]["status"], "ready")
        self.assertEqual(ledger_count, 1)
        self.assertEqual(maintenance_count, 1)

    def test_changed_processed_payload_invalidates_reviewed_revision(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            payload = json.loads(
                fixture["processed_path"].read_text(encoding="utf-8")
            )
            payload["metadata"]["post_audit_change"] = True
            fixture["processed_path"].write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            fixture["processed_path"].chmod(0o600)

            with self.assertRaisesRegex(RuntimeError, "plan is stale"):
                fixture["manager"].repair_capture_ledger(
                    confirm=True,
                    expected_revision=audit["audit_revision"],
                )

            self.assertIsNone(self._ledger_row(root, fixture["capture_id"]))
            self.assertEqual(list((root / "backups").glob("*.sqlite3")), [])

    def test_ambiguous_deployment_blocks_repair(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            event_id = int(fixture["original_row"]["deployment_event_id"])
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                conn.row_factory = sqlite3.Row
                event = conn.execute(
                    "SELECT * FROM agent_context_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                assert event is not None
                inserted = conn.execute(
                    """
                    INSERT INTO agent_context_events (
                        context_id, source_surface, event_type, summary,
                        payload_json, agent_targets_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event["context_id"],
                        event["source_surface"],
                        event["event_type"],
                        event["summary"],
                        event["payload_json"],
                        event["agent_targets_json"],
                        float(event["created_at"]) + 1.0,
                    ),
                ).lastrowid
                targets = conn.execute(
                    """
                    SELECT target_kind, target_id, created_at
                    FROM agent_context_event_targets WHERE event_id = ?
                    """,
                    (event_id,),
                ).fetchall()
                conn.executemany(
                    """
                    INSERT INTO agent_context_event_targets (
                        event_id, target_kind, target_id, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    [
                        (
                            inserted,
                            target["target_kind"],
                            target["target_id"],
                            target["created_at"],
                        )
                        for target in targets
                    ],
                )
                conn.commit()

            audit = fixture["manager"].audit_capture_ledger()
            self.assertEqual(audit["status"], "blocked")
            self.assertFalse(audit["repairable"])
            self.assertIn(
                "ambiguous-durable-deployment",
                audit["finding_samples"][0]["reasons"],
            )

    def test_unexpected_maintenance_receipt_trigger_blocks_before_repair(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                conn.executescript(
                    """
                    CREATE TRIGGER fail_capture_reconciliation_receipt
                    BEFORE INSERT ON store_maintenance_receipts
                    WHEN NEW.operation_type = 'capture-ledger-reconciliation'
                    BEGIN
                        SELECT RAISE(ABORT, 'injected reconciliation receipt failure');
                    END;
                    """
                )
                conn.commit()

            with self.assertRaisesRegex(
                RuntimeError,
                "unexpected-trigger",
            ):
                fixture["manager"].repair_capture_ledger(
                    confirm=True,
                    expected_revision=audit["audit_revision"],
                )

            self.assertIsNone(self._ledger_row(root, fixture["capture_id"]))
            backup_dir = root / "backups"
            self.assertEqual(
                list(backup_dir.glob("*pre-capture-ledger-reconciliation*.sqlite3")),
                [],
            )
            self.assertEqual(
                list(
                    backup_dir.glob(
                        "*pre-capture-ledger-reconciliation*.receipt.json"
                    )
                ),
                [],
            )

    def test_noncanonical_evidence_root_can_be_audited_but_never_repairs_db(self):
        with TemporaryDirectory() as tmp:
            canonical_root = Path(tmp) / "canonical"
            canonical_root.mkdir(mode=0o700)
            fixture = self._seed_legacy_gap(canonical_root)
            alternate_root = Path(tmp) / "alternate"
            alternate_root.mkdir(mode=0o700)
            CaptureInboxDaemon(root=alternate_root).status()
            copied = alternate_root / "capture_processed" / fixture[
                "processed_path"
            ].name
            shutil.copy2(fixture["processed_path"], copied)
            copied.chmod(0o600)
            manager = VerifiedRecoveryManager(
                fixture["backend"].memory_store,
                capture_root=alternate_root,
                allow_noncanonical_capture_root=True,
            )

            audit = manager.audit_capture_ledger()
            with self.assertRaisesRegex(ValueError, "canonical memory-store"):
                manager.repair_capture_ledger(
                    confirm=True,
                    expected_revision=audit["audit_revision"],
                )
            ledger_row = self._ledger_row(
                canonical_root,
                fixture["capture_id"],
            )

        self.assertEqual(
            audit["capture_root_provenance"],
            "explicit-noncanonical",
        )
        self.assertTrue(audit["repairable"])
        self.assertIsNone(ledger_row)

    def test_legacy_text_comparison_preserves_word_boundaries(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            event_id = int(fixture["original_row"]["deployment_event_id"])
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                conn.row_factory = sqlite3.Row
                deployment = conn.execute(
                    "SELECT payload_json FROM agent_context_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                assert deployment is not None
                payload = json.loads(str(deployment["payload_json"]))
                memory_id = str(payload["events"][0]["memory_id"])
                source_text = str(payload["events"][0]["segment"]["text"])
                changed_text = source_text.replace(" bounded ", " bounded", 1)
                self.assertNotEqual(changed_text, source_text)
                payload["events"][0]["segment"]["text"] = changed_text
                conn.execute(
                    "UPDATE memory_entries SET source_text = ? WHERE memory_id = ?",
                    (changed_text, memory_id),
                )
                conn.execute(
                    "UPDATE agent_context_events SET payload_json = ? WHERE event_id = ?",
                    (
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        event_id,
                    ),
                )
                conn.commit()

            audit = fixture["manager"].audit_capture_ledger()

        self.assertEqual(audit["status"], "blocked")
        self.assertFalse(audit["repairable"])
        self.assertIn(
            "legacy-capture-text-mismatch",
            audit["finding_samples"][0]["reasons"],
        )

    def test_legacy_request_metadata_must_match_durable_event_metadata(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            payload = json.loads(
                fixture["processed_path"].read_text(encoding="utf-8")
            )
            payload["metadata"]["fixture"] = "changed-after-durable-write"
            fixture["processed_path"].write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            fixture["processed_path"].chmod(0o600)

            audit = fixture["manager"].audit_capture_ledger()

        self.assertEqual(audit["status"], "blocked")
        self.assertFalse(audit["repairable"])
        self.assertIn(
            "legacy-capture-metadata-mismatch",
            audit["finding_samples"][0]["reasons"],
        )

    def test_malformed_capture_ledger_schema_blocks_repair(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                conn.execute("DROP INDEX ix_capture_operations_context_committed")
                conn.commit()

            with self.assertRaisesRegex(RuntimeError, "schema is invalid"):
                fixture["manager"].repair_capture_ledger(
                    confirm=True,
                    expected_revision=audit["audit_revision"],
                )
            ledger_row = self._ledger_row(root, fixture["capture_id"])

        self.assertIsNone(ledger_row)

    def test_safety_backup_failure_leaves_gap_untouched(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            with mock.patch.object(
                fixture["manager"].store,
                "_verified_safety_backup",
                side_effect=OSError("injected safety backup failure"),
            ):
                with self.assertRaisesRegex(OSError, "safety backup failure"):
                    fixture["manager"].repair_capture_ledger(
                        confirm=True,
                        expected_revision=audit["audit_revision"],
                    )
            self.assertIsNone(self._ledger_row(root, fixture["capture_id"]))

    def test_explicit_v2_ledger_loss_requires_verified_restore(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_exact_capture(root)
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                conn.execute(
                    "DELETE FROM capture_operations WHERE capture_id = ?",
                    (fixture["capture_id"],),
                )
                conn.commit()

            audit = fixture["manager"].audit_capture_ledger()

        self.assertEqual(audit["status"], "blocked")
        self.assertFalse(audit["repairable"])
        self.assertEqual(audit["missing_authoritative_ledger_count"], 1)
        self.assertIn(
            "explicit-v2-ledger-loss-requires-verified-restore",
            audit["finding_samples"][0]["reasons"],
        )

    def test_ledger_backed_payload_mutation_blocks_bundle_before_publication(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_exact_capture(root)
            payload = json.loads(
                fixture["processed_path"].read_text(encoding="utf-8")
            )
            payload["metadata"]["tampered_after_commit"] = True
            fixture["processed_path"].write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            fixture["processed_path"].chmod(0o600)
            output = root / "backups" / "verified" / "should-not-exist.sqlite3"

            audit = fixture["manager"].audit_capture_ledger()
            with self.assertRaisesRegex(
                RuntimeError,
                "capture ledger reconciliation is required",
            ):
                fixture["manager"].create_bundle(output)

            publication_journals = list(
                (root / "backups" / "publication-journals").glob(
                    "*.prepared.receipt.json"
                )
            )

        self.assertEqual(audit["status"], "blocked")
        self.assertEqual(audit["ledger_binding_mismatch_count"], 1)
        self.assertFalse(output.exists())
        self.assertEqual(publication_journals, [])

    def test_database_evidence_change_invalidates_reviewed_revision(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                conn.execute(
                    """
                    UPDATE agent_context_events
                    SET summary = summary || ' changed'
                    WHERE event_id = ?
                    """,
                    (int(fixture["original_row"]["deployment_event_id"]),),
                )
                conn.commit()

            with self.assertRaisesRegex(RuntimeError, "plan is stale"):
                fixture["manager"].repair_capture_ledger(
                    confirm=True,
                    expected_revision=audit["audit_revision"],
                )

            self.assertIsNone(self._ledger_row(root, fixture["capture_id"]))
            self.assertEqual(
                list(
                    (root / "backups").glob(
                        "*pre-capture-ledger-reconciliation*.sqlite3"
                    )
                ),
                [],
            )

    def test_mid_repair_fault_rolls_back_ledger_and_receipt(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()

            def fail_after_ledger(stage: str):
                if stage == "after_ledger_1":
                    raise RuntimeError("injected mid-repair failure")

            with self.assertRaisesRegex(RuntimeError, "mid-repair failure"):
                fixture["manager"].repair_capture_ledger(
                    confirm=True,
                    expected_revision=audit["audit_revision"],
                    fault_hook=fail_after_ledger,
                )

            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                receipt_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM store_maintenance_receipts
                    WHERE operation_type = 'capture-ledger-reconciliation'
                    """
                ).fetchone()[0]

            self.assertIsNone(self._ledger_row(root, fixture["capture_id"]))
            self.assertEqual(receipt_count, 0)
            self.assertEqual(
                list(
                    (root / "backups").glob(
                        "*pre-capture-ledger-reconciliation*.sqlite3"
                    )
                ),
                [],
            )

    def test_repaired_capture_replays_idempotently_without_graph_change(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            fixture["manager"].repair_capture_ledger(
                confirm=True,
                expected_revision=audit["audit_revision"],
            )
            payload = json.loads(
                fixture["processed_path"].read_text(encoding="utf-8")
            )
            normalized = fixture["manager"].daemon._normalize_payload_before_capture(
                path=fixture["processed_path"],
                payload=payload,
                version=2,
            )
            request = fixture["manager"].daemon._canonical_capture_request(
                normalized
            )

            replay = fixture["backend"].capture_conversation(**request)
            with closing(sqlite3.connect(root / "memory.sqlite3")) as conn:
                graph_counts = {
                    "entries": conn.execute(
                        "SELECT COUNT(*) FROM memory_entries"
                    ).fetchone()[0],
                    "relationships": conn.execute(
                        "SELECT COUNT(*) FROM memory_relationships"
                    ).fetchone()[0],
                    "deployments": conn.execute(
                        "SELECT COUNT(*) FROM agent_context_events"
                    ).fetchone()[0],
                }

        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(graph_counts, fixture["graph_counts"])

    def test_repaired_legacy_capture_has_stable_bundle_and_restore_binding_proof(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            fixture["manager"].repair_capture_ledger(
                confirm=True,
                expected_revision=audit["audit_revision"],
            )
            bundle = fixture["manager"].create_bundle(
                root / "backups" / "verified" / "legacy-repaired.sqlite3",
                purpose="legacy-reconciliation-proof",
            )
            verified_once = fixture["manager"].verify_bundle(
                bundle["bundle_receipt_path"]
            )
            verified_twice = fixture["manager"].verify_bundle(
                bundle["bundle_receipt_path"]
            )
            restored = fixture["manager"].restore_bundle_isolated(
                bundle["bundle_receipt_path"],
                root / "isolated-proof",
                confirm=True,
            )
            proof = json.loads(
                Path(restored["recovery_proof_path"]).read_text(
                    encoding="utf-8"
                )
            )

        binding = verified_once["capture_ledger_binding"]
        self.assertTrue(binding["verified"])
        self.assertEqual(binding["verified_capture_count"], 1)
        self.assertEqual(
            binding,
            verified_twice["capture_ledger_binding"],
        )
        self.assertEqual(binding, restored["capture_ledger_binding"])
        self.assertEqual(binding, proof["capture_ledger_binding"])
        self.assertTrue(verified_once["cutover_ready"])
        self.assertTrue(restored["cutover_ready"])
        rendered_binding = json.dumps(binding, sort_keys=True)
        self.assertNotIn("request_fingerprint", rendered_binding)
        self.assertNotIn("relative_path", rendered_binding)
        self.assertNotIn("metadata", rendered_binding)

    def test_public_audit_does_not_expose_private_evidence_digests_or_paths(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = self._seed_legacy_gap(root)
            audit = fixture["manager"].audit_capture_ledger()
            serialized = json.dumps(audit, sort_keys=True)

        self.assertNotIn("file_sha256", serialized)
        self.assertNotIn("request_fingerprint", serialized)
        self.assertNotIn("relative_path", serialized)
        self.assertNotIn(fixture["processed_path"].name, serialized)
        self.assertNotIn(str(root), serialized)


if __name__ == "__main__":
    unittest.main()

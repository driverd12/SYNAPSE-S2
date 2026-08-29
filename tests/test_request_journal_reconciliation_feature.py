from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import sqlite3
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import mcp_server
import synapse_cli
from core_client import CoreClient
from core_service import AuthoritativeCoreService, CORE_OPERATION_CONTRACTS, CoreConfig
from dashboard_server import DashboardRuntime
from memory_store import (
    DurableMemoryStore,
    REQUEST_JOURNAL_RECONCILIATION_MAX_RECEIPTS,
    RequestJournalReconciliationRejected,
)
from recovery_manager import VerifiedRecoveryManager
from replication_manager import ReplicationManager
from tests.test_core_service import FakeBackend


_RECONCILIATION_CONTRACTS = {
    name: CORE_OPERATION_CONTRACTS[name]
    for name in (
        "health",
        "request_status",
        "request_journal_inventory",
        "reconcile_request_journal",
    )
}


class _TemporaryReconciliationService:
    """A real governed core backed only by disposable test paths."""

    def __init__(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state_root = self.root / "state"
        self.state_root.mkdir(mode=0o700)
        os.chmod(self.state_root, 0o700)
        self.config = CoreConfig(
            socket_path=self.state_root / "core" / "service.sock",
            state_path=self.state_root / "runtime_state.json",
            memory_path=self.state_root / "memory.sqlite3",
            capture_root=None,
            dimension=8,
            num_neurons=8,
            default_top_k=4,
            recall_count=2,
            authority_timeout_seconds=0.0,
        )
        self.backend = FakeBackend()
        self.service = AuthoritativeCoreService(
            self.config,
            backend_factory=lambda lease: self.backend.attach_memory_store(
                DurableMemoryStore(
                    self.config.memory_path,
                    authority_lease=lease,
                )
            ),
            operation_contracts=_RECONCILIATION_CONTRACTS,
            operation_handlers_factory=lambda _backend: {},
        )
        self.thread = threading.Thread(
            target=self.service.serve_forever,
            name="test-request-journal-reconciliation-core",
            daemon=True,
        )
        self.thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self.service._started_event.is_set():
                break
            time.sleep(0.01)
        if not self.service._started_event.is_set():
            raise AssertionError("temporary reconciliation core did not start")

    def client(self, *, caller: str = "reconciliation-test-client") -> CoreClient:
        return CoreClient(
            socket_path=self.config.socket_path,
            caller=caller,
            default_timeout_seconds=5.0,
        )

    def add_explicit_ambiguous_request(
        self,
        *,
        caller: str = "source-client",
        request_id: str = "source-request",
        operation: str = "commit_cortical_trace",
    ) -> None:
        journal = self.service._request_journal
        if journal is None:
            raise AssertionError("temporary request journal is unavailable")
        fingerprint = hashlib.sha256(
            f"{caller}:{request_id}:{operation}".encode("utf-8")
        ).hexdigest()
        decision = journal.accept(
            caller=caller,
            request_id=request_id,
            operation=operation,
            request_fingerprint=fingerprint,
        )
        if decision.disposition != "accepted":
            raise AssertionError("ambiguous test request was not newly admitted")
        journal.finish(
            caller=caller,
            request_id=request_id,
            operation=operation,
            request_fingerprint=fingerprint,
            result=None,
            safe_error_code="outcome_unknown",
        )

    def close(self) -> None:
        self.service.close()
        self.thread.join(timeout=3.0)
        self.temporary.cleanup()


class RequestJournalReconciliationFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _TemporaryReconciliationService()
        self.addCleanup(self.harness.close)
        self.harness.add_explicit_ambiguous_request()

    @staticmethod
    def _reconciliation_arguments(item: dict, inventory: dict) -> dict:
        return {
            "target_caller": item["caller"],
            "target_request_id": item["request_id"],
            "expected_operation": item["operation"],
            "expected_authority_epoch": item["authority_epoch"],
            "expected_entry_revision": item["entry_revision"],
            "expected_journal_id": inventory["journal_id"],
            "inventory_snapshot_revision": inventory["reconciliation_guard"][
                "snapshot_revision"
            ],
            "disposition": "confirmed_no_effect",
            "evidence_kind": "authoritative_no_effect_readback",
            "evidence_sha256": hashlib.sha256(
                b"content-free-authoritative-no-effect-readback"
            ).hexdigest(),
            "confirm": True,
        }

    def test_service_reconciliation_preserves_raw_ambiguity_and_never_replays(
        self,
    ) -> None:
        client = self.harness.client()
        before_health = client.health()["request_journal"]
        inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        self.assertEqual(inventory["pagination"]["total"], 1)
        self.assertEqual(len(inventory["items"]), 1)
        candidate = inventory["items"][0]
        self.assertEqual(candidate["state"], "ambiguous")
        self.assertTrue(candidate["reconciliation_eligible"])
        self.assertFalse(candidate["replay_safe"])
        self.assertEqual(candidate["reconciliation"]["status"], "unresolved")
        self.assertNotEqual(
            inventory["snapshot_revision"],
            inventory["reconciliation_guard"]["snapshot_revision"],
        )

        arguments = self._reconciliation_arguments(candidate, inventory)
        first = client.reconcile_request_journal(
            **arguments,
            request_id="reconcile-source-request-first",
        )
        second = client.reconcile_request_journal(
            **arguments,
            request_id="reconcile-source-request-idempotent",
        )

        self.assertEqual(first["status"], "reconciled")
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["resolution_id"], first["resolution_id"])
        self.assertEqual(second["receipt_digest"], first["receipt_digest"])
        self.assertTrue(first["signature_verified"])
        self.assertTrue(first["original_journal_state_preserved"])
        self.assertFalse(first["replay_safe"])

        after_inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
            expected_snapshot_revision=inventory["snapshot_revision"],
        )
        self.assertEqual(
            after_inventory["snapshot_revision"],
            inventory["snapshot_revision"],
        )
        self.assertEqual(after_inventory["pagination"]["total"], 1)
        reconciled = after_inventory["items"][0]
        self.assertEqual(reconciled["state"], "ambiguous")
        self.assertFalse(reconciled["reconciliation_eligible"])
        self.assertEqual(reconciled["reconciliation"]["status"], "reconciled")
        self.assertTrue(reconciled["reconciliation"]["signature_verified"])
        self.assertFalse(reconciled["reconciliation"]["replay_safe"])
        self.assertEqual(
            after_inventory["reconciliation_summary"]["record_count"],
            1,
        )

        status = client.request_status(
            caller=candidate["caller"],
            request_id=candidate["request_id"],
        )
        self.assertTrue(status["known"])
        self.assertEqual(status["state"], "ambiguous")
        self.assertEqual(status["safe_error_code"], "outcome_unknown")
        self.assertFalse(status["replay_safe"])

        after_health = client.health()["request_journal"]
        self.assertEqual(before_health["explicit_ambiguous_count"], 1)
        self.assertEqual(after_health["explicit_ambiguous_count"], 1)
        self.assertEqual(after_health["reconciliation_record_count"], 1)
        self.assertEqual(after_health["reconciled_explicit_ambiguous_count"], 1)
        self.assertEqual(after_health["unresolved_explicit_ambiguous_count"], 0)
        self.assertTrue(after_health["reconciliation_signatures_verified"])
        self.assertEqual(
            after_health["accepted_capacity_remaining"],
            before_health["accepted_capacity_remaining"],
        )
        self.assertLess(
            after_health["accepted_capacity_remaining"],
            after_health["max_accepted_rows"],
        )
        self.assertEqual(after_health["used_rows"], before_health["used_rows"] + 2)
        self.assertEqual(
            after_health["remaining_rows"],
            before_health["remaining_rows"] - 2,
        )

    def test_paired_recovery_verifies_snapshot_containing_signed_receipt(
        self,
    ) -> None:
        client = self.harness.client(caller="paired-recovery-test-client")
        inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        candidate = inventory["items"][0]
        receipt = client.reconcile_request_journal(
            **self._reconciliation_arguments(candidate, inventory),
            request_id="reconcile-before-paired-recovery",
        )
        self.assertTrue(receipt["signature_verified"])

        store = self.harness.backend.memory_store
        self.assertIsNotNone(store)
        assert store is not None
        live_receipts = store.request_journal_reconciliation_inventory(
            request_journal_id=inventory["journal_id"],
            store_identity=inventory["store_identity"],
        )
        self.assertEqual(live_receipts["count"], 1)
        self.assertEqual(
            live_receipts["items"][0]["receipt_digest"],
            receipt["receipt_digest"],
        )

        manager = VerifiedRecoveryManager(
            store,
            capture_root=self.harness.state_root,
        )
        backup_root = self.harness.state_root / "backups" / "reconciliation-test"
        backup_root.mkdir(parents=True, mode=0o700)
        os.chmod(backup_root, 0o700)
        bundle = manager.create_bundle(
            backup_root / "pre-cleanup-reconciliation.sqlite3",
            purpose="request-journal-reconciliation-test",
            pinned=True,
        )
        verified = manager.verify_bundle(bundle["bundle_receipt_path"])

        self.assertTrue(bundle["bundle_verified"])
        self.assertTrue(verified["verified"])
        self.assertTrue(verified["database"]["verified"])
        self.assertEqual(
            verified["database"][
                "request_journal_reconciliation_receipt_count"
            ],
            1,
        )
        self.assertTrue(
            verified["database"][
                "request_journal_reconciliation_signatures_verified"
            ]
        )
        self.assertEqual(
            verified["database"]["secret_audit"][
                "redaction_changing_cell_count"
            ],
            0,
        )
        self.assertEqual(
            verified["database"]["secret_audit"][
                "raw_digest_changing_cell_count"
            ],
            0,
        )
        self.assertEqual(
            verified["database"]["logical_snapshot_sha256"],
            bundle["logical_snapshot_sha256"],
        )
        self.assertTrue(verified["request_journal"]["verified"])
        self.assertEqual(
            verified["request_journal_reconciliation"]["receipt_count"],
            1,
        )
        self.assertTrue(
            verified["request_journal_reconciliation"][
                "source_row_bindings_verified"
            ]
        )
        self.assertFalse(
            verified["request_journal_reconciliation"][
                "generic_replay_authorized"
            ]
        )
        self.assertTrue(verified["runtime_state"]["verified"])

    def test_recovery_rejects_signed_receipt_without_source_row(self) -> None:
        client = self.harness.client(caller="orphan-receipt-test-client")
        inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        store = self.harness.backend.memory_store
        assert store is not None
        store.reconcile_request_journal(
            request_journal_id=inventory["journal_id"],
            store_identity=inventory["store_identity"],
            target_caller="missing-source-client",
            target_request_id="missing-source-request",
            target_operation="cortex_tick",
            target_authority_epoch=inventory["items"][0]["authority_epoch"],
            target_original_state="ambiguous",
            target_entry_revision="1" * 64,
            inventory_snapshot_revision=inventory["reconciliation_guard"][
                "snapshot_revision"
            ],
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="2" * 64,
            reconciled_by="core:local-owner:" + ("3" * 24),
            confirm=True,
        )

        health = client.health()["request_journal"]
        self.assertFalse(health["ready"])
        self.assertEqual(
            health["blocker"],
            "request_journal_reconciliation_invalid",
        )
        manager = VerifiedRecoveryManager(
            store,
            capture_root=self.harness.state_root,
        )
        backup_root = self.harness.state_root / "backups" / "orphan-receipt"
        backup_root.mkdir(parents=True, mode=0o700)
        os.chmod(backup_root, 0o700)
        with self.assertRaisesRegex(
            RuntimeError,
            "request-journal reconciliation source row is missing",
        ):
            manager.create_bundle(
                backup_root / "orphan-receipt.sqlite3",
                purpose="orphan-request-journal-reconciliation-test",
                pinned=True,
            )

    def test_only_active_receive_peer_keys_extend_receipt_trust(self) -> None:
        peer_key = "a" * 64
        manager = ReplicationManager.__new__(ReplicationManager)
        manager.ledger = SimpleNamespace(
            peers_for_integrity=lambda: [
                {
                    "direction": "receive",
                    "revoked": 0,
                    "signing_key_id": peer_key,
                },
                {
                    "direction": "send",
                    "revoked": 0,
                    "signing_key_id": "b" * 64,
                },
                {
                    "direction": "receive",
                    "revoked": 1,
                    "signing_key_id": "c" * 64,
                },
            ]
        )
        self.assertEqual(
            manager._active_receive_peer_signing_key_ids(),
            (peer_key,),
        )

    def test_unrelated_self_signed_receipt_blocks_health_and_backup(self) -> None:
        client = self.harness.client(caller="untrusted-receipt-test-client")
        inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        candidate = inventory["items"][0]
        arguments = self._reconciliation_arguments(candidate, inventory)
        foreign_store = DurableMemoryStore(
            self.harness.root / "foreign-signer" / "memory.sqlite3"
        )
        self.addCleanup(foreign_store.close)
        foreign = foreign_store.reconcile_request_journal(
            request_journal_id=inventory["journal_id"],
            store_identity=inventory["store_identity"],
            target_caller=arguments["target_caller"],
            target_request_id=arguments["target_request_id"],
            target_operation=arguments["expected_operation"],
            target_authority_epoch=arguments["expected_authority_epoch"],
            target_original_state="ambiguous",
            target_entry_revision=arguments["expected_entry_revision"],
            inventory_snapshot_revision=arguments[
                "inventory_snapshot_revision"
            ],
            disposition=arguments["disposition"],
            evidence_kind=arguments["evidence_kind"],
            evidence_sha256=arguments["evidence_sha256"],
            reconciled_by="core:local-owner:" + ("f" * 24),
            confirm=True,
        )
        with closing(sqlite3.connect(foreign_store.db_path)) as conn:
            row = conn.execute(
                "SELECT operation_id, operation_type, context_id, "
                "before_revision, after_revision, payload_json, created_at "
                "FROM store_maintenance_receipts WHERE operation_id = ?",
                (foreign["resolution_id"],),
            ).fetchone()
        live_store = self.harness.backend.memory_store
        assert live_store is not None
        with closing(sqlite3.connect(live_store.db_path)) as conn:
            conn.execute(
                "INSERT INTO store_maintenance_receipts ("
                "operation_id, operation_type, context_id, before_revision, "
                "after_revision, payload_json, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                row,
            )
            conn.commit()

        health = client.health()["request_journal"]
        self.assertFalse(health["ready"])
        self.assertEqual(
            health["blocker"],
            "request_journal_reconciliation_invalid",
        )
        with self.assertRaises(RuntimeError):
            live_store.backup(purpose="untrusted-reconciliation-receipt")

    def test_foreign_authority_binding_is_not_silently_ignored(self) -> None:
        store = self.harness.backend.memory_store
        assert store is not None
        store.reconcile_request_journal(
            request_journal_id="journal-" + ("1" * 24),
            store_identity="store-" + ("2" * 24),
            target_caller="foreign-client",
            target_request_id="foreign-request",
            target_operation="cortex_tick",
            target_authority_epoch="foreign-epoch",
            target_original_state="ambiguous",
            target_entry_revision="3" * 64,
            inventory_snapshot_revision="4" * 64,
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="5" * 64,
            reconciled_by="core:local-owner:" + ("6" * 24),
            confirm=True,
        )
        health = self.harness.client().health()["request_journal"]
        self.assertFalse(health["ready"])
        self.assertEqual(
            health["blocker"],
            "request_journal_reconciliation_invalid",
        )

    def test_local_receipt_does_not_depend_on_replication_provider(self) -> None:
        client = self.harness.client(caller="local-receipt-trust-test")
        inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        client.reconcile_request_journal(
            **self._reconciliation_arguments(inventory["items"][0], inventory),
            request_id="reconcile-before-provider-failure",
        )
        store = self.harness.backend.memory_store
        assert store is not None

        def unavailable_provider():
            raise RuntimeError("replication ledger unavailable")

        store.set_request_journal_reconciliation_trusted_key_provider(
            unavailable_provider
        )
        health = client.health()["request_journal"]
        self.assertTrue(health["ready"])
        backup = store.backup(purpose="local-reconciliation-trust")
        self.assertTrue(backup["verified"])
        self.assertEqual(
            backup["request_journal_reconciliation_receipt_count"],
            1,
        )

    def test_zero_receipts_do_not_load_keys_or_peer_trust(self) -> None:
        inventory = self.harness.client().request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        store = self.harness.backend.memory_store
        assert store is not None

        def unavailable_provider() -> tuple[str, ...]:
            raise RuntimeError("replication ledger unavailable")

        store.set_request_journal_reconciliation_trusted_key_provider(
            unavailable_provider
        )
        with mock.patch.object(
            store,
            "_backup_receipt_signing_key",
            side_effect=RuntimeError("recovery key unavailable"),
        ):
            receipts = store.request_journal_reconciliation_inventory(
                request_journal_id=inventory["journal_id"],
                store_identity=inventory["store_identity"],
            )
        self.assertEqual(receipts["count"], 0)

    def test_exact_signature_cache_skips_repeat_ed25519_verification(self) -> None:
        client = self.harness.client(caller="signature-cache-test-client")
        inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        client.reconcile_request_journal(
            **self._reconciliation_arguments(inventory["items"][0], inventory),
            request_id="reconcile-before-signature-cache-test",
        )
        store = self.harness.backend.memory_store
        assert store is not None
        with store._receipt_signature_cache_lock:
            store._receipt_signature_cache.clear()
        first = store.request_journal_reconciliation_inventory(
            request_journal_id=inventory["journal_id"],
            store_identity=inventory["store_identity"],
        )
        self.assertEqual(first["count"], 1)
        with mock.patch(
            "memory_store.Ed25519PublicKey.from_public_bytes",
            side_effect=AssertionError("cached signature was reverified"),
        ):
            second = store.request_journal_reconciliation_inventory(
                request_journal_id=inventory["journal_id"],
                store_identity=inventory["store_identity"],
            )
        self.assertEqual(second, first)

    def test_peer_trust_provider_is_frozen_once_per_inventory(self) -> None:
        inventory = self.harness.client().request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        live_store = self.harness.backend.memory_store
        assert live_store is not None
        local_receipt = live_store.reconcile_request_journal(
            request_journal_id=inventory["journal_id"],
            store_identity=inventory["store_identity"],
            target_caller="local-source-client",
            target_request_id="local-source-request",
            target_operation="cortex_tick",
            target_authority_epoch=inventory["items"][0]["authority_epoch"],
            target_original_state="ambiguous",
            target_entry_revision="8" * 64,
            inventory_snapshot_revision=inventory["reconciliation_guard"][
                "snapshot_revision"
            ],
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="9" * 64,
            reconciled_by="core:local-owner:" + ("a" * 24),
            confirm=True,
        )
        foreign_store = DurableMemoryStore(
            self.harness.root / "peer-signer" / "memory.sqlite3"
        )
        self.addCleanup(foreign_store.close)
        resolution_ids: list[str] = []
        peer_key_id = ""
        for index in range(2):
            receipt = foreign_store.reconcile_request_journal(
                request_journal_id=inventory["journal_id"],
                store_identity=inventory["store_identity"],
                target_caller=f"peer-source-client-{index}",
                target_request_id=f"peer-source-request-{index}",
                target_operation="cortex_tick",
                target_authority_epoch=inventory["items"][0][
                    "authority_epoch"
                ],
                target_original_state="ambiguous",
                target_entry_revision=f"{index + 3:x}" * 64,
                inventory_snapshot_revision=inventory[
                    "reconciliation_guard"
                ]["snapshot_revision"],
                disposition="confirmed_no_effect",
                evidence_kind="authoritative_no_effect_readback",
                evidence_sha256=f"{index + 5:x}" * 64,
                reconciled_by="core:peer-owner:" + ("7" * 24),
                confirm=True,
            )
            resolution_ids.append(receipt["resolution_id"])
            peer_key_id = receipt["auth_key_id"]

        with closing(sqlite3.connect(foreign_store.db_path)) as source:
            rows = source.execute(
                "SELECT operation_id, operation_type, context_id, "
                "before_revision, after_revision, payload_json, created_at "
                "FROM store_maintenance_receipts WHERE operation_id IN (?, ?) "
                "ORDER BY operation_id",
                tuple(resolution_ids),
            ).fetchall()
        with closing(sqlite3.connect(live_store.db_path)) as destination:
            destination.executemany(
                "INSERT INTO store_maintenance_receipts ("
                "operation_id, operation_type, context_id, before_revision, "
                "after_revision, payload_json, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            destination.commit()

        provider_calls = 0

        def trusted_peer_keys() -> tuple[str, ...]:
            nonlocal provider_calls
            provider_calls += 1
            return (peer_key_id,)

        live_store.set_request_journal_reconciliation_trusted_key_provider(
            trusted_peer_keys
        )
        with mock.patch.object(
            live_store,
            "_backup_receipt_signing_key",
            wraps=live_store._backup_receipt_signing_key,
        ) as signing_key_read:
            receipts = live_store.request_journal_reconciliation_inventory(
                request_journal_id=inventory["journal_id"],
                store_identity=inventory["store_identity"],
            )
        self.assertEqual(receipts["count"], 3)
        self.assertEqual(provider_calls, 1)
        self.assertEqual(signing_key_read.call_count, 1)
        self.assertEqual(
            {item["auth_key_id"] for item in receipts["items"]},
            {local_receipt["auth_key_id"], peer_key_id},
        )

    def test_receipt_cap_preserves_idempotence_and_rejects_new_target(
        self,
    ) -> None:
        client = self.harness.client(caller="receipt-cap-test-client")
        inventory = client.request_journal_inventory(
            states=["ambiguous"],
            limit=10,
        )
        candidate = inventory["items"][0]
        arguments = self._reconciliation_arguments(candidate, inventory)
        store = self.harness.backend.memory_store
        assert store is not None
        first = store.reconcile_request_journal(
            request_journal_id=inventory["journal_id"],
            store_identity=inventory["store_identity"],
            target_caller=arguments["target_caller"],
            target_request_id=arguments["target_request_id"],
            target_operation=arguments["expected_operation"],
            target_authority_epoch=arguments["expected_authority_epoch"],
            target_original_state="ambiguous",
            target_entry_revision=arguments["expected_entry_revision"],
            inventory_snapshot_revision=arguments[
                "inventory_snapshot_revision"
            ],
            disposition=arguments["disposition"],
            evidence_kind=arguments["evidence_kind"],
            evidence_sha256=arguments["evidence_sha256"],
            reconciled_by="core:local-owner:" + ("c" * 24),
            confirm=True,
        )
        with closing(sqlite3.connect(store.db_path)) as conn:
            row = conn.execute(
                "SELECT payload_json FROM store_maintenance_receipts "
                "WHERE operation_id = ?",
                (first["resolution_id"],),
            ).fetchone()
        self.assertIsNotNone(row)
        existing = json.loads(str(row[0]))
        capped_receipts = [existing]
        capped_receipts.extend(
            {
                "target_caller": f"other-caller-{index}",
                "target_request_id": f"other-request-{index}",
            }
            for index in range(
                REQUEST_JOURNAL_RECONCILIATION_MAX_RECEIPTS - 1
            )
        )

        def capped_rows(*_args, **kwargs):
            if kwargs.get("operation_id") is not None:
                return [existing]
            return capped_receipts

        with mock.patch.object(
            store,
            "_request_journal_reconciliation_rows",
            side_effect=capped_rows,
        ):
            repeated = store.reconcile_request_journal(
                request_journal_id=inventory["journal_id"],
                store_identity=inventory["store_identity"],
                target_caller=arguments["target_caller"],
                target_request_id=arguments["target_request_id"],
                target_operation=arguments["expected_operation"],
                target_authority_epoch=arguments["expected_authority_epoch"],
                target_original_state="ambiguous",
                target_entry_revision=arguments["expected_entry_revision"],
                inventory_snapshot_revision=arguments[
                    "inventory_snapshot_revision"
                ],
                disposition=arguments["disposition"],
                evidence_kind=arguments["evidence_kind"],
                evidence_sha256=arguments["evidence_sha256"],
                reconciled_by="core:local-owner:" + ("c" * 24),
                confirm=True,
            )
            self.assertTrue(repeated["idempotent"])
            with self.assertRaisesRegex(
                RequestJournalReconciliationRejected,
                "receipt capacity is exhausted",
            ):
                store.reconcile_request_journal(
                    request_journal_id=inventory["journal_id"],
                    store_identity=inventory["store_identity"],
                    target_caller="new-source-client",
                    target_request_id="new-source-request",
                    target_operation=arguments["expected_operation"],
                    target_authority_epoch=arguments[
                        "expected_authority_epoch"
                    ],
                    target_original_state="ambiguous",
                    target_entry_revision="f" * 64,
                    inventory_snapshot_revision=arguments[
                        "inventory_snapshot_revision"
                    ],
                    disposition=arguments["disposition"],
                    evidence_kind=arguments["evidence_kind"],
                    evidence_sha256="a" * 64,
                    reconciled_by="core:local-owner:" + ("c" * 24),
                    confirm=True,
                )


class RequestJournalReconciliationSurfaceTests(unittest.TestCase):
    @staticmethod
    def _client_reconciliation_arguments() -> dict:
        return {
            "target_caller": "source-client",
            "target_request_id": "source-request",
            "expected_operation": "commit_cortical_trace",
            "expected_authority_epoch": "epoch-1",
            "expected_entry_revision": "b" * 64,
            "expected_journal_id": "journal-" + "c" * 24,
            "inventory_snapshot_revision": "d" * 64,
            "disposition": "confirmed_no_effect",
            "evidence_kind": "authoritative_no_effect_readback",
            "evidence_sha256": "e" * 64,
            "confirm": True,
        }

    def test_core_client_requires_and_preserves_predeclared_outer_request_id(
        self,
    ) -> None:
        signature = inspect.signature(CoreClient.reconcile_request_journal)
        self.assertIs(
            signature.parameters["request_id"].default,
            inspect.Parameter.empty,
        )
        with TemporaryDirectory() as temporary:
            client = CoreClient(
                socket_path=Path(temporary) / "core" / "service.sock",
                state_path=Path(temporary) / "runtime_state.json",
                caller="request-id-contract-test",
            )
            client.call = mock.Mock(return_value={"status": "reconciled"})
            arguments = self._client_reconciliation_arguments()

            with self.assertRaisesRegex(ValueError, "predeclared request_id"):
                client.reconcile_request_journal(**arguments, request_id="")
            with self.assertRaisesRegex(ValueError, "predeclared request_id"):
                client.reconcile_request_journal(**arguments, request_id="   ")
            result = client.reconcile_request_journal(
                **arguments,
                request_id="reconcile-client-exact-target",
            )

        self.assertEqual(result["status"], "reconciled")
        client.call.assert_called_once()
        self.assertEqual(
            client.call.call_args.kwargs["request_id"],
            "reconcile-client-exact-target",
        )

    def test_cli_parser_and_command_require_nonempty_outer_request_id(
        self,
    ) -> None:
        base = [
            "request-journal-reconcile",
            "--caller",
            "source-client",
            "--request-id",
            "source-request",
            "--expected-operation",
            "commit_cortical_trace",
            "--expected-authority-epoch",
            "epoch-1",
            "--expected-entry-revision",
            "b" * 64,
            "--expected-journal-id",
            "journal-" + "c" * 24,
            "--inventory-snapshot-revision",
            "d" * 64,
            "--disposition",
            "confirmed_no_effect",
            "--evidence-kind",
            "authoritative_no_effect_readback",
            "--evidence-sha256",
            "e" * 64,
            "--confirm",
        ]
        parser = synapse_cli.build_parser()
        with self.assertRaises(synapse_cli.SafeArgumentParseError):
            parser.parse_args(base)

        rejected = SimpleNamespace(
            caller="source-client",
            request_id="source-request",
            expected_operation="commit_cortical_trace",
            expected_authority_epoch="epoch-1",
            expected_entry_revision="b" * 64,
            expected_journal_id="journal-" + "c" * 24,
            inventory_snapshot_revision="d" * 64,
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="e" * 64,
            confirm=True,
            core_request_id="",
        )
        with (
            mock.patch.object(synapse_cli, "build_backend") as build_backend,
            self.assertRaisesRegex(ValueError, "--core-request-id"),
        ):
            synapse_cli.command_request_journal_reconcile(rejected)
        build_backend.assert_not_called()

        accepted = parser.parse_args(
            [
                *base,
                "--core-request-id",
                "reconcile-cli-predeclared",
            ]
        )
        self.assertEqual(
            accepted.core_request_id,
            "reconcile-cli-predeclared",
        )

    def test_mcp_requires_outer_request_id_and_disallows_blind_retry_hint(
        self,
    ) -> None:
        signature = inspect.signature(mcp_server.reconcile_core_request_journal)
        self.assertIs(
            signature.parameters["core_request_id"].default,
            inspect.Parameter.empty,
        )

        client = mock.Mock()
        with mock.patch.object(
            mcp_server.CoreClient,
            "from_environment",
            return_value=client,
        ):
            rejected = json.loads(
                mcp_server.reconcile_core_request_journal(
                    caller="source-client",
                    request_id="source-request",
                    expected_operation="commit_cortical_trace",
                    expected_authority_epoch="epoch-1",
                    expected_entry_revision="b" * 64,
                    expected_journal_id="journal-" + "c" * 24,
                    inventory_snapshot_revision="d" * 64,
                    disposition="confirmed_no_effect",
                    evidence_kind="authoritative_no_effect_readback",
                    evidence_sha256="e" * 64,
                    core_request_id="",
                    confirm=True,
                )
            )
        self.assertIn("error", rejected)
        client.reconcile_request_journal.assert_not_called()

        async def inspect_tools():
            return {tool.name: tool for tool in await mcp_server.mcp.list_tools()}

        tools = asyncio.run(inspect_tools())
        reconciliation_tool = tools["reconcile_core_request_journal"]
        annotation = reconciliation_tool.annotations
        self.assertIn(
            "core_request_id",
            reconciliation_tool.parameters["required"],
        )
        self.assertFalse(annotation.readOnlyHint)
        self.assertFalse(annotation.idempotentHint)

    def test_cli_inventory_and_reconcile_forward_only_reviewed_contract_fields(
        self,
    ) -> None:
        backend = mock.Mock()
        backend.request_journal_inventory.return_value = {"read_only": True}
        backend.reconcile_request_journal.return_value = {"status": "reconciled"}
        inventory_args = SimpleNamespace(
            journal_states=["ambiguous"],
            caller="source-client",
            operation="commit_cortical_trace",
            limit=10,
            after_caller=None,
            after_request_id=None,
            expected_snapshot_revision="a" * 64,
        )
        reconcile_args = SimpleNamespace(
            caller="source-client",
            request_id="source-request",
            expected_operation="commit_cortical_trace",
            expected_authority_epoch="epoch-1",
            expected_entry_revision="b" * 64,
            expected_journal_id="journal-" + "c" * 24,
            inventory_snapshot_revision="d" * 64,
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="e" * 64,
            confirm=True,
            core_request_id="reconcile-cli-exact-target",
        )

        with mock.patch.object(
            synapse_cli,
            "build_backend",
            return_value=backend,
        ) as build_backend:
            inventory = synapse_cli.command_request_journal_inventory(
                inventory_args
            )
            reconciled = synapse_cli.command_request_journal_reconcile(
                reconcile_args
            )

        self.assertTrue(inventory["read_only"])
        self.assertEqual(reconciled["status"], "reconciled")
        self.assertEqual(
            build_backend.call_args_list,
            [mock.call(inventory_args), mock.call(reconcile_args)],
        )
        backend.request_journal_inventory.assert_called_once_with(
            states=["ambiguous"],
            caller="source-client",
            operation="commit_cortical_trace",
            limit=10,
            after_caller=None,
            after_request_id=None,
            expected_snapshot_revision="a" * 64,
        )
        backend.reconcile_request_journal.assert_called_once_with(
            target_caller="source-client",
            target_request_id="source-request",
            expected_operation="commit_cortical_trace",
            expected_authority_epoch="epoch-1",
            expected_entry_revision="b" * 64,
            expected_journal_id="journal-" + "c" * 24,
            inventory_snapshot_revision="d" * 64,
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="e" * 64,
            confirm=True,
            request_id="reconcile-cli-exact-target",
        )

    def test_mcp_inventory_and_reconcile_preserve_explicit_transport_handle(
        self,
    ) -> None:
        client = mock.Mock()
        client.request_journal_inventory.return_value = {
            "schema": "synapse-s2.request-journal-inventory.v1",
            "read_only": True,
        }
        client.reconcile_request_journal.return_value = {
            "schema": "synapse-s2.request-journal-reconciliation-result.v1",
            "status": "reconciled",
            "replay_safe": False,
        }
        with mock.patch.object(
            mcp_server.CoreClient,
            "from_environment",
            return_value=client,
        ):
            inventory = json.loads(
                mcp_server.list_core_request_journal(
                    states=["ambiguous"],
                    caller=" source-client ",
                    operation=" commit_cortical_trace ",
                    limit=10,
                    expected_snapshot_revision="a" * 64,
                )
            )
            reconciled = json.loads(
                mcp_server.reconcile_core_request_journal(
                    caller="source-client",
                    request_id="source-request",
                    expected_operation="commit_cortical_trace",
                    expected_authority_epoch="epoch-1",
                    expected_entry_revision="b" * 64,
                    expected_journal_id="journal-" + "c" * 24,
                    inventory_snapshot_revision="d" * 64,
                    disposition="confirmed_no_effect",
                    evidence_kind="authoritative_no_effect_readback",
                    evidence_sha256="e" * 64,
                    confirm=True,
                    core_request_id="reconcile-mcp-exact-target",
                )
            )

        self.assertTrue(inventory["read_only"])
        self.assertEqual(reconciled["status"], "reconciled")
        self.assertFalse(reconciled["replay_safe"])
        client.request_journal_inventory.assert_called_once_with(
            states=["ambiguous"],
            caller="source-client",
            operation="commit_cortical_trace",
            limit=10,
            after_caller=None,
            after_request_id=None,
            expected_snapshot_revision="a" * 64,
        )
        client.reconcile_request_journal.assert_called_once_with(
            target_caller="source-client",
            target_request_id="source-request",
            expected_operation="commit_cortical_trace",
            expected_authority_epoch="epoch-1",
            expected_entry_revision="b" * 64,
            expected_journal_id="journal-" + "c" * 24,
            inventory_snapshot_revision="d" * 64,
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="e" * 64,
            confirm=True,
            request_id="reconcile-mcp-exact-target",
        )

    @staticmethod
    def _decode_dashboard(response: tuple[int, dict[str, str], bytes]) -> tuple[int, dict]:
        status, headers, body = response
        if headers.get("Content-Type") != "application/json; charset=utf-8":
            raise AssertionError("dashboard response was not JSON")
        return status, json.loads(body.decode("utf-8"))

    def test_dashboard_requires_review_gate_and_forwards_one_exact_target(
        self,
    ) -> None:
        backend = mock.Mock()
        backend.request_journal_inventory.return_value = {
            "schema": "synapse-s2.request-journal-inventory.v1",
            "read_only": True,
        }
        backend.reconcile_request_journal.return_value = {
            "schema": "synapse-s2.request-journal-reconciliation-result.v1",
            "status": "reconciled",
            "replay_safe": False,
        }
        runtime = DashboardRuntime(backend)
        inventory_body = {
            "states": ["ambiguous"],
            "caller": "source-client",
            "operation": "commit_cortical_trace",
            "limit": 10,
            "after_caller": None,
            "after_request_id": None,
            "expected_snapshot_revision": "a" * 64,
        }
        reconcile_body = {
            "caller": "source-client",
            "request_id": "source-request",
            "expected_operation": "commit_cortical_trace",
            "expected_authority_epoch": "epoch-1",
            "expected_entry_revision": "b" * 64,
            "expected_journal_id": "journal-" + "c" * 24,
            "inventory_snapshot_revision": "d" * 64,
            "disposition": "confirmed_no_effect",
            "evidence_kind": "authoritative_no_effect_readback",
            "evidence_sha256": "e" * 64,
            "reviewed": True,
            "confirm": True,
            "core_request_id": "reconcile-dashboard-exact-target",
        }

        inventory_status, inventory = self._decode_dashboard(
            runtime.handle(
                "POST",
                "/api/request-journal/inventory",
                json.dumps(inventory_body).encode("utf-8"),
            )
        )
        unreviewed_body = {**reconcile_body, "reviewed": False}
        rejected_status, rejected = self._decode_dashboard(
            runtime.handle(
                "POST",
                "/api/request-journal/reconcile",
                json.dumps(unreviewed_body).encode("utf-8"),
            )
        )
        normalized_body = {
            **reconcile_body,
            "core_request_id": " reconcile-dashboard-exact-target ",
        }
        normalized_status, normalized = self._decode_dashboard(
            runtime.handle(
                "POST",
                "/api/request-journal/reconcile",
                json.dumps(normalized_body).encode("utf-8"),
            )
        )
        reconcile_status, reconciled = self._decode_dashboard(
            runtime.handle(
                "POST",
                "/api/request-journal/reconcile",
                json.dumps(reconcile_body).encode("utf-8"),
            )
        )

        self.assertEqual(inventory_status, 200)
        self.assertTrue(inventory["read_only"])
        self.assertEqual(rejected_status, 400)
        self.assertIn("reviewed=true", rejected["error"])
        self.assertEqual(normalized_status, 400)
        self.assertIn("preserved exactly", normalized["error"])
        self.assertEqual(reconcile_status, 200)
        self.assertEqual(reconciled["status"], "reconciled")
        self.assertFalse(reconciled["replay_safe"])
        backend.request_journal_inventory.assert_called_once_with(
            states=["ambiguous"],
            caller="source-client",
            operation="commit_cortical_trace",
            limit=10,
            after_caller=None,
            after_request_id=None,
            expected_snapshot_revision="a" * 64,
        )
        backend.reconcile_request_journal.assert_called_once_with(
            target_caller="source-client",
            target_request_id="source-request",
            expected_operation="commit_cortical_trace",
            expected_authority_epoch="epoch-1",
            expected_entry_revision="b" * 64,
            expected_journal_id="journal-" + "c" * 24,
            inventory_snapshot_revision="d" * 64,
            disposition="confirmed_no_effect",
            evidence_kind="authoritative_no_effect_readback",
            evidence_sha256="e" * 64,
            confirm=True,
            request_id="reconcile-dashboard-exact-target",
        )


if __name__ == "__main__":
    unittest.main()

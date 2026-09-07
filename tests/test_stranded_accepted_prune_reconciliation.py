from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import synapse_cli
from core_client import CoreClient, CoreOutcomeUnknown, CoreRemoteError
from core_protocol import build_request, receive_frame, send_frame, validate_response
from core_request_journal import CoreRequestJournalError
from core_service import (
    AuthoritativeCoreService,
    CORE_OPERATION_CONTRACTS,
    CoreConfig,
    CoreServiceError,
)
from memory_store import (
    DurableMemoryStore,
    REQUEST_JOURNAL_RECONCILIATION_OPERATION_TYPE,
    REQUEST_JOURNAL_RECONCILIATION_RECEIPT_FIELDS,
    REQUEST_JOURNAL_RECONCILIATION_RECEIPT_SCHEMA,
    RequestJournalReconciliationRejected,
    STRANDED_ACCEPTED_PRUNE_RECONCILIATION_RECEIPT_FIELDS,
    STRANDED_ACCEPTED_PRUNE_RECONCILIATION_RECEIPT_SCHEMA,
)
from recovery_manager import VerifiedRecoveryManager
from tests.test_core_service import FakeBackend


_CONTRACTS = {
    name: CORE_OPERATION_CONTRACTS[name]
    for name in (
        "health",
        "request_status",
        "request_journal_inventory",
        "reconcile_request_journal",
        "reconcile_stranded_accepted_prune",
        "prune_memory",
    )
}

_DEPLOYED_RECONCILIATION_OPERATION_TYPE = "request-journal-reconciliation"
_DEPLOYED_RECONCILIATION_SCHEMA = (
    "synapse-s2.request-journal-reconciliation-receipt.v1"
)
_DEPLOYED_RECONCILIATION_FIELDS = frozenset(
    {
        "schema",
        "resolution_id",
        "request_journal_id",
        "store_identity",
        "target_caller",
        "target_request_id",
        "target_operation",
        "target_authority_epoch",
        "target_original_state",
        "target_entry_revision",
        "inventory_snapshot_revision",
        "disposition",
        "evidence_kind",
        "evidence_sha256",
        "reconciled_by",
        "replay_safe",
        "reconciled_at_unix_ms",
        "auth_algorithm",
        "auth_key_id",
        "signing_public_key",
        "receipt_digest",
        "receipt_signature",
    }
)


def _deployed_v1_contract_check(payload: object) -> None:
    if (
        not isinstance(payload, dict)
        or set(payload) != _DEPLOYED_RECONCILIATION_FIELDS
        or payload.get("schema") != _DEPLOYED_RECONCILIATION_SCHEMA
    ):
        raise RuntimeError(
            "request-journal reconciliation receipt contract is invalid"
        )


def _entry(store: DurableMemoryStore, *, tag: str, context_id: str = "default") -> dict:
    return store.upsert_entry(
        tag=tag,
        context_id=context_id,
        source_text="Disposable test memory text.",
        metadata={"fixture": True},
        embedding_dimensions=8,
        spike_indices=[1, 3],
        neuron_indices=[1, 3],
    )


def _store_arguments(
    store: DurableMemoryStore,
    *,
    candidate_memory_id: str,
    survivor_memory_id: str,
    context_id: str = "default",
) -> dict:
    return {
        "request_journal_id": "journal-" + ("1" * 24),
        "store_identity": store.store_identity_for_path(store.db_path),
        "target_caller": "core-client-incident",
        "target_request_id": "req-stranded-prune",
        "target_authority_epoch": "epoch-57",
        "target_entry_revision": "2" * 64,
        "inventory_snapshot_revision": "3" * 64,
        "expected_reconciling_authority_epoch": "epoch-58",
        "expected_reconciling_root_generation_id": (
            "generation-" + ("4" * 24)
        ),
        "expected_reconciling_build_id": "source-" + ("5" * 24),
        "expected_reconciling_config_fingerprint": "6" * 64,
        "observed_context_id": context_id,
        "observed_candidate_memory_id": candidate_memory_id,
        "observed_survivor_memory_id": survivor_memory_id,
        "evidence_sha256": "7" * 64,
        "reconciliation_request_caller": "stranding-reconciler",
        "reconciliation_request_id": "req-record-stranded-prune-once",
        "reconciliation_request_fingerprint": "8" * 64,
        "reconciled_by": "core:local-owner:operator",
        "confirm": True,
    }


def _reconcile_store(
    store: DurableMemoryStore,
    arguments: dict,
) -> dict:
    marker = {
        "epoch": int(
            arguments["expected_reconciling_authority_epoch"].removeprefix(
                "epoch-"
            )
        ),
        "root_generation_id": arguments[
            "expected_reconciling_root_generation_id"
        ],
        "build_id": arguments["expected_reconciling_build_id"],
        "config_fingerprint": arguments[
            "expected_reconciling_config_fingerprint"
        ],
        "request_journal_id": arguments["request_journal_id"],
        "store_identity": arguments["store_identity"],
    }
    with mock.patch.object(
        store,
        "_stranded_accepted_prune_authority_marker",
        return_value=marker,
    ):
        return store.reconcile_stranded_accepted_prune(**arguments)


def _assert_private_fingerprint_absent(test: unittest.TestCase, value: object) -> None:
    if isinstance(value, dict):
        test.assertNotIn("reconciliation_request_fingerprint", value)
        test.assertNotIn("request_fingerprint", value)
        for child in value.values():
            _assert_private_fingerprint_absent(test, child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_private_fingerprint_absent(test, child)


class StrandedAcceptedPruneStoreTests(unittest.TestCase):
    def _store(self) -> tuple[TemporaryDirectory, DurableMemoryStore]:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = DurableMemoryStore(Path(temporary.name) / "memory.sqlite3")
        self.addCleanup(store.close)
        return temporary, store

    def test_v2_receipt_is_signed_idempotent_and_never_claims_completion(self) -> None:
        _temporary, store = self._store()
        survivor = _entry(store, tag="canonical-survivor")
        candidate_memory_id = "s2_" + ("a" * 32)
        self.assertNotEqual(candidate_memory_id, survivor["memory_id"])
        arguments = _store_arguments(
            store,
            candidate_memory_id=candidate_memory_id,
            survivor_memory_id=survivor["memory_id"],
        )

        first = _reconcile_store(store, arguments)
        second = _reconcile_store(store, arguments)

        self.assertEqual(first["status"], "stranding_recorded")
        self.assertFalse(first["idempotent"])
        self.assertTrue(second["idempotent"])
        self.assertEqual(second["resolution_id"], first["resolution_id"])
        self.assertEqual(second["receipt_digest"], first["receipt_digest"])
        self.assertEqual(first["target_original_state"], "accepted")
        self.assertEqual(first["target_operation"], "prune_memory")
        self.assertEqual(first["target_operation_outcome"], "unknown")
        self.assertFalse(first["target_operation_completion_confirmed"])
        self.assertFalse(first["target_argument_binding_confirmed"])
        self.assertFalse(first["cause_attributed_to_target_request"])
        self.assertTrue(first["source_row_preserved"])
        self.assertTrue(first["original_journal_state_preserved"])
        self.assertFalse(first["capacity_recovered"])
        self.assertFalse(first["replay_safe"])
        self.assertTrue(first["signature_verified"])

        inventory = store.request_journal_reconciliation_inventory(
            request_journal_id=arguments["request_journal_id"],
            store_identity=arguments["store_identity"],
        )
        self.assertEqual(inventory["count"], 1)
        self.assertEqual(inventory["ambiguous_count"], 0)
        self.assertEqual(inventory["stranded_accepted_prune_count"], 1)
        self.assertEqual(
            inventory["items"][0]["receipt_schema"],
            STRANDED_ACCEPTED_PRUNE_RECONCILIATION_RECEIPT_SCHEMA,
        )
        self.assertFalse(
            inventory["items"][0]["cause_attributed_to_target_request"]
        )
        self.assertEqual(
            [item["memory_id"] for item in store.list_entries_by_ids(
                [candidate_memory_id, survivor["memory_id"]],
                context_id="default",
            )],
            [survivor["memory_id"]],
        )

        forbidden_keys = {
            "arguments",
            "request_fingerprint",
            "response",
            "result",
            "text",
            "source_text",
            "embedding",
            "embeddings",
            "tag",
            "reason",
            "relationship_id",
            "event_id",
            "evidence",
            "evidence_body",
            "path",
            "memory_db_path",
        }
        self.assertTrue(forbidden_keys.isdisjoint(first))
        self.assertNotIn("Disposable test memory text.", repr(first))
        self.assertNotIn("Disposable test memory text.", repr(inventory))
        status = store.request_journal_reconciliation_request_status(
            request_journal_id=arguments["request_journal_id"],
            store_identity=arguments["store_identity"],
            caller=arguments["reconciliation_request_caller"],
            request_id=arguments["reconciliation_request_id"],
        )
        self.assertTrue(status["known"])
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["result_kind"], "signed_receipt")
        _assert_private_fingerprint_absent(self, first)
        _assert_private_fingerprint_absent(self, inventory)
        _assert_private_fingerprint_absent(self, status)

    def test_v2_readback_and_semantic_drift_fail_closed_without_receipt(self) -> None:
        for case in ("candidate-present", "survivor-missing", "wrong-context"):
            with self.subTest(case=case):
                _temporary, store = self._store()
                survivor_context = "other" if case == "wrong-context" else "default"
                survivor = (
                    None
                    if case == "survivor-missing"
                    else _entry(
                        store,
                        tag=f"survivor-{case}",
                        context_id=survivor_context,
                    )
                )
                candidate = (
                    _entry(store, tag="candidate-present")
                    if case == "candidate-present"
                    else {"memory_id": "s2_" + ("b" * 32)}
                )
                survivor_memory_id = (
                    "s2_" + ("c" * 32)
                    if survivor is None
                    else survivor["memory_id"]
                )
                arguments = _store_arguments(
                    store,
                    candidate_memory_id=candidate["memory_id"],
                    survivor_memory_id=survivor_memory_id,
                )
                with self.assertRaisesRegex(
                    RequestJournalReconciliationRejected,
                    "readback changed",
                ):
                    _reconcile_store(store, arguments)
                inventory = store.request_journal_reconciliation_inventory(
                    request_journal_id=arguments["request_journal_id"],
                    store_identity=arguments["store_identity"],
                )
                self.assertEqual(inventory["count"], 0)

        _temporary, store = self._store()
        survivor = _entry(store, tag="semantic-survivor")
        arguments = _store_arguments(
            store,
            candidate_memory_id="s2_" + ("d" * 32),
            survivor_memory_id=survivor["memory_id"],
        )
        _reconcile_store(store, arguments)
        with self.assertRaisesRegex(
            RequestJournalReconciliationRejected,
            "conflicts with existing receipt",
        ):
            _reconcile_store(
                store,
                {**arguments, "evidence_sha256": "9" * 64},
            )
        self.assertEqual(
            store.request_journal_reconciliation_inventory(
                request_journal_id=arguments["request_journal_id"],
                store_identity=arguments["store_identity"],
            )["count"],
            1,
        )

    def test_v2_requires_strict_successor_epoch_and_distinct_public_ids(self) -> None:
        _temporary, store = self._store()
        survivor = _entry(store, tag="epoch-survivor")
        base = _store_arguments(
            store,
            candidate_memory_id="s2_" + ("e" * 32),
            survivor_memory_id=survivor["memory_id"],
        )
        invalid_overrides = (
            {"expected_reconciling_authority_epoch": "epoch-57"},
            {"expected_reconciling_authority_epoch": "epoch-56"},
            {"target_authority_epoch": "epoch-057"},
            {
                "observed_candidate_memory_id": survivor["memory_id"],
                "observed_survivor_memory_id": survivor["memory_id"],
            },
            {"observed_candidate_memory_id": "not-a-public-memory-id"},
        )
        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides), self.assertRaises(
                RequestJournalReconciliationRejected
            ):
                _reconcile_store(store, {**base, **overrides})
        self.assertEqual(
            store.request_journal_reconciliation_inventory(
                request_journal_id=base["request_journal_id"],
                store_identity=base["store_identity"],
            )["count"],
            0,
        )

    def test_v2_outer_handle_and_authority_collisions_fail_without_new_receipt(
        self,
    ) -> None:
        _temporary, store = self._store()
        survivor = _entry(store, tag="collision-survivor")
        base = _store_arguments(
            store,
            candidate_memory_id="s2_" + ("1" * 32),
            survivor_memory_id=survivor["memory_id"],
        )

        mismatched_marker = {
            "epoch": 58,
            "root_generation_id": base[
                "expected_reconciling_root_generation_id"
            ],
            "build_id": "source-" + ("0" * 24),
            "config_fingerprint": base[
                "expected_reconciling_config_fingerprint"
            ],
            "request_journal_id": base["request_journal_id"],
            "store_identity": base["store_identity"],
        }
        with (
            mock.patch.object(
                store,
                "_stranded_accepted_prune_authority_marker",
                return_value=mismatched_marker,
            ),
            self.assertRaisesRegex(
                RequestJournalReconciliationRejected,
                "authority binding changed",
            ),
        ):
            store.reconcile_stranded_accepted_prune(**base)
        self.assertEqual(
            store.request_journal_reconciliation_inventory(
                request_journal_id=base["request_journal_id"],
                store_identity=base["store_identity"],
            )["count"],
            0,
        )

        first = _reconcile_store(store, base)
        conflict_cases = (
            {
                **base,
                "reconciliation_request_fingerprint": "9" * 64,
            },
            {
                **base,
                "reconciliation_request_id": "req-different-outer-handle",
            },
            {
                **base,
                "target_request_id": "req-different-stranded-prune",
                "target_entry_revision": "a" * 64,
                "inventory_snapshot_revision": "b" * 64,
                "observed_candidate_memory_id": "s2_" + ("2" * 32),
            },
        )
        for arguments in conflict_cases:
            with self.subTest(arguments=arguments), self.assertRaises(
                RequestJournalReconciliationRejected
            ):
                _reconcile_store(store, arguments)
        inventory = store.request_journal_reconciliation_inventory(
            request_journal_id=base["request_journal_id"],
            store_identity=base["store_identity"],
        )
        self.assertEqual(inventory["count"], 1)
        self.assertEqual(inventory["items"][0]["resolution_id"], first["resolution_id"])

    def test_v2_uses_deployed_v1_contract_as_downgrade_fence(
        self,
    ) -> None:
        self.assertEqual(
            REQUEST_JOURNAL_RECONCILIATION_OPERATION_TYPE,
            _DEPLOYED_RECONCILIATION_OPERATION_TYPE,
        )
        self.assertEqual(
            REQUEST_JOURNAL_RECONCILIATION_RECEIPT_SCHEMA,
            _DEPLOYED_RECONCILIATION_SCHEMA,
        )
        self.assertEqual(
            REQUEST_JOURNAL_RECONCILIATION_RECEIPT_FIELDS,
            _DEPLOYED_RECONCILIATION_FIELDS,
        )
        self.assertNotEqual(
            STRANDED_ACCEPTED_PRUNE_RECONCILIATION_RECEIPT_SCHEMA,
            _DEPLOYED_RECONCILIATION_SCHEMA,
        )

        _temporary, store = self._store()
        survivor = _entry(store, tag="downgrade-fence-survivor")
        arguments = _store_arguments(
            store,
            candidate_memory_id="s2_" + ("3" * 32),
            survivor_memory_id=survivor["memory_id"],
        )
        captured: list[dict] = []
        current_validator = (
            store._validate_request_journal_reconciliation_receipt
        )

        def capture_current_validation(payload, **kwargs):
            if (
                isinstance(payload, dict)
                and payload.get("schema")
                == STRANDED_ACCEPTED_PRUNE_RECONCILIATION_RECEIPT_SCHEMA
                and not captured
            ):
                captured.append(dict(payload))
            return current_validator(payload, **kwargs)

        with mock.patch.object(
            store,
            "_validate_request_journal_reconciliation_receipt",
            side_effect=capture_current_validation,
        ):
            _reconcile_store(store, arguments)
        self.assertEqual(len(captured), 1)
        payload = captured[0]
        before = hashlib.sha256(
            json.dumps(
                payload,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(
            RuntimeError,
            "^request-journal reconciliation receipt contract is invalid$",
        ):
            _deployed_v1_contract_check(payload)
        after = hashlib.sha256(
            json.dumps(
                payload,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(after, before)
        self.assertEqual(
            store.request_journal_reconciliation_inventory(
                request_journal_id=arguments["request_journal_id"],
                store_identity=arguments["store_identity"],
            )["stranded_accepted_prune_count"],
            1,
        )


class _SuccessorServiceHarness:
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
        self.services: list[
            tuple[AuthoritativeCoreService, threading.Thread, FakeBackend]
        ] = []
        self.prune_handler_calls = 0

    def _unexpected_prune_handler(self, **_arguments) -> dict:
        self.prune_handler_calls += 1
        return {"unexpected_prune_dispatch": True}

    def start(self) -> tuple[AuthoritativeCoreService, FakeBackend]:
        backend = FakeBackend()
        service = AuthoritativeCoreService(
            self.config,
            backend_factory=lambda lease: backend.attach_memory_store(
                DurableMemoryStore(
                    self.config.memory_path,
                    authority_lease=lease,
                )
            ),
            operation_contracts=_CONTRACTS,
            operation_handlers_factory=lambda _backend: {
                "prune_memory": self._unexpected_prune_handler,
            },
        )
        failures: list[BaseException] = []

        def run() -> None:
            try:
                service.serve_forever()
            except BaseException as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        thread = threading.Thread(
            target=run,
            name="test-stranded-prune-successor-core",
            daemon=True,
        )
        thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if failures:
                raise failures[0]
            if service._started_event.is_set():
                break
            time.sleep(0.01)
        if failures:
            raise failures[0]
        if not service._started_event.is_set():
            raise AssertionError("temporary successor core did not start")
        self.services.append((service, thread, backend))
        return service, backend

    def stop(self, service: AuthoritativeCoreService) -> None:
        for index, (candidate, thread, _backend) in enumerate(self.services):
            if candidate is service:
                service.close()
                thread.join(timeout=3.0)
                self.services.pop(index)
                return
        raise AssertionError("service not registered")

    def close(self) -> None:
        for service, thread, _backend in reversed(self.services):
            service.close()
            thread.join(timeout=3.0)
        self.services.clear()
        self.temporary.cleanup()

    def send(self, request: dict) -> dict:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(3.0)
        try:
            connection.connect(str(self.config.socket_path))
            send_frame(connection, request)
            response = receive_frame(connection)
        finally:
            connection.close()
        return validate_response(response, expected_request=request)


class StrandedAcceptedPruneServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = _SuccessorServiceHarness()
        self.addCleanup(self.harness.close)

    def _prepare_successor_target(self) -> dict:
        first_service, first_backend = self.harness.start()
        store = first_backend.memory_store
        assert store is not None
        survivor = _entry(store, tag="lost-response-canonical-survivor")
        candidate_memory_id = "s2_" + ("c" * 32)
        authentication_key = first_service._authentication_key
        assert authentication_key is not None
        original_request = build_request(
            request_id="req-original-lost-response-prune",
            caller="core-client-lost-response-prune",
            deadline_unix_ms=int((time.time() + 300.0) * 1000),
            operation="prune_memory",
            arguments={
                "context_id": "default",
                "target_type": "memory",
                "memory_id": candidate_memory_id,
                "tag": "",
                "relationship_id": "",
                "event_id": 0,
                "reason": "disposable lost-response no-replay test",
                "source_surface": "dashboard",
                "publish_audit": True,
                "confirm": True,
            },
            authentication_key=authentication_key,
        )
        journal = first_service._request_journal
        assert journal is not None
        admission = journal.accept(
            caller=original_request["caller"],
            request_id=original_request["request_id"],
            operation=original_request["operation"],
            request_fingerprint=original_request["request_fingerprint"],
        )
        self.assertEqual(admission.disposition, "accepted")
        self.harness.stop(first_service)

        successor, successor_backend = self.harness.start()
        client = CoreClient(
            socket_path=self.harness.config.socket_path,
            caller="stranding-reconciler",
            default_timeout_seconds=5.0,
        )
        inventory = client.request_journal_inventory(
            states=["accepted"],
            limit=10,
        )
        target = next(
            item
            for item in inventory["items"]
            if item["request_id"] == original_request["request_id"]
        )
        authority = inventory["reconciling_authority"]
        return {
            "successor": successor,
            "backend": successor_backend,
            "client": client,
            "inventory": inventory,
            "target": target,
            "authority": authority,
            "survivor": survivor,
            "candidate_memory_id": candidate_memory_id,
            "original_request": original_request,
        }

    @staticmethod
    def _reconciliation_call_arguments(prepared: dict) -> dict:
        target = prepared["target"]
        inventory = prepared["inventory"]
        authority = prepared["authority"]
        return {
            "target_caller": target["caller"],
            "target_request_id": target["request_id"],
            "expected_authority_epoch": target["authority_epoch"],
            "expected_entry_revision": target["entry_revision"],
            "expected_journal_id": inventory["journal_id"],
            "expected_store_identity": inventory["store_identity"],
            "inventory_snapshot_revision": inventory[
                "reconciliation_guard"
            ]["snapshot_revision"],
            "expected_reconciling_authority_epoch": authority[
                "authority_epoch"
            ],
            "expected_reconciling_root_generation_id": authority[
                "root_generation_id"
            ],
            "expected_reconciling_build_id": authority["build_id"],
            "expected_reconciling_config_fingerprint": authority[
                "config_fingerprint"
            ],
            "observed_context_id": "default",
            "observed_candidate_memory_id": prepared["candidate_memory_id"],
            "observed_survivor_memory_id": prepared["survivor"]["memory_id"],
            "evidence_sha256": hashlib.sha256(
                b"content-free-lost-response-reconciliation-evidence"
            ).hexdigest(),
            "confirm": True,
        }

    def test_successor_records_stranding_preserves_source_and_never_replays(self) -> None:
        first_service, first_backend = self.harness.start()
        store = first_backend.memory_store
        assert store is not None
        survivor = _entry(store, tag="canonical-session-boundary-survivor")
        candidate_memory_id = "s2_" + ("f" * 32)
        self.assertNotEqual(candidate_memory_id, survivor["memory_id"])
        authentication_key = first_service._authentication_key
        assert authentication_key is not None
        original_request = build_request(
            request_id="req-original-stranded-prune",
            caller="core-client-original-prune",
            deadline_unix_ms=int((time.time() + 300.0) * 1000),
            operation="prune_memory",
            arguments={
                "context_id": "default",
                "target_type": "memory",
                "memory_id": candidate_memory_id,
                "tag": "",
                "relationship_id": "",
                "event_id": 0,
                "reason": "disposable no-replay test",
                "source_surface": "dashboard",
                "publish_audit": True,
                "confirm": True,
            },
            authentication_key=authentication_key,
        )
        journal = first_service._request_journal
        assert journal is not None
        admission = journal.accept(
            caller=original_request["caller"],
            request_id=original_request["request_id"],
            operation=original_request["operation"],
            request_fingerprint=original_request["request_fingerprint"],
        )
        self.assertEqual(admission.disposition, "accepted")
        target_epoch = first_service.identity["neural_epoch"]
        self.harness.stop(first_service)

        successor, successor_backend = self.harness.start()
        self.assertGreater(
            int(successor.identity["neural_epoch"].removeprefix("epoch-")),
            int(target_epoch.removeprefix("epoch-")),
        )
        client = CoreClient(
            socket_path=self.harness.config.socket_path,
            caller="stranding-reconciler",
            default_timeout_seconds=5.0,
        )
        before_health = client.health()["request_journal"]
        inventory = client.request_journal_inventory(
            states=["accepted"],
            limit=10,
        )
        target = next(
            item
            for item in inventory["items"]
            if item["request_id"] == original_request["request_id"]
        )
        self.assertEqual(target["state"], "accepted")
        self.assertEqual(target["operation"], "prune_memory")
        self.assertTrue(target["reconciliation_eligible"])
        self.assertEqual(
            target["reconciliation_kind"],
            "stranded_accepted_prune",
        )
        self.assertFalse(target["replay_safe"])
        authority = inventory["reconciling_authority"]

        receipt = client.reconcile_stranded_accepted_prune(
            target_caller=target["caller"],
            target_request_id=target["request_id"],
            expected_authority_epoch=target["authority_epoch"],
            expected_entry_revision=target["entry_revision"],
            expected_journal_id=inventory["journal_id"],
            expected_store_identity=inventory["store_identity"],
            inventory_snapshot_revision=inventory["reconciliation_guard"][
                "snapshot_revision"
            ],
            expected_reconciling_authority_epoch=authority[
                "authority_epoch"
            ],
            expected_reconciling_root_generation_id=authority[
                "root_generation_id"
            ],
            expected_reconciling_build_id=authority["build_id"],
            expected_reconciling_config_fingerprint=authority[
                "config_fingerprint"
            ],
            observed_context_id="default",
            observed_candidate_memory_id=candidate_memory_id,
            observed_survivor_memory_id=survivor["memory_id"],
            evidence_sha256=hashlib.sha256(
                b"content-free-reviewed-candidate-survivor-evidence"
            ).hexdigest(),
            confirm=True,
            request_id="req-record-stranded-prune-once",
        )
        self.assertEqual(receipt["status"], "stranding_recorded")
        self.assertEqual(receipt["target_operation_outcome"], "unknown")
        self.assertFalse(receipt["target_operation_completion_confirmed"])
        self.assertFalse(receipt["target_argument_binding_confirmed"])
        self.assertFalse(receipt["cause_attributed_to_target_request"])
        self.assertTrue(receipt["reconciliation_request_completion_confirmed"])
        self.assertEqual(
            receipt["reconciliation_request_outcome"],
            "receipt_committed",
        )
        self.assertFalse(receipt["replay_safe"])
        self.assertEqual(self.harness.prune_handler_calls, 0)

        after_inventory = client.request_journal_inventory(
            states=["accepted"],
            limit=10,
            expected_snapshot_revision=inventory["snapshot_revision"],
        )
        source = next(
            item
            for item in after_inventory["items"]
            if item["request_id"] == original_request["request_id"]
        )
        self.assertEqual(source["state"], "accepted")
        self.assertEqual(source["entry_revision"], target["entry_revision"])
        self.assertFalse(source["reconciliation_eligible"])
        self.assertEqual(
            source["reconciliation"]["status"],
            "stranding_recorded",
        )
        status = client.request_status(
            caller=target["caller"],
            request_id=target["request_id"],
        )
        self.assertEqual(status["state"], "accepted")
        self.assertIsNone(status["finished_age_ms"])
        self.assertFalse(status["replay_safe"])
        outer_status = client.request_status(
            caller="stranding-reconciler",
            request_id="req-record-stranded-prune-once",
        )
        self.assertTrue(outer_status["known"])
        self.assertEqual(outer_status["state"], "completed")
        self.assertTrue(outer_status["receipt_journaled"])
        self.assertEqual(
            outer_status["target_operation_outcome"],
            "unknown",
        )
        self.assertFalse(
            outer_status["target_operation_completion_confirmed"]
        )
        self.assertFalse(outer_status["target_argument_binding_confirmed"])
        self.assertFalse(
            outer_status["cause_attributed_to_target_request"]
        )
        self.assertNotIn("request_fingerprint", outer_status)

        repeated_original = self.harness.send(original_request)
        self.assertFalse(repeated_original["ok"])
        self.assertEqual(
            repeated_original["error"],
            {"code": "outcome_unknown", "retryable": False},
        )
        self.assertEqual(self.harness.prune_handler_calls, 0)

        after_health = client.health()["request_journal"]
        self.assertEqual(after_health["accepted_count"], before_health["accepted_count"])
        self.assertEqual(
            after_health["accepted_capacity_remaining"],
            before_health["accepted_capacity_remaining"],
        )
        self.assertEqual(after_health["reconciliation_record_count"], 1)
        self.assertEqual(after_health["reconciled_explicit_ambiguous_count"], 0)
        self.assertEqual(after_health["stranded_accepted_prune_record_count"], 1)
        self.assertTrue(after_health["reconciliation_signatures_verified"])

        successor_store = successor_backend.memory_store
        assert successor_store is not None
        readback = successor_store.list_entries_by_ids(
            [candidate_memory_id, survivor["memory_id"]],
            context_id="default",
        )
        self.assertEqual(
            [item["memory_id"] for item in readback],
            [survivor["memory_id"]],
        )

        manager = VerifiedRecoveryManager(
            successor_store,
            capture_root=self.harness.state_root,
        )
        backup_root = self.harness.state_root / "backups" / "stranding-test"
        backup_root.mkdir(parents=True, mode=0o700)
        bundle = manager.create_bundle(
            backup_root / "stranded-accepted-prune.sqlite3",
            purpose="stranded-accepted-prune-reconciliation-test",
            pinned=True,
        )
        verified = manager.verify_bundle(bundle["bundle_receipt_path"])
        self.assertTrue(bundle["bundle_verified"])
        self.assertTrue(verified["verified"])
        reconciliation = verified["request_journal_reconciliation"]
        self.assertEqual(reconciliation["receipt_count"], 1)
        self.assertEqual(reconciliation["ambiguous_count"], 0)
        self.assertEqual(
            reconciliation["stranded_accepted_prune_count"],
            1,
        )
        self.assertTrue(reconciliation["source_row_bindings_verified"])
        self.assertTrue(reconciliation["original_accepted_rows_preserved"])
        self.assertFalse(reconciliation["generic_replay_authorized"])

    def test_lost_outer_response_resolves_from_receipt_after_restart(self) -> None:
        prepared = self._prepare_successor_target()
        successor = prepared["successor"]
        successor_backend = prepared["backend"]
        client = prepared["client"]
        arguments = self._reconciliation_call_arguments(prepared)
        outer_request_id = "req-lost-reconciliation-response"
        store = successor_backend.memory_store
        assert store is not None
        committed_reconcile = store.reconcile_stranded_accepted_prune

        def commit_then_lose_response(**kwargs) -> dict:
            result = committed_reconcile(**kwargs)
            self.assertEqual(result["status"], "stranding_recorded")
            raise CoreServiceError()

        with mock.patch.object(
            store,
            "reconcile_stranded_accepted_prune",
            side_effect=commit_then_lose_response,
        ):
            with self.assertRaises(CoreOutcomeUnknown) as raised:
                client.reconcile_stranded_accepted_prune(
                    **arguments,
                    request_id=outer_request_id,
                )
        self.assertEqual(raised.exception.request_id, outer_request_id)
        journal = successor._request_journal
        assert journal is not None
        self.assertFalse(
            journal.request_status(
                caller="stranding-reconciler",
                request_id=outer_request_id,
            )["known"]
        )
        inventory = store.request_journal_reconciliation_inventory(
            request_journal_id=prepared["inventory"]["journal_id"],
            store_identity=prepared["inventory"]["store_identity"],
        )
        self.assertEqual(inventory["count"], 1)
        self.assertEqual(self.harness.prune_handler_calls, 0)

        self.harness.stop(successor)
        restarted, _restarted_backend = self.harness.start()
        restarted_client = CoreClient(
            socket_path=self.harness.config.socket_path,
            caller="stranding-reconciler",
            default_timeout_seconds=5.0,
        )
        status = restarted_client.request_status(
            caller="stranding-reconciler",
            request_id=outer_request_id,
        )
        self.assertTrue(status["known"])
        self.assertEqual(status["state"], "completed")
        self.assertTrue(status["receipt_journaled"])
        self.assertIsNone(status["accepted_age_ms"])
        self.assertEqual(status["reconciliation_request_outcome"], "receipt_committed")
        self.assertEqual(status["target_operation_outcome"], "unknown")
        self.assertFalse(status["target_operation_completion_confirmed"])
        self.assertFalse(status["target_argument_binding_confirmed"])
        self.assertFalse(status["cause_attributed_to_target_request"])
        self.assertEqual(self.harness.prune_handler_calls, 0)
        _assert_private_fingerprint_absent(self, status)
        self.assertTrue(restarted_client.health()["request_journal"]["ready"])

        restarted_journal = restarted._request_journal
        assert restarted_journal is not None
        self.assertFalse(
            restarted_journal.request_status(
                caller="stranding-reconciler",
                request_id=outer_request_id,
            )["known"]
        )

    def test_cross_ledger_collision_and_source_drift_fail_closed(self) -> None:
        prepared = self._prepare_successor_target()
        successor = prepared["successor"]
        client = prepared["client"]
        arguments = self._reconciliation_call_arguments(prepared)
        outer_request_id = "req-cross-ledger-reconciliation"
        receipt = client.reconcile_stranded_accepted_prune(
            **arguments,
            request_id=outer_request_id,
        )
        self.assertEqual(receipt["status"], "stranding_recorded")

        authentication_key = successor._authentication_key
        assert authentication_key is not None
        generic_collision = build_request(
            request_id=outer_request_id,
            caller="stranding-reconciler",
            deadline_unix_ms=int((time.time() + 60.0) * 1000),
            operation="prune_memory",
            arguments={},
            authentication_key=authentication_key,
        )
        self.assertEqual(successor._journal_accept(generic_collision), "conflict")

        journal = successor._request_journal
        assert journal is not None
        legacy_caller = "legacy-generic-reconciler"
        legacy_request_id = "req-legacy-generic-reconciliation"
        legacy_request = build_request(
            request_id=legacy_request_id,
            caller=legacy_caller,
            deadline_unix_ms=int((time.time() + 60.0) * 1000),
            operation="reconcile_stranded_accepted_prune",
            arguments={},
            authentication_key=authentication_key,
        )
        admission = journal.accept(
            caller=legacy_caller,
            request_id=legacy_request_id,
            operation="reconcile_stranded_accepted_prune",
            request_fingerprint=legacy_request["request_fingerprint"],
        )
        self.assertEqual(admission.disposition, "accepted")
        self.assertEqual(successor._journal_accept(legacy_request), "conflict")

        with mock.patch.object(
            journal,
            "review_reconciliation_targets",
            side_effect=CoreServiceError(),
        ):
            with self.assertRaises(CoreRemoteError) as raised:
                client.request_status(
                    caller="stranding-reconciler",
                    request_id=outer_request_id,
                )
        self.assertEqual(raised.exception.code, "service_unavailable")

        colliding_outer_request = build_request(
            request_id=outer_request_id,
            caller="stranding-reconciler",
            deadline_unix_ms=int((time.time() + 60.0) * 1000),
            operation="reconcile_stranded_accepted_prune",
            arguments=arguments,
            authentication_key=authentication_key,
        )
        collision_admission = journal.accept(
            caller=colliding_outer_request["caller"],
            request_id=colliding_outer_request["request_id"],
            operation=colliding_outer_request["operation"],
            request_fingerprint=colliding_outer_request[
                "request_fingerprint"
            ],
        )
        self.assertEqual(collision_admission.disposition, "accepted")
        with self.assertRaises(CoreRemoteError) as status_error:
            client.request_status(
                caller="stranding-reconciler",
                request_id=outer_request_id,
            )
        self.assertEqual(status_error.exception.code, "request_conflict")
        health = client.health()["request_journal"]
        self.assertFalse(health["ready"])
        self.assertEqual(
            health["blocker"],
            "request_journal_reconciliation_invalid",
        )
        unrelated_mutation = build_request(
            request_id="req-unrelated-mutation-after-ledger-collision",
            caller="unrelated-mutation-client",
            deadline_unix_ms=int((time.time() + 60.0) * 1000),
            operation="prune_memory",
            arguments={},
            authentication_key=authentication_key,
        )
        with self.assertRaises(CoreRequestJournalError):
            successor._journal_accept(unrelated_mutation)
        self.assertEqual(self.harness.prune_handler_calls, 0)


class StrandedAcceptedPruneSurfaceTests(unittest.TestCase):
    @staticmethod
    def _namespace() -> SimpleNamespace:
        return SimpleNamespace(
            caller="core-client-original-prune",
            request_id="req-original-stranded-prune",
            expected_authority_epoch="epoch-57",
            expected_entry_revision="1" * 64,
            expected_journal_id="journal-" + ("2" * 24),
            expected_store_identity="store-" + ("3" * 24),
            inventory_snapshot_revision="4" * 64,
            expected_reconciling_authority_epoch="epoch-58",
            expected_reconciling_root_generation_id=(
                "generation-" + ("5" * 24)
            ),
            expected_reconciling_build_id="source-" + ("6" * 24),
            expected_reconciling_config_fingerprint="7" * 64,
            observed_context_id="default",
            observed_candidate_memory_id="s2_" + ("8" * 32),
            observed_survivor_memory_id="s2_" + ("9" * 32),
            evidence_sha256="a" * 64,
            confirm=True,
            core_request_id="req-record-stranded-prune-once",
        )

    def test_cli_forwards_closed_contract_and_requires_predeclared_handle(self) -> None:
        backend = mock.Mock()
        backend.reconcile_stranded_accepted_prune.return_value = {
            "status": "stranding_recorded"
        }
        arguments = self._namespace()
        with mock.patch.object(
            synapse_cli,
            "build_backend",
            return_value=backend,
        ):
            result = synapse_cli.command_request_journal_reconcile_stranded_prune(
                arguments
            )
        self.assertEqual(result["status"], "stranding_recorded")
        backend.reconcile_stranded_accepted_prune.assert_called_once_with(
            target_caller=arguments.caller,
            target_request_id=arguments.request_id,
            expected_authority_epoch=arguments.expected_authority_epoch,
            expected_entry_revision=arguments.expected_entry_revision,
            expected_journal_id=arguments.expected_journal_id,
            expected_store_identity=arguments.expected_store_identity,
            inventory_snapshot_revision=arguments.inventory_snapshot_revision,
            expected_reconciling_authority_epoch=(
                arguments.expected_reconciling_authority_epoch
            ),
            expected_reconciling_root_generation_id=(
                arguments.expected_reconciling_root_generation_id
            ),
            expected_reconciling_build_id=(
                arguments.expected_reconciling_build_id
            ),
            expected_reconciling_config_fingerprint=(
                arguments.expected_reconciling_config_fingerprint
            ),
            observed_context_id=arguments.observed_context_id,
            observed_candidate_memory_id=(
                arguments.observed_candidate_memory_id
            ),
            observed_survivor_memory_id=(
                arguments.observed_survivor_memory_id
            ),
            evidence_sha256=arguments.evidence_sha256,
            confirm=True,
            request_id=arguments.core_request_id,
        )
        rejected = self._namespace()
        rejected.core_request_id = ""
        with (
            mock.patch.object(synapse_cli, "build_backend") as build_backend,
            self.assertRaisesRegex(ValueError, "predeclared"),
        ):
            synapse_cli.command_request_journal_reconcile_stranded_prune(
                rejected
            )
        build_backend.assert_not_called()

    def test_cli_parser_exposes_no_completion_or_replay_classification(self) -> None:
        values = self._namespace()
        argv = [
            "request-journal-reconcile-stranded-prune",
            "--caller",
            values.caller,
            "--request-id",
            values.request_id,
            "--expected-authority-epoch",
            values.expected_authority_epoch,
            "--expected-entry-revision",
            values.expected_entry_revision,
            "--expected-journal-id",
            values.expected_journal_id,
            "--expected-store-identity",
            values.expected_store_identity,
            "--inventory-snapshot-revision",
            values.inventory_snapshot_revision,
            "--expected-reconciling-authority-epoch",
            values.expected_reconciling_authority_epoch,
            "--expected-reconciling-root-generation-id",
            values.expected_reconciling_root_generation_id,
            "--expected-reconciling-build-id",
            values.expected_reconciling_build_id,
            "--expected-reconciling-config-fingerprint",
            values.expected_reconciling_config_fingerprint,
            "--observed-context-id",
            values.observed_context_id,
            "--observed-candidate-memory-id",
            values.observed_candidate_memory_id,
            "--observed-survivor-memory-id",
            values.observed_survivor_memory_id,
            "--evidence-sha256",
            values.evidence_sha256,
            "--core-request-id",
            values.core_request_id,
            "--confirm",
        ]
        parsed = synapse_cli.build_parser().parse_args(argv)
        self.assertEqual(parsed.core_request_id, values.core_request_id)
        self.assertFalse(hasattr(parsed, "disposition"))
        self.assertFalse(hasattr(parsed, "evidence_kind"))
        self.assertFalse(hasattr(parsed, "replay"))


if __name__ == "__main__":
    unittest.main()

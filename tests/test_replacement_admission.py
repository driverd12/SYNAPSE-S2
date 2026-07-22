from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]

from memory_store import (  # noqa: E402
    CORE_RUNTIME_PUBLICATION_SCHEMA,
    LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
    SQLITE_APPLICATION_ID,
    SQLITE_USER_VERSION,
    DurableMemoryStore,
)
from capture_daemon import CaptureInboxDaemon, write_capture_drop  # noqa: E402
from core_authority import CoreAuthorityLease  # noqa: E402
from core_request_journal import (  # noqa: E402
    JOURNAL_BINDING_SCHEMA,
    JOURNAL_SCHEMA_IDENTITY,
    JOURNAL_SCHEMA_VERSION,
)
from core_service import (  # noqa: E402
    REPLACEMENT_ADMISSION_ENV,
    REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX,
    REPLACEMENT_CERTIFICATION_MODE,
    AuthoritativeCoreService,
    CoreConfig,
)
from recovery_manager import VerifiedRecoveryManager  # noqa: E402
from scripts import core_cutover_preflight as preflight  # noqa: E402


class ReplacementAdmissionTests(unittest.TestCase):
    candidate_build_id = "source-" + "2" * 24
    predecessor_build_id = "source-" + "1" * 24
    config_fingerprint = "3" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="synapse-replacement-admission-"
        )
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / "data"
        self.core = self.data / "core"
        self.data.mkdir(mode=0o700)
        self.core.mkdir(mode=0o700)
        self.data.chmod(0o700)
        self.core.chmod(0o700)
        self.memory_db = self.data / "memory.sqlite3"
        store = DurableMemoryStore(self.memory_db)
        seed = {"schema": "replacement-admission-test-key.v1"}
        store._authenticate_receipt(seed)
        self.auth_key_id = str(seed["auth_key_id"])
        store.close()
        self.receipt_path = self.root / "bundle.receipt.json"
        self.proof_path = self.root / "restore.proof.json"
        self.admission_path = self.core / preflight.REPLACEMENT_ADMISSION_NAME

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _marker(self) -> dict:
        return {
            "schema_version": 1,
            "service_required": True,
            "epoch": 7,
            "instance_id": "core-predecessor",
            "config_fingerprint": self.config_fingerprint,
            "build_id": self.predecessor_build_id,
            "protocol_version": "synapse-core.v1",
            "lock_generation_id": "lockfs-v1-a-b",
            "store_identity": "store-" + "4" * 24,
            "request_journal_id": "journal-" + "5" * 24,
            "request_journal_binding_schema": JOURNAL_BINDING_SCHEMA,
            "request_journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "root_generation_id": "generation-" + "6" * 24,
            "embedding_space_identity": "7" * 64,
            "restored_target_binding_receipt_digest": None,
            "claimed_at": 1_000.0,
            "updated_at": 1_001.0,
        }

    def _inspection(self) -> dict:
        marker = self._marker()
        marker_sha256 = DurableMemoryStore._core_authority_marker_sha256(marker)
        logical = {
            "schema": LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
            "sha256": "8" * 64,
            "schema_sha256": "9" * 64,
            "application_id": SQLITE_APPLICATION_ID,
            "user_version": SQLITE_USER_VERSION,
            "table_count": 20,
            "column_count": 100,
            "row_count": 500,
            "value_bytes": 1_024,
        }
        publication = {
            "schema": CORE_RUNTIME_PUBLICATION_SCHEMA,
            "status": "complete",
            "marker_sha256": marker_sha256,
            "authority_epoch_number": 7,
            "lock_generation_id": marker["lock_generation_id"],
            "instance_id": marker["instance_id"],
            "config_fingerprint": marker["config_fingerprint"],
            "build_id": marker["build_id"],
            "protocol_version": marker["protocol_version"],
            "runtime_state_path_sha256": "a" * 64,
            "started_at": 1_000.0,
            "completed_at": 1_001.0,
            "updated_at": 1_001.0,
        }
        return {
            "governance_mode": "authoritative-v6",
            "schema_identity": f"sqlite-{SQLITE_APPLICATION_ID:x}-v6",
            "previous_epoch": 7,
            "next_epoch": 8,
            "logical_snapshot": logical,
            "marker": marker,
            "runtime_publication": publication,
            "store_identity": marker["store_identity"],
            "new_empty_bootstrap": False,
        }

    def _provisional_inspection(self) -> dict:
        inspection = self._inspection()
        marker = inspection["marker"]
        marker["instance_id"] = (
            REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX + "resume-test"
        )
        publication = inspection["runtime_publication"]
        publication["instance_id"] = marker["instance_id"]
        publication["marker_sha256"] = (
            DurableMemoryStore._core_authority_marker_sha256(marker)
        )
        return inspection

    def _recovery(self) -> dict:
        marker = self._marker()
        return {
            "governance_mode": "authoritative-v6",
            "store_identity": marker["store_identity"],
            "store_generation": "epoch-7",
            "authority_epoch_number": 7,
            "database_schema_identity": f"sqlite-{SQLITE_APPLICATION_ID:x}-v6",
            "database_logical_snapshot_schema": LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
            "database_logical_snapshot_sha256": "8" * 64,
            "capture_manifest_sha256": "b" * 64,
            "recovery_pending_file_count": 0,
            "recovery_replay_required_file_count": 0,
            "recovery_replay_required_capture_count": 0,
            "runtime_state_required": True,
            "runtime_state_present": True,
            "runtime_state_canonical_sha256": "c" * 64,
            "request_journal_id": marker["request_journal_id"],
            "request_journal_schema_identity": JOURNAL_SCHEMA_IDENTITY,
            "request_journal_logical_snapshot_schema": (
                LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            ),
            "request_journal_logical_snapshot_sha256": "d" * 64,
            "request_journal_binding_receipt_digest": "e" * 64,
            "restored_target": False,
            "restored_target_binding_receipt_digest": None,
            "recovery_bundle_receipt_digest": "f" * 64,
            "recovery_restore_proof_receipt_digest": "0" * 64,
            "recovery_auth_key_id": self.auth_key_id,
        }

    @staticmethod
    def _delivery_audit() -> dict:
        return {
            "protocol_version": "context-delivery-publication-repair.v1",
            "status": "ready",
            "audit_revision": "1" * 64,
            "settled_audit_revision": "2" * 64,
            "repair_required": False,
            "repairable": True,
            "cursor_mismatch_count": 0,
            "target_reconciliation_needed": False,
            "target_highwater": 12,
            "latest_event_id": 12,
            "delivery_schema_error_count": 0,
            "unrelated_delivery_error_count": 0,
            "target_canonicalization_needed": False,
            "target_integrity_error_count": 0,
            "event_ledger_integrity_error_count": 0,
            "target_highwater_error_count": 0,
            "highwater_contract_error_count": 0,
            "derivation_source_sha256": "3" * 64,
            "derivation_source_row_count": 44,
            "repair_receipt_integrity_error_count": 0,
            "repair_receipt_semantic_error_count": 0,
            "pending_repair_receipt_semantic_error_count": 0,
            "verified_repair_receipt_semantic_error_count": 0,
            "pending_repair_receipt_count": 0,
        }

    def _content(self, *, now: int) -> dict:
        return preflight._replacement_admission_content(
            created_at_unix_ms=now,
            expires_at_unix_ms=now + 300_000,
            git_head="a" * 40,
            candidate_build_id=self.candidate_build_id,
            candidate_config_fingerprint=self.config_fingerprint,
            receipt_path=self.receipt_path,
            restore_proof_path=self.proof_path,
            inspection=self._inspection(),
            delivery_audit=self._delivery_audit(),
            recovery=self._recovery(),
        )

    def _signed(self, content: dict) -> dict:
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        try:
            payload = copy.deepcopy(content)
            store._authenticate_receipt(payload)
            return payload
        finally:
            store.close()

    def test_closed_contract_accepts_exact_signed_build_only_successor(self) -> None:
        now = int(time.time() * 1000)
        content = self._content(now=now)
        payload = self._signed(content)
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        try:
            digest = preflight._validate_replacement_admission(
                payload,
                store=store,
                expected_content=content,
                expected_auth_key_id=self.auth_key_id,
                now_unix_ms=now,
                minimum_remaining_seconds=120,
            )
        finally:
            store.close()
        self.assertEqual(digest, payload["receipt_digest"])
        self.assertEqual(content["authority_epoch_number"], 7)
        self.assertEqual(content["next_authority_epoch_number"], 8)
        self.assertNotEqual(
            content["candidate_build_id"],
            content["predecessor_build_id"],
        )
        self.assertEqual(
            content["candidate_config_fingerprint"],
            content["predecessor_config_fingerprint"],
        )

    def test_contract_binds_exact_pending_capture_counts(self) -> None:
        now = int(time.time() * 1000)
        positive = self._content(now=now)
        positive.update(
            {
                "recovery_pending_file_count": 1,
                "recovery_replay_required_file_count": 1,
                "recovery_replay_required_capture_count": 1,
            }
        )
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        try:
            payload = self._signed(positive)
            self.assertEqual(
                preflight._validate_replacement_admission(
                    payload,
                    store=store,
                    expected_content=positive,
                    expected_auth_key_id=self.auth_key_id,
                    now_unix_ms=now,
                ),
                payload["receipt_digest"],
            )
            invalid_bindings = (
                {"recovery_pending_file_count": True},
                {"recovery_pending_file_count": -1},
                {
                    "recovery_pending_file_count": (
                        preflight.REPLACEMENT_ADMISSION_MAX_PENDING_FILES + 1
                    ),
                    "recovery_replay_required_file_count": (
                        preflight.REPLACEMENT_ADMISSION_MAX_PENDING_FILES + 1
                    ),
                    "recovery_replay_required_capture_count": (
                        preflight.REPLACEMENT_ADMISSION_MAX_PENDING_FILES + 1
                    ),
                },
                {"recovery_replay_required_file_count": 0},
                {"recovery_replay_required_capture_count": 0},
            )
            for override in invalid_bindings:
                with self.subTest(override=override):
                    invalid = {**positive, **override}
                    signed = self._signed(invalid)
                    with self.assertRaisesRegex(
                        preflight.CutoverPreflightError,
                        "values are invalid",
                    ):
                        preflight._validate_replacement_admission(
                            signed,
                            store=store,
                            expected_auth_key_id=self.auth_key_id,
                            now_unix_ms=now,
                        )
        finally:
            store.close()

    def test_contract_rejects_expiry_tampering_and_predecessor_drift(self) -> None:
        now = int(time.time() * 1000)
        content = self._content(now=now)
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        try:
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "values",
            ):
                preflight._validate_replacement_admission(
                    self._signed(
                        {
                            **content,
                            "expires_at_unix_ms": now + 30_000,
                        }
                    ),
                    store=store,
                    now_unix_ms=now,
                    minimum_remaining_seconds=120,
                )
            tampered = self._signed(content)
            tampered["database_logical_snapshot_sha256"] = "4" * 64
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "signature",
            ):
                preflight._validate_replacement_admission(
                    tampered,
                    store=store,
                    now_unix_ms=now,
                )
        finally:
            store.close()

        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        try:
            longest = {
                **content,
                "expires_at_unix_ms": now
                + int(preflight.REPLACEMENT_ADMISSION_MAX_TTL_SECONDS * 1000),
            }
            signed_longest = self._signed(longest)
            self.assertEqual(
                preflight._validate_replacement_admission(
                    signed_longest,
                    store=store,
                    now_unix_ms=now,
                ),
                signed_longest["receipt_digest"],
            )
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "values",
            ):
                preflight._validate_replacement_admission(
                    self._signed(
                        {
                            **longest,
                            "expires_at_unix_ms": longest[
                                "expires_at_unix_ms"
                            ]
                            + 1,
                        }
                    ),
                    store=store,
                    now_unix_ms=now,
                )
        finally:
            store.close()

        inspection = self._inspection()
        inspection["next_epoch"] = 9
        with self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "predecessor identity",
        ):
            preflight._replacement_admission_content(
                created_at_unix_ms=now,
                expires_at_unix_ms=now + 300_000,
                git_head="a" * 40,
                candidate_build_id=self.candidate_build_id,
                candidate_config_fingerprint=self.config_fingerprint,
                receipt_path=self.receipt_path,
                restore_proof_path=self.proof_path,
                inspection=inspection,
                delivery_audit=self._delivery_audit(),
                recovery=self._recovery(),
            )

    def test_same_build_requires_exact_provisional_predecessor(self) -> None:
        now = int(time.time() * 1000)
        ordinary = self._inspection()
        with self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "exact provisional resume",
        ):
            preflight._replacement_admission_content(
                created_at_unix_ms=now,
                expires_at_unix_ms=now + 300_000,
                git_head="a" * 40,
                candidate_build_id=self.predecessor_build_id,
                candidate_config_fingerprint=self.config_fingerprint,
                receipt_path=self.receipt_path,
                restore_proof_path=self.proof_path,
                inspection=ordinary,
                delivery_audit=self._delivery_audit(),
                recovery=self._recovery(),
            )

        forged = self._content(now=now)
        forged["candidate_build_id"] = self.predecessor_build_id
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        try:
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "values",
            ):
                preflight._validate_replacement_admission(
                    self._signed(forged),
                    store=store,
                    now_unix_ms=now,
                )
        finally:
            store.close()

        provisional = self._provisional_inspection()
        content = preflight._replacement_admission_content(
            created_at_unix_ms=now,
            expires_at_unix_ms=now + 300_000,
            git_head="a" * 40,
            candidate_build_id=self.predecessor_build_id,
            candidate_config_fingerprint=self.config_fingerprint,
            receipt_path=self.receipt_path,
            restore_proof_path=self.proof_path,
            inspection=provisional,
            delivery_audit=self._delivery_audit(),
            recovery=self._recovery(),
        )
        payload = self._signed(content)
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        try:
            digest = preflight._validate_replacement_admission(
                payload,
                store=store,
                expected_content=content,
                expected_auth_key_id=self.auth_key_id,
                now_unix_ms=now,
                minimum_remaining_seconds=120,
            )
        finally:
            store.close()
        self.assertEqual(digest, payload["receipt_digest"])
        self.assertEqual(
            content["candidate_build_id"],
            content["predecessor_build_id"],
        )
        self.assertTrue(
            content["predecessor_instance_id"].startswith(
                REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
            )
        )
        self.assertEqual(content["authority_epoch_number"], 7)
        self.assertEqual(content["next_authority_epoch_number"], 8)

    def test_publish_and_core_verify_recompute_every_live_binding(self) -> None:
        inspection = self._inspection()
        recovery = self._recovery()
        delivery = self._delivery_audit()
        recovery_expiry = time.time() + 3_600
        request = preflight.ReplacementAdmissionRequest(
            path=self.admission_path,
            build_id=self.candidate_build_id,
            config_fingerprint=self.config_fingerprint,
        )
        with (
            mock.patch.object(
                preflight,
                "_git_snapshot",
                return_value=("a" * 40, ""),
            ),
            mock.patch(
                "core_service._manifest_build_id",
                return_value=self.candidate_build_id,
            ),
            mock.patch.object(
                preflight,
                "_replacement_recovery_binding",
                return_value=(recovery, recovery_expiry),
            ) as verify_recovery,
            mock.patch.object(
                preflight,
                "_replacement_delivery_binding",
                return_value=delivery,
            ) as verify_delivery,
        ):
            published = preflight.publish_replacement_admission(
                request=request,
                root=ROOT,
                memory_db=self.memory_db,
                capture_root=self.data,
                recovery_bundle_receipt=self.receipt_path,
                recovery_restore_proof=self.proof_path,
                inspection=inspection,
                delivery_audit=delivery,
            )
            verified = preflight.verify_replacement_admission_for_core(
                root=ROOT,
                memory_db=self.memory_db,
                capture_root=self.data,
                attestation_path=self.admission_path,
                expected_build_id=self.candidate_build_id,
                expected_config_fingerprint=self.config_fingerprint,
                inspection=inspection,
                delivery_audit=delivery,
            )
        self.assertTrue(published["verified"])
        self.assertTrue(verified["verified"])
        self.assertEqual(
            verified["schema"],
            preflight.REPLACEMENT_ADMISSION_VERIFICATION_SCHEMA,
        )
        self.assertEqual(verified["receipt_digest"], published["receipt_digest"])
        self.assertEqual(stat.S_IMODE(self.admission_path.stat().st_mode), 0o600)
        self.assertGreaterEqual(verify_recovery.call_count, 2)
        self.assertGreaterEqual(verify_delivery.call_count, 2)
        persisted = json.loads(self.admission_path.read_text(encoding="utf-8"))
        self.assertEqual(
            hashlib.sha256(self.admission_path.read_bytes()).hexdigest(),
            published["artifact_sha256"],
        )
        self.assertEqual(
            persisted["predecessor_lock_generation_id"],
            inspection["marker"]["lock_generation_id"],
        )

    def test_publish_rejects_dirty_source_and_core_verify_rejects_live_drift(self) -> None:
        request = preflight.ReplacementAdmissionRequest(
            path=self.admission_path,
            build_id=self.candidate_build_id,
            config_fingerprint=self.config_fingerprint,
        )
        with mock.patch.object(
            preflight,
            "_git_snapshot",
            return_value=("a" * 40, " M core_service.py"),
        ), self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "clean repository",
        ):
            preflight.publish_replacement_admission(
                request=request,
                root=ROOT,
                memory_db=self.memory_db,
                capture_root=self.data,
                recovery_bundle_receipt=self.receipt_path,
                recovery_restore_proof=self.proof_path,
                inspection=self._inspection(),
                delivery_audit=self._delivery_audit(),
            )

        recovery = self._recovery()
        delivery = self._delivery_audit()
        with (
            mock.patch.object(
                preflight,
                "_git_snapshot",
                return_value=("a" * 40, ""),
            ),
            mock.patch(
                "core_service._manifest_build_id",
                return_value=self.candidate_build_id,
            ),
            mock.patch.object(
                preflight,
                "_replacement_recovery_binding",
                return_value=(recovery, time.time() + 3_600),
            ),
            mock.patch.object(
                preflight,
                "_replacement_delivery_binding",
                return_value=delivery,
            ),
        ):
            preflight.publish_replacement_admission(
                request=request,
                root=ROOT,
                memory_db=self.memory_db,
                capture_root=self.data,
                recovery_bundle_receipt=self.receipt_path,
                recovery_restore_proof=self.proof_path,
                inspection=self._inspection(),
                delivery_audit=delivery,
            )
            drifted = self._inspection()
            drifted["logical_snapshot"]["sha256"] = "4" * 64
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "verified recovery",
            ):
                preflight.verify_replacement_admission_for_core(
                    root=ROOT,
                    memory_db=self.memory_db,
                    capture_root=self.data,
                    attestation_path=self.admission_path,
                    expected_build_id=self.candidate_build_id,
                    expected_config_fingerprint=self.config_fingerprint,
                    inspection=drifted,
                    delivery_audit=delivery,
                )

    def test_replacement_recovery_rejects_mixed_v1_v2_capture_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="replacement-mixed-") as tmp:
            root = Path(tmp).resolve()
            root.chmod(0o700)
            memory_db = root / "memory.sqlite3"
            seed_store = DurableMemoryStore(memory_db)
            seed_store.close()
            authority = CoreAuthorityLease.acquire_core(
                memory_db,
                timeout_seconds=0.0,
                instance_id="replacement-mixed-test",
            )
            store = DurableMemoryStore.open_existing_for_core_maintenance(
                memory_db,
                authority_lease=authority,
            )
            try:
                manager = VerifiedRecoveryManager(store, capture_root=root)
                paths = manager.daemon.paths()
                manager.daemon._ensure_transport_dirs(paths)
                drop = write_capture_drop(
                    root=root,
                    context_id="replacement-mixed-test",
                    source_tag="replacement-session-boundary",
                    speaker="codex",
                    text=(
                        "A canonical v2 record must never conceal legacy replay work."
                    ),
                    capture_id="s2cap_92929292929292929292929292929292",
                )
                v2_record = json.loads(drop.read_text(encoding="utf-8"))
                drop.write_text(
                    json.dumps(
                        [
                            v2_record,
                            {
                                "version": 1,
                                "text": (
                                    "Identifierless legacy work cannot share a v2 file."
                                ),
                                "context_id": "replacement-mixed-test",
                                "source_tag": "legacy-replay",
                            },
                        ],
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                drop.chmod(0o600)

                with self.assertRaisesRegex(
                    ValueError,
                    "cannot mix v1 and v2",
                ):
                    with manager.guarded_recovery_transaction(
                        root / "replacement-mixed-restore",
                        purpose="replacement-admission",
                        replacement_pending_limit=1,
                    ):
                        self.fail(
                            "mixed capture versions reached replacement admission"
                        )
            finally:
                store.close()
                authority.close()

    def test_real_guarded_v6_recovery_publishes_and_reverifies(self) -> None:
        # Keep the Unix socket below macOS's short sockaddr_un limit even when
        # the main fixture receives a descriptive randomized prefix.
        short_root = tempfile.TemporaryDirectory(prefix="ra-")
        self.addCleanup(short_root.cleanup)
        state_root = Path(short_root.name).resolve()
        state_root.chmod(0o700)
        config = CoreConfig(
            socket_path=state_root / "core" / "service.sock",
            state_path=state_root / "runtime_state.json",
            memory_path=state_root / "memory.sqlite3",
            capture_root=state_root,
            dimension=8,
            num_neurons=8,
            default_top_k=4,
            recall_count=2,
            authority_timeout_seconds=0.0,
            capture_poll_seconds=0.25,
        )
        first = AuthoritativeCoreService(config)
        first.start()
        daemon = CaptureInboxDaemon(root=state_root)
        transport_paths = daemon.paths()
        daemon._ensure_transport_dirs(transport_paths)
        cleanup_capture_id = "s2cap_90909090909090909090909090909090"
        cleanup_drop = write_capture_drop(
            root=state_root,
            context_id="replacement-pending-test",
            source_tag="replacement-cleanup-boundary",
            speaker="codex",
            text=(
                "A crash after the ledger commit must resume transport cleanup "
                "without writing the capture twice."
            ),
            capture_id=cleanup_capture_id,
        )
        initial_deadline = time.monotonic() + 5.0
        while time.monotonic() < initial_deadline:
            initial_status = daemon.status()
            if (
                initial_status["pending_file_count"] == 0
                and initial_status["processing_file_count"] == 0
                and initial_status["processed_file_count"] == 1
            ):
                break
            time.sleep(0.05)
        else:
            self.fail("initial core did not commit the cleanup fixture")
        first.close()
        self.assertFalse(cleanup_drop.exists())
        cleanup_receipt = (
            transport_paths["receipt_dir"] / f"{cleanup_capture_id}.json"
        )
        self.assertTrue(cleanup_receipt.exists())
        cleanup_receipt_bytes = cleanup_receipt.read_bytes()
        cleanup_receipt.unlink()
        processed_payloads = daemon._capture_files(
            transport_paths["processed_dir"]
        )
        self.assertEqual(len(processed_payloads), 1)
        cleanup_requeue = (
            transport_paths["inbox_dir"] / "cleanup-after-ledger.json"
        )
        os.replace(processed_payloads[0], cleanup_requeue)
        cleanup_claim = daemon._claim_inbox_file(
            inbox_path=cleanup_requeue,
            inbox_dir=transport_paths["inbox_dir"],
            processing_dir=transport_paths["processing_dir"],
        )
        self.assertIsNotNone(cleanup_claim)
        cleanup_claim_dir, cleanup_claim_path = cleanup_claim
        maintenance_lock = (
            transport_paths["lock_dir"] / ".capture-maintenance.lock"
        )
        maintenance_lock.write_bytes(b"")
        maintenance_lock.chmod(0o600)
        pending_capture_id = "s2cap_91919191919191919191919191919191"
        pending_drop = write_capture_drop(
            root=state_root,
            context_id="replacement-pending-test",
            source_tag="replacement-session-boundary",
            speaker="codex",
            text=(
                "The replacement core must drain this signed pending capture "
                "exactly once after it claims provisional authority."
            ),
            capture_id=pending_capture_id,
        )
        claimed = daemon._claim_inbox_file(
            inbox_path=pending_drop,
            inbox_dir=transport_paths["inbox_dir"],
            processing_dir=transport_paths["processing_dir"],
        )
        self.assertIsNotNone(claimed)
        pending_claim_dir, pending_claim_path = claimed
        candidate_build_id = "source-" + "d" * 24
        admission_path = state_root / "core" / preflight.REPLACEMENT_ADMISSION_NAME
        restore_root = state_root / "replacement-restore"

        authority = CoreAuthorityLease.acquire_core(
            config.memory_path,
            timeout_seconds=0.0,
            instance_id="replacement-publication-test",
        )
        store = DurableMemoryStore.open_existing_for_core_maintenance(
            config.memory_path,
            authority_lease=authority,
        )
        try:
            inspection = store.inspect_core_authority_preclaim()
            delivery = store.audit_context_delivery_publication_repair()
            manager = VerifiedRecoveryManager(
                store,
                capture_root=state_root,
                runtime_state_path=config.state_path,
            )
            cleanup_receipt.write_bytes(cleanup_receipt_bytes)
            cleanup_receipt.chmod(0o600)
            with self.assertRaisesRegex(
                RuntimeError,
                "unsupported replay work",
            ):
                with manager.guarded_recovery_transaction(
                    state_root / "receipt-backed-restore",
                    purpose="replacement-admission",
                    replacement_pending_limit=2,
                ):
                    self.fail("receipt-backed queued work reached admission")
            cleanup_receipt.unlink()

            cleanup_original = cleanup_claim_path.read_bytes()
            cleanup_payload = json.loads(cleanup_original.decode("utf-8"))
            cleanup_payload["source_tag"] = "mismatched-cleanup-binding"
            cleanup_claim_path.write_text(
                json.dumps(cleanup_payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            cleanup_claim_path.chmod(0o600)
            with self.assertRaisesRegex(
                RuntimeError,
                "authoritative ledger binding",
            ):
                with manager.guarded_recovery_transaction(
                    state_root / "mismatched-binding-restore",
                    purpose="replacement-admission",
                    replacement_pending_limit=2,
                ):
                    self.fail("mismatched cleanup claim reached admission")
            cleanup_claim_path.write_bytes(cleanup_original)
            cleanup_claim_path.chmod(0o600)
            strict_bundle = state_root / "strict-pending.sqlite3"
            strict_restore = state_root / "strict-pending-restore"
            with self.assertRaisesRegex(
                RuntimeError,
                "capture transport is not quiescent",
            ):
                with manager.guarded_recovery_transaction(
                    strict_restore,
                    path=strict_bundle,
                    purpose="operator-certification",
                ):
                    self.fail("ordinary guarded recovery admitted pending work")
            self.assertFalse(strict_bundle.exists())
            self.assertFalse(strict_restore.exists())
            with manager.guarded_recovery_transaction(
                restore_root,
                purpose="replacement-admission",
                pinned=True,
                replacement_pending_limit=2,
            ) as publication:
                self.assertFalse(publication.evidence["cutover_ready"])
                self.assertTrue(
                    publication.evidence["replacement_stage_ready"]
                )
                self.assertEqual(
                    publication.evidence["pending_file_count"],
                    2,
                )
                expected_debt = {
                    "replay_required_capture_count": 1,
                    "replay_required_file_count": 1,
                    "identifierless_replay_file_count": 0,
                    "unclassified_file_count": 0,
                    "missing_authoritative_ledger_count": 0,
                }
                for evidence_key in ("bundle", "verification", "restore"):
                    observed = publication.evidence[evidence_key][
                        "reconciliation"
                    ]
                    self.assertEqual(
                        {key: observed[key] for key in expected_debt},
                        expected_debt,
                    )
                self.assertEqual(
                    publication.evidence["verification"][
                        "capture_pending_state"
                    ],
                    {
                        "pending_file_count": 2,
                        "replay_required_file_count": 1,
                        "replay_required_capture_count": 1,
                        "receipt_backed_file_count": 0,
                        "canonical_v2": True,
                    },
                )

                def publish(evidence: dict) -> dict:
                    return preflight.publish_replacement_admission(
                        request=preflight.ReplacementAdmissionRequest(
                            path=admission_path,
                            build_id=candidate_build_id,
                            config_fingerprint=config.fingerprint,
                            expected_pending_file_count=2,
                            expected_replay_required_file_count=1,
                        ),
                        root=ROOT,
                        memory_db=config.memory_path,
                        capture_root=state_root,
                        recovery_bundle_receipt=Path(
                            evidence["bundle"]["bundle_receipt_path"]
                        ),
                        recovery_restore_proof=Path(
                            evidence["restore"]["recovery_proof_path"]
                        ),
                        inspection=inspection,
                        delivery_audit=delivery,
                    )

                with (
                    mock.patch.object(
                        preflight,
                        "_git_snapshot",
                        return_value=("a" * 40, ""),
                    ),
                    mock.patch(
                        "core_service._manifest_build_id",
                        return_value=candidate_build_id,
                    ),
                ):
                    published = publication.publish(publish)
        finally:
            store.close()
            authority.close()

        successor = None
        try:
            with (
                mock.patch.object(
                    preflight,
                    "_git_snapshot",
                    return_value=("a" * 40, ""),
                ),
                mock.patch(
                    "core_service._manifest_build_id",
                    return_value=candidate_build_id,
                ),
                mock.patch(
                    "core_service._source_build_id",
                    return_value=candidate_build_id,
                ),
                mock.patch.dict(
                    os.environ,
                    {REPLACEMENT_ADMISSION_ENV: "1"},
                ),
            ):
                successor = AuthoritativeCoreService(config)
                successor.start()
                drain_deadline = time.monotonic() + 5.0
                while time.monotonic() < drain_deadline:
                    drained_status = CaptureInboxDaemon(root=state_root).status()
                    if (
                        drained_status["pending_file_count"] == 0
                        and drained_status["processing_file_count"] == 0
                    ):
                        break
                    time.sleep(0.05)
                else:
                    self.fail("provisional core did not drain admitted capture")
                health = successor._health_result()
                with closing(sqlite3.connect(config.memory_path)) as connection:
                    successor_marker = json.loads(
                        connection.execute(
                            "SELECT value_json FROM store_metadata "
                            "WHERE key = 'core_authority'"
                        ).fetchone()[0]
                    )
        finally:
            if successor is not None:
                successor.close()
        self.assertTrue(published["verified"])
        self.assertEqual(published["recovery_pending_file_count"], 2)
        self.assertEqual(published["recovery_replay_required_file_count"], 1)
        self.assertEqual(published["recovery_replay_required_capture_count"], 1)
        self.assertFalse(pending_drop.exists())
        self.assertFalse(pending_claim_path.exists())
        self.assertFalse(pending_claim_dir.exists())
        self.assertFalse(cleanup_claim_path.exists())
        self.assertFalse(cleanup_claim_dir.exists())
        self.assertEqual(drained_status["pending_file_count"], 0)
        self.assertEqual(drained_status["processing_file_count"], 0)
        self.assertEqual(drained_status["processed_file_count"], 2)
        self.assertEqual(drained_status["receipt_count"], 2)
        self.assertEqual(drained_status["error_file_count"], 0)
        self.assertEqual(drained_status["unresolved_error_count"], 0)
        self.assertEqual(drained_status["unsafe_error_artifact_count"], 0)
        self.assertTrue(health["capture"]["ready"])
        self.assertGreaterEqual(health["capture"]["iteration_count"], 1)
        self.assertEqual(health["capture"]["processed_count"], 2)
        self.assertEqual(health["capture"]["error_count"], 0)
        audit_store = DurableMemoryStore.open_existing_for_audit(
            config.memory_path
        )
        try:
            captured = audit_store.get_capture_operation(pending_capture_id)
            cleanup_captured = audit_store.get_capture_operation(
                cleanup_capture_id
            )
        finally:
            audit_store.close()
        self.assertIsNotNone(captured)
        self.assertEqual(captured["capture_id"], pending_capture_id)
        self.assertIsNotNone(cleanup_captured)
        self.assertEqual(cleanup_captured["capture_id"], cleanup_capture_id)
        with closing(sqlite3.connect(config.memory_path)) as connection:
            capture_rows = connection.execute(
                "SELECT COUNT(*), COUNT(DISTINCT deployment_event_id), "
                "SUM(CASE WHEN deployment_event_id IS NOT NULL THEN 1 ELSE 0 END) "
                "FROM capture_operations WHERE capture_id = ?",
                (pending_capture_id,),
            ).fetchone()
        self.assertEqual(capture_rows, (1, 1, 1))
        self.assertTrue(health["ready"])
        self.assertEqual(
            health["deployment_mode"],
            REPLACEMENT_CERTIFICATION_MODE,
        )
        self.assertEqual(
            health["replacement_admission_receipt_digest"],
            published["receipt_digest"],
        )
        self.assertEqual(successor_marker["epoch"], 2)
        self.assertEqual(successor_marker["build_id"], candidate_build_id)
        self.assertTrue(
            successor_marker["instance_id"].startswith(
                REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
            )
        )

        resume_authority = CoreAuthorityLease.acquire_core(
            config.memory_path,
            timeout_seconds=0.0,
            instance_id="replacement-resume-publication-test",
        )
        resume_store = DurableMemoryStore.open_existing_for_core_maintenance(
            config.memory_path,
            authority_lease=resume_authority,
        )
        try:
            resume_inspection = resume_store.inspect_core_authority_preclaim()
            resume_delivery = (
                resume_store.audit_context_delivery_publication_repair()
            )
            self.assertEqual(
                resume_inspection["marker"]["build_id"],
                candidate_build_id,
            )
            self.assertTrue(
                resume_inspection["marker"]["instance_id"].startswith(
                    REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
                )
            )

            # The admission that claimed epoch 2 cannot be replayed against
            # the new marker/snapshot.  A resume requires new recovery and a
            # newly signed ticket bound to this exact provisional predecessor.
            with (
                mock.patch.object(
                    preflight,
                    "_git_snapshot",
                    return_value=("a" * 40, ""),
                ),
                mock.patch(
                    "core_service._manifest_build_id",
                    return_value=candidate_build_id,
                ),
                self.assertRaises(preflight.CutoverPreflightError),
            ):
                preflight.verify_replacement_admission_for_core(
                    root=ROOT,
                    memory_db=config.memory_path,
                    capture_root=state_root,
                    attestation_path=admission_path,
                    expected_build_id=candidate_build_id,
                    expected_config_fingerprint=config.fingerprint,
                    inspection=resume_inspection,
                    delivery_audit=resume_delivery,
                )

            resume_manager = VerifiedRecoveryManager(
                resume_store,
                capture_root=state_root,
                runtime_state_path=config.state_path,
            )
            with resume_manager.guarded_recovery_transaction(
                state_root / "replacement-resume-restore",
                purpose="replacement-provisional-resume-test",
                pinned=True,
            ) as resume_publication:

                def publish_resume(evidence: dict) -> dict:
                    return preflight.publish_replacement_admission(
                        request=preflight.ReplacementAdmissionRequest(
                            path=admission_path,
                            build_id=candidate_build_id,
                            config_fingerprint=config.fingerprint,
                        ),
                        root=ROOT,
                        memory_db=config.memory_path,
                        capture_root=state_root,
                        recovery_bundle_receipt=Path(
                            evidence["bundle"]["bundle_receipt_path"]
                        ),
                        recovery_restore_proof=Path(
                            evidence["restore"]["recovery_proof_path"]
                        ),
                        inspection=resume_inspection,
                        delivery_audit=resume_delivery,
                    )

                with (
                    mock.patch.object(
                        preflight,
                        "_git_snapshot",
                        return_value=("a" * 40, ""),
                    ),
                    mock.patch(
                        "core_service._manifest_build_id",
                        return_value=candidate_build_id,
                    ),
                ):
                    resume_published = resume_publication.publish(
                        publish_resume
                    )

            with (
                mock.patch.object(
                    preflight,
                    "_git_snapshot",
                    return_value=("a" * 40, ""),
                ),
                mock.patch(
                    "core_service._manifest_build_id",
                    return_value=candidate_build_id,
                ),
            ):
                resume_verified = (
                    preflight.verify_replacement_admission_for_core(
                        root=ROOT,
                        memory_db=config.memory_path,
                        capture_root=state_root,
                        attestation_path=admission_path,
                        expected_build_id=candidate_build_id,
                        expected_config_fingerprint=config.fingerprint,
                        inspection=resume_inspection,
                        delivery_audit=resume_delivery,
                    )
                )
        finally:
            resume_store.close()
            resume_authority.close()
        self.assertTrue(resume_published["verified"])
        self.assertTrue(resume_verified["verified"])
        self.assertNotEqual(
            resume_published["receipt_digest"],
            published["receipt_digest"],
        )
        self.assertEqual(
            resume_published["candidate_build_id"],
            resume_published["predecessor_build_id"],
        )
        self.assertEqual(resume_verified["authority_epoch_number"], 2)
        self.assertEqual(resume_verified["next_authority_epoch_number"], 3)
        self.assertTrue(
            resume_verified["predecessor_instance_id"].startswith(
                REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
            )
        )


if __name__ == "__main__":
    unittest.main()

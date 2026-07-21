from __future__ import annotations

import hashlib
import copy
import base64
import json
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core_authority import CoreAuthorityLease
from core_request_journal import CoreRequestJournal
from memory_store import DurableMemoryStore
from recovery_manager import VerifiedRecoveryManager
from replication_manager import ReplicationManager
from replication_protocol import (
    AUTH_FIELDS,
    ReplicationProtocolError,
    checkpoint_id_for,
    read_private_json,
    sign_payload,
    validate_ack,
    validate_checkpoint,
    validate_node_descriptor,
    write_private_json_exclusive,
)
from replication_store import ReplicationLedger


class ReplicationManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_BACKUP_MIN_FREE_BYTES": "0",
                "SYNAPSE_S2_BACKUP_COPY_RESERVE_BYTES": "0",
                "SYNAPSE_S2_REPLICATION_MIN_FREE_BYTES": "0",
            },
            clear=False,
        )
        self.environment.start()
        self.stores: list[DurableMemoryStore] = []
        self.authorities: list[CoreAuthorityLease] = []
        self.journals: list[CoreRequestJournal] = []

    def tearDown(self) -> None:
        for journal in reversed(self.journals):
            journal.close()
        for store in reversed(self.stores):
            store.close()
        for authority in reversed(self.authorities):
            authority.close()
        self.environment.stop()
        self.temporary.cleanup()

    def manager(self, name: str) -> ReplicationManager:
        root = self.root / name
        root.mkdir(mode=0o700)
        db_path = root / "memory.sqlite3"
        authority = CoreAuthorityLease.acquire_core(
            db_path,
            timeout_seconds=0.0,
            instance_id=f"replication-test-{name}",
        )
        store = DurableMemoryStore(db_path, authority_lease=authority)
        inspection = store.inspect_core_authority_preclaim()
        previous_epoch = int(inspection["previous_epoch"])
        journal = CoreRequestJournal(
            root / "core" / "requests.sqlite3",
            authority_epoch=f"epoch-{previous_epoch + 1}",
            store_identity=str(inspection["store_identity"]),
        )
        binding = journal.binding()
        store.claim_core_authority(
            instance_id=authority.instance_id,
            config_fingerprint=hashlib.sha256(name.encode("utf-8")).hexdigest(),
            build_id="replication-test",
            protocol_version="synapse-core.v1",
            expected_store_identity=str(inspection["store_identity"]),
            request_journal_id=str(binding["journal_id"]),
            request_journal_binding_schema=str(binding["schema"]),
            request_journal_schema_version=int(binding["journal_schema_version"]),
            expected_preclaim_logical_snapshot_sha256=str(
                inspection["logical_snapshot"]["sha256"]
            ),
            expected_previous_epoch=previous_epoch,
            expected_next_epoch=previous_epoch + 1,
            root_generation_id="generation-" + hashlib.sha256(name.encode()).hexdigest()[:24],
            embedding_space_identity=hashlib.sha256((name + "-embedding").encode()).hexdigest(),
            attestation_receipt_digest="b" * 64,
            attestation_expires_at_unix_ms=int(time.time() * 1000) + 60_000,
        )
        runtime_state = root / "runtime_state.json"
        runtime_state.write_text(
            json.dumps(
                {
                    "version": 2,
                    "global_enabled": True,
                    "context_overrides": {},
                    "cortex_sessions": {},
                    "runtime_state_repair": {},
                    "memory_db_path": str(db_path),
                    "updated_at": 100.0,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        runtime_state.chmod(0o600)
        capture_state = root / "capture_daemon_state.json"
        capture_state.write_text(
            '{"schema":"replication-test-capture-state.v1","status":"ready"}\n',
            encoding="utf-8",
        )
        capture_state.chmod(0o600)
        self.authorities.append(authority)
        self.stores.append(store)
        self.journals.append(journal)
        recovery = VerifiedRecoveryManager(store, capture_root=root)
        return ReplicationManager(store, recovery_manager=recovery)

    @staticmethod
    def pair(
        source: ReplicationManager,
        receiver: ReplicationManager,
        *,
        lineage_id: str | None = None,
    ) -> str:
        lineage = lineage_id or source.new_lineage_id()
        source.pair_peer(
            receiver.node_descriptor(),
            lineage_id=lineage,
            direction="send",
            expected_descriptor_digest=str(
                receiver.node_descriptor()["receipt_digest"]
            ),
            confirm=True,
        )
        receiver.pair_peer(
            source.node_descriptor(),
            lineage_id=lineage,
            direction="receive",
            expected_descriptor_digest=str(source.node_descriptor()["receipt_digest"]),
            confirm=True,
        )
        return lineage

    def signed_variant(
        self,
        source: ReplicationManager,
        exported: dict[str, object],
        *,
        name: str,
        changes: dict[str, object],
    ) -> Path:
        original_root = Path(str(exported["checkpoint_directory"]))
        original = read_private_json(Path(str(exported["manifest_path"])))
        unsigned = {key: value for key, value in original.items() if key not in AUTH_FIELDS}
        unsigned.update(changes)
        variant = sign_payload(source.store, unsigned)
        validate_checkpoint(variant)
        root = self.root / name
        root.mkdir(mode=0o700)
        for record in variant["artifacts"]:
            source_path = original_root / str(record["name"])
            destination = root / str(record["name"])
            destination.write_bytes(source_path.read_bytes())
            destination.chmod(0o600)
        path = root / "checkpoint.manifest.json"
        write_private_json_exclusive(source.store, path, variant)
        return path

    def test_signed_descriptor_pairing_requires_confirmation_and_pins_identity(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        descriptor = receiver.node_descriptor()
        validated = validate_node_descriptor(descriptor)
        self.assertEqual(validated["node_id"], receiver.node_id)
        lineage = source.new_lineage_id()
        with self.assertRaisesRegex(ValueError, "confirm=true"):
            source.pair_peer(
                descriptor,
                lineage_id=lineage,
                direction="send",
                expected_descriptor_digest=str(descriptor["receipt_digest"]),
            )
        paired = source.pair_peer(
            descriptor,
            lineage_id=lineage,
            direction="send",
            expected_descriptor_digest=str(descriptor["receipt_digest"]),
            confirm=True,
        )
        replay = source.pair_peer(
            descriptor,
            lineage_id=lineage,
            direction="send",
            expected_descriptor_digest=str(descriptor["receipt_digest"]),
            confirm=True,
        )
        self.assertEqual(paired, replay)
        tampered = dict(descriptor)
        tampered["created_at"] = float(tampered["created_at"]) + 1.0
        with self.assertRaises(ReplicationProtocolError):
            validate_node_descriptor(tampered)

    def test_pairing_requires_reviewed_descriptor_digest_and_returns_deep_copies(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        descriptor = receiver.node_descriptor()
        with self.assertRaisesRegex(ReplicationProtocolError, "reviewed fingerprint"):
            source.pair_peer(
                descriptor,
                lineage_id=source.new_lineage_id(),
                direction="send",
                expected_descriptor_digest="f" * 64,
                confirm=True,
            )
        descriptor["capabilities"].append("mutated-by-caller")
        self.assertNotIn("mutated-by-caller", receiver.node_descriptor()["capabilities"])

    def test_round_trip_stages_isolated_restore_and_records_ack_idempotently(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        lineage = self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        self.assertEqual(exported["lineage_id"], lineage)
        self.assertTrue(exported["memory_recovery_cutover_ready"])
        self.assertFalse(exported["replication_promotion_ready"])
        self.assertFalse(exported["promotion_supported"])
        self.assertFalse(exported["live_overwrite_performed"])
        self.assertNotIn("cutover_ready", exported)
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(staged["verified"])
        self.assertTrue(staged["memory_recovery_cutover_ready"])
        self.assertFalse(staged["replication_promotion_ready"])
        self.assertFalse(staged["promotion_supported"])
        self.assertFalse(staged["live_overwrite_performed"])
        self.assertNotIn("cutover_ready", staged)
        acknowledgement = read_private_json(Path(staged["ack_path"]))
        self.assertTrue(acknowledgement["memory_recovery_cutover_ready"])
        self.assertNotIn("cutover_ready", acknowledgement)
        self.assertTrue(Path(staged["restore_root"]).is_dir())
        replay = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["ack_digest"], staged["ack_digest"])
        self.assertTrue(replay["memory_recovery_cutover_ready"])
        self.assertFalse(replay["replication_promotion_ready"])
        self.assertFalse(replay["promotion_supported"])
        self.assertFalse(replay["live_overwrite_performed"])
        self.assertNotIn("cutover_ready", replay)
        recorded = source.record_acknowledgement(staged["ack_path"])
        self.assertEqual(recorded["state"], "acknowledged")
        recorded_replay = source.record_acknowledgement(staged["ack_path"])
        self.assertTrue(recorded_replay["idempotent_replay"])
        source_status = source.status()
        receiver_status = receiver.status()
        self.assertEqual(source_status["checkpoint_counts"]["outgoing:acknowledged"], 1)
        self.assertEqual(receiver_status["checkpoint_counts"]["incoming:staged"], 1)
        self.assertEqual(receiver_status["acknowledgement_count"], 1)
        self.assertEqual(source_status["integrity"]["state"], "ready")
        self.assertEqual(receiver_status["integrity"]["state"], "ready")
        for status in (source_status, receiver_status):
            self.assertFalse(status["memory_recovery_cutover_ready"])
            self.assertFalse(status["replication_promotion_ready"])
            self.assertFalse(status["promotion_supported"])
            self.assertFalse(status["live_overwrite_performed"])
            self.assertNotIn("cutover_ready", status)
            self.assertNotIn("cutover_ready", status["integrity"])
            self.assertEqual(
                status["ack_policy"],
                "receiver-signs-after-memory-recovery-ready-proof",
            )

    def test_checkpoint_contract_rejects_bool_counts_reserved_manifest_and_v5(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        original = read_private_json(Path(exported["manifest_path"]))
        unsigned = {key: value for key, value in original.items() if key not in AUTH_FIELDS}
        variants: list[tuple[str, dict[str, object]]] = []
        bool_count = copy.deepcopy(unsigned)
        bool_count["artifact_count"] = True
        variants.append(("artifact count", bool_count))
        reserved = copy.deepcopy(unsigned)
        reserved["artifacts"][0]["name"] = "checkpoint.manifest.json"
        variants.append(("reserved", reserved))
        legacy = copy.deepcopy(unsigned)
        legacy["governance_mode"] = "pre-governed-v5"
        legacy["store_generation"] = "legacy-v5"
        legacy["authority_epoch_number"] = None
        variants.append(("authority epoch|authoritative-v6", legacy))
        for message, payload in variants:
            with self.subTest(message=message):
                signed = sign_payload(source.store, payload)
                with self.assertRaisesRegex(ReplicationProtocolError, message):
                    validate_checkpoint(signed)

    def test_one_exported_checkpoint_is_replayed_until_acknowledged(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        first = source.create_checkpoint(receiver.node_id)
        replay = source.create_checkpoint(receiver.node_id)
        self.assertEqual(replay["sequence"], 1)
        self.assertEqual(replay["checkpoint_digest"], first["checkpoint_digest"])
        self.assertTrue(replay["recovered_publication"])

    def test_neutral_high_water_remains_backup_secret_safe(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        conn = source.store._connect_read_only()
        try:
            row = conn.execute(
                "SELECT value_json FROM store_metadata WHERE key = ?",
                ("replication_ledger_neutral_high_water.v1",),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        assert row is not None
        self.assertTrue(str(row["value_json"]).isdigit())
        exported = source.create_checkpoint(receiver.node_id)
        manifest = read_private_json(Path(exported["manifest_path"]))
        verified = source._verify_recovery_checkpoint(
            received_root=Path(exported["checkpoint_directory"]),
            checkpoint=manifest,
        )
        self.assertTrue(verified["cutover_ready"])
        self.assertTrue(verified["verified"])

    def test_signed_anchor_rejects_direct_checkpoint_ledger_rollback(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        with closing(sqlite3.connect(source.ledger.path)) as conn:
            conn.execute(
                "DELETE FROM checkpoints WHERE checkpoint_digest = ?",
                (exported["checkpoint_digest"],),
            )
            conn.commit()
        self.assertEqual(source.status()["integrity"]["state"], "degraded")
        with self.assertRaisesRegex(RuntimeError, "signed anchor"):
            source.create_checkpoint(receiver.node_id)

    def test_checkpoint_row_must_exactly_match_signed_manifest(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        lineage = self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        manifest = read_private_json(Path(exported["manifest_path"]))
        with self.assertRaisesRegex(ReplicationProtocolError, "signed manifest"):
            source.ledger.record_checkpoint(
                checkpoint_digest=str(manifest["receipt_digest"]),
                checkpoint_id=str(manifest["checkpoint_id"]),
                lineage_id=lineage,
                direction="outgoing",
                peer_id=receiver.node_id,
                term=int(manifest["term"]),
                sequence=int(manifest["sequence"]) + 1,
                parent_checkpoint_digest=manifest["parent_checkpoint_digest"],
                bundle_receipt_digest=str(manifest["bundle_receipt_digest"]),
                source_store_identity=str(manifest["source_store_identity"]),
                store_generation=str(manifest["store_generation"]),
                authority_epoch_number=int(manifest["authority_epoch_number"]),
                manifest_path=str(exported["manifest_path"]),
                restore_root=None,
                state="exported",
                now=time.time(),
            )

    def test_signed_anchor_rejects_direct_ack_ledger_rollback(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        with closing(sqlite3.connect(receiver.ledger.path)) as conn:
            conn.execute(
                "DELETE FROM acknowledgements WHERE checkpoint_digest = ?",
                (exported["checkpoint_digest"],),
            )
            conn.commit()
        self.assertEqual(receiver.status()["integrity"]["state"], "degraded")
        with self.assertRaisesRegex(RuntimeError, "signed anchor"):
            receiver.stage_checkpoint(exported["manifest_path"])

    def test_same_position_different_signed_digest_revokes_peer_for_equivocation(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        receiver.stage_checkpoint(exported["manifest_path"])
        original = read_private_json(Path(exported["manifest_path"]))
        unsigned = {key: value for key, value in original.items() if key not in AUTH_FIELDS}
        unsigned["created_at"] = float(unsigned["created_at"]) + 1.0
        equivocation = sign_payload(source.store, unsigned)
        validate_checkpoint(equivocation)
        equivocation_root = self.root / "equivocation"
        equivocation_root.mkdir(mode=0o700)
        equivocation_path = equivocation_root / "checkpoint.manifest.json"
        write_private_json_exclusive(source.store, equivocation_path, equivocation)
        with self.assertRaisesRegex(ReplicationProtocolError, "equivocation"):
            receiver.stage_checkpoint(equivocation_path)
        peer = receiver.status()["peers"][0]
        self.assertTrue(peer["revoked"])

    def test_target_binding_rejects_checkpoint_on_another_paired_receiver(self):
        source = self.manager("source")
        intended = self.manager("intended")
        other = self.manager("other")
        lineage = self.pair(source, intended)
        other.pair_peer(
            source.node_descriptor(),
            lineage_id=lineage,
            direction="receive",
            expected_descriptor_digest=str(source.node_descriptor()["receipt_digest"]),
            confirm=True,
        )
        exported = source.create_checkpoint(intended.node_id)
        with self.assertRaisesRegex(ReplicationProtocolError, "target or lineage"):
            other.stage_checkpoint(exported["manifest_path"])

    def test_revoked_peer_and_wrong_directory_mode_are_rejected(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        checkpoint_root = Path(exported["checkpoint_directory"])
        checkpoint_root.chmod(0o755)
        with self.assertRaises(PermissionError):
            receiver.stage_checkpoint(exported["manifest_path"])
        checkpoint_root.chmod(0o700)
        receiver.revoke_peer(
            source.node_id,
            reason="operator-test-revocation",
            confirm=True,
        )
        with self.assertRaisesRegex(ReplicationProtocolError, "revoked"):
            receiver.stage_checkpoint(exported["manifest_path"])

    def test_disk_guard_rejects_before_copy_or_restore(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        with mock.patch.dict(
            os.environ,
            {"SYNAPSE_S2_REPLICATION_MIN_FREE_BYTES": str(2**63 - 1)},
            clear=False,
        ):
            with self.assertRaisesRegex(OSError, "insufficient free space"):
                receiver.stage_checkpoint(exported["manifest_path"])
        self.assertNotIn("incoming:staged", receiver.status()["checkpoint_counts"])

    def test_ledger_rejects_schema_extension(self):
        manager = self.manager("source")
        with closing(sqlite3.connect(manager.ledger.path)) as conn:
            conn.execute("CREATE TABLE injected(value TEXT)")
            conn.commit()
        self.assertEqual(manager.status()["integrity"]["state"], "degraded")

    def test_signed_anchor_rejects_peer_revocation_rollback(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        source.revoke_peer(
            receiver.node_id,
            reason="operator-revoked",
            confirm=True,
        )
        with closing(sqlite3.connect(source.ledger.path)) as conn:
            conn.execute(
                "UPDATE peers SET revoked = 0, revoke_reason = NULL WHERE peer_id = ?",
                (receiver.node_id,),
            )
            conn.commit()
        self.assertEqual(source.status()["integrity"]["state"], "degraded")
        with self.assertRaisesRegex(RuntimeError, "signed anchor"):
            source.create_checkpoint(receiver.node_id)

    def test_anchor_history_rejects_coordinated_sqlite_and_current_anchor_rollback(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        genesis_bytes = source.ledger.anchor_path.read_bytes()
        genesis = read_private_json(source.ledger.anchor_path)
        genesis_witness_bytes = source.ledger.witness_path.read_bytes()
        self.pair(source, receiver)
        with closing(sqlite3.connect(source.ledger.path)) as conn:
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM peers")
            conn.execute(
                """
                UPDATE ledger_meta
                SET anchor_revision = 0, anchor_digest = ?, previous_anchor_digest = NULL
                WHERE singleton = 1
                """,
                (str(genesis["receipt_digest"]),),
            )
            conn.commit()
        source.ledger.anchor_path.write_bytes(genesis_bytes)
        source.ledger.anchor_path.chmod(0o600)
        source.ledger.witness_path.write_bytes(genesis_witness_bytes)
        source.ledger.witness_path.chmod(0o600)
        for history_path in source.ledger.anchor_history_root.iterdir():
            if history_path.name != "anchor-00000000000000000000.receipt.json":
                history_path.unlink()
        conn = source.store._connect_read_only()
        try:
            self.assertGreater(
                int(source.ledger._read_neutral_high_water_conn(conn)),
                0,
            )
        finally:
            conn.close()
        self.assertEqual(source.status()["integrity"]["state"], "degraded")

    def test_missing_external_witness_fails_closed_after_nonempty_ledger(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        source.ledger.witness_path.unlink()
        status = source.status()
        self.assertEqual(status["integrity"]["state"], "degraded")
        self.assertFalse(status["memory_recovery_cutover_ready"])
        self.assertFalse(status["replication_promotion_ready"])
        self.assertFalse(status["promotion_supported"])
        self.assertFalse(status["live_overwrite_performed"])
        self.assertNotIn("cutover_ready", status)
        self.assertNotIn("cutover_ready", status["integrity"])

    def test_empty_genesis_can_recreate_missing_external_witness(self):
        manager = self.manager("source")
        manager.ledger.witness_path.unlink()
        status = manager.status()
        self.assertEqual(status["integrity"]["state"], "ready")
        self.assertFalse(status["memory_recovery_cutover_ready"])
        self.assertEqual(status["latest_checkpoint_count"], 0)
        witness = read_private_json(manager.ledger.witness_path)
        self.assertEqual(witness["anchor_revision"], 0)

    def test_committed_ledger_recovers_witness_before_anchor_publication(self):
        manager = self.manager("source")
        receiver = self.manager("receiver")
        descriptor = receiver.node_descriptor()
        original_advance = manager.ledger._advance_high_water_witness
        failed = {"value": False}

        def fail_once(anchor, **kwargs):
            if int(anchor["revision"]) > 0 and not failed["value"]:
                failed["value"] = True
                raise OSError("injected-witness-publication-failure")
            return original_advance(anchor, **kwargs)

        with mock.patch.object(
            manager.ledger,
            "_advance_high_water_witness",
            side_effect=fail_once,
        ):
            with self.assertRaisesRegex(OSError, "witness-publication"):
                manager.pair_peer(
                    descriptor,
                    lineage_id=manager.new_lineage_id(),
                    direction="send",
                    expected_descriptor_digest=str(descriptor["receipt_digest"]),
                    confirm=True,
                )
        self.assertTrue(manager.ledger.pending_anchor_path.is_file())
        self.assertEqual(
            read_private_json(manager.ledger.witness_path)["anchor_revision"],
            0,
        )
        self.assertEqual(manager.status()["integrity"]["state"], "ready")
        self.assertFalse(manager.ledger.pending_anchor_path.exists())
        self.assertGreater(
            read_private_json(manager.ledger.witness_path)["anchor_revision"],
            0,
        )

    def test_stale_signed_pending_anchor_never_advances_external_witness(self):
        manager = self.manager("source")
        genesis = read_private_json(manager.ledger.anchor_path)
        receiver = self.manager("receiver")
        self.pair(manager, receiver)
        write_private_json_exclusive(
            manager.store,
            manager.ledger.pending_anchor_path,
            genesis,
        )
        before = read_private_json(manager.ledger.witness_path)
        with mock.patch.object(
            manager.ledger,
            "_advance_high_water_witness",
            wraps=manager.ledger._advance_high_water_witness,
        ) as advance:
            self.assertEqual(manager.status()["integrity"]["state"], "ready")
        advance.assert_not_called()
        after = read_private_json(manager.ledger.witness_path)
        self.assertEqual(after["receipt_digest"], before["receipt_digest"])

    def test_normal_readiness_is_constant_history_lookup_and_full_audit_is_explicit(self):
        manager = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(manager, receiver)
        with mock.patch(
            "replication_store.os.scandir",
            side_effect=AssertionError("normal-readiness-scanned-history"),
        ):
            self.assertEqual(manager.status()["integrity"]["state"], "ready")
        audited = manager.ledger.audit_anchor_history(maximum=100)
        self.assertTrue(audited["full_chain_verified"])

    def test_status_reports_exact_peer_projection_beyond_display_limit(self):
        manager = self.manager("source")
        now = time.time()
        with manager.ledger._transaction() as conn:
            for index in range(129):
                public = Ed25519PrivateKey.generate().public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
                key_id = hashlib.sha256(public).hexdigest()
                conn.execute(
                    """
                    INSERT INTO peers(
                        peer_id, lineage_id, direction, signing_key_id,
                        signing_public_key, descriptor_digest, revoked,
                        revoke_reason, paired_at, updated_at
                    ) VALUES (?, ?, 'send', ?, ?, ?, 0, NULL, ?, ?)
                    """,
                    (
                        f"s2node_{key_id[:32]}",
                        f"s2lineage_{index:032x}",
                        key_id,
                        base64.b64encode(public).decode("ascii"),
                        hashlib.sha256(f"descriptor-{index}".encode()).hexdigest(),
                        now + index,
                        now + index,
                    ),
                )
        status = manager.status()
        self.assertEqual(status["integrity"]["state"], "ready")
        self.assertEqual(status["peer_count"], 129)
        self.assertEqual(status["peer_returned_count"], 128)
        self.assertTrue(status["peers_truncated"])
        self.assertEqual(status["peer_pagination"]["total"], 129)

    def test_status_uses_one_authenticated_ledger_snapshot(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        source.record_acknowledgement(staged["ack_path"])
        with mock.patch.object(
            source.ledger,
            "_open",
            wraps=source.ledger._open,
        ) as ledger_open:
            self.assertEqual(source.status()["integrity"]["state"], "ready")
        self.assertEqual(ledger_open.call_count, 1)

    def test_checkpoint_and_audit_rollback_retries_same_sequence(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        with mock.patch.object(
            ReplicationLedger,
            "_insert_audit_conn",
            side_effect=RuntimeError("injected-audit-failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected-audit-failure"):
                source.create_checkpoint(receiver.node_id)
        retried = source.create_checkpoint(receiver.node_id)
        self.assertEqual(retried["sequence"], 1)
        self.assertTrue(retried["verified"])

    def test_anchor_revision_exhaustion_rejects_before_mutation(self):
        manager = self.manager("source")
        current = read_private_json(manager.ledger.anchor_path)
        exhausted = dict(current)
        exhausted["revision"] = 100_000
        before = manager.ledger.status()["audit_event_count"]
        with mock.patch.object(
            manager.ledger,
            "_validate_anchor",
            return_value=exhausted,
        ):
            with self.assertRaisesRegex(RuntimeError, "revision is exhausted"):
                manager.ledger.audit(
                    action="exhaustion-test",
                    state="rejected",
                    detail_code="preflight",
                )
        self.assertEqual(manager.ledger.status()["audit_event_count"], before)

    def test_committed_ledger_transaction_recovers_pending_signed_anchor(self):
        manager = self.manager("source")
        receiver = self.manager("receiver")
        descriptor = receiver.node_descriptor()
        with mock.patch.object(
            manager.ledger,
            "_publish_pending_anchor",
            side_effect=OSError("injected-anchor-publication-failure"),
        ):
            with self.assertRaisesRegex(OSError, "anchor-publication"):
                manager.pair_peer(
                    descriptor,
                    lineage_id=manager.new_lineage_id(),
                    direction="send",
                    expected_descriptor_digest=str(descriptor["receipt_digest"]),
                    confirm=True,
                )
        self.assertTrue(manager.ledger.pending_anchor_path.is_file())
        pending = read_private_json(manager.ledger.pending_anchor_path)
        witness = read_private_json(manager.ledger.witness_path)
        self.assertEqual(witness["anchor_revision"], pending["revision"])
        self.assertEqual(witness["anchor_digest"], pending["receipt_digest"])
        status = manager.status()
        self.assertEqual(status["integrity"]["state"], "ready")
        self.assertFalse(manager.ledger.pending_anchor_path.exists())

    def test_incomplete_outgoing_directory_is_quarantined_without_skipping_sequence(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        lineage = self.pair(source, receiver)
        checkpoint_id = checkpoint_id_for(
            source_node_id=source.node_id,
            target_node_id=receiver.node_id,
            lineage_id=lineage,
            term=1,
            sequence=1,
        )
        lineage_root = source.outgoing_root / lineage
        source._ensure_private_directory(lineage_root)
        poisoned = lineage_root / checkpoint_id
        poisoned.mkdir(mode=0o700)
        partial = poisoned / "partial.tmp"
        partial.write_bytes(b"partial")
        partial.chmod(0o600)
        exported = source.create_checkpoint(receiver.node_id)
        self.assertEqual(exported["sequence"], 1)
        quarantined = list((source.quarantine_root / lineage).iterdir())
        self.assertEqual(len(quarantined), 1)
        self.assertTrue((quarantined[0] / "partial.tmp").is_file())

    def test_source_store_identity_and_authority_epoch_cannot_roll_back(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        lineage = self.pair(source, receiver)
        first = source.create_checkpoint(receiver.node_id)
        staged = receiver.stage_checkpoint(first["manifest_path"])
        source.record_acknowledgement(staged["ack_path"])
        second = source.create_checkpoint(receiver.node_id)
        forged_path = self.signed_variant(
            source,
            second,
            name="foreign-store-second",
            changes={"source_store_identity": "store-" + ("f" * 24)},
        )
        with self.assertRaisesRegex(ReplicationProtocolError, "identity or authority epoch"):
            receiver.stage_checkpoint(forged_path)

        staged_second = receiver.stage_checkpoint(second["manifest_path"])
        source.record_acknowledgement(staged_second["ack_path"])
        peer = source.ledger.peer(receiver.node_id)
        assert peer is not None

        def install_epoch_variant(
            *,
            sequence: int,
            parent_digest: str,
            authority_epoch: int,
        ) -> tuple[dict[str, object], Path]:
            original = read_private_json(Path(str(second["manifest_path"])))
            unsigned = {
                key: value for key, value in original.items() if key not in AUTH_FIELDS
            }
            checkpoint_id = checkpoint_id_for(
                source_node_id=source.node_id,
                target_node_id=receiver.node_id,
                lineage_id=lineage,
                term=1,
                sequence=sequence,
            )
            unsigned.update(
                {
                    "checkpoint_id": checkpoint_id,
                    "sequence": sequence,
                    "parent_checkpoint_digest": parent_digest,
                    "store_generation": f"epoch-{authority_epoch}",
                    "authority_epoch_number": authority_epoch,
                    "created_at": float(unsigned["created_at"]) + sequence,
                }
            )
            manifest = sign_payload(source.store, unsigned)
            validate_checkpoint(manifest)
            checkpoint_root = source.outgoing_root / lineage / checkpoint_id
            checkpoint_root.mkdir(mode=0o700)
            original_root = Path(str(second["checkpoint_directory"]))
            for record in manifest["artifacts"]:
                target = checkpoint_root / str(record["name"])
                target.write_bytes((original_root / str(record["name"])).read_bytes())
                target.chmod(0o600)
            manifest_path = checkpoint_root / "checkpoint.manifest.json"
            write_private_json_exclusive(source.store, manifest_path, manifest)
            return manifest, manifest_path

        epoch_two, epoch_two_path = install_epoch_variant(
            sequence=3,
            parent_digest=str(second["checkpoint_digest"]),
            authority_epoch=2,
        )
        source.ledger.record_checkpoint(
            checkpoint_digest=str(epoch_two["receipt_digest"]),
            checkpoint_id=str(epoch_two["checkpoint_id"]),
            lineage_id=lineage,
            direction="outgoing",
            peer_id=receiver.node_id,
            term=1,
            sequence=3,
            parent_checkpoint_digest=str(second["checkpoint_digest"]),
            bundle_receipt_digest=str(epoch_two["bundle_receipt_digest"]),
            source_store_identity=str(peer["source_store_identity"]),
            store_generation="epoch-2",
            authority_epoch_number=2,
            manifest_path=str(epoch_two_path),
            restore_root=None,
            state="exported",
            now=time.time(),
        )
        epoch_one, epoch_one_path = install_epoch_variant(
            sequence=4,
            parent_digest=str(epoch_two["receipt_digest"]),
            authority_epoch=1,
        )
        with self.assertRaisesRegex(ReplicationProtocolError, "rolled back"):
            source.ledger.record_checkpoint(
                checkpoint_digest=str(epoch_one["receipt_digest"]),
                checkpoint_id=str(epoch_one["checkpoint_id"]),
                lineage_id=lineage,
                direction="outgoing",
                peer_id=receiver.node_id,
                term=1,
                sequence=4,
                parent_checkpoint_digest=str(epoch_two["receipt_digest"]),
                bundle_receipt_digest=str(epoch_one["bundle_receipt_digest"]),
                source_store_identity=str(peer["source_store_identity"]),
                store_generation="epoch-1",
                authority_epoch_number=1,
                manifest_path=str(epoch_one_path),
                restore_root=None,
                state="exported",
                now=time.time(),
            )

    def test_staged_replay_revalidates_current_memory_journal_runtime_and_capture(self):
        def add_unmanifested_capture(root: Path) -> None:
            unexpected = root / "capture-root" / "unexpected.json"
            unexpected.write_text('{"capture_id":"s2cap_unmanifested"}', encoding="utf-8")
            unexpected.chmod(0o600)

        def mutate_signed_capture(root: Path) -> None:
            target = root / "capture-root" / "capture_daemon_state.json"
            target.write_text('{"status":"tampered"}\n', encoding="utf-8")
            target.chmod(0o600)

        def delete_signed_capture(root: Path) -> None:
            (root / "capture-root" / "capture_daemon_state.json").unlink()

        def symlink_signed_capture(root: Path) -> None:
            target = root / "capture-root" / "capture_daemon_state.json"
            escaped = self.root / f"escaped-{root.name}-capture-state.json"
            os.rename(target, escaped)
            os.symlink(escaped, target)

        cases = (
            ("memory", lambda root: (root / "memory.sqlite3").chmod(0o644)),
            (
                "journal",
                lambda root: (root / "core" / "requests.sqlite3").chmod(0o644),
            ),
            ("runtime", lambda root: (root / "runtime_state.json").chmod(0o644)),
            ("capture-mode", lambda root: (root / "capture-root").chmod(0o755)),
            ("capture-content", add_unmanifested_capture),
            ("capture-signed-mutation", mutate_signed_capture),
            ("capture-signed-delete", delete_signed_capture),
            ("capture-signed-symlink", symlink_signed_capture),
        )
        for index, (label, mutate) in enumerate(cases):
            with self.subTest(label=label):
                source = self.manager(f"source-{index}")
                receiver = self.manager(f"receiver-{index}")
                self.pair(source, receiver)
                exported = source.create_checkpoint(receiver.node_id)
                staged = receiver.stage_checkpoint(exported["manifest_path"])
                mutate(Path(staged["restore_root"]))
                with self.assertRaises((PermissionError, RuntimeError, ReplicationProtocolError)):
                    receiver.stage_checkpoint(exported["manifest_path"])
                self.assertEqual(
                    receiver.status()["integrity"]["state"], "degraded"
                )

    def test_restore_and_ack_replays_reject_symlinked_path_redirection(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        staged = receiver.stage_checkpoint(exported["manifest_path"])

        restore_root = Path(staged["restore_root"])
        escaped_restore = self.root / "escaped-restore"
        os.rename(restore_root, escaped_restore)
        os.symlink(escaped_restore, restore_root)
        with self.assertRaisesRegex(ReplicationProtocolError, "escapes"):
            receiver.stage_checkpoint(exported["manifest_path"])

        source.record_acknowledgement(staged["ack_path"])
        ack = read_private_json(Path(staged["ack_path"]))
        local_ack = (
            source.acks_root
            / str(ack["lineage_id"])
            / f"received-{ack['ack_id']}.json"
        )
        escaped_ack = self.root / "escaped-ack.json"
        os.rename(local_ack, escaped_ack)
        os.symlink(escaped_ack, local_ack)
        with self.assertRaisesRegex(ReplicationProtocolError, "escapes"):
            source.record_acknowledgement(staged["ack_path"])

    def test_valid_conflicting_ack_atomically_revokes_and_audits_peer(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        source.record_acknowledgement(staged["ack_path"])
        original = read_private_json(Path(staged["ack_path"]))
        unsigned = {key: value for key, value in original.items() if key not in AUTH_FIELDS}
        unsigned["acked_at"] = float(unsigned["acked_at"]) + 1.0
        conflict = sign_payload(receiver.store, unsigned)
        validate_ack(conflict)
        with self.assertRaisesRegex(ReplicationProtocolError, "equivocation"):
            source.record_acknowledgement(conflict)
        status = source.status()
        self.assertTrue(status["peers"][0]["revoked"])
        self.assertGreaterEqual(status["audit_event_count"], 1)

    def test_acknowledgement_cannot_bind_checkpoint_to_another_paired_peer(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        other = self.manager("other")
        self.pair(source, receiver)
        source.pair_peer(
            other.node_descriptor(),
            lineage_id=source.new_lineage_id(),
            direction="send",
            expected_descriptor_digest=str(
                other.node_descriptor()["receipt_digest"]
            ),
            confirm=True,
        )
        exported = source.create_checkpoint(receiver.node_id)
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        ack = read_private_json(Path(staged["ack_path"]))
        with self.assertRaisesRegex(ReplicationProtocolError, "peer does not match"):
            source.ledger.record_acknowledgement(
                ack_digest=str(ack["receipt_digest"]),
                ack_id=str(ack["ack_id"]),
                checkpoint_digest=str(ack["checkpoint_digest"]),
                peer_id=other.node_id,
                ack_path=str(staged["ack_path"]),
                now=float(ack["acked_at"]),
                checkpoint_state="acknowledged",
            )
        source.record_acknowledgement(staged["ack_path"])
        with source.ledger._transaction() as conn:
            conn.execute(
                "UPDATE acknowledgements SET peer_id = ? WHERE checkpoint_digest = ?",
                (other.node_id, str(exported["checkpoint_digest"])),
            )
        self.assertEqual(source.status()["integrity"]["state"], "degraded")

    def test_bounded_scandir_short_circuits_and_directory_fd_is_closed(self):
        counter = {"value": 0}

        class Entry:
            def __init__(self, name: str) -> None:
                self.name = name

        class Scan:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                counter["value"] += 1
                if counter["value"] > 100:
                    raise StopIteration
                return Entry(str(counter["value"]))

        with mock.patch("replication_manager.os.scandir", return_value=Scan()):
            with self.assertRaisesRegex(ReplicationProtocolError, "entry bound"):
                ReplicationManager._bounded_directory_names(999, 2)
        self.assertEqual(counter["value"], 3)

        manager = self.manager("source")
        guarded = self.root / "guarded"
        guarded.mkdir(mode=0o700)
        extra = guarded / "extra"
        extra.write_bytes(b"x")
        extra.chmod(0o600)
        with mock.patch("replication_manager.os.close", wraps=os.close) as closer:
            with self.assertRaises(ReplicationProtocolError):
                with manager._private_directory_guard(
                    guarded,
                    expected_names=set(),
                    maximum_entries=0,
                ):
                    pass
        closer.assert_called()

    def test_artifact_copy_closes_source_if_destination_open_fails_and_rejects_zero_write(self):
        manager = self.manager("source")
        source = self.root / "artifact-source"
        source.write_bytes(b"replication-artifact")
        source.chmod(0o600)
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        destination = self.root / "artifact-destination"
        real_open = os.open
        real_close = os.close
        source_descriptors: list[int] = []

        def fail_destination(path, flags, *args):
            if Path(path) == destination:
                raise OSError("injected-destination-open-failure")
            descriptor = real_open(path, flags, *args)
            if Path(path) == source:
                source_descriptors.append(descriptor)
            return descriptor

        with mock.patch("replication_manager.os.open", side_effect=fail_destination), mock.patch(
            "replication_manager.os.close", wraps=os.close
        ) as closer:
            with self.assertRaisesRegex(OSError, "destination-open"):
                manager._copy_artifact(
                    source=source,
                    destination=destination,
                    expected_digest=digest,
                    expected_size=source.stat().st_size,
                )
        self.assertEqual(len(source_descriptors), 1)
        closer.assert_any_call(source_descriptors[0])

        source_descriptors.clear()
        with mock.patch(
            "replication_manager.os.open", side_effect=fail_destination
        ), mock.patch(
            "replication_manager.hashlib.sha256",
            side_effect=RuntimeError("injected-hash-initialization-failure"),
        ), mock.patch("replication_manager.os.close", wraps=os.close) as closer:
            with self.assertRaisesRegex(RuntimeError, "hash-initialization"):
                manager._copy_artifact(
                    source=source,
                    destination=destination,
                    expected_digest=digest,
                    expected_size=source.stat().st_size,
                )
        self.assertEqual(len(source_descriptors), 1)
        closer.assert_any_call(source_descriptors[0])

        with mock.patch("replication_manager.os.write", return_value=0):
            with self.assertRaisesRegex(OSError, "no write progress"):
                manager._copy_artifact(
                    source=source,
                    destination=destination,
                    expected_digest=digest,
                    expected_size=source.stat().st_size,
                )

        opened: dict[str, int] = {}
        closed: list[int] = []

        def track_open(path, flags, *args):
            descriptor = real_open(path, flags, *args)
            if Path(path) == source:
                opened["source"] = descriptor
            elif Path(path) == destination:
                opened["destination"] = descriptor
            return descriptor

        def fail_destination_close(descriptor):
            closed.append(descriptor)
            real_close(descriptor)
            if descriptor == opened.get("destination"):
                raise OSError("injected-destination-close-failure")

        with mock.patch(
            "replication_manager.os.open", side_effect=track_open
        ), mock.patch(
            "replication_manager.os.close", side_effect=fail_destination_close
        ):
            with self.assertRaisesRegex(OSError, "destination-close"):
                manager._copy_artifact(
                    source=source,
                    destination=destination,
                    expected_digest=digest,
                    expected_size=source.stat().st_size,
                )
        self.assertIn(opened["source"], closed)


if __name__ == "__main__":
    unittest.main()

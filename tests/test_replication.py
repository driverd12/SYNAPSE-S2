from __future__ import annotations

import hashlib
import copy
import base64
import binascii
import json
import os
import shutil
import sqlite3
import struct
import tempfile
import time
import unittest
import zlib
from contextlib import closing
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core_authority import CoreAuthorityLease
from core_client_binding import CoreClientBinding
from core_request_journal import CoreRequestJournal
from image_capture import ConversionResult, ImageCaptureCache
from memora_governance import MemoraGovernance
from memora_shadow import build_shadow_plan
from memory_store import DurableMemoryStore
from recovery_manager import VerifiedRecoveryManager
from replication_manager import ReplicationManager
from replication_protocol import (
    AUTH_FIELDS,
    BASE_NODE_CAPABILITIES,
    MEDIA_ARTIFACT_CAPABILITY,
    NODE_CAPABILITIES,
    NODE_DESCRIPTOR_SCHEMA,
    REPLICATION_PROTOCOL_VERSION,
    ReplicationProtocolError,
    checkpoint_id_for,
    read_private_json,
    sign_payload,
    validate_ack,
    validate_checkpoint,
    validate_descriptor_transition,
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

    def manager(
        self,
        name: str,
        *,
        memora_provider_identity: dict[str, object] | None = None,
    ) -> ReplicationManager:
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
        return ReplicationManager(
            store,
            memora_provider_identity=memora_provider_identity,
        )

    @staticmethod
    def _memora_identity() -> dict[str, object]:
        return {
            "provider": "mlx-embeddings",
            "provider_type": "mlx-neural",
            "model_id": "replication-test-model",
            "revision": "revision-1",
            "config_fingerprint": "e" * 64,
            "dimensions": 8,
            "semantic": True,
            "local_only": True,
            "ready": True,
            "learned": True,
        }

    @classmethod
    def _attach_promoted_memora(
        cls,
        store: DurableMemoryStore,
    ) -> dict[str, object]:
        context = "memora-replication-tests"
        for index in range(4):
            store.upsert_entry(
                tag=f"memora-replication-{index}",
                context_id=context,
                source_text=f"synthetic replication cue evidence alpha {index}",
                metadata={"sequence": index},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[2],
                registered_at=150.0 + index,
            )
        provider_info = {
            **cls._memora_identity(),
            "configuration_sha256": "e" * 64,
        }
        provider_info.pop("config_fingerprint")
        provider_info.pop("learned")

        def embed(text: str) -> list[float]:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            return [
                struct.unpack(">I", digest[offset : offset + 4])[0] / 2**32
                for offset in range(0, 32, 4)
            ]

        def recompute(context_id: str) -> dict:
            page = store.memora_source_page(context_id=context_id)
            revision = {
                "revision": page["snapshot_revision"],
                "entry_count": page["total"],
                "sampling_truncated": page["has_more"],
            }
            return build_shadow_plan(
                context_id=context_id,
                entries=page["entries"],
                revision_before=revision,
                revision_after=revision,
                provider_info=provider_info,
                embed=embed,
                similarity_threshold=0.0,
                witnesses=page["witnesses"],
            )

        governance = MemoraGovernance(
            store,
            plan_recomputer=recompute,
            allow_test_time=True,
        )
        plan = recompute(context)
        proposed = governance.propose_binding(
            context_id=context,
            plan_digest=plan["plan_digest"],
            cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
            proposed_by="replication-operator-a",
            reason="replication recovery proof fixture",
            now=200.0,
        )["binding"]
        return governance.promote_binding(
            binding_id=proposed["binding_id"],
            expected_revision=proposed["revision"],
            reviewed_by="replication-operator-b",
            reason="replication recovery proof reviewed",
            confirm=True,
            active_provider_identity=cls._memora_identity(),
            now=201.0,
        )

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

    def test_memora_governance_survives_stage_and_is_revalidated_on_replay(self):
        identity = self._memora_identity()
        source = self.manager("memora-source", memora_provider_identity=identity)
        binding = self._attach_promoted_memora(source.store)
        receiver = self.manager(
            "memora-receiver",
            memora_provider_identity=identity,
        )
        self.pair(source, receiver)

        exported = source.create_checkpoint(receiver.node_id)
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(staged["verified"])
        audit = staged["memora_integrity"]
        self.assertEqual(audit["binding_projection_count"], 1)
        self.assertEqual(audit["governance_event_receipt_count"], 2)
        self.assertEqual(audit["effective_binding_count"], 1)
        restore_root = Path(staged["restore_root"])
        proof = read_private_json(restore_root / "recovery-proof.receipt.json")
        self.assertEqual(proof["memora_integrity"], audit)

        restored_store = DurableMemoryStore.open_existing_for_audit(
            restore_root / "memory.sqlite3",
            immutable=True,
        )
        try:
            governance = MemoraGovernance(restored_store)
            self.assertTrue(
                governance.audit_integrity(binding["binding_id"])["chain_valid"]
            )
            self.assertEqual(
                len(
                    governance.effective_bindings(
                        context_id=binding["context_id"],
                        active_provider_identity=identity,
                    )["bindings"]
                ),
                1,
            )
        finally:
            restored_store.close()

        replay = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["memora_integrity"], audit)

        with closing(sqlite3.connect(restore_root / "memory.sqlite3")) as conn:
            conn.execute(
                "UPDATE store_metadata SET value_json = '{}' "
                "WHERE key LIKE 'memora_governance.binding.v1.%'"
            )
            conn.commit()
        with self.assertRaises((RuntimeError, ReplicationProtocolError)):
            receiver.stage_checkpoint(exported["manifest_path"])
        self.assertEqual(receiver.status()["integrity"]["state"], "degraded")

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

    # ------------------------------------------------------------------
    # Recovery-bundle v3 media artifact replication
    # ------------------------------------------------------------------

    @staticmethod
    def _media_png_bytes(seed: int) -> bytes:
        def chunk(kind: bytes, data: bytes) -> bytes:
            return (
                struct.pack(">I", len(data))
                + kind
                + data
                + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
            )

        width, height = 32, 16
        rows = bytearray()
        for y in range(height):
            rows.append(0)
            for x in range(width):
                rows.extend(
                    ((x * 7 + seed) % 256, (y * 13 + seed) % 256, ((x + y) * 11 + seed) % 256)
                )
        return (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
            + chunk(b"IEND", b"")
        )

    @staticmethod
    def _media_converter(source: Path, work_root: Path) -> ConversionResult:
        del source
        width, height = 32, 16
        row_stride = ((width * 24 + 31) // 32) * 4
        pixel_bytes = bytearray()
        for source_y in range(height - 1, -1, -1):
            row = bytearray()
            for x in range(width):
                row.extend(((x * 3) % 256, (source_y * 5) % 256, ((x + source_y) * 7) % 256))
            row.extend(b"\x00" * (row_stride - len(row)))
            pixel_bytes.extend(row)
        pixel_offset = 14 + 40
        bmp = (
            b"BM"
            + struct.pack("<IHHI", pixel_offset + len(pixel_bytes), 0, 0, pixel_offset)
            + struct.pack(
                "<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixel_bytes), 2835, 2835, 0, 0
            )
            + bytes(pixel_bytes)
        )
        bmp_path = work_root / "normalized.bmp"
        thumbnail_path = work_root / "thumbnail.jpg"
        bmp_path.write_bytes(bmp)
        thumbnail_path.write_bytes(b"\xff\xd8\xff\xe0replication-media-thumb\xff\xd9")
        bmp_path.chmod(0o600)
        thumbnail_path.chmod(0o600)
        return ConversionResult(
            source_width=32, source_height=16, bmp_path=bmp_path, thumbnail_path=thumbnail_path
        )

    def _attach_media(
        self,
        store: DurableMemoryStore,
        node_root: Path,
        media_id: str,
        elements: tuple[float, ...],
    ) -> None:
        """Reference one image memory and place its validated cache object."""

        store.upsert_entry(
            tag=f"replication-image-{media_id[-6:]}",
            context_id="default",
            source_text="Replication media fixture",
            metadata={"context_memory_type": "image", "media_id": media_id},
            embedding_dimensions=8,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=100.0,
        )
        parent = Path("/private/tmp")
        with tempfile.TemporaryDirectory(
            prefix="s2-replication-media-",
            dir=str(parent) if parent.is_dir() else None,
        ) as fixture_name:
            fixture_root = Path(fixture_name)
            fixture_root.chmod(0o700)
            repo_root = fixture_root / "repo"
            data_root = repo_root / ".synapse_s2"
            (data_root / "core").mkdir(parents=True, mode=0o700)
            data_root.chmod(0o700)
            binding = CoreClientBinding(
                repo_root=repo_root,
                data_root=data_root,
                config_path=data_root / "core" / "service.json",
                socket_path=data_root / "core" / "service.sock",
                state_path=data_root / "runtime_state.json",
                memory_path=data_root / "memory.sqlite3",
                capture_root=data_root,
                export_root=data_root / "exports",
                backup_root=data_root / "backups",
                recovery_root=data_root / "recovery",
                replication_inbox_root=data_root / "replication" / "inbox",
                core_label="replication-media-fixture-core",
                config_digest="a" * 64,
                config_fingerprint="b" * 64,
                embedding_space_identity="c" * 64,
                layout="canonical",
                authority_mode="authoritative-core-v6",
            )
            source = fixture_root / "source.png"
            source.write_bytes(self._media_png_bytes(seed=len(media_id)))
            source.chmod(0o600)

            def enricher(_source: Path, mode: str, derivative: str) -> dict:
                feature_data = struct.pack(f"<{len(elements)}f", *elements)
                return {
                    "schema": "synapse-s2.apple-vision-enrichment.v1",
                    "provider": "apple-vision",
                    "mode": mode,
                    "status": "ready",
                    "input_derivative": derivative,
                    "input_dimensions": {"width": 32, "height": 16},
                    "feature_print": {
                        "status": "ready",
                        "schema": "synapse-s2.apple-vision-feature-print.v1",
                        "request_revision": 2,
                        "element_type": "float32",
                        "element_count": len(elements),
                        "encoding": "base64-little-endian",
                        "data": base64.b64encode(feature_data).decode("ascii"),
                    },
                }

            ImageCaptureCache(
                binding,
                converter=self._media_converter,
                vision_enricher=enricher,
            ).capture_image(
                source,
                media_id=media_id,
                vision_mode="feature-print",
                vision_required=True,
            )
            objects_root = node_root / "media-cache" / "objects"
            (node_root / "media-cache").mkdir(mode=0o700, exist_ok=True)
            objects_root.mkdir(mode=0o700, exist_ok=True)
            shutil.move(
                str(data_root / "media-cache" / "objects" / media_id),
                str(objects_root / media_id),
            )

    def _media_source(self) -> tuple[ReplicationManager, str]:
        source = self.manager("source")
        media_id = "s2img_" + "a" * 32
        self._attach_media(
            source.store,
            self.root / "source",
            media_id,
            (0.25, 0.5, 0.75, 1.0),
        )
        return source, media_id

    def test_v3_media_artifact_is_bound_through_stage_and_ack(self):
        source, media_id = self._media_source()
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        records = {str(item["kind"]): item for item in manifest["artifacts"]}
        self.assertIn("media", records)
        self.assertEqual(len(manifest["artifacts"]), 8)
        receipt = read_private_json(
            Path(str(exported["checkpoint_directory"]))
            / str(manifest["bundle_receipt_name"])
        )
        self.assertEqual(receipt["schema"], "synapse-s2.recovery-bundle.v3")
        self.assertEqual(records["media"]["sha256"], receipt["media_sha256"])
        self.assertEqual(records["media"]["name"], receipt["media_artifact_name"])

        staged = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(staged["verified"])
        restore_root = Path(str(staged["restore_root"]))
        restored_objects = restore_root / "media-cache" / "objects"
        self.assertEqual(
            sorted(path.name for path in restored_objects.iterdir()),
            [media_id],
        )
        proof = read_private_json(restore_root / "recovery-proof.receipt.json")
        self.assertIs(proof["media_included"], True)
        self.assertIs(proof["media_recovery_complete"], True)
        self.assertEqual(proof["media_sha256"], receipt["media_sha256"])
        # The receiver's live cache is never touched by staging.
        self.assertFalse((self.root / "receiver" / "media-cache").exists())

        replay = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["ack_digest"], staged["ack_digest"])
        recorded = source.record_acknowledgement(staged["ack_path"])
        self.assertEqual(recorded["state"], "acknowledged")

    def test_media_artifact_missing_swapped_or_tampered_is_rejected(self):
        source, _media_id = self._media_source()
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        records = [dict(item) for item in manifest["artifacts"]]
        media_record = next(item for item in records if item["kind"] == "media")

        # Missing media artifact: manifest without the media record while the
        # signed v3 receipt still requires it.
        without_media = [item for item in records if item["kind"] != "media"]
        missing_path = self.signed_variant(
            source,
            exported,
            name="missing-media",
            changes={
                "artifacts": without_media,
                "artifact_count": len(without_media),
                "artifact_total_bytes": sum(
                    int(item["size_bytes"]) for item in without_media
                ),
            },
        )
        with self.assertRaises((ReplicationProtocolError, ValueError, RuntimeError)):
            receiver.stage_checkpoint(missing_path)

        # Swapped media digest: a validly-shaped manifest that binds a foreign
        # digest for the media artifact.
        swapped_records = [
            {**item, "sha256": "f" * 64} if item["kind"] == "media" else item
            for item in records
        ]
        swapped_path = self.signed_variant(
            source,
            exported,
            name="swapped-media",
            changes={"artifacts": swapped_records},
        )
        with self.assertRaises((ReplicationProtocolError, ValueError, RuntimeError)):
            receiver.stage_checkpoint(swapped_path)

        # Tampered media bytes under the correct manifest.
        tampered_root = self.root / "tampered-media"
        tampered_root.mkdir(mode=0o700)
        original_root = Path(str(exported["checkpoint_directory"]))
        for item in records:
            data = (original_root / str(item["name"])).read_bytes()
            destination = tampered_root / str(item["name"])
            destination.write_bytes(data)
            destination.chmod(0o600)
        media_path = tampered_root / str(media_record["name"])
        tampered = bytearray(media_path.read_bytes())
        tampered[len(tampered) // 2] ^= 0x01
        media_path.write_bytes(bytes(tampered))
        media_path.chmod(0o600)
        manifest_path = tampered_root / "checkpoint.manifest.json"
        write_private_json_exclusive(source.store, manifest_path, manifest)
        with self.assertRaises((ReplicationProtocolError, ValueError, RuntimeError)):
            receiver.stage_checkpoint(manifest_path)
        self.assertFalse(
            (self.root / "receiver" / "media-cache").exists()
        )

    def test_downgraded_media_absent_checkpoint_fails_closed(self):
        source, _media_id = self._media_source()
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        original_root = Path(str(exported["checkpoint_directory"]))
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        records = [dict(item) for item in manifest["artifacts"]]
        receipt_name = str(manifest["bundle_receipt_name"])
        receipt = read_private_json(original_root / receipt_name)

        downgraded = {
            key: value
            for key, value in receipt.items()
            if not key.startswith("media_") and key != "memora_integrity"
        }
        downgraded["schema"] = "synapse-s2.recovery-bundle.v2"
        source.store._authenticate_receipt(downgraded)
        variant_root = self.root / "downgraded-media"
        variant_root.mkdir(mode=0o700)
        downgraded_records = []
        for item in records:
            if item["kind"] == "media":
                continue
            if item["kind"] == "bundle_receipt":
                destination = variant_root / receipt_name
                write_private_json_exclusive(source.store, destination, downgraded)
                payload = destination.read_bytes()
                downgraded_records.append(
                    {
                        **item,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size_bytes": len(payload),
                    }
                )
                continue
            data = (original_root / str(item["name"])).read_bytes()
            destination = variant_root / str(item["name"])
            destination.write_bytes(data)
            destination.chmod(0o600)
            downgraded_records.append(item)
        unsigned = {
            key: value for key, value in manifest.items() if key not in AUTH_FIELDS
        }
        unsigned["artifacts"] = downgraded_records
        unsigned["artifact_count"] = len(downgraded_records)
        unsigned["artifact_total_bytes"] = sum(
            int(item["size_bytes"]) for item in downgraded_records
        )
        unsigned["bundle_receipt_digest"] = str(downgraded["receipt_digest"])
        variant = sign_payload(source.store, unsigned)
        validate_checkpoint(variant)
        manifest_path = variant_root / "checkpoint.manifest.json"
        write_private_json_exclusive(source.store, manifest_path, variant)

        # A signed v2 checkpoint whose database still references image
        # memories but that ships no media stages is incomplete: it must
        # never verify, advance lineage, or earn a cutover-ready ACK.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "does not match its recovery proof inputs"
        ):
            receiver.stage_checkpoint(manifest_path)
        self.assertIsNone(
            receiver.ledger.latest_checkpoint(
                lineage_id=str(variant["lineage_id"]), direction="incoming"
            )
        )
        staged_lineage = (
            receiver.staged_root
            / str(variant["lineage_id"])
            / str(variant["checkpoint_id"])
        )
        self.assertFalse(staged_lineage.exists())

    def _downgrade_node(self, manager: ReplicationManager) -> dict[str, object]:
        """Rewrite a node's active descriptor to the legacy baseline list."""

        baseline = sign_payload(
            manager.store,
            {
                "schema": NODE_DESCRIPTOR_SCHEMA,
                "protocol_version": REPLICATION_PROTOCOL_VERSION,
                "node_id": manager.node_id,
                "role": "offline-checkpoint-peer",
                "capabilities": list(BASE_NODE_CAPABILITIES),
                "created_at": time.time(),
            },
        )
        validate_node_descriptor(baseline)
        manager.descriptor_path.unlink()
        write_private_json_exclusive(manager.store, manager.descriptor_path, baseline)
        manager._descriptor = baseline
        return baseline

    def test_bilateral_media_activation_requires_both_nodes_and_pins(self):
        source, media_id = self._media_source()
        receiver = self.manager("receiver")
        source_baseline = self._downgrade_node(source)
        receiver_baseline = self._downgrade_node(receiver)
        lineage = self.pair(source, receiver)

        # State 1: both nodes baseline.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "this node's active descriptor"
        ):
            source.create_checkpoint(receiver.node_id)

        # State 2: sender node upgraded, target pin still baseline.
        source_full = source.upgrade_node_descriptor(
            expected_current_digest=str(source_baseline["receipt_digest"]),
            confirm=True,
        )
        self.assertEqual(
            [str(item) for item in source_full["capabilities"]],
            list(NODE_CAPABILITIES),
        )
        with self.assertRaisesRegex(
            ReplicationProtocolError, "target peer does not advertise"
        ):
            source.create_checkpoint(receiver.node_id)

        # State 3: receiver node upgraded too, but the sender's pin of the
        # receiver has not been re-reviewed, so media stays blocked.
        receiver_full = receiver.upgrade_node_descriptor(
            expected_current_digest=str(receiver_baseline["receipt_digest"]),
            confirm=True,
        )
        with self.assertRaisesRegex(
            ReplicationProtocolError, "target peer does not advertise"
        ):
            source.create_checkpoint(receiver.node_id)

        upgraded_pin = source.upgrade_peer_descriptor(
            receiver.node_descriptor(),
            expected_descriptor_digest=str(receiver_full["receipt_digest"]),
            expected_previous_descriptor_digest=str(
                receiver_baseline["receipt_digest"]
            ),
            confirm=True,
        )
        self.assertEqual(
            upgraded_pin["descriptor_digest"], str(receiver_full["receipt_digest"])
        )
        exported = source.create_checkpoint(receiver.node_id)
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        self.assertIn(
            "media", {str(item["kind"]) for item in manifest["artifacts"]}
        )
        status = source.status()
        pinned = {str(item["peer_id"]): item for item in status["peers"]}
        self.assertEqual(
            pinned[receiver.node_id]["previous_descriptor_digest"],
            str(receiver_baseline["receipt_digest"]),
        )
        self.assertTrue(pinned[receiver.node_id]["media_ready"])

        # State 4: the receiver's own pin of the source is still baseline, so
        # the receiver independently rejects the media checkpoint before any
        # staging work, regardless of what the sender enforced.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "pinned source peer"
        ):
            receiver.stage_checkpoint(exported["manifest_path"])
        self.assertIsNone(
            receiver.ledger.latest_checkpoint(
                lineage_id=lineage, direction="incoming"
            )
        )
        self.assertFalse(
            (receiver.staged_root / lineage / str(manifest["checkpoint_id"])).exists()
        )

        receiver.upgrade_peer_descriptor(
            source.node_descriptor(),
            expected_descriptor_digest=str(source_full["receipt_digest"]),
            expected_previous_descriptor_digest=str(
                source_baseline["receipt_digest"]
            ),
            confirm=True,
        )
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(staged["verified"])
        restore_root = Path(str(staged["restore_root"]))
        self.assertEqual(
            sorted(
                path.name
                for path in (restore_root / "media-cache" / "objects").iterdir()
            ),
            [media_id],
        )

    def test_non_media_replication_stays_compatible_between_baseline_nodes(self):
        # A legacy baseline sender (old code, v2 recovery bundle, no media
        # artifact, no image references) must keep replicating into a
        # receiver whose own descriptor and pinned source evidence are both
        # baseline: the media gates never fire on non-media checkpoints.
        source = self.manager("plain-source")
        receiver = self.manager("plain-receiver")
        self.pair(source, receiver)
        exported = source.create_checkpoint(receiver.node_id)
        original_root = Path(str(exported["checkpoint_directory"]))
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        receipt_name = str(manifest["bundle_receipt_name"])
        receipt = read_private_json(original_root / receipt_name)
        legacy_receipt = {
            key: value
            for key, value in receipt.items()
            if not key.startswith("media_") and key != "memora_integrity"
        }
        legacy_receipt["schema"] = "synapse-s2.recovery-bundle.v2"
        source.store._authenticate_receipt(legacy_receipt)
        variant_root = self.root / "legacy-plain"
        variant_root.mkdir(mode=0o700)
        legacy_records = []
        for item in [dict(entry) for entry in manifest["artifacts"]]:
            if item["kind"] == "media":
                continue
            if item["kind"] == "bundle_receipt":
                destination = variant_root / receipt_name
                write_private_json_exclusive(
                    source.store, destination, legacy_receipt
                )
                payload = destination.read_bytes()
                legacy_records.append(
                    {
                        **item,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size_bytes": len(payload),
                    }
                )
                continue
            data = (original_root / str(item["name"])).read_bytes()
            destination = variant_root / str(item["name"])
            destination.write_bytes(data)
            destination.chmod(0o600)
            legacy_records.append(item)
        unsigned = {
            key: value for key, value in manifest.items() if key not in AUTH_FIELDS
        }
        unsigned["artifacts"] = legacy_records
        unsigned["artifact_count"] = len(legacy_records)
        unsigned["artifact_total_bytes"] = sum(
            int(item["size_bytes"]) for item in legacy_records
        )
        unsigned["bundle_receipt_digest"] = str(legacy_receipt["receipt_digest"])
        variant = sign_payload(source.store, unsigned)
        validate_checkpoint(variant)
        manifest_path = variant_root / "checkpoint.manifest.json"
        write_private_json_exclusive(source.store, manifest_path, variant)

        # Emulate a legacy receiver: baseline active descriptor and a source
        # pinned before capability negotiation (no descriptor evidence).
        self._downgrade_node(receiver)
        (
            receiver.peers_root
            / f"{source.node_id}.descriptor.{str(source.node_descriptor()['receipt_digest'])}.json"
        ).unlink()
        staged = receiver.stage_checkpoint(manifest_path)
        self.assertTrue(staged["verified"])
        self.assertTrue(staged["memory_recovery_cutover_ready"])
        proof = read_private_json(
            Path(str(staged["restore_root"])) / "recovery-proof.receipt.json"
        )
        self.assertIs(proof["media_included"], False)

    def test_current_v3_zero_reference_checkpoint_replicates_between_baseline_nodes(self):
        # A current node whose database references zero image memories
        # natively produces a verified media-absent v3 bundle: two
        # baseline-descriptor nodes must complete the full create/stage/ack
        # round trip because no media artifact means no media-artifact-v1
        # activation is required on either side.
        source = self.manager("zero-source")
        receiver = self.manager("zero-receiver")
        self._downgrade_node(source)
        self._downgrade_node(receiver)
        lineage = self.pair(source, receiver)

        exported = source.create_checkpoint(receiver.node_id)
        self.assertTrue(exported["memory_recovery_cutover_ready"])
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        self.assertNotIn(
            "media", {str(item["kind"]) for item in manifest["artifacts"]}
        )
        receipt = read_private_json(
            Path(str(exported["checkpoint_directory"]))
            / str(manifest["bundle_receipt_name"])
        )
        self.assertEqual(receipt["schema"], "synapse-s2.recovery-bundle.v3")
        self.assertIs(receipt["media_included"], False)
        self.assertIsNone(receipt["media_sha256"])

        staged = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(staged["verified"])
        self.assertTrue(staged["memory_recovery_cutover_ready"])
        restore_root = Path(str(staged["restore_root"]))
        proof = read_private_json(restore_root / "recovery-proof.receipt.json")
        self.assertIs(proof["media_included"], False)
        self.assertTrue(proof["media_recovery_complete"])
        self.assertEqual(
            proof["media_recovery"], "media-not-required-zero-references"
        )
        self.assertEqual(proof["media_object_count"], 0)
        self.assertFalse((restore_root / "media-cache").exists())

        recorded = source.record_acknowledgement(staged["ack_path"])
        self.assertEqual(recorded["state"], "acknowledged")
        self.assertEqual(
            source.status()["checkpoint_counts"]["outgoing:acknowledged"], 1
        )
        self.assertIsNotNone(
            receiver.ledger.latest_checkpoint(
                lineage_id=lineage, direction="incoming"
            )
        )

    def test_baseline_sender_with_image_references_is_rejected_at_create(self):
        # The zero-reference compatibility path never weakens the media gate:
        # as soon as the database references an image memory, the bundle
        # includes its media archive, and a baseline sender must be blocked
        # at creation before any checkpoint is published or lineage advances.
        source, _media_id = self._media_source()
        receiver = self.manager("receiver")
        self._downgrade_node(source)
        lineage = self.pair(source, receiver)
        with self.assertRaisesRegex(
            ReplicationProtocolError,
            "this node's active descriptor does not advertise media-artifact-v1",
        ):
            source.create_checkpoint(receiver.node_id)
        self.assertIsNone(
            source.ledger.latest_checkpoint(
                lineage_id=lineage, direction="outgoing"
            )
        )
        self.assertEqual(source.status()["checkpoint_counts"], {})

    def test_descriptor_upgrade_evidence_survives_cas_crash_and_replays(self):
        source, _media_id = self._media_source()
        receiver = self.manager("receiver")
        receiver_baseline = self._downgrade_node(receiver)
        self.pair(source, receiver)
        receiver_full = receiver.upgrade_node_descriptor(
            expected_current_digest=str(receiver_baseline["receipt_digest"]),
            confirm=True,
        )
        new_digest = str(receiver_full["receipt_digest"])
        previous_digest = str(receiver_baseline["receipt_digest"])

        with mock.patch.object(
            source.ledger,
            "update_peer_descriptor",
            side_effect=RuntimeError("simulated crash before the ledger pointer"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated crash"):
                source.upgrade_peer_descriptor(
                    receiver.node_descriptor(),
                    expected_descriptor_digest=new_digest,
                    expected_previous_descriptor_digest=previous_digest,
                    confirm=True,
                )
        # Evidence and the signed transition receipt were published before
        # the crash, but the anchored ledger pointer never moved: media stays
        # blocked and the pinned digest is unchanged.
        evidence_path = (
            source.peers_root / f"{receiver.node_id}.descriptor.{new_digest}.json"
        )
        transition_path = (
            source.peers_root / f"{receiver.node_id}.transition.{new_digest}.json"
        )
        self.assertTrue(evidence_path.exists())
        self.assertTrue(transition_path.exists())
        transition = validate_descriptor_transition(
            read_private_json(transition_path)
        )
        self.assertEqual(
            str(transition["previous_descriptor_digest"]), previous_digest
        )
        self.assertEqual(str(transition["descriptor_digest"]), new_digest)
        self.assertEqual(str(transition["recorder_node_id"]), source.node_id)
        pinned = source.ledger.peer(receiver.node_id)
        self.assertEqual(str(pinned["descriptor_digest"]), previous_digest)
        with self.assertRaisesRegex(
            ReplicationProtocolError, "target peer does not advertise"
        ):
            source.create_checkpoint(receiver.node_id)

        # A retry reconciles the pre-CAS evidence idempotently and completes
        # the compare-and-swap.
        upgraded = source.upgrade_peer_descriptor(
            receiver.node_descriptor(),
            expected_descriptor_digest=new_digest,
            expected_previous_descriptor_digest=previous_digest,
            confirm=True,
        )
        self.assertEqual(upgraded["descriptor_digest"], new_digest)

        # A replay after a lost response converges on the same pinned state.
        replay = source.upgrade_peer_descriptor(
            receiver.node_descriptor(),
            expected_descriptor_digest=new_digest,
            expected_previous_descriptor_digest=previous_digest,
            confirm=True,
        )
        self.assertEqual(replay["descriptor_digest"], new_digest)
        exported = source.create_checkpoint(receiver.node_id)
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        self.assertIn(
            "media", {str(item["kind"]) for item in manifest["artifacts"]}
        )

    def test_tampered_descriptor_evidence_fails_closed_and_surfaces_in_status(self):
        source, _media_id = self._media_source()
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        digest = str(receiver.node_descriptor()["receipt_digest"])
        evidence_path = (
            source.peers_root / f"{receiver.node_id}.descriptor.{digest}.json"
        )
        document = json.loads(evidence_path.read_text(encoding="utf-8"))
        document["capabilities"] = ["tampered-capability"]
        evidence_path.write_text(
            json.dumps(document, sort_keys=True), encoding="utf-8"
        )
        evidence_path.chmod(0o600)
        with self.assertRaises(ReplicationProtocolError):
            source.create_checkpoint(receiver.node_id)
        status = source.status()
        pinned = {str(item["peer_id"]): item for item in status["peers"]}
        self.assertEqual(
            pinned[receiver.node_id]["capability_state"],
            "invalid-descriptor-evidence",
        )
        self.assertFalse(pinned[receiver.node_id]["media_ready"])
        # Tampered pinned evidence is an integrity defect, not a display
        # detail: the global verdict degrades with the exact reason while
        # the per-peer surface stays visible.
        self.assertIsNotNone(pinned[receiver.node_id]["evidence_problem"])
        self.assertEqual(status["integrity"]["state"], "degraded")
        self.assertFalse(status["integrity"]["semantic_paths_verified"])
        self.assertTrue(status["integrity"]["anchor_verified"])
        self.assertTrue(
            any(
                receiver.node_id in reason
                for reason in status["integrity"]["descriptor_evidence_problems"]
            )
        )

    def test_tampered_active_node_descriptor_degrades_global_integrity(self):
        node = self.manager("solo-node-tamper")
        document = json.loads(node.descriptor_path.read_text(encoding="utf-8"))
        document["capabilities"] = list(document["capabilities"]) + [
            "tampered-capability"
        ]
        node.descriptor_path.write_text(
            json.dumps(document, sort_keys=True), encoding="utf-8"
        )
        node.descriptor_path.chmod(0o600)
        status = node.status()
        self.assertEqual(
            status["node_descriptor_state"], "invalid-descriptor-evidence"
        )
        self.assertEqual(status["capabilities"], [])
        self.assertFalse(status["media_artifact_capable"])
        self.assertEqual(status["integrity"]["state"], "degraded")
        self.assertFalse(status["integrity"]["semantic_paths_verified"])
        self.assertIn(
            "active node descriptor evidence is missing or tampered",
            status["integrity"]["descriptor_evidence_problems"],
        )
        # The missing pointer file degrades identically.
        node.descriptor_path.unlink()
        status = node.status()
        self.assertEqual(status["integrity"]["state"], "degraded")
        self.assertFalse(status["integrity"]["semantic_paths_verified"])

    def test_upgraded_pin_requires_exact_cross_bound_transition_receipt(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        receiver_baseline = self._downgrade_node(receiver)
        self.pair(source, receiver)
        receiver_full = receiver.upgrade_node_descriptor(
            expected_current_digest=str(receiver_baseline["receipt_digest"]),
            confirm=True,
        )
        source.upgrade_peer_descriptor(
            receiver.node_descriptor(),
            expected_descriptor_digest=str(receiver_full["receipt_digest"]),
            expected_previous_descriptor_digest=str(
                receiver_baseline["receipt_digest"]
            ),
            confirm=True,
        )
        status = source.status()
        self.assertEqual(status["integrity"]["state"], "ready")
        self.assertTrue(status["integrity"]["semantic_paths_verified"])
        pinned = {str(item["peer_id"]): item for item in status["peers"]}
        self.assertEqual(
            pinned[receiver.node_id]["previous_descriptor_digest"],
            str(receiver_baseline["receipt_digest"]),
        )

        transition_path = (
            source.peers_root
            / f"{receiver.node_id}.transition.{receiver_full['receipt_digest']}.json"
        )
        original_transition = transition_path.read_bytes()
        original_record = json.loads(original_transition.decode("utf-8"))

        def degraded_reason() -> str:
            status = source.status()
            self.assertEqual(status["integrity"]["state"], "degraded")
            self.assertFalse(status["integrity"]["semantic_paths_verified"])
            pinned = {
                str(item["peer_id"]): item for item in status["peers"]
            }
            entry = pinned[receiver.node_id]
            self.assertEqual(
                entry["capability_state"], "invalid-descriptor-evidence"
            )
            self.assertEqual(entry["capabilities"], [])
            self.assertFalse(entry["media_ready"])
            problems = status["integrity"]["descriptor_evidence_problems"]
            self.assertEqual(len(problems), 1)
            return str(problems[0])

        # Missing old->new transition receipt for an upgraded pin.
        transition_path.unlink()
        self.assertIn("lacks its signed transition receipt", degraded_reason())

        # Properly signed receipt whose binding names the wrong direction:
        # signature validity alone is never enough, the receipt must
        # cross-bind recorder, peer, lineage, direction, key, and digests.
        forged = {
            key: value
            for key, value in original_record.items()
            if key not in AUTH_FIELDS
        }
        forged["direction"] = "receive" if forged["direction"] == "send" else "send"
        write_private_json_exclusive(
            source.store, transition_path, sign_payload(source.store, forged)
        )
        self.assertIn("not cross-bound", degraded_reason())

        # Byte-level tampering breaks the signature itself.
        transition_path.unlink()
        tampered = dict(original_record)
        tampered["previous_descriptor_digest"] = "d" * 64
        transition_path.write_text(
            json.dumps(tampered, sort_keys=True), encoding="utf-8"
        )
        transition_path.chmod(0o600)
        degraded_reason()

        # Restoring the genuine receipt returns the node to ready.
        transition_path.unlink()
        transition_path.write_bytes(original_transition)
        transition_path.chmod(0o600)
        status = source.status()
        self.assertEqual(status["integrity"]["state"], "ready")
        self.assertTrue(status["integrity"]["semantic_paths_verified"])
        self.assertEqual(
            status["integrity"]["descriptor_evidence_problems"], []
        )

        # An upgraded pin whose descriptor document evidence disappears is
        # inconsistent, never silently legacy-baseline.
        (
            source.peers_root
            / f"{receiver.node_id}.descriptor.{receiver_full['receipt_digest']}.json"
        ).unlink()
        self.assertIn(
            "upgraded peer descriptor evidence is missing", degraded_reason()
        )

    def test_status_surfaces_capability_activation_and_legacy_pins(self):
        source = self.manager("source")
        receiver = self.manager("receiver")
        self.pair(source, receiver)
        status = source.status()
        self.assertTrue(status["media_artifact_capable"])
        self.assertEqual(status["node_descriptor_state"], "valid")
        self.assertEqual(
            status["descriptor_digest"],
            str(source.node_descriptor()["receipt_digest"]),
        )
        self.assertEqual(status["capabilities"], list(NODE_CAPABILITIES))
        pinned = {str(item["peer_id"]): item for item in status["peers"]}
        entry = pinned[receiver.node_id]
        self.assertEqual(entry["capability_state"], MEDIA_ARTIFACT_CAPABILITY)
        self.assertEqual(entry["capabilities"], list(NODE_CAPABILITIES))
        self.assertTrue(entry["media_ready"])
        self.assertIsNone(entry["previous_descriptor_digest"])

        # A peer pinned before capability negotiation has no descriptor
        # evidence: it must surface as legacy and never media-ready.
        digest = str(receiver.node_descriptor()["receipt_digest"])
        (
            source.peers_root / f"{receiver.node_id}.descriptor.{digest}.json"
        ).unlink()
        status = source.status()
        pinned = {str(item["peer_id"]): item for item in status["peers"]}
        entry = pinned[receiver.node_id]
        self.assertEqual(entry["capability_state"], "legacy-no-descriptor")
        self.assertEqual(entry["capabilities"], list(BASE_NODE_CAPABILITIES))
        self.assertFalse(entry["media_ready"])

    def test_node_descriptor_upgrade_preserves_immutable_evidence(self):
        node = self.manager("solo")
        baseline = self._downgrade_node(node)
        previous_digest = str(baseline["receipt_digest"])
        with self.assertRaises(ValueError):
            node.upgrade_node_descriptor(expected_current_digest=previous_digest)
        # The compare-and-swap binds the operator's reviewed digest: a stale
        # or wrong digest is rejected before any evidence or pointer moves.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "reviewed current descriptor digest"
        ):
            node.upgrade_node_descriptor(
                expected_current_digest="f" * 64, confirm=True
            )
        self.assertEqual(
            str(read_private_json(node.descriptor_path)["receipt_digest"]),
            previous_digest,
        )
        upgraded = node.upgrade_node_descriptor(
            expected_current_digest=previous_digest, confirm=True
        )
        new_digest = str(upgraded["receipt_digest"])
        self.assertNotEqual(previous_digest, new_digest)
        self.assertEqual(
            [str(item) for item in upgraded["capabilities"]],
            list(NODE_CAPABILITIES),
        )
        old_evidence = node.root / f"node-descriptor.{previous_digest}.json"
        new_evidence = node.root / f"node-descriptor.{new_digest}.json"
        self.assertTrue(old_evidence.exists())
        self.assertTrue(new_evidence.exists())
        self.assertEqual(
            str(read_private_json(old_evidence)["receipt_digest"]),
            previous_digest,
        )
        active = read_private_json(node.descriptor_path)
        self.assertEqual(str(active["receipt_digest"]), new_digest)
        # A replay after a lost response is idempotent and needs no confirm,
        # whether the retried review names the now-active digest or the
        # preserved pre-upgrade descriptor it replaced.
        again = node.upgrade_node_descriptor(expected_current_digest=new_digest)
        self.assertEqual(str(again["receipt_digest"]), new_digest)
        retried = node.upgrade_node_descriptor(
            expected_current_digest=previous_digest
        )
        self.assertEqual(str(retried["receipt_digest"]), new_digest)
        # A digest that never named one of this node's descriptors stays
        # rejected even after the upgrade completed.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "reviewed current descriptor digest"
        ):
            node.upgrade_node_descriptor(expected_current_digest="e" * 64)

    def test_peer_upgrade_replay_never_synthesizes_deleted_transition_history(self):
        # Once the ledger compare-and-swap pins the new digest, a replay must
        # validate the already-published transition receipt against the
        # anchored predecessor record: it never signs new history from a
        # caller-supplied predecessor, so a deleted receipt stays failed and
        # an arbitrary claimed predecessor is rejected outright.
        source = self.manager("source")
        receiver = self.manager("receiver")
        receiver_baseline = self._downgrade_node(receiver)
        self.pair(source, receiver)
        receiver_full = receiver.upgrade_node_descriptor(
            expected_current_digest=str(receiver_baseline["receipt_digest"]),
            confirm=True,
        )
        new_digest = str(receiver_full["receipt_digest"])
        previous_digest = str(receiver_baseline["receipt_digest"])
        source.upgrade_peer_descriptor(
            receiver.node_descriptor(),
            expected_descriptor_digest=new_digest,
            expected_previous_descriptor_digest=previous_digest,
            confirm=True,
        )
        transition_path = (
            source.peers_root
            / f"{receiver.node_id}.transition.{new_digest}.json"
        )
        original_transition = transition_path.read_bytes()
        transition_path.unlink()

        # An arbitrary caller predecessor conflicts with the anchored audit
        # record and is rejected before any evidence could be signed.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "recorded predecessor"
        ):
            source.upgrade_peer_descriptor(
                receiver.node_descriptor(),
                expected_descriptor_digest=new_digest,
                expected_previous_descriptor_digest="f" * 64,
                confirm=True,
            )
        self.assertFalse(transition_path.exists())

        # The correct predecessor still cannot resurrect the deleted receipt:
        # the replay fails and the node stays degraded.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "lacks its signed transition receipt"
        ):
            source.upgrade_peer_descriptor(
                receiver.node_descriptor(),
                expected_descriptor_digest=new_digest,
                expected_previous_descriptor_digest=previous_digest,
                confirm=True,
            )
        self.assertFalse(transition_path.exists())
        status = source.status()
        self.assertEqual(status["integrity"]["state"], "degraded")

        # Restoring the genuine receipt makes the replay idempotent again.
        transition_path.write_bytes(original_transition)
        transition_path.chmod(0o600)
        replay = source.upgrade_peer_descriptor(
            receiver.node_descriptor(),
            expected_descriptor_digest=new_digest,
            expected_previous_descriptor_digest=previous_digest,
            confirm=True,
        )
        self.assertEqual(replay["descriptor_digest"], new_digest)
        status = source.status()
        self.assertEqual(status["integrity"]["state"], "ready")
        self.assertEqual(
            status["integrity"]["descriptor_evidence_problems"], []
        )
        self.assertEqual(
            status["integrity"]["descriptor_evidence_problem_total"], 0
        )
        self.assertFalse(
            status["integrity"]["descriptor_evidence_problems_truncated"]
        )

    def test_node_upgrade_replay_rejects_staged_but_never_active_candidate(self):
        # Candidate evidence is published before the pointer swap, so a crash
        # between the two leaves a fully signed candidate that never became
        # active. A retry converges on a NEW candidate, and the stale one is
        # rejected forever: only the active digest and the exact predecessor
        # named by the active descriptor's swap receipt replay idempotently.
        node = self.manager("swap-crash")
        baseline = self._downgrade_node(node)
        previous_digest = str(baseline["receipt_digest"])
        with mock.patch(
            "replication_manager.os.replace",
            side_effect=OSError("simulated crash before the pointer swap"),
        ):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                node.upgrade_node_descriptor(
                    expected_current_digest=previous_digest, confirm=True
                )
        # The active pointer never moved.
        self.assertEqual(
            str(read_private_json(node.descriptor_path)["receipt_digest"]),
            previous_digest,
        )
        staged = sorted(node.root.glob("node-descriptor.next.*.json"))
        self.assertEqual(len(staged), 1)
        stale_digest = staged[0].name.split(".")[2]
        self.assertTrue(
            (
                node.root / f"node-descriptor.transition.{stale_digest}.json"
            ).exists()
        )
        # The staged candidate is not the active descriptor, so replaying its
        # digest is rejected even before the retry.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "reviewed current descriptor digest"
        ):
            node.upgrade_node_descriptor(expected_current_digest=stale_digest)

        retried = node.upgrade_node_descriptor(
            expected_current_digest=previous_digest, confirm=True
        )
        new_digest = str(retried["receipt_digest"])
        self.assertNotEqual(new_digest, stale_digest)
        self.assertEqual(
            str(read_private_json(node.descriptor_path)["receipt_digest"]),
            new_digest,
        )
        # Response-loss replays accept the active digest and the exact
        # predecessor recorded by the swap receipt.
        self.assertEqual(
            str(
                node.upgrade_node_descriptor(expected_current_digest=new_digest)[
                    "receipt_digest"
                ]
            ),
            new_digest,
        )
        self.assertEqual(
            str(
                node.upgrade_node_descriptor(
                    expected_current_digest=previous_digest
                )["receipt_digest"]
            ),
            new_digest,
        )
        # The staged-but-never-active candidate can never be laundered into
        # history, even though its signed evidence and receipt still exist.
        with self.assertRaisesRegex(
            ReplicationProtocolError, "reviewed current descriptor digest"
        ):
            node.upgrade_node_descriptor(expected_current_digest=stale_digest)

    def test_media_gates_fail_closed_on_deleted_or_tampered_transition(self):
        # Media enforcement uses the same integrity-verified capability
        # resolver as status: once a pin was upgraded, a deleted or tampered
        # old->new transition receipt blocks media at create AND at stage,
        # never quietly resolving the peer to baseline while status degrades.
        source, media_id = self._media_source()
        receiver = self.manager("receiver")
        source_baseline = self._downgrade_node(source)
        receiver_baseline = self._downgrade_node(receiver)
        lineage = self.pair(source, receiver)
        source_full = source.upgrade_node_descriptor(
            expected_current_digest=str(source_baseline["receipt_digest"]),
            confirm=True,
        )
        receiver_full = receiver.upgrade_node_descriptor(
            expected_current_digest=str(receiver_baseline["receipt_digest"]),
            confirm=True,
        )
        source.upgrade_peer_descriptor(
            receiver.node_descriptor(),
            expected_descriptor_digest=str(receiver_full["receipt_digest"]),
            expected_previous_descriptor_digest=str(
                receiver_baseline["receipt_digest"]
            ),
            confirm=True,
        )
        receiver.upgrade_peer_descriptor(
            source.node_descriptor(),
            expected_descriptor_digest=str(source_full["receipt_digest"]),
            expected_previous_descriptor_digest=str(
                source_baseline["receipt_digest"]
            ),
            confirm=True,
        )

        # Sender side: the target pin's transition receipt disappears.
        sender_transition = (
            source.peers_root
            / f"{receiver.node_id}.transition.{receiver_full['receipt_digest']}.json"
        )
        sender_original = sender_transition.read_bytes()
        sender_transition.unlink()
        with self.assertRaisesRegex(
            ReplicationProtocolError, "failed integrity verification"
        ):
            source.create_checkpoint(receiver.node_id)
        self.assertIsNone(
            source.ledger.latest_checkpoint(
                lineage_id=lineage, direction="outgoing"
            )
        )
        # A byte-tampered receipt fails identically.
        tampered = json.loads(sender_original.decode("utf-8"))
        tampered["previous_descriptor_digest"] = "d" * 64
        sender_transition.write_text(
            json.dumps(tampered, sort_keys=True), encoding="utf-8"
        )
        sender_transition.chmod(0o600)
        with self.assertRaisesRegex(
            ReplicationProtocolError, "failed integrity verification"
        ):
            source.create_checkpoint(receiver.node_id)
        sender_transition.unlink()
        sender_transition.write_bytes(sender_original)
        sender_transition.chmod(0o600)
        exported = source.create_checkpoint(receiver.node_id)
        manifest = read_private_json(Path(str(exported["manifest_path"])))
        self.assertIn(
            "media", {str(item["kind"]) for item in manifest["artifacts"]}
        )

        # Receiver side: the pinned source's transition receipt disappears
        # before staging; the media checkpoint is rejected before any
        # staging work or ledger effect.
        receiver_transition = (
            receiver.peers_root
            / f"{source.node_id}.transition.{source_full['receipt_digest']}.json"
        )
        receiver_original = receiver_transition.read_bytes()
        receiver_transition.unlink()
        with self.assertRaisesRegex(
            ReplicationProtocolError, "failed integrity verification"
        ):
            receiver.stage_checkpoint(exported["manifest_path"])
        self.assertIsNone(
            receiver.ledger.latest_checkpoint(
                lineage_id=lineage, direction="incoming"
            )
        )
        self.assertFalse(
            (
                receiver.staged_root / lineage / str(manifest["checkpoint_id"])
            ).exists()
        )
        receiver_transition.write_bytes(receiver_original)
        receiver_transition.chmod(0o600)
        staged = receiver.stage_checkpoint(exported["manifest_path"])
        self.assertTrue(staged["verified"])
        self.assertEqual(
            sorted(
                path.name
                for path in (
                    Path(str(staged["restore_root"])) / "media-cache" / "objects"
                ).iterdir()
            ),
            [media_id],
        )


if __name__ == "__main__":
    unittest.main()

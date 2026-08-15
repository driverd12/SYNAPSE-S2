"""Tests for the governed Memora cue-binding lifecycle.

Covers the durable proposal/promotion lifecycle end to end on disposable
temporary stores: non-content lifecycle-witness integrity (no content, no
digest, no key material -- nothing that could act as an offline equality
oracle), CAS + exactly-once semantics, fail-closed tamper detection,
provider drift, source mutation/deletion invalidation, key-free
recovery/replication verification, the transactional promoted-binding
capacity ceiling, and operator-review governance (distinct reviewer,
confirm gates, no automatic promotion).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memora_governance import (
    MAX_EFFECTIVE_BINDINGS,
    MemoraGovernance,
    MemoraGovernanceConflict,
    MemoraGovernanceIntegrityError,
    MemoraGovernanceInvalidTransition,
    MemoraGovernanceStaleRevision,
    MemoraGovernanceValidationError,
    _with_revision,
)
from memora_shadow import build_shadow_plan
from memory_store import MEMORA_WITNESS_SCHEMA, DurableMemoryStore

LEARNED_PROVIDER_INFO = {
    "provider": "mlx-embeddings",
    "provider_type": "mlx-neural",
    "model_id": "test-model",
    "revision": "rev-1",
    "configuration_sha256": "c" * 64,
    "dimensions": 8,
    "semantic": True,
    "local_only": True,
    "ready": True,
}

FALLBACK_PROVIDER_INFO = {
    **LEARNED_PROVIDER_INFO,
    "provider_type": "semantic-hash",
    "semantic": False,
}

RAW_SENTENCE = "alpha topic shared deterministic subject matter entry"


def _hash_embed(text: str) -> list[float]:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return [
        struct.unpack(">I", digest[i : i + 4])[0] / 2**32
        for i in range(0, 32, 4)
    ]


class MemoraGovernanceTests(unittest.TestCase):
    def _make_env(self, *, provider_info: dict | None = None, entries: int = 4):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = DurableMemoryStore(Path(tmp.name) / "memory.sqlite3")
        ctx = "memora-governance-tests"
        for i in range(entries):
            store.upsert_entry(
                tag=f"alpha-topic-{i}",
                context_id=ctx,
                source_text=f"{RAW_SENTENCE} {i} alpha alpha",
                metadata={"seq": i},
                embedding_dimensions=8,
                spike_indices=[1],
                neuron_indices=[2],
                registered_at=100.0 + i,
            )
        info = provider_info if provider_info is not None else LEARNED_PROVIDER_INFO

        def recompute(context_id: str) -> dict:
            page = store.memora_source_page(context_id=context_id)
            snap = {
                "revision": page["snapshot_revision"],
                "entry_count": page["total"],
                "sampling_truncated": page["has_more"],
            }
            return build_shadow_plan(
                context_id=context_id,
                entries=page["entries"],
                revision_before=snap,
                revision_after=snap,
                provider_info=info,
                embed=_hash_embed,
                similarity_threshold=0.0,
                witnesses=page["witnesses"],
            )

        gov = MemoraGovernance(store, plan_recomputer=recompute, allow_test_time=True)
        return store, gov, ctx, recompute

    def _propose(self, gov, ctx, recompute, **kwargs):
        plan = recompute(ctx)
        return gov.propose_binding(
            context_id=ctx,
            plan_digest=plan["plan_digest"],
            cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
            proposed_by=kwargs.pop("proposed_by", "operator-a"),
            reason=kwargs.pop("reason", "test proposal"),
            now=kwargs.pop("now", 200.0),
            **kwargs,
        )["binding"]

    def _promote(self, gov, binding, **kwargs):
        return gov.promote_binding(
            binding_id=binding["binding_id"],
            expected_revision=kwargs.pop("expected_revision", binding["revision"]),
            reviewed_by=kwargs.pop("reviewed_by", "operator-b"),
            reason=kwargs.pop("reason", "test promotion"),
            confirm=kwargs.pop("confirm", True),
            active_provider_identity=kwargs.pop(
                "active_provider_identity", self._active_identity()
            ),
            now=kwargs.pop("now", 201.0),
            **kwargs,
        )

    @staticmethod
    def _active_identity() -> dict:
        return {
            "provider": "mlx-embeddings",
            "provider_type": "mlx-neural",
            "model_id": "test-model",
            "revision": "rev-1",
            "config_fingerprint": "c" * 64,
            "dimensions": 8,
            "semantic": True,
            "local_only": True,
            "ready": True,
            "learned": True,
        }

    # ------------------------------------------------------------------
    # E2E lifecycle
    # ------------------------------------------------------------------

    def test_propose_get_promote_immediate_e2e(self):
        """The P0 regression: a stored projection must round-trip the
        sanitizer unchanged, so get/promote work immediately after propose."""

        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self.assertEqual(binding["state"], "proposed")
        self.assertFalse(binding["automatic_promotion"])
        for witness in binding["sources"]:
            self.assertEqual(witness["schema"], MEMORA_WITNESS_SCHEMA)
            # Lifecycle facts only: identity, version times, byte counts,
            # oversized flags, and the memory-event frontier.
            self.assertGreaterEqual(witness["event_count"], 1)
            self.assertGreaterEqual(witness["upsert_event_count"], 1)
            self.assertGreaterEqual(witness["last_event_id"], 1)
            self.assertGreater(witness["last_event_at"], 0.0)
            self.assertIs(witness["source_text_oversized"], False)
            self.assertIs(witness["metadata_oversized"], False)
            # No content, digest, or key material: any of these would be a
            # durable offline equality oracle.
            for forbidden in (
                "signature",
                "public_key",
                "key_id",
                "algorithm",
                "source_text",
                "tag",
                "metadata",
                "source_text_sha256",
                "tag_sha256",
                "metadata_sha256",
            ):
                self.assertNotIn(forbidden, witness)

        got = gov.get_binding(binding["binding_id"])
        self.assertEqual(got["binding"]["revision"], binding["revision"])

        promoted = self._promote(gov, binding)
        self.assertEqual(promoted["state"], "promoted")

        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(len(effective["bindings"]), 1)
        self.assertEqual(effective["invalidated"], [])
        self.assertEqual(effective["integrity_failures"], [])

        audit = gov.audit_integrity(binding["binding_id"])
        self.assertTrue(audit["chain_valid"])
        self.assertTrue(audit["catalog_cross_checked"])
        self.assertEqual(audit["events_validated"], 2)

    def test_mutation_between_plan_and_propose_fails_closed(self):
        store, gov, ctx, recompute = self._make_env()
        plan = recompute(ctx)
        store.upsert_entry(
            tag="alpha-topic-late",
            context_id=ctx,
            source_text=f"{RAW_SENTENCE} late",
            metadata={},
            embedding_dimensions=8,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=150.0,
        )
        with self.assertRaises(MemoraGovernanceStaleRevision):
            gov.propose_binding(
                context_id=ctx,
                plan_digest=plan["plan_digest"],
                cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
                proposed_by="operator-a",
                reason="stale proposal",
                now=200.0,
            )

    def test_fallback_plan_is_never_promotable(self):
        store, gov, ctx, recompute = self._make_env(
            provider_info=FALLBACK_PROVIDER_INFO
        )
        plan = recompute(ctx)
        self.assertFalse(plan["learned"])
        with self.assertRaises(MemoraGovernanceValidationError):
            gov.propose_binding(
                context_id=ctx,
                plan_digest=plan["plan_digest"],
                cluster_ordinal=0,
                proposed_by="operator-a",
                reason="fallback",
                now=200.0,
            )

    # ------------------------------------------------------------------
    # Governance controls
    # ------------------------------------------------------------------

    def test_self_promotion_refused_and_two_actor_succeeds(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute, proposed_by="operator-a")
        with self.assertRaises(MemoraGovernanceValidationError):
            self._promote(gov, binding, reviewed_by="operator-a")
        promoted = self._promote(gov, binding, reviewed_by="operator-b")
        self.assertEqual(promoted["state"], "promoted")

    def test_promote_requires_confirm_and_exact_revision(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        with self.assertRaises(MemoraGovernanceValidationError):
            self._promote(gov, binding, confirm=False)
        with self.assertRaises(MemoraGovernanceValidationError):
            self._promote(gov, binding, confirm="yes")
        with self.assertRaises(
            (MemoraGovernanceStaleRevision, MemoraGovernanceConflict)
        ):
            self._promote(gov, binding, expected_revision="0" * 64)
        # The failed attempts changed nothing: the original CAS still works.
        promoted = self._promote(gov, binding)
        self.assertEqual(promoted["state"], "promoted")

    def test_provider_drift_blocks_promotion_and_retrieval(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        drifted = {**self._active_identity(), "revision": "rev-2"}
        with self.assertRaises(MemoraGovernanceConflict):
            self._promote(gov, binding, active_provider_identity=drifted)
        promoted = self._promote(gov, binding)["binding"]
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=drifted
        )
        self.assertEqual(effective["bindings"], [])
        self.assertEqual(
            effective["invalidated"][0]["binding_id"], promoted["binding_id"]
        )

    def test_revoke_removes_routing_without_deleting_sources(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        promoted = self._promote(gov, binding)["binding"]
        with self.assertRaises(MemoraGovernanceValidationError):
            gov.revoke_binding(
                binding_id=promoted["binding_id"],
                expected_revision=promoted["revision"],
                revoked_by="operator-c",
                reason="revoke without confirm",
                confirm=False,
                now=202.0,
            )
        revoked = gov.revoke_binding(
            binding_id=promoted["binding_id"],
            expected_revision=promoted["revision"],
            revoked_by="operator-c",
            reason="governed revocation",
            confirm=True,
            now=202.0,
        )
        self.assertEqual(revoked["state"], "revoked")
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(effective["bindings"], [])
        # Sources are untouched by revocation.
        page = store.memora_source_page(context_id=ctx)
        self.assertEqual(page["total"], 4)

    # ------------------------------------------------------------------
    # Exactly-once / CAS / concurrency
    # ------------------------------------------------------------------

    def test_propose_is_idempotent_for_identical_requests(self):
        store, gov, ctx, recompute = self._make_env()
        first = self._propose(gov, ctx, recompute)
        replay = gov.propose_binding(
            context_id=ctx,
            plan_digest=first["plan"]["plan_digest"],
            cluster_ordinal=first["plan"]["cluster_ordinal"],
            proposed_by="operator-a",
            reason="test proposal",
            now=250.0,
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["binding_id"], first["binding_id"])

    def test_same_request_id_with_different_args_conflicts(self):
        store, gov, ctx, recompute = self._make_env()
        plan = recompute(ctx)
        gov.propose_binding(
            context_id=ctx,
            plan_digest=plan["plan_digest"],
            cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
            proposed_by="operator-a",
            reason="first reason",
            governance_request_id="req.fixed.1",
            now=200.0,
        )
        with self.assertRaises(MemoraGovernanceConflict):
            gov.propose_binding(
                context_id=ctx,
                plan_digest=plan["plan_digest"],
                cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
                proposed_by="operator-a",
                reason="second reason",
                governance_request_id="req.fixed.1",
                now=200.0,
            )

    def test_lost_response_promote_replay_reports_current_state(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        promoted = self._promote(
            gov, binding, governance_request_id="req.promote.1"
        )
        gov.revoke_binding(
            binding_id=binding["binding_id"],
            expected_revision=promoted["binding"]["revision"],
            revoked_by="operator-c",
            reason="revoked after promote",
            confirm=True,
            now=203.0,
        )
        replay = self._promote(
            gov, binding, governance_request_id="req.promote.1"
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["historical_state"], "promoted")
        self.assertEqual(replay["current_state"], "revoked")

    def test_propose_replay_after_source_drift_returns_original(self):
        """Exactly-once replay resolves BEFORE plan recomputation: a
        lost-response retry of an identical propose request must return the
        validated original receipt even after the namespace drifted, while
        conflicting reuse of the request id still rejects."""

        store, gov, ctx, recompute = self._make_env()
        plan = recompute(ctx)
        args = dict(
            context_id=ctx,
            plan_digest=plan["plan_digest"],
            cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
            proposed_by="operator-a",
            reason="drift replay proposal",
        )
        first = gov.propose_binding(
            **args, governance_request_id="req.propose.drift", now=200.0
        )
        # The namespace drifts after the successful (lost-response) write.
        store.upsert_entry(
            tag="alpha-topic-late",
            context_id=ctx,
            source_text=f"{RAW_SENTENCE} late",
            metadata={},
            embedding_dimensions=8,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=250.0,
        )
        # A NEW request with the now-stale digest still fails closed.
        with self.assertRaises(MemoraGovernanceStaleRevision):
            gov.propose_binding(
                **args, governance_request_id="req.propose.fresh", now=260.0
            )
        # The identical retry returns the original receipt, not stale.
        replay = gov.propose_binding(
            **args, governance_request_id="req.propose.drift", now=260.0
        )
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["binding_id"], first["binding_id"])
        self.assertEqual(replay["historical_state"], "proposed")
        self.assertEqual(replay["current_state"], "proposed")
        # Conflicting reuse of the same request id still rejects.
        with self.assertRaises(MemoraGovernanceConflict):
            gov.propose_binding(
                **{**args, "reason": "different reason"},
                governance_request_id="req.propose.drift",
                now=260.0,
            )

    def test_concurrent_promotions_yield_exactly_one_winner(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        barrier = threading.Barrier(2)
        outcomes: list[tuple[str, object]] = []
        lock = threading.Lock()

        def attempt(reviewer: str, request_id: str) -> None:
            barrier.wait()
            try:
                result = self._promote(
                    gov,
                    binding,
                    reviewed_by=reviewer,
                    governance_request_id=request_id,
                )
                with lock:
                    outcomes.append(("ok", result))
            except (
                MemoraGovernanceConflict,
                MemoraGovernanceStaleRevision,
                MemoraGovernanceInvalidTransition,
            ) as exc:
                with lock:
                    outcomes.append(("error", exc))

        threads = [
            threading.Thread(target=attempt, args=("operator-b", "req.promote.a")),
            threading.Thread(target=attempt, args=("operator-c", "req.promote.b")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        kinds = sorted(kind for kind, _ in outcomes)
        self.assertEqual(kinds, ["error", "ok"])
        winner = next(result for kind, result in outcomes if kind == "ok")
        self.assertEqual(winner["state"], "promoted")
        current = gov.get_binding(binding["binding_id"])["binding"]
        self.assertEqual(current["state"], "promoted")
        # Exactly one reviewer's identity landed in the projection.
        self.assertEqual(current["reviewed_by"], winner["binding"]["reviewed_by"])
        gov.audit_integrity(binding["binding_id"])

    # ------------------------------------------------------------------
    # Source drift / witness verification
    # ------------------------------------------------------------------

    def test_source_mutation_invalidates_promoted_binding(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        store.upsert_entry(
            tag="alpha-topic-0",
            context_id=ctx,
            source_text="completely different content now",
            metadata={"seq": 0},
            embedding_dimensions=8,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=300.0,
        )
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(effective["bindings"], [])
        self.assertEqual(len(effective["invalidated"]), 1)

    def test_source_deletion_invalidates_promoted_binding(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        victim = binding["sources"][0]["memory_id"]
        with closing(store._connect()) as conn:
            with store._transaction(conn, immediate=True):
                conn.execute(
                    "DELETE FROM memory_entries WHERE memory_id = ?", (victim,)
                )
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(effective["bindings"], [])
        reasons = effective["invalidated"][0]["reasons"]
        self.assertTrue(
            any(reason.startswith("source-missing") for reason in reasons),
            reasons,
        )

    def test_same_length_replacement_through_store_api_is_detected(self):
        """A byte count alone would miss a same-length replacement, but any
        replacement made through the MemoryStore mutation API appends a
        memory event and advances ``updated_at``, so the lifecycle witness
        invalidates it."""

        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        victim = binding["sources"][0]["memory_id"]
        with closing(store._connect_read_only()) as conn:
            row = conn.execute(
                "SELECT tag, source_text FROM memory_entries "
                "WHERE memory_id = ?",
                (victim,),
            ).fetchone()
        original = str(row["source_text"])
        replacement = "X" * len(original.encode("utf-8"))
        self.assertEqual(
            len(replacement.encode("utf-8")), len(original.encode("utf-8"))
        )
        store.upsert_entry(
            tag=str(row["tag"]),
            context_id=ctx,
            source_text=replacement,
            metadata={"seq": 0},
            embedding_dimensions=8,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=400.0,
        )
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(effective["bindings"], [])
        reasons = effective["invalidated"][0]["reasons"]
        self.assertTrue(
            any(reason.startswith("lifecycle-mismatch") for reason in reasons),
            reasons,
        )

    def test_out_of_band_sql_tamper_is_outside_witness_scope(self):
        """Honest scope statement: a direct SQLite UPDATE that bypasses the
        mutation API -- preserving byte length, ``updated_at``, and the
        event frontier -- is invisible to the non-content lifecycle
        witness by design.  Detecting out-of-band file tamper is the job of
        store/recovery integrity auditing, not of a content witness; a
        content-bearing witness (hash or public signature) would itself be
        a durable offline equality oracle."""

        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        victim = binding["sources"][0]["memory_id"]
        with closing(store._connect()) as conn:
            row = conn.execute(
                "SELECT source_text FROM memory_entries WHERE memory_id = ?",
                (victim,),
            ).fetchone()
            original = str(row["source_text"])
            replacement = "X" * len(original.encode("utf-8"))
            with store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE memory_entries SET source_text = ? "
                    "WHERE memory_id = ?",
                    (replacement, victim),
                )
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        # The binding still routes: the witness makes no content-integrity
        # claim about writes that bypass the mutation API.
        self.assertEqual(len(effective["bindings"]), 1)

    # ------------------------------------------------------------------
    # Secrecy: no equality oracle, no key material, no raw text
    # ------------------------------------------------------------------

    def test_projections_and_receipts_carry_no_secrets(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        with closing(store._connect_read_only()) as conn:
            blobs = [
                str(row["value_json"])
                for row in conn.execute(
                    "SELECT value_json FROM store_metadata "
                    "WHERE key LIKE 'memora_governance.%'"
                ).fetchall()
            ]
            blobs.extend(
                str(row["payload_json"])
                for row in conn.execute(
                    "SELECT payload_json FROM store_maintenance_receipts "
                    "WHERE operation_type LIKE 'memora-governance-v1.%'"
                ).fetchall()
            )
        self.assertTrue(blobs)
        for blob in blobs:
            # No raw-content digests: a stored hash of untrusted content is
            # a durable equality oracle.
            self.assertNotIn("source_text_sha256", blob)
            self.assertNotIn("tag_sha256", blob)
            self.assertNotIn("metadata_sha256", blob)
            # No signatures or key material either: a deterministic public
            # signature over content is equally an offline equality oracle.
            self.assertNotIn('"signature"', blob)
            self.assertNotIn('"public_key"', blob)
            self.assertNotIn('"key_id"', blob)
            self.assertNotIn("ed25519", blob)
            # No raw source text.
            self.assertNotIn(RAW_SENTENCE, blob)
            self.assertNotIn("PRIVATE KEY", blob)
            # No vectors.
            parsed = json.loads(blob)
            self._assert_no_vector_keys(parsed)

    def _assert_no_vector_keys(self, value) -> None:
        forbidden = {"embedding", "embeddings", "vector", "vectors", "centroid"}
        if isinstance(value, dict):
            for key, inner in value.items():
                self.assertNotIn(str(key).lower(), forbidden)
                self._assert_no_vector_keys(inner)
        elif isinstance(value, list):
            for inner in value:
                self._assert_no_vector_keys(inner)

    # ------------------------------------------------------------------
    # Tamper detection
    # ------------------------------------------------------------------

    def _read_projection(self, store, key: str) -> dict:
        with closing(store._connect_read_only()) as conn:
            row = conn.execute(
                "SELECT value_json FROM store_metadata WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(str(row["value_json"]))

    def _write_raw(self, store, key: str, value: dict) -> None:
        with closing(store._connect()) as conn:
            with store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                    (json.dumps(value, sort_keys=True), key),
                )

    def test_projection_tamper_fails_closed(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        key = f"memora_governance.binding.v1.{binding['binding_id']}"
        # Naive tamper: digest breaks.
        naive = self._read_projection(store, key)
        naive["state"] = "promoted"
        self._write_raw(store, key, naive)
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.get_binding(binding["binding_id"])
        # Sophisticated tamper: recomputed self-digest, but the receipt chain
        # does not corroborate the forged state.
        forged = self._read_projection(store, key)
        forged.pop("revision", None)
        forged["state"] = "promoted"
        self._write_raw(store, key, _with_revision(forged))
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.get_binding(binding["binding_id"])

    def test_catalog_tamper_fails_closed(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        key = f"memora_governance.catalog.v1.{ctx}"
        catalog = self._read_projection(store, key)
        catalog["bindings"][0]["state"] = "promoted"
        catalog.pop("revision", None)
        self._write_raw(store, key, _with_revision(catalog))
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.get_binding(binding["binding_id"])
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(effective["bindings"], [])

    def test_historical_receipt_tamper_fails_audit(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        with closing(store._connect()) as conn:
            row = conn.execute(
                "SELECT operation_id, payload_json FROM store_maintenance_receipts "
                "WHERE operation_type = 'memora-governance-v1.propose'"
            ).fetchone()
            payload = json.loads(str(row["payload_json"]))
            payload["actor"] = "forged-operator"
            with store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE store_maintenance_receipts SET payload_json = ? "
                    "WHERE operation_id = ?",
                    (json.dumps(payload, sort_keys=True), row["operation_id"]),
                )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.audit_integrity(binding["binding_id"])
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.binding_history(binding["binding_id"])

    def _tamper_receipt_payload(self, store, operation_type: str, mutate) -> None:
        with closing(store._connect()) as conn:
            row = conn.execute(
                "SELECT operation_id, payload_json FROM store_maintenance_receipts "
                "WHERE operation_type = ?",
                (operation_type,),
            ).fetchone()
            payload = json.loads(str(row["payload_json"]))
            mutate(payload)
            with store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE store_maintenance_receipts SET payload_json = ? "
                    "WHERE operation_id = ?",
                    (json.dumps(payload, sort_keys=True), row["operation_id"]),
                )

    def test_receipt_reason_tamper_fails_audit(self):
        """The receipt's reason is bound to the reason the projection
        recorded for that proposal/decision."""

        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        self._tamper_receipt_payload(
            store,
            "memora-governance-v1.propose",
            lambda payload: payload.__setitem__("reason", "forged reason"),
        )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.audit_integrity(binding["binding_id"])
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.binding_history(binding["binding_id"])

    def test_receipt_fingerprint_tamper_fails_audit(self):
        """The receipt's request fingerprint is bound to the projection's
        recorded last_request_fingerprint."""

        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        promoted = self._promote(
            gov, binding, governance_request_id="req.promote.fp"
        )
        self.assertEqual(promoted["state"], "promoted")
        self._tamper_receipt_payload(
            store,
            "memora-governance-v1.promote",
            lambda payload: payload.__setitem__(
                "request_fingerprint", "e" * 64
            ),
        )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.audit_integrity(binding["binding_id"])
        # A replay of the promote request must also fail closed, not return
        # the tampered receipt.
        with self.assertRaises(
            (MemoraGovernanceIntegrityError, MemoraGovernanceConflict)
        ):
            self._promote(gov, binding, governance_request_id="req.promote.fp")

    def test_receipt_result_envelope_tamper_fails_audit(self):
        """The stored result must be exactly the recomputed envelope over
        its own historical projection: no unchecked top-level field can
        survive into history, audit, or replay output."""

        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)

        def _forge_envelope(payload: dict) -> None:
            payload["result"]["operation"] = "reject-memora-binding"

        self._tamper_receipt_payload(
            store, "memora-governance-v1.promote", _forge_envelope
        )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.audit_integrity(binding["binding_id"])

        # An extra unchecked top-level field is equally rejected.
        store2, gov2, ctx2, recompute2 = self._make_env()
        binding2 = self._propose(gov2, ctx2, recompute2)
        self._promote(gov2, binding2)
        self._tamper_receipt_payload(
            store2,
            "memora-governance-v1.promote",
            lambda payload: payload["result"].__setitem__(
                "smuggled_field", True
            ),
        )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov2.audit_integrity(binding2["binding_id"])

    def test_corrupt_projection_has_zero_retrieval_effect(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)
        key = f"memora_governance.binding.v1.{binding['binding_id']}"
        corrupted = self._read_projection(store, key)
        corrupted["sources"] = []
        corrupted.pop("revision", None)
        self._write_raw(store, key, _with_revision(corrupted))
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(effective["bindings"], [])
        self.assertIn(binding["binding_id"], effective["integrity_failures"])

    # ------------------------------------------------------------------
    # Catalog agreement is a transition precondition
    # ------------------------------------------------------------------

    def _rewrite_catalog(self, store, ctx: str, mutate) -> None:
        key = f"memora_governance.catalog.v1.{ctx}"
        catalog = self._read_projection(store, key)
        mutate(catalog)
        catalog.pop("revision", None)
        self._write_raw(store, key, _with_revision(catalog))

    def test_promote_with_deleted_catalog_entry_fails_and_never_mutates(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._rewrite_catalog(
            store, ctx, lambda catalog: catalog.__setitem__("bindings", [])
        )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            self._promote(gov, binding)
        # Nothing was mutated or silently healed: the stored projection is
        # still the proposed one.
        key = f"memora_governance.binding.v1.{binding['binding_id']}"
        self.assertEqual(self._read_projection(store, key)["state"], "proposed")

    def test_transition_with_stale_catalog_state_or_revision_fails(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        # Stale state in the catalog row.
        self._rewrite_catalog(
            store,
            ctx,
            lambda catalog: catalog["bindings"][0].__setitem__(
                "state", "rejected"
            ),
        )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            self._promote(gov, binding)
        with self.assertRaises(MemoraGovernanceIntegrityError):
            gov.reject_binding(
                binding_id=binding["binding_id"],
                expected_revision=binding["revision"],
                reviewed_by="operator-b",
                reason="reject on stale catalog",
                now=205.0,
            )
        # Stale revision in the catalog row.
        self._rewrite_catalog(
            store,
            ctx,
            lambda catalog: catalog["bindings"][0].update(
                {"state": "proposed", "revision": "f" * 64}
            ),
        )
        with self.assertRaises(MemoraGovernanceIntegrityError):
            self._promote(gov, binding)
        key = f"memora_governance.binding.v1.{binding['binding_id']}"
        self.assertEqual(self._read_projection(store, key)["state"], "proposed")

    def test_cross_context_catalog_injection_never_routes_or_mutates(self):
        store, gov, ctx, recompute = self._make_env()
        other_ctx = "memora-governance-other"
        store.upsert_entry(
            tag="other-topic-0",
            context_id=other_ctx,
            source_text=f"{RAW_SENTENCE} other",
            metadata={},
            embedding_dimensions=8,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=100.0,
        )
        binding = self._propose(gov, ctx, recompute)
        own_key = f"memora_governance.catalog.v1.{ctx}"
        own_catalog = self._read_projection(store, own_key)
        entry = dict(own_catalog["bindings"][0])
        # Inject the entry into a foreign namespace's catalog and delete it
        # from its own.
        foreign = _with_revision(
            {
                "schema": own_catalog["schema"],
                "context_id": other_ctx,
                "bindings": [entry],
                "event_count": 1,
                "updated_at": 201.0,
            }
        )
        with closing(store._connect()) as conn:
            with store._transaction(conn, immediate=True):
                conn.execute(
                    "INSERT OR REPLACE INTO store_metadata "
                    "(key, value_json, updated_at) VALUES (?, ?, ?)",
                    (
                        f"memora_governance.catalog.v1.{other_ctx}",
                        json.dumps(foreign, sort_keys=True),
                        201.0,
                    ),
                )
        self._rewrite_catalog(
            store, ctx, lambda catalog: catalog.__setitem__("bindings", [])
        )
        # The binding cannot transition: its own catalog omits it.
        with self.assertRaises(MemoraGovernanceIntegrityError):
            self._promote(gov, binding)
        # The foreign catalog's injected reference never routes: the
        # projection's namespace disagrees with the requesting namespace.
        effective = gov.effective_bindings(
            context_id=other_ctx,
            active_provider_identity=self._active_identity(),
        )
        self.assertEqual(effective["bindings"], [])
        key = f"memora_governance.binding.v1.{binding['binding_id']}"
        self.assertEqual(self._read_projection(store, key)["state"], "proposed")

    # ------------------------------------------------------------------
    # Transactional promoted-binding capacity ceiling
    # ------------------------------------------------------------------

    def _promote_distinct_binding(self, store, gov, ctx, recompute, *, index):
        """Add one entry (creating a fresh abstraction), propose, promote."""

        now = 300.0 + index
        store.upsert_entry(
            tag=f"capacity-topic-{index}",
            context_id=ctx,
            source_text=f"{RAW_SENTENCE} capacity {index} alpha alpha",
            metadata={"cap": index},
            embedding_dimensions=8,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=now,
        )
        plan = recompute(ctx)
        proposed = gov.propose_binding(
            context_id=ctx,
            plan_digest=plan["plan_digest"],
            cluster_ordinal=plan["clusters"][0]["cluster_ordinal"],
            proposed_by="operator-a",
            reason=f"capacity proposal {index}",
            now=now + 0.25,
        )["binding"]
        return proposed

    def test_capacity_33rd_promotion_rejected_and_supersede_succeeds(self):
        """Promotion enforces MAX_EFFECTIVE_BINDINGS transactionally: the
        33rd active promotion is rejected unless the same transaction
        atomically supersedes one, so a state=promoted row that retrieval
        would silently ignore is never stored."""

        store, gov, ctx, recompute = self._make_env()
        first = self._propose(gov, ctx, recompute)
        self._promote(gov, first, now=299.5)
        promoted_ids = [first["binding_id"]]
        for index in range(1, MAX_EFFECTIVE_BINDINGS):
            proposed = self._promote_distinct_binding(
                store, gov, ctx, recompute, index=index
            )
            self._promote(gov, proposed, now=300.0 + index + 0.5)
            promoted_ids.append(proposed["binding_id"])

        # 32 promoted bindings: retrieval sees all of them, untruncated.
        effective = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(len(effective["bindings"]), MAX_EFFECTIVE_BINDINGS)
        self.assertFalse(effective["truncated"])

        # The 33rd active promotion is rejected at the gate.
        extra = self._promote_distinct_binding(
            store, gov, ctx, recompute, index=MAX_EFFECTIVE_BINDINGS
        )
        with self.assertRaises(MemoraGovernanceConflict) as caught:
            self._promote(gov, extra, now=340.0)
        self.assertIn("capacity", str(caught.exception))
        key = f"memora_governance.binding.v1.{extra['binding_id']}"
        self.assertEqual(self._read_projection(store, key)["state"], "proposed")

        # Superseding one promoted binding in the same transaction keeps the
        # net active count unchanged, so the promotion succeeds.
        promoted = self._promote(
            gov,
            extra,
            now=341.0,
            supersedes_binding_id=promoted_ids[0],
        )
        self.assertEqual(promoted["state"], "promoted")
        superseded = gov.get_binding(promoted_ids[0])["binding"]
        self.assertEqual(superseded["state"], "superseded")
        after = gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(len(after["bindings"]), MAX_EFFECTIVE_BINDINGS)
        self.assertFalse(after["truncated"])
        self.assertEqual(after["invalidated"], [])
        self.assertEqual(after["integrity_failures"], [])

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def test_binding_history_is_chain_walked_and_paged(self):
        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        promoted = self._promote(gov, binding)["binding"]
        gov.revoke_binding(
            binding_id=binding["binding_id"],
            expected_revision=promoted["revision"],
            revoked_by="operator-c",
            reason="history revocation",
            confirm=True,
            now=203.0,
        )
        history = gov.binding_history(binding["binding_id"])
        self.assertEqual(history["total_events"], 3)
        self.assertEqual(
            [event["action"] for event in history["events"]],
            ["revoke", "promote", "propose"],
        )
        self.assertFalse(history["truncated"])
        page = gov.binding_history(binding["binding_id"], limit=1)
        self.assertEqual(len(page["events"]), 1)
        self.assertEqual(page["events"][0]["action"], "revoke")
        self.assertTrue(page["truncated"])
        older = gov.binding_history(
            binding["binding_id"],
            limit=1,
            before_sequence=page["next_before_sequence"],
        )
        self.assertEqual(older["events"][0]["action"], "promote")

    # ------------------------------------------------------------------
    # Recovery / replication: automatic, key-free verification
    # ------------------------------------------------------------------

    def test_replicated_store_verifies_automatically(self):
        """A backup/restore or replica needs no trust configuration at all:
        the lifecycle witness holds no key material, so verification is a
        pure recompute-and-compare against the replicated rows."""

        store, gov, ctx, recompute = self._make_env()
        binding = self._propose(gov, ctx, recompute)
        self._promote(gov, binding)

        replica_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(replica_tmp.cleanup)
        replica_path = Path(replica_tmp.name) / "memory.sqlite3"
        with closing(sqlite3.connect(store.db_path)) as src:
            with closing(sqlite3.connect(replica_path)) as dst:
                src.backup(dst)
        os.chmod(replica_tmp.name, 0o700)
        os.chmod(replica_path, 0o600)
        # The replica carries only the database: no recovery-keys directory
        # and no trust environment variable are needed anywhere.
        self.assertFalse((Path(replica_tmp.name) / "recovery-keys").exists())
        previous = os.environ.pop("SYNAPSE_S2_TRUSTED_BACKUP_KEY_IDS", None)

        def _restore_env():
            if previous is not None:
                os.environ["SYNAPSE_S2_TRUSTED_BACKUP_KEY_IDS"] = previous

        self.addCleanup(_restore_env)

        replica = DurableMemoryStore(replica_path)
        replica_gov = MemoraGovernance(replica, allow_test_time=True)

        got = replica_gov.get_binding(binding["binding_id"])
        self.assertEqual(got["binding"]["state"], "promoted")
        replica_gov.audit_integrity(binding["binding_id"])
        effective = replica_gov.effective_bindings(
            context_id=ctx, active_provider_identity=self._active_identity()
        )
        self.assertEqual(len(effective["bindings"]), 1)
        self.assertEqual(effective["invalidated"], [])
        self.assertEqual(effective["integrity_failures"], [])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from bridge_governance import (
    BridgeGovernance,
    BridgeGovernanceConflict,
    BridgeGovernanceExpired,
    BridgeGovernanceIntegrityError,
    BridgeGovernanceInvalidTransition,
    BridgeGovernanceStaleRevision,
    LINK_KEY_PREFIX,
    PROPOSAL_KEY_PREFIX,
    _with_revision,
)
from memory_store import DurableMemoryStore, NAMESPACE_CATALOG_METADATA_PREFIX


NOW = 1_700_000_000.0


class BridgeGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "memory.sqlite3"
        self.store = DurableMemoryStore(self.db_path)
        self.governance = BridgeGovernance(self.store, allow_test_time=True)
        self.compat_governance = BridgeGovernance(
            self.store,
            require_distinct_reviewer=False,
            allow_compatibility_approval=True,
            allow_test_time=True,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def propose(
        self,
        *,
        source: str = "alpha",
        target: str = "beta",
        request_id: str = "proposal-request",
        now: float = NOW,
        proposal_expires_at: float | None = None,
        link_expires_at: float | None = None,
        evidence: dict | None = None,
        reason: str = "The namespaces have operator-reviewed overlap.",
    ) -> dict:
        return self.governance.propose_namespace_link(
            source_context_id=source,
            target_context_id=target,
            relation_type="related",
            weight=0.73,
            evidence=evidence or {"basis": "operator review"},
            direction="bidirectional",
            proposed_by="alice",
            reason=reason,
            proposal_expires_at=proposal_expires_at,
            link_expires_at=link_expires_at,
            governance_request_id=request_id,
            now=now,
        )

    def approve(
        self,
        proposed: dict,
        *,
        request_id: str = "approval-request",
        reviewer: str = "bob",
        now: float = NOW + 1,
    ) -> dict:
        proposal = proposed["proposal"]
        return self.governance.review_namespace_link(
            proposal_id=proposal["proposal_id"],
            decision="approve",
            reviewed_by=reviewer,
            reason="The evidence supports deliberate connected recall.",
            expected_revision=proposal["revision"],
            governance_request_id=request_id,
            now=now,
        )

    def raw_scalar(self, sql: str, params: tuple = ()):
        with closing(self.store._connect_read_only()) as conn:
            row = conn.execute(sql, params).fetchone()
        return row[0]

    def test_proposal_is_pending_canonical_and_does_not_write_memory_or_link(self) -> None:
        result = self.propose(source="zeta", target="alpha")
        proposal = result["proposal"]

        self.assertEqual(result["state"], "pending")
        self.assertEqual(proposal["source_context_id"], "alpha")
        self.assertEqual(proposal["target_context_id"], "zeta")
        self.assertEqual(len(proposal["revision"]), 64)
        self.assertFalse(result["automatic_cross_namespace_write"])
        self.assertEqual(self.store.list_context_links(), [])
        self.assertEqual(self.raw_scalar("SELECT COUNT(*) FROM memory_entries"), 0)

        history = self.governance.list_namespace_link_history(
            proposal_id=proposal["proposal_id"]
        )
        self.assertEqual(history["event_count"], 1)
        self.assertEqual(history["events"][0]["action"], "propose")

        catalog_keys = set(
            self._metadata_keys(NAMESPACE_CATALOG_METADATA_PREFIX + "%")
        )
        self.assertEqual(
            catalog_keys,
            {
                NAMESPACE_CATALOG_METADATA_PREFIX + "alpha",
                NAMESPACE_CATALOG_METADATA_PREFIX + "zeta",
            },
        )
        self.assertEqual(self.governance.audit_integrity(now=NOW + 1)["status"], "ready")

    def test_review_approval_is_cas_distinct_actor_and_idempotent(self) -> None:
        proposed = self.propose()
        proposal = proposed["proposal"]
        with self.assertRaises(BridgeGovernanceInvalidTransition):
            self.governance.review_namespace_link(
                proposal_id=proposal["proposal_id"],
                decision="approve",
                reviewed_by="alice",
                reason="Self approval should fail.",
                expected_revision=proposal["revision"],
                governance_request_id="self-review",
                now=NOW + 1,
            )

        approved = self.approve(proposed)
        replay = self.approve(proposed)
        self.assertEqual(approved["state"], "approved")
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(
            replay["proposal"]["revision"], approved["proposal"]["revision"]
        )
        self.assertEqual(
            self.governance.list_namespace_link_history(
                proposal_id=proposal["proposal_id"]
            )["event_count"],
            2,
        )
        self.assertEqual(len(self.governance.list_active_namespace_links(now=NOW + 2)), 1)

        recall = self.governance.resolve_recall_contexts(
            context_id="alpha", scope="connected", now=NOW + 2
        )
        self.assertEqual([item["context_id"] for item in recall], ["alpha", "beta", "global"])
        self.assertEqual(recall[1]["recall_provenance"], "connected")
        self.assertEqual(
            recall[1]["via_context_link_id"], approved["link"]["context_link_id"]
        )

        with self.assertRaises(BridgeGovernanceStaleRevision):
            self.governance.review_namespace_link(
                proposal_id=proposal["proposal_id"],
                decision="reject",
                reviewed_by="carol",
                reason="This observation is stale.",
                expected_revision=proposal["revision"],
                governance_request_id="stale-reject",
                now=NOW + 2,
            )
        self.assertEqual(self.governance.audit_integrity(now=NOW + 2)["status"], "ready")

    def test_rejection_never_materializes_an_active_link(self) -> None:
        proposed = self.propose()
        proposal = proposed["proposal"]
        rejected = self.governance.review_namespace_link(
            proposal_id=proposal["proposal_id"],
            decision="reject",
            reviewed_by="bob",
            reason="Evidence is insufficient.",
            expected_revision=proposal["revision"],
            governance_request_id="reject-request",
            now=NOW + 1,
        )

        self.assertEqual(rejected["state"], "rejected")
        self.assertEqual(self.store.list_context_links(), [])
        self.assertEqual(self.governance.list_active_namespace_links(now=NOW + 2), [])
        self.assertEqual(self.governance.audit_integrity(now=NOW + 2)["status"], "ready")

    def test_direct_approval_compatibility_is_atomic_audited_and_canonical(self) -> None:
        with self.assertRaises(ValueError):
            self.compat_governance.approve_namespace_link_compat(
                source_context_id="zeta",
                target_context_id="alpha",
                approved_by="operator",
                reason="Explicit compatibility approval.",
                governance_request_id="compat-request",
                now=NOW,
            )

        approved = self.compat_governance.approve_namespace_link_compat(
            source_context_id="zeta",
            target_context_id="alpha",
            relation_type="related",
            weight=0.8,
            evidence={"basis": "operator confirmation"},
            direction="bidirectional",
            approved_by="operator",
            reason="Explicit compatibility approval.",
            governance_request_id="compat-request",
            confirm=True,
            now=NOW,
        )
        replay = self.compat_governance.approve_namespace_link_compat(
            source_context_id="zeta",
            target_context_id="alpha",
            relation_type="related",
            weight=0.8,
            evidence={"basis": "operator confirmation"},
            direction="bidirectional",
            approved_by="operator",
            reason="Explicit compatibility approval.",
            governance_request_id="compat-request",
            confirm=True,
            now=NOW,
        )

        expected_id = self.store.stable_context_link_id(
            source_context_id="alpha",
            target_context_id="zeta",
            relation_type="related",
            direction="bidirectional",
        )
        self.assertEqual(approved["link"]["context_link_id"], expected_id)
        self.assertEqual(approved["proposal"]["source_context_id"], "alpha")
        self.assertEqual(approved["state"], "approved")
        self.assertTrue(approved["compatibility_mode"])
        self.assertTrue(replay["idempotent_replay"])
        history = self.governance.list_namespace_link_history(
            proposal_id=approved["proposal"]["proposal_id"]
        )
        self.assertEqual(history["event_count"], 2)
        self.assertEqual({event["action"] for event in history["events"]}, {"propose", "approve"})
        self.assertEqual(self.raw_scalar("SELECT COUNT(*) FROM memory_entries"), 0)
        self.assertEqual(self.governance.audit_integrity(now=NOW + 1)["status"], "ready")

    def test_disable_then_revoke_preserves_row_and_removes_connected_recall(self) -> None:
        approved = self.approve(self.propose())
        link_id = approved["link"]["context_link_id"]
        disabled = self.governance.disable_namespace_link(
            context_link_id=link_id,
            disabled_by="carol",
            reason="The bridge needs a safety pause.",
            expected_revision=approved["proposal"]["revision"],
            governance_request_id="disable-request",
            confirm=True,
            now=NOW + 2,
        )
        self.assertEqual(disabled["state"], "disabled")
        self.assertFalse(disabled["link"]["enabled"])
        self.assertEqual(
            [
                item["context_id"]
                for item in self.governance.resolve_recall_contexts(
                    context_id="alpha", scope="connected", now=NOW + 2
                )
            ],
            ["alpha", "global"],
        )

        revoked = self.governance.revoke_namespace_link(
            context_link_id=link_id,
            revoked_by="dana",
            reason="The relationship is no longer authorized.",
            expected_revision=disabled["proposal"]["revision"],
            governance_request_id="revoke-request",
            confirm=True,
            now=NOW + 3,
        )
        self.assertEqual(revoked["state"], "revoked")
        self.assertEqual(
            self.raw_scalar(
                "SELECT COUNT(*) FROM context_relationships WHERE context_link_id = ?",
                (link_id,),
            ),
            1,
        )
        self.assertEqual(
            self.raw_scalar(
                "SELECT enabled FROM context_relationships WHERE context_link_id = ?",
                (link_id,),
            ),
            0,
        )
        self.assertEqual(
            self.governance.list_namespace_link_history(context_link_id=link_id)["event_count"],
            4,
        )
        self.assertEqual(self.governance.audit_integrity(now=NOW + 4)["status"], "ready")

    def test_pending_and_active_expiry_fail_closed_and_are_materialized(self) -> None:
        pending = self.propose(
            request_id="pending-expiry",
            proposal_expires_at=NOW + 60,
        )
        pending_sweep = self.governance.expire_due(now=NOW + 60)
        self.assertEqual(pending_sweep["expired_count"], 1)
        pending_view = self.governance.list_namespace_link_proposals(now=NOW + 60)
        self.assertEqual(pending_view["proposals"][0]["state"], "expired")
        with self.assertRaises((BridgeGovernanceExpired, BridgeGovernanceStaleRevision)):
            self.approve(pending, request_id="late-approval", now=NOW + 61)

        active = self.compat_governance.approve_namespace_link_compat(
            source_context_id="gamma",
            target_context_id="delta",
            approved_by="operator",
            reason="Temporary incident bridge.",
            link_expires_at=NOW + 60,
            governance_request_id="active-expiry",
            confirm=True,
            now=NOW,
        )
        link_id = active["link"]["context_link_id"]
        self.assertEqual(len(self.governance.list_active_namespace_links(now=NOW + 59)), 1)
        self.assertEqual(self.governance.list_active_namespace_links(now=NOW + 60), [])
        self.assertEqual(
            [
                item["context_id"]
                for item in self.governance.resolve_recall_contexts(
                    context_id="gamma", scope="connected", now=NOW + 60
                )
            ],
            ["gamma", "global"],
        )
        active_sweep = self.governance.expire_due(now=NOW + 60)
        self.assertEqual(active_sweep["expired_count"], 1)
        self.assertEqual(
            self.raw_scalar(
                "SELECT enabled FROM context_relationships WHERE context_link_id = ?",
                (link_id,),
            ),
            0,
        )
        self.assertEqual(self.governance.audit_integrity(now=NOW + 61)["status"], "ready")

    def test_concurrent_reviews_allow_exactly_one_revision_winner(self) -> None:
        proposed = self.propose()
        proposal = proposed["proposal"]
        barrier = threading.Barrier(2)

        def review(request_id: str, reviewer: str, decision: str):
            barrier.wait(timeout=5)
            try:
                return self.governance.review_namespace_link(
                    proposal_id=proposal["proposal_id"],
                    decision=decision,
                    reviewed_by=reviewer,
                    reason=f"Concurrent {decision} decision.",
                    expected_revision=proposal["revision"],
                    governance_request_id=request_id,
                    now=NOW + 1,
                )
            except Exception as exc:  # return the race outcome for deterministic assertions
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    lambda args: review(*args),
                    [
                        ("concurrent-approve", "bob", "approve"),
                        ("concurrent-reject", "carol", "reject"),
                    ],
                )
            )

        winners = [item for item in outcomes if isinstance(item, dict)]
        losers = [item for item in outcomes if isinstance(item, Exception)]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)
        self.assertIsInstance(losers[0], BridgeGovernanceStaleRevision)
        self.assertEqual(
            self.governance.list_namespace_link_history(
                proposal_id=proposal["proposal_id"]
            )["event_count"],
            2,
        )
        self.assertEqual(self.governance.audit_integrity(now=NOW + 2)["status"], "ready")

    def test_review_rolls_back_projection_link_and_receipt_on_event_failure(self) -> None:
        proposed = self.propose()
        proposal = proposed["proposal"]
        with patch.object(
            self.governance,
            "_insert_event",
            side_effect=RuntimeError("injected event failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected event failure"):
                self.approve(proposed)

        current = self.governance.list_namespace_link_proposals(now=NOW + 1)["proposals"][0]
        self.assertEqual(current["state"], "pending")
        self.assertEqual(current["revision"], proposal["revision"])
        self.assertEqual(self.store.list_context_links(), [])
        self.assertEqual(
            self.governance.list_namespace_link_history(
                proposal_id=proposal["proposal_id"]
            )["event_count"],
            1,
        )
        self.assertEqual(self.governance.audit_integrity(now=NOW + 1)["status"], "ready")

    def test_direct_approval_rolls_back_all_surfaces_on_event_failure(self) -> None:
        with patch.object(
            self.compat_governance,
            "_insert_event",
            side_effect=RuntimeError("injected compatibility event failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "compatibility event failure"):
                self.compat_governance.approve_namespace_link_compat(
                    source_context_id="alpha",
                    target_context_id="beta",
                    approved_by="operator",
                    reason="Explicit compatibility approval.",
                    governance_request_id="compat-fault",
                    confirm=True,
                    now=NOW,
                )

        self.assertEqual(self._metadata_keys(PROPOSAL_KEY_PREFIX + "%"), [])
        self.assertEqual(self._metadata_keys(LINK_KEY_PREFIX + "%"), [])
        self.assertEqual(self.store.list_context_links(), [])
        self.assertEqual(
            self.raw_scalar(
                "SELECT COUNT(*) FROM store_maintenance_receipts "
                "WHERE operation_type LIKE 'bridge-governance-v1.%'"
            ),
            0,
        )
        self.assertEqual(
            self._metadata_keys(NAMESPACE_CATALOG_METADATA_PREFIX + "%"), []
        )

    def test_request_ids_replay_only_identical_sanitized_requests(self) -> None:
        first = self.propose(request_id="same-request")
        replay = self.propose(request_id="same-request")
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(
            first["proposal"]["revision"], replay["proposal"]["revision"]
        )
        with self.assertRaises(BridgeGovernanceConflict):
            self.propose(target="gamma", request_id="same-request")

    def test_omitted_request_id_is_deterministic_and_does_not_duplicate(self) -> None:
        arguments = {
            "source_context_id": "alpha",
            "target_context_id": "beta",
            "relation_type": "related",
            "weight": 0.73,
            "evidence": {"basis": "operator review"},
            "direction": "bidirectional",
            "proposed_by": "alice",
            "reason": "The namespaces have operator-reviewed overlap.",
            "now": NOW,
        }
        first = self.governance.propose_namespace_link(**arguments)
        replay = self.governance.propose_namespace_link(**arguments)

        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(
            replay["proposal"]["proposal_id"],
            first["proposal"]["proposal_id"],
        )
        self.assertEqual(
            self.governance.list_namespace_link_proposals(now=NOW)["proposal_count"],
            1,
        )

    def test_expiry_is_bounded(self) -> None:
        with self.assertRaises(ValueError):
            self.propose(proposal_expires_at=NOW + 59)
        with self.assertRaises(ValueError):
            self.propose(
                proposal_expires_at=NOW + 30 * 24 * 60 * 60 + 1,
                request_id="too-long",
            )
        with self.assertRaises(ValueError):
            self.propose(link_expires_at=NOW + 59, request_id="short-link")

    def test_evidence_reasons_and_receipts_never_retain_raw_secrets(self) -> None:
        raw_api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
        raw_password = "hunter2-do-not-store"
        raw_bearer = "bearer-token-value-123456789"
        proposed = self.propose(
            evidence={
                "api_key": raw_api_key,
                "nested": {"password": raw_password},
                "basis": "Authorization: Bearer " + raw_bearer,
            },
            reason="Authorization: Bearer " + raw_bearer,
        )
        self.approve(proposed)

        with closing(self.store._connect_read_only()) as conn:
            metadata = "\n".join(
                str(row[0])
                for row in conn.execute(
                    "SELECT value_json FROM store_metadata "
                    "WHERE key LIKE ? OR key LIKE ?",
                    (PROPOSAL_KEY_PREFIX + "%", LINK_KEY_PREFIX + "%"),
                ).fetchall()
            )
            receipts = "\n".join(
                str(row[0])
                for row in conn.execute(
                    "SELECT payload_json FROM store_maintenance_receipts "
                    "WHERE operation_type LIKE 'bridge-governance-v1.%'"
                ).fetchall()
            )
            durable = "\n".join(
                str(row[0])
                for row in conn.execute(
                    "SELECT evidence_json FROM context_relationships"
                ).fetchall()
            )
        serialized = "\n".join((metadata, receipts, durable))
        self.assertNotIn(raw_api_key, serialized)
        self.assertNotIn(raw_password, serialized)
        self.assertNotIn(raw_bearer, serialized)
        self.assertIn("[REDACTED_SECRET]", serialized)

    def test_integrity_audit_detects_projection_ledger_and_impossible_state(self) -> None:
        approved = self.approve(self.propose())
        proposal = dict(approved["proposal"])
        proposal["state"] = "rejected"
        proposal = _with_revision(proposal)
        key = PROPOSAL_KEY_PREFIX + proposal["proposal_id"]
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                    (
                        json.dumps(
                            proposal,
                            sort_keys=True,
                            separators=(",", ":"),
                            allow_nan=False,
                        ),
                        key,
                    ),
                )

        audit = self.governance.audit_integrity(now=NOW + 2)
        self.assertEqual(audit["status"], "degraded")
        self.assertTrue(
            any(
                error.startswith("projection-event-mismatch:")
                for error in audit["error_samples"]
            )
        )
        self.assertTrue(
            any(
                error.startswith("impossible-link-state:")
                for error in audit["error_samples"]
            )
        )
        self.assertTrue(
            any(
                error.startswith("link-proposal-mismatch:")
                for error in audit["error_samples"]
            )
        )

    def test_durable_edge_tamper_degrades_audit_and_cannot_redirect_recall(self) -> None:
        approved = self.approve(self.propose())
        link_id = approved["link"]["context_link_id"]
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE context_relationships SET source_context_id = 'evil' "
                    "WHERE context_link_id = ?",
                    (link_id,),
                )

        audit = self.governance.audit_integrity(now=NOW + 2)
        recall = self.governance.resolve_recall_contexts(
            context_id="alpha", scope="connected", now=NOW + 2
        )

        self.assertEqual(audit["status"], "degraded")
        self.assertTrue(
            any(
                error == f"link-structure-mismatch:{link_id}"
                for error in audit["error_samples"]
            )
        )
        self.assertEqual([item["context_id"] for item in recall], ["alpha", "global"])

    def test_compatibility_lane_cannot_bypass_distinct_reviewer_policy(self) -> None:
        with self.assertRaises(BridgeGovernanceInvalidTransition):
            self.governance.approve_namespace_link_compat(
                source_context_id="alpha",
                target_context_id="beta",
                approved_by="alice",
                reason="This lane is not privileged.",
                governance_request_id="strict-compat",
                confirm=True,
                now=NOW,
            )

    def test_distinct_overlength_request_ids_never_alias(self) -> None:
        with self.assertRaises(ValueError):
            self.propose(request_id="x" * 160 + "A")
        with self.assertRaises(ValueError):
            self.propose(request_id="x" * 160 + "B")
        self.assertEqual(self.governance.list_namespace_link_proposals(now=NOW)["proposal_count"], 0)

    def test_expired_approval_replay_reports_authorization_inactive(self) -> None:
        approved = self.compat_governance.approve_namespace_link_compat(
            source_context_id="alpha",
            target_context_id="beta",
            approved_by="operator",
            reason="Temporary governed bridge.",
            link_expires_at=NOW + 60,
            governance_request_id="expiring-replay",
            confirm=True,
            now=NOW,
        )
        self.assertEqual(approved["state"], "approved")
        self.governance.expire_due(now=NOW + 60)
        replay = self.compat_governance.approve_namespace_link_compat(
            source_context_id="alpha",
            target_context_id="beta",
            approved_by="operator",
            reason="Temporary governed bridge.",
            link_expires_at=NOW + 60,
            governance_request_id="expiring-replay",
            confirm=True,
            now=NOW + 61,
        )

        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["historical_state"], "approved")
        self.assertEqual(replay["state"], "expired")
        self.assertFalse(replay["authorization_active"])
        self.assertFalse(replay["link"]["enabled"])

    def test_expired_approval_replay_before_sweep_is_inactive_without_mutation(
        self,
    ) -> None:
        approved = self.compat_governance.approve_namespace_link_compat(
            source_context_id="alpha",
            target_context_id="beta",
            approved_by="operator",
            reason="Temporary governed bridge.",
            link_expires_at=NOW + 60,
            governance_request_id="unswept-expiring-replay",
            confirm=True,
            now=NOW,
        )
        replay = self.compat_governance.approve_namespace_link_compat(
            source_context_id="alpha",
            target_context_id="beta",
            approved_by="operator",
            reason="Temporary governed bridge.",
            link_expires_at=NOW + 60,
            governance_request_id="unswept-expiring-replay",
            confirm=True,
            now=NOW + 61,
        )

        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["historical_state"], "approved")
        self.assertEqual(replay["state"], "expired")
        self.assertTrue(replay["materialization_pending"])
        self.assertFalse(replay["authorization_active"])
        self.assertFalse(replay["link"]["enabled"])
        self.assertTrue(replay["link"]["durable_enabled"])
        self.assertEqual(
            self.raw_scalar(
                "SELECT enabled FROM context_relationships WHERE context_link_id = ?",
                (approved["link"]["context_link_id"],),
            ),
            1,
        )
        self.assertEqual(
            self.governance.list_active_namespace_links(now=NOW + 61),
            [],
        )
        audit = self.governance.audit_integrity(now=NOW + 61)
        self.assertEqual(audit["status"], "ready")
        self.assertEqual(audit["expiry_due_count"], 1)
        self.assertTrue(audit["expiry_materialization_required"])

    def test_review_rejects_link_that_expired_while_proposal_was_pending(self) -> None:
        proposed = self.propose(
            request_id="link-window-elapsed",
            link_expires_at=NOW + 60,
        )

        with self.assertRaises(BridgeGovernanceExpired):
            self.approve(
                proposed,
                request_id="late-link-window-review",
                now=NOW + 61,
            )

        self.assertEqual(self.store.list_context_links(), [])
        current = self.governance.list_namespace_link_proposals(now=NOW + 61)
        self.assertEqual(current["proposals"][0]["state"], "pending")
        self.assertEqual(self.governance.audit_integrity(now=NOW + 61)["status"], "ready")

    def test_tampered_durable_link_cannot_be_returned_by_approval_replay(self) -> None:
        proposed = self.propose(request_id="tampered-replay-proposal")
        approved = self.approve(proposed, request_id="tampered-replay-approval")
        link_id = approved["link"]["context_link_id"]
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE context_relationships SET source_context_id = 'evil' "
                    "WHERE context_link_id = ?",
                    (link_id,),
                )

        with self.assertRaises(BridgeGovernanceIntegrityError):
            self.approve(proposed, request_id="tampered-replay-approval")

        self.assertEqual(self.governance.list_active_namespace_links(now=NOW + 2), [])
        self.assertEqual(self.governance.audit_integrity(now=NOW + 2)["status"], "degraded")

    def test_durable_provenance_and_full_evidence_tamper_fail_closed(self) -> None:
        proposed = self.propose(request_id="durable-provenance-proposal")
        approved = self.approve(
            proposed,
            request_id="durable-provenance-approval",
        )
        link_id = approved["link"]["context_link_id"]
        baseline = self.governance.audit_integrity(now=NOW + 1)
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                row = conn.execute(
                    "SELECT evidence_json FROM context_relationships "
                    "WHERE context_link_id = ?",
                    (link_id,),
                ).fetchone()
                evidence = json.loads(str(row["evidence_json"]))
                evidence["forged"] = "unreceipted"
                evidence["governance"]["automatic_cross_namespace_write"] = True
                conn.execute(
                    "UPDATE context_relationships "
                    "SET approved_by = ?, approved_at = approved_at + 5, "
                    "evidence_json = ? WHERE context_link_id = ?",
                    (
                        "mallory",
                        json.dumps(evidence, sort_keys=True, separators=(",", ":")),
                        link_id,
                    ),
                )

        self.assertEqual(
            self.governance.list_active_namespace_links(now=NOW + 2),
            [],
        )
        audit = self.governance.audit_integrity(now=NOW + 2)
        self.assertEqual(audit["status"], "degraded")
        self.assertNotEqual(audit["audit_revision"], baseline["audit_revision"])
        self.assertIn(f"link-evidence-mismatch:{link_id}", audit["error_samples"])
        self.assertIn(f"link-provenance-mismatch:{link_id}", audit["error_samples"])
        self.assertIn(f"link-receipt-mismatch:{link_id}", audit["error_samples"])
        with self.assertRaises(BridgeGovernanceIntegrityError):
            self.approve(
                proposed,
                request_id="durable-provenance-approval",
                now=NOW + 2,
            )

    def test_deleting_both_governed_link_surfaces_degrades_audit(self) -> None:
        proposed = self.propose(request_id="missing-surfaces-proposal")
        approved = self.approve(
            proposed,
            request_id="missing-surfaces-approval",
        )
        link_id = approved["link"]["context_link_id"]
        baseline = self.governance.audit_integrity(now=NOW + 1)
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "DELETE FROM store_metadata WHERE key = ?",
                    (LINK_KEY_PREFIX + link_id,),
                )
                conn.execute(
                    "DELETE FROM context_relationships WHERE context_link_id = ?",
                    (link_id,),
                )

        self.assertEqual(
            self.governance.list_active_namespace_links(now=NOW + 2),
            [],
        )
        audit = self.governance.audit_integrity(now=NOW + 2)
        self.assertEqual(audit["status"], "degraded")
        self.assertNotEqual(audit["audit_revision"], baseline["audit_revision"])
        self.assertIn(
            f"materialized-link-missing-projection:{link_id}",
            audit["error_samples"],
        )
        self.assertIn(
            f"materialized-link-missing-durable:{link_id}",
            audit["error_samples"],
        )
        with self.assertRaises(BridgeGovernanceIntegrityError):
            self.approve(
                proposed,
                request_id="missing-surfaces-approval",
                now=NOW + 2,
            )

    def test_reapproval_reuses_materialized_link_without_false_audit_error(self) -> None:
        first = self.compat_governance.approve_namespace_link_compat(
            source_context_id="alpha",
            target_context_id="beta",
            approved_by="operator",
            reason="Initial reviewed compatibility approval.",
            governance_request_id="reapproval-first",
            confirm=True,
            now=NOW,
        )
        self.compat_governance.revoke_namespace_link(
            context_link_id=first["link"]["context_link_id"],
            revoked_by="operator",
            reason="Retire the first authorization.",
            expected_revision=first["proposal"]["revision"],
            governance_request_id="reapproval-revoke",
            confirm=True,
            now=NOW + 1,
        )
        second = self.compat_governance.approve_namespace_link_compat(
            source_context_id="alpha",
            target_context_id="beta",
            approved_by="operator",
            reason="A new reviewed authorization is required.",
            governance_request_id="reapproval-second",
            confirm=True,
            now=NOW + 2,
        )

        self.assertNotEqual(
            first["proposal"]["proposal_id"],
            second["proposal"]["proposal_id"],
        )
        self.assertEqual(
            first["link"]["context_link_id"],
            second["link"]["context_link_id"],
        )
        self.assertEqual(
            self.governance.audit_integrity(now=NOW + 3)["status"],
            "ready",
        )

    def test_receipt_reason_fingerprint_and_created_at_tamper_degrade_audit(
        self,
    ) -> None:
        approved = self.approve(
            self.propose(request_id="receipt-binding-proposal"),
            request_id="receipt-binding-approval",
        )
        event_id = approved["proposal"]["last_event_id"]
        with closing(self.store._connect()) as conn:
            original = conn.execute(
                "SELECT payload_json, created_at FROM store_maintenance_receipts "
                "WHERE operation_id = ?",
                (event_id,),
            ).fetchone()
        original_payload = str(original["payload_json"])
        original_created_at = float(original["created_at"])
        baseline = self.governance.audit_integrity(now=NOW + 2)["audit_revision"]
        cases = (
            ("reason", f"event-reason-mismatch:{event_id}"),
            ("request_fingerprint", f"event-fingerprint-mismatch:{event_id}"),
            ("created_at", f"event-created-at-mismatch:{event_id}"),
        )
        for field, expected_error in cases:
            with self.subTest(field=field):
                payload = json.loads(original_payload)
                created_at = original_created_at
                if field == "reason":
                    payload["reason"] = "forged rationale"
                elif field == "request_fingerprint":
                    payload["request_fingerprint"] = "0" * 64
                else:
                    created_at += 7.0
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_maintenance_receipts "
                            "SET payload_json = ?, created_at = ? "
                            "WHERE operation_id = ?",
                            (
                                json.dumps(
                                    payload,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                                created_at,
                                event_id,
                            ),
                        )
                audit = self.governance.audit_integrity(now=NOW + 2)
                self.assertEqual(audit["status"], "degraded")
                self.assertIn(expected_error, audit["error_samples"])
                self.assertNotEqual(audit["audit_revision"], baseline)
                with self.assertRaises(BridgeGovernanceIntegrityError):
                    self.governance.get_namespace_link_proposal(
                        proposal_id=approved["proposal"]["proposal_id"],
                        now=NOW + 2,
                    )
                with self.assertRaises(BridgeGovernanceIntegrityError):
                    self.governance.list_namespace_link_history(
                        proposal_id=approved["proposal"]["proposal_id"],
                    )
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_maintenance_receipts "
                            "SET payload_json = ?, created_at = ? "
                            "WHERE operation_id = ?",
                            (original_payload, original_created_at, event_id),
                        )

    def test_receipt_result_envelope_tamper_degrades_audit_and_replay(self) -> None:
        proposed = self.propose(request_id="result-envelope-proposal")
        approved = self.approve(
            proposed,
            request_id="result-envelope-approval",
        )
        event_id = approved["proposal"]["last_event_id"]
        with closing(self.store._connect()) as conn:
            original = conn.execute(
                "SELECT payload_json FROM store_maintenance_receipts "
                "WHERE operation_id = ?",
                (event_id,),
            ).fetchone()
        original_payload = str(original["payload_json"])
        baseline = self.governance.audit_integrity(now=NOW + 2)["audit_revision"]
        cases = (
            ("action", "forged-action"),
            ("automatic_cross_namespace_write", True),
            ("link_active", False),
            ("compatibility_mode", True),
            ("idempotent_replay", True),
        )
        for field, value in cases:
            with self.subTest(field=field):
                payload = json.loads(original_payload)
                payload["result"][field] = value
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_maintenance_receipts "
                            "SET payload_json = ? WHERE operation_id = ?",
                            (
                                json.dumps(
                                    payload,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                                event_id,
                            ),
                        )
                audit = self.governance.audit_integrity(now=NOW + 2)
                self.assertEqual(audit["status"], "degraded")
                self.assertIn(
                    f"event-result-envelope:{event_id}",
                    audit["error_samples"],
                )
                self.assertNotEqual(audit["audit_revision"], baseline)
                with self.assertRaises(BridgeGovernanceIntegrityError):
                    self.approve(
                        proposed,
                        request_id="result-envelope-approval",
                        now=NOW + 2,
                    )
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_maintenance_receipts "
                            "SET payload_json = ? WHERE operation_id = ?",
                            (original_payload, event_id),
                        )

    def test_historical_receipt_link_tamper_degrades_audit_and_history(self) -> None:
        proposed = self.propose(request_id="historical-link-proposal")
        approved = self.approve(
            proposed,
            request_id="historical-link-approval",
        )
        approval_event_id = approved["proposal"]["last_event_id"]
        disabled = self.governance.disable_namespace_link(
            context_link_id=approved["link"]["context_link_id"],
            disabled_by="operator",
            reason="Contain this bridge after approval.",
            expected_revision=approved["proposal"]["revision"],
            governance_request_id="historical-link-disable",
            confirm=True,
            now=NOW + 2,
        )
        with closing(self.store._connect()) as conn:
            original = conn.execute(
                "SELECT payload_json FROM store_maintenance_receipts "
                "WHERE operation_id = ?",
                (approval_event_id,),
            ).fetchone()
        original_payload = str(original["payload_json"])
        baseline = self.governance.audit_integrity(now=NOW + 3)["audit_revision"]
        self.assertEqual(
            self.governance.resolve_recall_contexts(
                context_id="alpha",
                scope="connected",
                now=NOW + 3,
            ),
            [
                {
                    "context_id": "alpha",
                    "recall_scope": "connected",
                    "recall_provenance": "local",
                    "via_context_link_id": "",
                    "via_relation_type": "",
                },
                {
                    "context_id": "global",
                    "recall_scope": "connected",
                    "recall_provenance": "global",
                    "via_context_link_id": "",
                    "via_relation_type": "",
                },
            ],
        )
        cases = (
            ("approved_by", "mallory"),
            ("approved_at", NOW + 99),
            ("source_context_id", "evil"),
            ("created_at", NOW + 0.5),
            ("updated_at", NOW + 99),
            ("unknown_write_claim", True),
        )
        for field, value in cases:
            with self.subTest(field=field):
                payload = json.loads(original_payload)
                payload["result"]["link"][field] = value
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_maintenance_receipts "
                            "SET payload_json = ? WHERE operation_id = ?",
                            (
                                json.dumps(
                                    payload,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                                approval_event_id,
                            ),
                        )
                audit = self.governance.audit_integrity(now=NOW + 3)
                self.assertEqual(audit["status"], "degraded")
                self.assertIn(
                    f"event-link-mismatch:{approval_event_id}",
                    audit["error_samples"],
                )
                self.assertNotEqual(audit["audit_revision"], baseline)
                with self.assertRaises(BridgeGovernanceIntegrityError):
                    self.governance.list_namespace_link_history(
                        proposal_id=disabled["proposal"]["proposal_id"],
                    )
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_maintenance_receipts "
                            "SET payload_json = ? WHERE operation_id = ?",
                            (original_payload, approval_event_id),
                        )

    def test_link_projection_enabled_is_strictly_audit_bound(self) -> None:
        proposed = self.propose(request_id="projection-enabled-proposal")
        approved = self.approve(
            proposed,
            request_id="projection-enabled-approval",
        )
        link_id = approved["link"]["context_link_id"]
        key = LINK_KEY_PREFIX + link_id
        with closing(self.store._connect()) as conn:
            original = conn.execute(
                "SELECT value_json FROM store_metadata WHERE key = ?",
                (key,),
            ).fetchone()
        original_projection = str(original["value_json"])
        baseline = self.governance.audit_integrity(now=NOW + 2)["audit_revision"]
        for enabled in (False, 1):
            with self.subTest(enabled=enabled):
                projection = json.loads(original_projection)
                projection["enabled"] = enabled
                projection = _with_revision(projection)
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                            (
                                json.dumps(
                                    projection,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                                key,
                            ),
                        )
                audit = self.governance.audit_integrity(now=NOW + 2)
                self.assertEqual(audit["status"], "degraded")
                self.assertIn(
                    f"link-projection-enabled-mismatch:{link_id}",
                    audit["error_samples"],
                )
                self.assertNotEqual(audit["audit_revision"], baseline)
                self.assertEqual(
                    self.governance.list_active_namespace_links(now=NOW + 2),
                    [],
                )
                with self.assertRaises(BridgeGovernanceIntegrityError):
                    self.approve(
                        proposed,
                        request_id="projection-enabled-approval",
                        now=NOW + 2,
                    )
                with closing(self.store._connect()) as conn:
                    with self.store._transaction(conn, immediate=True):
                        conn.execute(
                            "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                            (original_projection, key),
                        )

    def test_reapproval_refuses_tampered_same_id_durable_structure(self) -> None:
        approved = self.compat_governance.approve_namespace_link_compat(
            source_context_id="alpha",
            target_context_id="beta",
            approved_by="operator",
            reason="Initial compatibility approval.",
            governance_request_id="initial-compat-approval",
            confirm=True,
            now=NOW,
        )
        revoked = self.compat_governance.revoke_namespace_link(
            context_link_id=approved["link"]["context_link_id"],
            revoked_by="operator",
            reason="Retire the initial approval.",
            expected_revision=approved["proposal"]["revision"],
            governance_request_id="initial-compat-revoke",
            confirm=True,
            now=NOW + 1,
        )
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE context_relationships SET source_context_id = 'evil' "
                    "WHERE context_link_id = ?",
                    (approved["link"]["context_link_id"],),
                )

        with self.assertRaises(BridgeGovernanceIntegrityError):
            self.compat_governance.approve_namespace_link_compat(
                source_context_id="alpha",
                target_context_id="beta",
                approved_by="operator",
                reason="A fresh approval must not adopt a tampered row.",
                governance_request_id="fresh-compat-approval",
                confirm=True,
                now=NOW + 2,
            )

        self.assertEqual(revoked["state"], "revoked")
        self.assertEqual(self.governance.list_active_namespace_links(now=NOW + 2), [])

    def test_deactivation_rejects_link_projection_redirected_to_other_proposal(self) -> None:
        first = self.approve(self.propose(request_id="first-link"))
        second_proposed = self.propose(
            source="gamma",
            target="delta",
            request_id="second-link",
            now=NOW + 2,
        )
        second = self.approve(
            second_proposed,
            request_id="second-link-approval",
            now=NOW + 3,
        )
        first_link_id = first["link"]["context_link_id"]
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                row = conn.execute(
                    "SELECT value_json FROM store_metadata WHERE key = ?",
                    (LINK_KEY_PREFIX + first_link_id,),
                ).fetchone()
                projection = json.loads(str(row["value_json"]))
                projection["proposal_id"] = second["proposal"]["proposal_id"]
                projection = _with_revision(projection)
                conn.execute(
                    "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                    (
                        json.dumps(projection, sort_keys=True, separators=(",", ":")),
                        LINK_KEY_PREFIX + first_link_id,
                    ),
                )

        with self.assertRaises(BridgeGovernanceIntegrityError):
            self.governance.disable_namespace_link(
                context_link_id=first_link_id,
                disabled_by="operator",
                reason="A redirected projection must fail closed.",
                expected_revision=second["proposal"]["revision"],
                governance_request_id="redirected-disable",
                confirm=True,
                now=NOW + 4,
            )

        self.assertTrue(
            self.raw_scalar(
                "SELECT enabled FROM context_relationships WHERE context_link_id = ?",
                (first_link_id,),
            )
        )
        self.assertTrue(
            self.raw_scalar(
                "SELECT enabled FROM context_relationships WHERE context_link_id = ?",
                (second["link"]["context_link_id"],),
            )
        )

    def test_receipt_actor_tamper_degrades_integrity_audit(self) -> None:
        approved = self.approve(self.propose())
        event_id = approved["proposal"]["last_event_id"]
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                row = conn.execute(
                    "SELECT payload_json FROM store_maintenance_receipts "
                    "WHERE operation_id = ?",
                    (event_id,),
                ).fetchone()
                payload = json.loads(str(row["payload_json"]))
                payload["actor"] = "mallory"
                conn.execute(
                    "UPDATE store_maintenance_receipts SET payload_json = ? "
                    "WHERE operation_id = ?",
                    (
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        event_id,
                    ),
                )

        audit = self.governance.audit_integrity(now=NOW + 2)
        self.assertEqual(audit["status"], "degraded")
        self.assertIn(f"event-actor-mismatch:{event_id}", audit["error_samples"])

    def test_pending_projection_tamper_cannot_be_laundered_by_review(self) -> None:
        proposed = self.propose(request_id="pending-tamper")
        original = proposed["proposal"]
        tampered = dict(original)
        tampered["source_context_id"] = "aardvark"
        tampered["context_link_id"] = self.store.stable_context_link_id(
            source_context_id="aardvark",
            target_context_id="beta",
            relation_type="related",
            direction="bidirectional",
        )
        tampered = _with_revision(tampered)
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                    (
                        json.dumps(tampered, sort_keys=True, separators=(",", ":")),
                        PROPOSAL_KEY_PREFIX + original["proposal_id"],
                    ),
                )

        with self.assertRaises(BridgeGovernanceIntegrityError):
            self.approve(proposed, request_id="pending-tamper-review")

        self.assertEqual(self.store.list_context_links(), [])
        self.assertEqual(self.governance.list_active_namespace_links(now=NOW + 2), [])
        self.assertEqual(self.governance.audit_integrity(now=NOW + 2)["status"], "degraded")

    def test_filters_apply_before_result_limits(self) -> None:
        first = self.propose(request_id="first-filtered", source="alpha", target="beta")
        self.propose(
            request_id="second-unrelated",
            source="gamma",
            target="delta",
            now=NOW + 1,
        )

        proposals = self.governance.list_namespace_link_proposals(
            context_id="alpha", limit=1, now=NOW + 2
        )
        history = self.governance.list_namespace_link_history(
            proposal_id=first["proposal"]["proposal_id"], limit=1
        )

        self.assertEqual(proposals["proposal_count"], 1)
        self.assertEqual(proposals["proposals"][0]["proposal_id"], first["proposal"]["proposal_id"])
        self.assertEqual(history["event_count"], 1)

    def test_literal_prefix_isolation_and_corrupt_expiry_row(self) -> None:
        pending = self.propose(
            request_id="valid-expiry-row",
            proposal_expires_at=NOW + 60,
        )
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "INSERT INTO store_metadata (key, value_json, updated_at) "
                    "VALUES (?, ?, ?)",
                    (
                        "bridgeXgovernance.proposal.v1.s2bgp_"
                        + "f" * 32,
                        json.dumps({"state": "pending"}),
                        NOW,
                    ),
                )

        listed = self.governance.list_namespace_link_proposals(now=NOW + 1)
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "INSERT INTO store_metadata (key, value_json, updated_at) "
                    "VALUES (?, ?, ?)",
                    (PROPOSAL_KEY_PREFIX + "corrupt", "{", NOW),
                )

        swept = self.governance.expire_due(now=NOW + 60)

        self.assertEqual(listed["proposal_count"], 1)
        self.assertEqual(listed["proposals"][0]["proposal_id"], pending["proposal"]["proposal_id"])
        self.assertEqual(swept["expired_count"], 1)
        self.assertEqual(swept["invalid_projection_count"], 1)

    def test_audit_reports_nan_projection_as_degraded(self) -> None:
        proposed = self.propose()
        projection = dict(proposed["proposal"])
        projection["weight"] = float("nan")
        with closing(self.store._connect()) as conn:
            with self.store._transaction(conn, immediate=True):
                conn.execute(
                    "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                    (
                        json.dumps(projection, allow_nan=True),
                        PROPOSAL_KEY_PREFIX + projection["proposal_id"],
                    ),
                )

        audit = self.governance.audit_integrity(now=NOW + 1)
        self.assertEqual(audit["status"], "degraded")
        self.assertTrue(
            any(error.startswith("revision-mismatch:") for error in audit["error_samples"])
        )

    def _metadata_keys(self, pattern: str) -> list[str]:
        with closing(self.store._connect_read_only()) as conn:
            rows = conn.execute(
                "SELECT key FROM store_metadata WHERE key LIKE ? ORDER BY key",
                (pattern,),
            ).fetchall()
        return [str(row[0]) for row in rows]


if __name__ == "__main__":
    unittest.main()

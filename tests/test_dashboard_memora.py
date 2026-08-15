"""Focused dashboard contracts for governed Memora cue lifecycle controls."""

from __future__ import annotations

import json
import unittest
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from core_client import CoreRemoteError
from dashboard_server import DashboardRuntime
from memora_governance import MemoraGovernanceIntegrityError


ROOT = Path(__file__).resolve().parents[1]
REVISION_A = "a" * 64
REVISION_B = "b" * 64
BINDING_ID = "s2mb_" + "1" * 32
TRUST = "untrusted-derived-routing-evidence"


def binding(*, state: str = "proposed", revision: str = REVISION_A) -> dict:
    return {
        "schema": "synapse-s2.memora-binding.v1",
        "schema_version": 1,
        "binding_id": BINDING_ID,
        "context_id": "ops",
        "state": state,
        "revision": revision,
        "previous_revision": None if revision == REVISION_A else REVISION_A,
        "created_at": 10.0,
        "updated_at": 11.0,
        "proposed_by": "core:local-owner:owner-digest:workflow:proposer-digest",
        "proposed_at": 10.0,
        "reviewed_by": (
            None
            if state == "proposed"
            else "core:local-owner:owner-digest:workflow:reviewer-digest"
        ),
        "reviewed_at": None if state == "proposed" else 11.0,
        "revoked_by": None,
        "revoked_at": None,
        "proposal_reason": "Reviewed candidate cue cluster.",
        "decision_reason": "",
        "plan": {
            "plan_digest": "c" * 64,
            "cluster_ordinal": 0,
            "cluster_id": "s2shadow_cluster_01",
            "planner_version": "memora-shadow-v1",
            "learned": True,
        },
        "provider": {
            "provider": "mlx-neural-v1",
            "provider_type": "mlx-neural",
            "model_id": "local/test-model",
            "revision": "pinned-revision",
            "configuration_sha256": "d" * 64,
            "dimensions": 32,
            "semantic": True,
            "local_only": True,
            "ready": True,
            "learned": True,
        },
        "abstraction": {
            "display_term": "Project Citadel",
            "member_count": 1,
            "trust": TRUST,
        },
        "cues": [
            {
                "cue_id": "s2shcue_" + "2" * 20,
                "term": "project citadel",
                "aspect": "semantic-facet",
                "member_support": 1,
                "supporting_memory_ids": ["s2_source_memory_01"],
                "trust": TRUST,
            }
        ],
        "sources": [{"memory_id": "s2_source_memory_01"}],
        "source_witnesses": [{"memory_id": "s2_source_memory_01", "bytes": 42}],
        "event_count": 1,
        "automatic_promotion": False,
        "raw_source_text_stored": False,
        "vectors_stored": False,
    }


def effectiveness(*, effective: bool = False) -> dict:
    return {
        "effective": effective,
        "reasons": [] if effective else ["state-not-promoted"],
    }


def catalog_payload() -> dict:
    return {
        "schema": "synapse-s2.memora-catalog.v1",
        "context_id": "ops",
        "catalog_revision": "e" * 64,
        "bindings": [
            {"binding": binding(), "effectiveness": effectiveness()}
        ],
        "total": 1,
        "returned": 1,
        "truncated": False,
    }


def binding_payload(*, state: str = "proposed", revision: str = REVISION_A) -> dict:
    current = binding(state=state, revision=revision)
    return {
        "schema": "synapse-s2.memora-binding.v1",
        "binding": current,
        "state": state,
        "revision": revision,
        "effectiveness": effectiveness(effective=state == "promoted"),
    }


def event(*, action: str = "propose", revision: str = REVISION_A) -> dict:
    return {
        "schema": "synapse-s2.memora-governance-event.v1",
        "action": action,
        "actor": "core:local-owner:owner-digest:workflow:role-digest",
        "reason": "Reviewed lifecycle evidence.",
        "before_state": "",
        "after_state": "proposed",
        "before_revision": "",
        "after_revision": revision,
        "event_sequence": 1,
        "created_at": 10.0,
    }


def history_payload() -> dict:
    return {
        "schema": "synapse-s2.memora-governance-event.v1",
        "binding_id": BINDING_ID,
        "events": [event()],
        "total_events": 1,
        "truncated": False,
        "next_before_sequence": None,
    }


def audit_payload() -> dict:
    return {
        "schema": "synapse-s2.memora-audit.v1",
        "binding_id": BINDING_ID,
        "current_revision": REVISION_A,
        "events": [event()],
        "event_count": 1,
        "events_validated": 1,
        "chain_valid": True,
        "catalog_cross_checked": True,
    }


def transition_payload(action: str, state: str) -> dict:
    current = binding(state=state, revision=REVISION_B)
    current["event_count"] = 2
    return {
        "operation": f"{action}-memora-binding",
        "binding": current,
        "state": state,
        "revision": REVISION_B,
        "automatic_promotion": False,
        "idempotent_replay": False,
    }


class DashboardMemoraTests(unittest.TestCase):
    @staticmethod
    def decode(response: tuple[int, dict[str, str], bytes]) -> tuple[int, dict]:
        status, _headers, body = response
        return status, json.loads(body.decode("utf-8"))

    def backend(self) -> SimpleNamespace:
        return SimpleNamespace(
            list_memora_bindings=mock.Mock(return_value=catalog_payload()),
            get_memora_binding=mock.Mock(return_value=binding_payload()),
            memora_binding_history=mock.Mock(return_value=history_payload()),
            audit_memora_binding=mock.Mock(return_value=audit_payload()),
            propose_memora_binding=mock.Mock(
                return_value=transition_payload("propose", "proposed")
            ),
            promote_memora_binding=mock.Mock(
                return_value=transition_payload("promote", "promoted")
            ),
            reject_memora_binding=mock.Mock(
                return_value=transition_payload("reject", "rejected")
            ),
            revoke_memora_binding=mock.Mock(
                return_value=transition_payload("revoke", "revoked")
            ),
        )

    def test_read_routes_publish_only_bounded_keyless_safe_projections(self) -> None:
        backend = self.backend()
        runtime = DashboardRuntime(backend=backend)
        routes = (
            "/api/memora-bindings?context_id=ops&limit=16",
            f"/api/memora-binding?binding_id={BINDING_ID}",
            f"/api/memora-history?binding_id={BINDING_ID}&limit=16",
            f"/api/memora-audit?binding_id={BINDING_ID}",
        )
        payloads = []
        for route in routes:
            with self.subTest(route=route):
                status, payload = self.decode(runtime.handle("GET", route))
                self.assertEqual(status, HTTPStatus.OK, payload)
                self.assertEqual(
                    payload["schema"],
                    "synapse-s2.dashboard-memora-governance.v1",
                )
                self.assertFalse(
                    payload["authority"]["workflow_roles_are_authenticated_people"]
                )
                payloads.append(payload)

        rendered = json.dumps(payloads, sort_keys=True)
        for forbidden in (
            "source_witnesses",
            "supporting_memory_ids",
            "s2_source_memory_01",
            '"embedding"',
            '"vector":',
            "public_key",
            "signature",
        ):
            self.assertNotIn(forbidden, rendered)
        backend.list_memora_bindings.assert_called_once_with(
            context_id="ops", state=None, limit=16
        )

    def test_mutations_require_confirmation_exact_cas_roles_and_request_ids(self) -> None:
        backend = self.backend()
        runtime = DashboardRuntime(backend=backend)
        base = {
            "binding_id": BINDING_ID,
            "expected_revision": REVISION_A,
            "reason": "Reviewed the current binding evidence.",
            "governance_request_id": "dashboard-memora-request-01",
        }
        rejected_status, rejected = self.decode(
            runtime.handle(
                "POST",
                "/api/memora-promotions",
                json.dumps(
                    {**base, "reviewed_by": "dashboard-reviewer", "confirm": False}
                ).encode("utf-8"),
            )
        )
        self.assertEqual(rejected_status, HTTPStatus.BAD_REQUEST)
        self.assertIn("unlocking", rejected["error"])
        backend.promote_memora_binding.assert_not_called()

        calls = (
            (
                "/api/memora-promotions",
                {**base, "reviewed_by": "dashboard-reviewer", "confirm": True},
                backend.promote_memora_binding,
                {"reviewed_by": "dashboard-reviewer", "confirm": True},
            ),
            (
                "/api/memora-rejections",
                {
                    **base,
                    "reviewed_by": "dashboard-reviewer",
                    "confirm": True,
                    "governance_request_id": "dashboard-memora-request-02",
                },
                backend.reject_memora_binding,
                {"reviewed_by": "dashboard-reviewer"},
            ),
            (
                "/api/memora-revocations",
                {
                    **base,
                    "revoked_by": "dashboard-reviewer",
                    "confirm": True,
                    "governance_request_id": "dashboard-memora-request-03",
                },
                backend.revoke_memora_binding,
                {"revoked_by": "dashboard-reviewer", "confirm": True},
            ),
        )
        for route, body, operation, expected in calls:
            with self.subTest(route=route):
                status, payload = self.decode(
                    runtime.handle("POST", route, json.dumps(body).encode("utf-8"))
                )
                self.assertEqual(status, HTTPStatus.OK, payload)
                kwargs = operation.call_args.kwargs
                self.assertEqual(kwargs["binding_id"], BINDING_ID)
                self.assertEqual(kwargs["expected_revision"], REVISION_A)
                self.assertEqual(kwargs["reason"], base["reason"])
                self.assertEqual(
                    kwargs["governance_request_id"],
                    body["governance_request_id"],
                )
                for key, value in expected.items():
                    self.assertEqual(kwargs[key], value)

    def test_proposal_is_confirmed_bounded_and_uses_server_plan_coordinates(self) -> None:
        backend = self.backend()
        runtime = DashboardRuntime(backend=backend)
        body = {
            "context_id": "ops",
            "plan_digest": "c" * 64,
            "cluster_ordinal": 0,
            "proposed_by": "dashboard-proposer",
            "reason": "Queue the reviewed cue cluster for a separate decision.",
            "governance_request_id": "dashboard-memora-proposal-01",
            "confirm": True,
        }
        status, payload = self.decode(
            runtime.handle(
                "POST",
                "/api/memora-proposals",
                json.dumps(body).encode("utf-8"),
            )
        )
        self.assertEqual(status, HTTPStatus.OK, payload)
        backend.propose_memora_binding.assert_called_once_with(
            context_id="ops",
            plan_digest="c" * 64,
            cluster_ordinal=0,
            proposed_by="dashboard-proposer",
            reason=body["reason"],
            governance_request_id="dashboard-memora-proposal-01",
        )

    def test_stale_and_integrity_failures_are_clear_and_fail_closed(self) -> None:
        backend = self.backend()
        backend.promote_memora_binding.side_effect = CoreRemoteError(
            "invalid_request"
        )
        runtime = DashboardRuntime(backend=backend)
        status, payload = self.decode(
            runtime.handle(
                "POST",
                "/api/memora-promotions",
                json.dumps(
                    {
                        "binding_id": BINDING_ID,
                        "expected_revision": REVISION_A,
                        "reviewed_by": "dashboard-reviewer",
                        "reason": "Reviewed the current binding evidence.",
                        "governance_request_id": "dashboard-stale-request",
                        "confirm": True,
                    }
                ).encode("utf-8"),
            )
        )
        self.assertEqual(status, HTTPStatus.CONFLICT)
        self.assertIn("exact revision", payload["error"])

        backend.audit_memora_binding.side_effect = MemoraGovernanceIntegrityError(
            "synthetic private witness detail"
        )
        status, payload = self.decode(
            runtime.handle("GET", f"/api/memora-audit?binding_id={BINDING_ID}")
        )
        self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE)
        self.assertIn("integrity validation", payload["error"])
        self.assertNotIn("synthetic", json.dumps(payload))

    def test_assets_include_accessible_guarded_responsive_governance_surface(self) -> None:
        index = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
        for marker in (
            'id="memoraGovernanceStatus"',
            'id="memoraUnlockButton"',
            'id="memoraDecisionConfirm"',
            'id="memoraCatalog"',
            'id="memoraBindingTitle" tabindex="-1"',
            'id="memoraHistory"',
            'id="memoraAudit"',
        ):
            self.assertIn(marker, index)
        self.assertIn("MEMORA_GOVERNANCE_UNLOCK_WINDOW_MS", app)
        self.assertIn("expected_revision", app)
        self.assertIn("governance_request_id", app)
        self.assertIn('event.key === "Escape" && state.memoraShadow.open', app)
        self.assertIn(".memora-governance-layout", styles)
        self.assertIn("@media (max-width: 720px)", styles)

    def test_binding_a_to_b_switch_invalidates_and_rebinds_exact_guard_scope(self) -> None:
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        selection = app[
            app.index("async function selectMemoraBinding") :
            app.index("async function refreshMemoraGovernance")
        ]
        transition = app[
            app.index("async function transitionMemoraBinding") :
            app.index("function setMemoraShadowDrawerOpen")
        ]

        clear_index = selection.index("state.memoraShadow.guardTarget = null;")
        lock_index = selection.index("lockMemoraGovernanceGuard();")
        select_index = selection.index("state.memoraShadow.selectedBindingId = cleanId;")
        self.assertLess(clear_index, lock_index)
        self.assertLess(lock_index, select_index)
        self.assertIn("selectedScope.binding_id !== cleanId", selection)
        self.assertIn('String(audit.revision || "") !== selectedScope.revision', selection)
        self.assertIn("state.memoraShadow.guardTarget = selectedScope;", selection)
        self.assertIn(
            "memoraGuardScopesMatch(state.memoraShadow.guardTarget, bindingScope)",
            transition,
        )
        self.assertIn("isMemoraGovernanceUnlocked(bindingScope)", transition)

    def test_namespace_and_refresh_switches_lock_before_authority_changes(self) -> None:
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        context_switch = app[
            app.index("async function applySelectedContext") :
            app.index("function initializeNamespaceGalaxy")
        ]
        refresh = app[
            app.index("async function refreshMemoraGovernance") :
            app.index("function isMemoraGovernanceUnlocked")
        ]

        clear_index = context_switch.index("state.memoraShadow.guardTarget = null;")
        lock_index = context_switch.index("lockMemoraGovernanceGuard();")
        context_index = context_switch.index("state.context = nextContext;")
        self.assertLess(clear_index, lock_index)
        self.assertLess(lock_index, context_index)
        self.assertLess(
            refresh.index("lockMemoraGovernanceGuard();"),
            refresh.index("await Promise.all([refreshMemoraShadow(), refreshMemoraCatalog()])"),
        )
        self.assertGreaterEqual(
            app.count(
                'state.memoraShadow.guardTarget = null;\n  lockMemoraGovernanceGuard();'
            ),
            4,
        )

    def test_proposal_guard_is_bound_to_exact_plan_and_cluster_coordinate(self) -> None:
        app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        proposal = app[
            app.index("async function proposeMemoraCluster") :
            app.index("async function transitionMemoraBinding")
        ]

        self.assertIn("memoraProposalGuardScope(plan, ordinal)", proposal)
        self.assertIn(
            "memoraGuardScopesMatch(state.memoraShadow.guardTarget, proposalScope)",
            proposal,
        )
        self.assertIn("isMemoraGovernanceUnlocked(proposalScope)", proposal)
        self.assertIn("plan_digest: proposalScope.plan_digest", proposal)
        self.assertIn("cluster_ordinal: proposalScope.cluster_ordinal", proposal)


if __name__ == "__main__":
    unittest.main()

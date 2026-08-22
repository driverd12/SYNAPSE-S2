"""Adversarial tests for the dormant release-activation journal contract."""

from __future__ import annotations

import ast
import copy
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/release_activation_journal.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


journal = _load("test_release_activation_journal_module", MODULE_PATH)


EXPECTED_ACTIVATION_CONTRACT_ID = (
    "activation-contract-"
    "db5a82b45bfc11d9a56a81fb7f0710e95d429fdfd313aac3743bd6d31abad276"
)
EXPECTED_TRANSACTION_ID = (
    "transaction-"
    "6677a3e9c08b9b4ed73b5778e6f76014b7af44c77c9bbf17d8437a5875ada819"
)
EXPECTED_JOURNAL_CONTRACT_ID = (
    "activation-journal-contract-"
    "bc13294365c58271c141eebf3bfc9496b79991ec9e50e27f998ffd130070194a"
)
EXPECTED_JOURNAL_SOURCE_SHA256 = (
    "36f8b4befcf2783608be4e3c95911ead8176bfab35b8bcf9593301f8e0bcc3df"
)

EXPECTED_GRAPH = {
    "start": ("prepared",),
    "prepared": ("quiesce-intent", "aborted-pre-pivot"),
    "quiesce-intent": (
        "quiescent-observed",
        "rollback-intent",
        "manual-recovery-required",
    ),
    "quiescent-observed": (
        "switch-intent",
        "rollback-intent",
        "manual-recovery-required",
    ),
    "switch-intent": ("activating", "manual-recovery-required"),
    "activating": (
        "rollback-intent",
        "candidate-healthy",
        "manual-recovery-required",
    ),
    "candidate-healthy": (
        "pivot-intent",
        "rollback-intent",
        "manual-recovery-required",
    ),
    "pivot-intent": (
        "state-pivot-committed-writer-fenced",
        "post-pivot-recovery-required",
    ),
    "rollback-intent": (
        "control-plane-rolled-back",
        "manual-recovery-required",
    ),
    "state-pivot-committed-writer-fenced": (
        "post-update-equivalent",
        "post-pivot-recovery-required",
    ),
    "post-update-equivalent": (
        "clients-publish-intent",
        "post-pivot-recovery-required",
    ),
    "clients-publish-intent": (
        "clients-converged",
        "post-pivot-recovery-required",
    ),
    "clients-converged": (
        "release-commit-intent",
        "post-pivot-recovery-required",
    ),
    "release-commit-intent": (
        "floor-recorded",
        "post-pivot-recovery-required",
    ),
    "floor-recorded": ("committed", "post-pivot-recovery-required"),
    "aborted-pre-pivot": (),
    "control-plane-rolled-back": (),
    "manual-recovery-required": (),
    "committed": (),
    "post-pivot-recovery-required": (),
}

EXPECTED_EDGE_OBSERVATIONS = {
    ("prepared", "quiesce-intent"): (
        "host-authority",
        "recovery-readiness",
    ),
    ("quiesce-intent", "quiescent-observed"): ("quiescence",),
    ("quiescent-observed", "switch-intent"): ("host-authority",),
    ("activating", "candidate-healthy"): ("candidate-health",),
    ("candidate-healthy", "pivot-intent"): ("host-authority",),
    ("pivot-intent", "state-pivot-committed-writer-fenced"): (
        "binding-published",
    ),
    (
        "state-pivot-committed-writer-fenced",
        "post-update-equivalent",
    ): ("memory-equivalence",),
    ("post-update-equivalent", "clients-publish-intent"): (
        "host-authority",
    ),
    ("clients-publish-intent", "clients-converged"): (
        "clients-converged",
    ),
    ("clients-converged", "release-commit-intent"): (
        "host-authority",
    ),
    ("release-commit-intent", "floor-recorded"): ("floor-recorded",),
    ("quiesce-intent", "rollback-intent"): (
        "protected-state-equality",
    ),
    ("quiescent-observed", "rollback-intent"): (
        "protected-state-equality",
    ),
    ("activating", "rollback-intent"): ("no-durable-claim",),
    ("candidate-healthy", "rollback-intent"): (
        "no-durable-claim",
    ),
    ("rollback-intent", "control-plane-rolled-back"): (
        "protected-state-equality",
    ),
}

EXPECTED_GATE_OBSERVATION_TYPES = (
    "binding-published",
    "candidate-health",
    "clients-converged",
    "floor-recorded",
    "host-authority",
    "memory-equivalence",
    "no-durable-claim",
    "protected-state-equality",
    "quiescence",
    "recovery-readiness",
)

PIVOT = "state-pivot-committed-writer-fenced"
POST_PIVOT = {
    PIVOT,
    "post-update-equivalent",
    "clients-publish-intent",
    "clients-converged",
    "release-commit-intent",
    "floor-recorded",
    "committed",
    "post-pivot-recovery-required",
}
PRE_PIVOT_EQUALITY = {
    "start",
    "prepared",
    "quiesce-intent",
    "quiescent-observed",
    "aborted-pre-pivot",
    "control-plane-rolled-back",
}
RECONCILIATION = {
    "switch-intent",
    "activating",
    "candidate-healthy",
    "pivot-intent",
    "rollback-intent",
    "manual-recovery-required",
}

FALSE_FLAGS = (
    "execution_supported",
    "mutation_supported",
    "activation_supported",
    "apply_supported",
    "apply_performed",
    "journal_write_supported",
    "journal_written",
    "live_state_accessed",
    "live_state_modified",
    "service_modified",
    "config_modified",
    "selector_modified",
    "provenance_floor_modified",
    "rollback_supported",
    "rollback_performed",
    "host_evidence_verified",
    "physical_separation_verified",
    "memory_equivalence_verified",
    "gate_observation_evidence_verified",
)

NONCLAIMS = (
    "bootstrap-trust-out-of-band",
    "no-activation",
    "no-apply",
    "no-candidate-import-or-execution",
    "no-client-convergence",
    "no-config-or-plist-publication",
    "no-data-rollback",
    "no-downgrade",
    "no-environment-build-or-verification",
    "no-filesystem-access",
    "no-gate-observation-history-verification",
    "no-hardware-durability-proof",
    "no-host-evidence-verification",
    "no-journal-recovery",
    "no-journal-write",
    "no-launchctl-bootstrap",
    "no-live-state-access",
    "no-malicious-preexisting-journal-authenticity",
    "no-memory-content-access",
    "no-memory-equivalence-verification",
    "no-migration",
    "no-network",
    "no-physical-separation-verification",
    "no-post-stage-immutability",
    "no-provenance-floor-mutation",
    "no-secret-access",
    "no-selector-or-binding-change",
    "no-service-control",
    "no-stage-authority",
    "no-writer-quiescence",
)

INTENT_KEYS = (
    "activation_nonce",
    "activation_policy_receipt_sha256",
    "candidate_dependency_component_id",
    "candidate_product_id",
    "candidate_source_build_id",
    "channel",
    "compatibility_result_sha256",
    "compatibility_ticket_sha256",
    "current_dependency_component_id",
    "current_product_id",
    "current_source_build_id",
    "desired_control_plane_projection_sha256",
    "environment_receipt_sha256",
    "host_evidence_purpose",
    "host_evidence_schema",
    "host_id_sha256",
    "idempotency_key_sha256",
    "incumbent_installed_record_sha256",
    "installed_floor_preimage_sha256",
    "inventory_policy_id",
    "layout_contract_id",
    "layout_id",
    "layout_mode",
    "layout_schema",
    "prior_control_plane_projection_sha256",
    "release_envelope_sha256",
    "release_sequence",
    "root_key_id",
    "schema",
    "source_sha",
    "stage_journal_head_sha256",
    "stage_result_sha256",
    "staged_product_id",
    "staged_source_build_id",
    "surfaces_digest",
    "trust_bundle_sha256",
    "trust_generation",
    "version",
)

REFRESHABLE_GATE_EVIDENCE_FIELDS = (
    "host_evidence_expires_at",
    "host_evidence_issued_at",
    "host_evidence_key_id",
    "host_evidence_sha256",
    "host_nonce",
    "minimum_authority_expires_at",
    "quiescence_evidence_sha256",
    "recovery_evidence_sha256",
    "protected_state_preimage_sha256",
)

EXPECTED_INTENT_EQUALITY_LEFTS = (
    "current_dependency_component_id",
    "staged_product_id",
    "staged_source_build_id",
)

_EXPECTED_PLAN_FIXED_UNSUPPORTED = (
    "unsupported:intent-key-count-invalid",
    "unsupported:intent-key-type-invalid",
    "unsupported:intent-keys-invalid",
    "unsupported:intent-type-invalid",
    "unsupported:internal-error",
)
EXPECTED_UNSUPPORTED_FIXED_BY_COMMAND = {
    "plan-activation-intent": _EXPECTED_PLAN_FIXED_UNSUPPORTED,
    "validate-transition": (
        "unsupported:current-state-invalid",
    )
    + _EXPECTED_PLAN_FIXED_UNSUPPORTED
    + (
        "unsupported:next-state-invalid",
        "unsupported:gate-observation-map-invalid",
    )
    + tuple(
        "unsupported:gate-observation-not-applicable:" + observation_type
        for observation_type in EXPECTED_GATE_OBSERVATION_TYPES
    )
    + tuple(
        "unsupported:gate-observation-invalid:" + observation_type
        for observation_type in EXPECTED_GATE_OBSERVATION_TYPES
    ),
    "render-result": (
        "unsupported:output-oversize",
        "unsupported:result-not-renderable",
    ),
}

RESULT_KEYS = frozenset(
    (
        "schema",
        "mode",
        "command",
        "status",
        "reason",
        "activation_contract_id",
        "pivot_state",
        "transaction_id",
        "intent_sha256",
        "intent",
        "activation_nonce",
        "idempotency_key_sha256",
        "channel",
        "version",
        "release_sequence",
        "trust_generation",
        "source_sha",
        "inventory_policy_id",
        "current_source_build_id",
        "candidate_source_build_id",
        "current_product_id",
        "candidate_product_id",
        "layout_contract_id",
        "layout_id",
        "trust_bundle_sha256",
        "release_envelope_sha256",
        "compatibility_ticket_sha256",
        "compatibility_result_sha256",
        "surfaces_digest",
        "declared_initial_state",
        "current_state",
        "next_state",
        "rollback_disposition",
        "post_pivot_forward_only",
        "gate_observations_by_type",
        "gate_observation_sha256_by_type",
        "requirements",
        "nonclaims",
    )
    + FALSE_FLAGS
)


def _h(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _intent(**overrides) -> dict:
    intent = {
        "schema": "synapse-s2.release-activation-intent.v1",
        "activation_nonce": "ab" * 16,
        "idempotency_key_sha256": _h("idem"),
        "activation_policy_receipt_sha256": _h("policy"),
        "root_key_id": "ed25519-" + _h("root"),
        "trust_generation": 3,
        "trust_bundle_sha256": _h("bundle"),
        "release_envelope_sha256": _h("envelope"),
        "compatibility_ticket_sha256": _h("ticket"),
        "compatibility_result_sha256": _h("compat"),
        "channel": "stable",
        "version": "2.1.0",
        "release_sequence": 7,
        "source_sha": _h("src")[:40],
        "inventory_policy_id": "inventory-policy-" + _h("inv"),
        "current_source_build_id": "source-" + _h("cur")[:24],
        "candidate_source_build_id": "source-" + _h("cand")[:24],
        "current_product_id": "product-" + _h("curp"),
        "candidate_product_id": "product-" + _h("candp"),
        "current_dependency_component_id": "component-" + _h("dep"),
        "candidate_dependency_component_id": "component-" + _h("dep"),
        "surfaces_digest": _h("surf"),
        "installed_floor_preimage_sha256": _h("floor"),
        "incumbent_installed_record_sha256": _h("installed"),
        "layout_schema": "synapse-s2.installed-layout-contract.v1",
        "layout_mode": "inactive-versioned-v1",
        "layout_contract_id": (
            "layout-contract-"
            "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
        ),
        "layout_id": "layout-" + _h("lid"),
        "stage_result_sha256": _h("stage"),
        "stage_journal_head_sha256": _h("sj"),
        "staged_product_id": "product-" + _h("candp"),
        "staged_source_build_id": "source-" + _h("cand")[:24],
        "environment_receipt_sha256": _h("env"),
        "host_evidence_schema": "synapse-s2.host-evidence-receipt.v1",
        "host_evidence_purpose": "release-activation",
        "host_id_sha256": _h("hid"),
        "prior_control_plane_projection_sha256": _h("prior"),
        "desired_control_plane_projection_sha256": _h("desired"),
    }
    intent.update(overrides)
    return intent


EVIDENCE = _h("no-durable-claim")
EQUALITY_EVIDENCE = _h("protected-state-equality")


def _gate_observation(
    observation_type: str,
    current: str,
    upcoming: str,
    *,
    intent: dict | None = None,
    observed_at: int = 1700000100,
) -> dict:
    stable_intent = _intent() if intent is None else intent
    transaction_id = journal.plan_activation_intent(stable_intent)[
        "transaction_id"
    ]
    document = {
        "schema": "synapse-s2.release-activation-gate-observation.v1",
        "transaction_id": transaction_id,
        "from_state": current,
        "to_state": upcoming,
        "observation_type": observation_type,
        "observed_at": observed_at,
        "observed_state_entry_sha256": _h(
            "entry:" + current + ":" + upcoming
        ),
        "evidence_sha256": _h(
            "gate:" + observation_type + ":" + current + ":" + upcoming
        ),
    }
    if observation_type == "host-authority":
        document.update(
            {
                "host_evidence_key_id": "ed25519-" + _h("host-key"),
                "host_nonce": "cd" * 16,
                "issued_at": 1700000000,
                "expires_at": 1700001000,
                "minimum_authority_expires_at": 1700000900,
            }
        )
    if observation_type in {
        "protected-state-equality",
        "quiescence",
        "recovery-readiness",
    }:
        document["protected_state_preimage_sha256"] = _h(
            "protected-state"
        )
    return document


def _gate_observations(
    current: str,
    upcoming: str,
    *,
    intent: dict | None = None,
) -> dict:
    return {
        observation_type: _gate_observation(
            observation_type,
            current,
            upcoming,
            intent=intent,
        )
        for observation_type in EXPECTED_EDGE_OBSERVATIONS.get(
            (current, upcoming), ()
        )
    }


def _gate_digests(current: str, upcoming: str) -> dict:
    return {
        observation_type: journal._gate_observation_sha256(document)
        for observation_type, document in _gate_observations(
            current, upcoming
        ).items()
    }


def _validate(current: str, upcoming: str, **kwargs) -> dict:
    intent = kwargs.setdefault("activation_intent", _intent())
    kwargs.setdefault(
        "gate_observations_by_type",
        _gate_observations(current, upcoming, intent=intent),
    )
    return journal.validate_transition(current, upcoming, **kwargs)


class _HookStr(str):
    calls: list = []

    def __eq__(self, other):
        type(self).calls.append("eq")
        return str.__eq__(self, other)

    __hash__ = str.__hash__


class _HookDict(dict):
    calls: list = []

    def keys(self):
        type(self).calls.append("keys")
        return dict.keys(self)

    def __iter__(self):
        type(self).calls.append("iter")
        return dict.__iter__(self)


class _HookList(list):
    calls: list = []

    def __iter__(self):
        type(self).calls.append("iter")
        return list.__iter__(self)


def _canonical(payload) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


JOURNAL_DECISION = 1_900_000_000


def _journal_root():
    return tempfile.TemporaryDirectory(
        prefix="release-activation-journal-test-", dir="/private/tmp"
    )


def _journal_directory(root: str) -> Path:
    return Path(root) / journal.JOURNAL_SUBDIRECTORY


def _journal_observations(
    prior: dict,
    upcoming: str,
    decision_at: int,
    *,
    intent: dict,
    protected_sha256: str | None = None,
) -> dict:
    documents = _gate_observations(
        prior["to_state"], upcoming, intent=intent
    )
    for document in documents.values():
        document["observed_state_entry_sha256"] = prior["entry_sha256"]
        document["observed_at"] = decision_at - 1
        if "protected_state_preimage_sha256" in document:
            document["protected_state_preimage_sha256"] = (
                _h("journal-protected-state")
                if protected_sha256 is None
                else protected_sha256
            )
    host = documents.get("host-authority")
    if host is not None:
        host["issued_at"] = decision_at - 10
        host["expires_at"] = decision_at + 1_000
        host["minimum_authority_expires_at"] = decision_at + 900
    return documents


def _journal_append(
    root: str,
    prior: dict,
    upcoming: str,
    decision_at: int,
    *,
    intent: dict,
    observations: dict | None = None,
    now_values: tuple[int, ...] | None = None,
    module=journal,
) -> dict:
    if observations is None:
        observations = _journal_observations(
            prior, upcoming, decision_at, intent=intent
        )
    samples = iter(
        (decision_at, decision_at) if now_values is None else now_values
    )
    original_now = module._JOURNAL_NOW
    module._JOURNAL_NOW = lambda: next(samples)
    try:
        return module.append_activation_transition(
            root,
            activation_intent=intent,
            observed_state_entry_sha256=prior["entry_sha256"],
            next_state=upcoming,
            decision_at=decision_at,
            gate_observations_by_type=observations,
        )
    finally:
        module._JOURNAL_NOW = original_now


def _journal_tip_fields(result: dict) -> dict:
    return {
        key: result[key]
        for key in (
            "transaction_id",
            "intent_sha256",
            "request_sha256",
            "entry_sha256",
            "prior_entry_sha256",
            "sequence",
            "from_state",
            "to_state",
            "tip_state",
            "protected_state_preimage_sha256",
        )
    }


def _journal_request_and_entries(root: str) -> tuple[Path, list[Path]]:
    directory = _journal_directory(root)
    requests = sorted(directory.glob("request-*.json"))
    entries = sorted(directory.glob("entry-*.json"))
    if len(requests) != 1:
        raise AssertionError("one request required")
    return requests[0], entries


def _rewrite_journal_document(path: Path, document: dict) -> None:
    encoded = (_canonical(document) + "\n").encode("ascii")
    descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class ContractProjectionTests(unittest.TestCase):
    def test_golden_id_and_self_consistency(self) -> None:
        first = journal.activation_contract_projection()
        second = journal.activation_contract_projection()
        self.assertEqual(first, second)
        self.assertEqual(
            first["activation_contract_id"], EXPECTED_ACTIVATION_CONTRACT_ID
        )
        payload = {
            key: value
            for key, value in first.items()
            if key not in ("status", "reason", "activation_contract_id")
        }
        digest = hashlib.sha256(
            b"SYNAPSE-S2\x00RELEASE-ACTIVATION-CONTRACT\x00v1\x00"
            + _canonical(payload).encode("ascii")
        ).hexdigest()
        self.assertEqual(
            first["activation_contract_id"], "activation-contract-" + digest
        )
        self.assertEqual(first["status"], "projected")

    def test_exact_pins(self) -> None:
        projection = journal.activation_contract_projection()
        self.assertEqual(projection["mode"], "dormant-source-only")
        self.assertEqual(projection["profile"], "exact-build-only")
        policies = projection["policies"]
        self.assertEqual(policies["host_evidence_policy"], "required-later")
        self.assertEqual(policies["migration_policy"], "blocked")
        self.assertEqual(policies["downgrade_policy"], "blocked")
        self.assertEqual(
            policies["layout_schema"],
            "synapse-s2.installed-layout-contract.v1",
        )
        self.assertEqual(policies["layout_mode"], "inactive-versioned-v1")
        self.assertEqual(
            policies["host_evidence_receipt_schema"],
            "synapse-s2.host-evidence-receipt.v1",
        )
        state_policy = projection["state_policy"]
        self.assertEqual(
            state_policy["state_constants"],
            {
                name: getattr(journal, name)
                for name in (
                    "STATE_ABORTED_PRE_PIVOT",
                    "STATE_ACTIVATING",
                    "STATE_CANDIDATE_HEALTHY",
                    "STATE_CLIENTS_PUBLISH_INTENT",
                    "STATE_CLIENTS_CONVERGED",
                    "STATE_COMMITTED",
                    "STATE_CONTROL_PLANE_ROLLED_BACK",
                    "STATE_FLOOR_RECORDED",
                    "STATE_MANUAL_RECOVERY_REQUIRED",
                    "STATE_PIVOT",
                    "STATE_PIVOT_INTENT",
                    "STATE_POST_UPDATE_EQUIVALENT",
                    "STATE_POST_PIVOT_RECOVERY_REQUIRED",
                    "STATE_PREPARED",
                    "STATE_QUIESCE_INTENT",
                    "STATE_QUIESCENT_OBSERVED",
                    "STATE_RELEASE_COMMIT_INTENT",
                    "STATE_ROLLBACK_INTENT",
                    "STATE_START",
                    "STATE_SWITCH_INTENT",
                )
            },
        )
        self.assertEqual(
            state_policy["graph"],
            {k: list(v) for k, v in EXPECTED_GRAPH.items()},
        )
        self.assertEqual(state_policy["initial_state"], "prepared")
        self.assertIs(state_policy["initial_state_authorized"], False)
        self.assertEqual(state_policy["pivot_state"], PIVOT)
        self.assertEqual(
            sorted(state_policy["terminal_states"]),
            sorted(k for k, v in EXPECTED_GRAPH.items() if not v),
        )
        self.assertEqual(
            state_policy["guarded_edges"],
            [
                [
                    "activating",
                    "rollback-intent",
                    ["no-durable-claim"],
                ],
                [
                    "candidate-healthy",
                    "rollback-intent",
                    ["no-durable-claim"],
                ],
                [
                    "quiesce-intent",
                    "rollback-intent",
                    ["protected-state-equality"],
                ],
                [
                    "quiescent-observed",
                    "rollback-intent",
                    ["protected-state-equality"],
                ],
                [
                    "rollback-intent",
                    "control-plane-rolled-back",
                    ["protected-state-equality"],
                ],
            ],
        )
        self.assertEqual(
            state_policy["unknown_pivot_outcome_edges"],
            [
                ["switch-intent", "activating"],
                ["switch-intent", "manual-recovery-required"],
                ["activating", "manual-recovery-required"],
                ["candidate-healthy", "pivot-intent"],
                ["pivot-intent", "post-pivot-recovery-required"],
            ],
        )
        self.assertEqual(
            projection["transition_input_policy"][
                "evidence_field_constants"
            ],
            {
                "EVIDENCE_NO_DURABLE_CLAIM": "no-durable-claim",
                "EVIDENCE_PROTECTED_STATE_EQUALITY": (
                    "protected-state-equality"
                ),
            },
        )
        self.assertEqual(
            projection["no_return_policy"]["state"], "switch-intent"
        )
        self.assertIs(
            projection["no_return_policy"][
                "automatic_predecessor_fallback_after_state"
            ],
            False,
        )
        self.assertEqual(
            policies["expected_layout_contract_id"],
            "layout-contract-"
            "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada",
        )
        rollback = projection["rollback_policy"]
        self.assertIs(rollback["forward_only_after_pivot"], True)
        self.assertIn("memory-database", rollback["never_restores"])
        self.assertIn("request-journal", rollback["never_restores"])
        intent_policy = projection["intent_policy"]
        self.assertEqual(tuple(intent_policy["keys"]), INTENT_KEYS)
        self.assertEqual(intent_policy["integer_maximum"], 2**53)
        self.assertEqual(
            intent_policy["refreshable_gate_evidence_excluded"],
            list(REFRESHABLE_GATE_EVIDENCE_FIELDS),
        )
        self.assertEqual(
            projection["late_gate_observation_policy"]["types"],
            list(EXPECTED_GATE_OBSERVATION_TYPES),
        )
        late_policy = projection["late_gate_observation_policy"]
        self.assertEqual(
            late_policy["common_fields"],
            [
                "schema",
                "transaction_id",
                "from_state",
                "to_state",
                "observation_type",
                "observed_at",
                "observed_state_entry_sha256",
                "evidence_sha256",
            ],
        )
        self.assertEqual(
            late_policy["string_grammars"],
            {
                "evidence_sha256": {
                    "pattern": r"\A[0-9a-f]{64}\Z",
                    "flags": int(re.UNICODE),
                },
                "host_evidence_key_id": {
                    "pattern": r"\Aed25519-[0-9a-f]{64}\Z",
                    "flags": int(re.UNICODE),
                },
                "host_nonce": {
                    "pattern": r"\A[0-9a-f]{32}\Z",
                    "flags": int(re.UNICODE),
                },
                "observed_state_entry_sha256": {
                    "pattern": r"\A[0-9a-f]{64}\Z",
                    "flags": int(re.UNICODE),
                },
                "protected_state_preimage_sha256": {
                    "pattern": r"\A[0-9a-f]{64}\Z",
                    "flags": int(re.UNICODE),
                },
            },
        )
        self.assertIs(late_policy["transaction_and_edge_bound"], True)
        self.assertIs(late_policy["observed_state_entry_bound"], True)
        self.assertIs(
            late_policy["shape_validation_is_not_evidence_verification"],
            True,
        )
        self.assertEqual(
            late_policy["protected_state_lineage_policy"]["types"],
            [
                "protected-state-equality",
                "quiescence",
                "recovery-readiness",
            ],
        )
        self.assertIs(
            projection["late_gate_observation_policy"][
                "refresh_preserves_transaction_id"
            ],
            True,
        )
        self.assertEqual(
            journal.EDGE_OBSERVATION_REQUIREMENTS,
            EXPECTED_EDGE_OBSERVATIONS,
        )
        expected_observation_edges = [
            [current, upcoming, list(EXPECTED_EDGE_OBSERVATIONS[edge])]
            for edge in sorted(EXPECTED_EDGE_OBSERVATIONS)
            for current, upcoming in (edge,)
        ]
        self.assertEqual(
            projection["late_gate_observation_policy"][
                "edge_observation_requirements"
            ],
            expected_observation_edges,
        )
        self.assertEqual(
            projection["transition_input_policy"][
                "edge_observation_requirements"
            ],
            expected_observation_edges,
        )
        self.assertEqual(
            projection["always_false_flags"], list(FALSE_FLAGS)
        )
        unsupported_policy = projection["result_policy"][
            "unsupported_reason_policy"
        ]
        self.assertEqual(
            unsupported_policy,
            {
                "fixed_by_command": {
                    command: list(reasons)
                    for command, reasons in (
                        EXPECTED_UNSUPPORTED_FIXED_BY_COMMAND.items()
                    )
                },
                "dynamic": [
                    {
                        "prefix": "unsupported:intent-field-invalid:",
                        "commands": [
                            "plan-activation-intent",
                            "validate-transition",
                        ],
                        "suffixes": sorted(INTENT_KEYS),
                    },
                    {
                        "prefix": (
                            "unsupported:intent-binding-mismatch:"
                        ),
                        "commands": [
                            "plan-activation-intent",
                            "validate-transition",
                        ],
                        "suffixes": sorted(
                            EXPECTED_INTENT_EQUALITY_LEFTS
                        ),
                    },
                ],
                "exact_command_match_required": True,
            },
        )
        self.assertEqual(
            list(EXPECTED_UNSUPPORTED_FIXED_BY_COMMAND["render-result"]),
            [
                "unsupported:output-oversize",
                "unsupported:result-not-renderable",
            ],
        )
        self.assertEqual(projection["nonclaims"], list(NONCLAIMS))

    def test_mutating_enforcement_constants_changes_id(self) -> None:
        base = journal.activation_contract_projection()[
            "activation_contract_id"
        ]
        entry_cases = [
            (journal.STATE_GRAPH, "committed", ("prepared",)),
            (journal.ROLLBACK_DISPOSITIONS, "committed", "eligible"),
            (journal._INTENT_FIXED, "layout_mode", "legacy-checkout"),
            (
                journal.GUARDED_EDGES,
                ("activating", "rollback-intent"),
                "nothing",
            ),
            (
                journal._INTENT_PATTERNS,
                "channel",
                re.compile(r"\A.+\Z"),
            ),
            (
                journal.EDGE_OBSERVATION_REQUIREMENTS,
                ("prepared", "quiesce-intent"),
                ("host-authority",),
            ),
            (
                journal._UNSUPPORTED_FIXED_REASONS_BY_COMMAND,
                journal.COMMAND_PLAN,
                ("unsupported:internal-error",),
            ),
        ]
        for table, key, bad in entry_cases:
            with self.subTest(key=str(key)):
                original = table[key]
                table[key] = bad
                try:
                    mutated = journal.activation_contract_projection()[
                        "activation_contract_id"
                    ]
                finally:
                    table[key] = original
                self.assertNotEqual(mutated, base)
        attribute_cases = [
            ("MAX_INT", 2**40),
            ("MAX_RESULT_BYTES", 65536),
            ("NONCLAIMS", journal.NONCLAIMS[:-1]),
            ("ALWAYS_FALSE_FLAGS", journal.ALWAYS_FALSE_FLAGS[:-1]),
            ("REQUIREMENTS", journal.REQUIREMENTS[:-1]),
            ("NO_RETURN_POLICY", journal.NO_RETURN_POLICY[:-1]),
            ("NO_RETURN_STATE", "activating"),
            ("HOST_EVIDENCE_POLICY", "optional"),
            ("MIGRATION_POLICY", "allowed"),
            ("DOWNGRADE_POLICY", "allowed"),
            ("PROFILE", "any-build"),
            ("GATE_OBSERVATION_SCHEMA", "synapse-s2.changed.v1"),
            ("GATE_OBSERVATION_TYPES", journal.GATE_OBSERVATION_TYPES[:-1]),
            ("_GATE_COMMON_FIELDS", journal._GATE_COMMON_FIELDS[:-1]),
            (
                "_GATE_HOST_AUTHORITY_FIELDS",
                journal._GATE_HOST_AUTHORITY_FIELDS[:-1],
            ),
            (
                "_GATE_PROTECTED_STATE_FIELDS",
                ("changed-protected-field",),
            ),
            (
                "_GATE_PROTECTED_STATE_TYPES",
                journal._GATE_PROTECTED_STATE_TYPES[:-1],
            ),
            (
                "_GATE_OBSERVATION_HASH_DOMAIN",
                b"SYNAPSE-S2\x00CHANGED\x00v1\x00",
            ),
            ("ROLLBACK_NEVER_RESTORES", ("nothing",)),
            ("COMMAND_PLAN", "plan-something-else"),
            ("STATUS_PLANNED", "authorized-looking"),
            (
                "_RESULT_IDENTITY_FIELDS",
                journal._RESULT_IDENTITY_FIELDS[:-1],
            ),
            (
                "_PLAN_RESULT_BINDINGS",
                {
                    key: value
                    for key, value in journal._PLAN_RESULT_BINDINGS.items()
                    if key != "candidate_product_id"
                },
            ),
        ]
        for name in journal._state_constant_map():
            attribute_cases.append(
                (name, "mutated-" + getattr(journal, name))
            )
        attribute_cases.extend(
            (
                ("EVIDENCE_NO_DURABLE_CLAIM", "mutated-no-claim"),
                (
                    "EVIDENCE_PROTECTED_STATE_EQUALITY",
                    "mutated-protected-equality",
                ),
            )
        )
        for name, bad in attribute_cases:
            with self.subTest(name=name):
                original = getattr(journal, name)
                setattr(journal, name, bad)
                try:
                    mutated = journal.activation_contract_projection()[
                        "activation_contract_id"
                    ]
                finally:
                    setattr(journal, name, original)
                self.assertNotEqual(mutated, base)
        self.assertEqual(
            journal.activation_contract_projection()[
                "activation_contract_id"
            ],
            base,
        )

    def test_regex_flags_are_bound_and_change_enforcement(self) -> None:
        base = journal.activation_contract_projection()[
            "activation_contract_id"
        ]
        original = journal._INTENT_PATTERNS["channel"]
        journal._INTENT_PATTERNS["channel"] = re.compile(
            original.pattern, re.IGNORECASE
        )
        try:
            mutated = journal.activation_contract_projection()[
                "activation_contract_id"
            ]
            admitted = journal.plan_activation_intent(
                _intent(channel="Stable")
            )
        finally:
            journal._INTENT_PATTERNS["channel"] = original
        self.assertNotEqual(mutated, base)
        self.assertEqual(admitted["status"], "planned")
        self.assertEqual(
            journal.plan_activation_intent(_intent(channel="Stable"))[
                "status"
            ],
            "unsupported",
        )

        grammar_cases = (
            (
                "evidence_sha256",
                "activating",
                "rollback-intent",
                "no-durable-claim",
            ),
            (
                "observed_state_entry_sha256",
                "activating",
                "rollback-intent",
                "no-durable-claim",
            ),
            (
                "protected_state_preimage_sha256",
                "rollback-intent",
                "control-plane-rolled-back",
                "protected-state-equality",
            ),
            (
                "host_evidence_key_id",
                "prepared",
                "quiesce-intent",
                "host-authority",
            ),
            (
                "host_nonce",
                "prepared",
                "quiesce-intent",
                "host-authority",
            ),
        )
        for field, current, upcoming, observation_type in grammar_cases:
            with self.subTest(gate_string_grammar=field):
                original = journal._GATE_OBSERVATION_STRING_PATTERNS[field]
                journal._GATE_OBSERVATION_STRING_PATTERNS[field] = re.compile(
                    original.pattern, re.IGNORECASE
                )
                try:
                    mutated_contract = (
                        journal.activation_contract_projection()[
                            "activation_contract_id"
                        ]
                    )
                    observations = _gate_observations(current, upcoming)
                    observations[observation_type][field] = observations[
                        observation_type
                    ][field].upper()
                    admitted = journal.validate_transition(
                        current,
                        upcoming,
                        activation_intent=_intent(),
                        gate_observations_by_type=observations,
                    )
                finally:
                    journal._GATE_OBSERVATION_STRING_PATTERNS[field] = (
                        original
                    )
                self.assertNotEqual(mutated_contract, base)
                self.assertEqual(admitted["status"], "valid")
                self.assertEqual(
                    journal.validate_transition(
                        current,
                        upcoming,
                        activation_intent=_intent(),
                        gate_observations_by_type=observations,
                    )["status"],
                    "unsupported",
                )

        original_transaction = journal._TRANSACTION_ID_PATTERN
        journal._TRANSACTION_ID_PATTERN = re.compile(
            original_transaction.pattern, re.IGNORECASE
        )
        try:
            transaction_contract = journal.activation_contract_projection()[
                "activation_contract_id"
            ]
            uppercase_result = journal.plan_activation_intent(_intent())
            uppercase_result["transaction_id"] = uppercase_result[
                "transaction_id"
            ].upper()
            self.assertEqual(journal.result_exit_code(uppercase_result), 2)
        finally:
            journal._TRANSACTION_ID_PATTERN = original_transaction
        self.assertNotEqual(transaction_contract, base)
        self.assertEqual(journal.result_exit_code(uppercase_result), 2)

    def test_layout_contract_pin_matches_sibling_projection(self) -> None:
        sibling = _load(
            "test_release_activation_layout_sibling",
            ROOT / "scripts" / "installed_layout.py",
        )
        projection = sibling.installed_layout_contract_projection(
            "inactive-versioned-v1"
        )
        self.assertEqual(
            projection["layout_contract_id"],
            journal.EXPECTED_LAYOUT_CONTRACT_ID,
        )

    def test_mutated_pin_also_changes_enforcement(self) -> None:
        original = journal._INTENT_FIXED["layout_mode"]
        journal._INTENT_FIXED["layout_mode"] = "legacy-checkout"
        try:
            result = journal.plan_activation_intent(_intent())
        finally:
            journal._INTENT_FIXED["layout_mode"] = original
        self.assertEqual(result["status"], "unsupported")


class StateGraphTests(unittest.TestCase):
    def test_every_pair_adjudicated_exactly(self) -> None:
        states = list(EXPECTED_GRAPH)
        equality_edges = {
            ("quiesce-intent", "rollback-intent"),
            ("quiescent-observed", "rollback-intent"),
            ("rollback-intent", "control-plane-rolled-back"),
        }
        no_claim_edges = {
            ("activating", "rollback-intent"),
            ("candidate-healthy", "rollback-intent"),
        }
        for current in states:
            for upcoming in states:
                with self.subTest(current=current, upcoming=upcoming):
                    legal = upcoming in EXPECTED_GRAPH[current]
                    edge = (current, upcoming)
                    bare = journal.validate_transition(
                        current, upcoming, activation_intent=_intent()
                    )
                    if not legal:
                        self.assertEqual(bare["status"], "denied")
                        expected = (
                            "denied:terminal-state"
                            if not EXPECTED_GRAPH[current]
                            else "denied:illegal-transition"
                        )
                        self.assertEqual(bare["reason"], expected)
                        self.assertEqual(journal.result_exit_code(bare), 3)
                        continue

                    required_observations = (
                        EXPECTED_EDGE_OBSERVATIONS.get(edge, ())
                    )
                    if required_observations:
                        self.assertEqual(bare["status"], "denied")
                        self.assertEqual(
                            bare["reason"],
                            "denied:gate-observation-required:"
                            + sorted(required_observations)[0],
                        )
                    else:
                        self.assertEqual(bare["status"], "valid")

                    admitted = _validate(current, upcoming)
                    self.assertEqual(admitted["status"], "valid")
                    self.assertEqual(journal.result_exit_code(admitted), 0)
                    self.assertEqual(
                        admitted["gate_observation_sha256_by_type"],
                        _gate_digests(current, upcoming),
                    )
                    if edge in no_claim_edges:
                        self.assertEqual(
                            admitted["reason"],
                            "valid:rollback-intent-admitted-after-"
                            "no-durable-claim-evidence",
                        )
                    elif edge in equality_edges:
                        expected_reason = (
                            "valid:control-plane-rollback-recorded-after-"
                            "protected-state-equality-evidence"
                            if upcoming == "control-plane-rolled-back"
                            else "valid:rollback-intent-admitted-after-"
                            "protected-state-equality-evidence"
                        )
                        self.assertEqual(admitted["reason"], expected_reason)
                    else:
                        self.assertEqual(
                            admitted["reason"], "valid:transition-allowed"
                        )

    def test_state_and_typed_observation_validation(self) -> None:
        for current, upcoming in (
            ("launching", "prepared"),
            (b"start", "prepared"),
            (7, "prepared"),
            (None, "prepared"),
            (True, "prepared"),
            ("start", "x" * 100000),
            ("start", None),
        ):
            with self.subTest(current=current, upcoming=upcoming):
                result = journal.validate_transition(
                    current, upcoming, activation_intent=_intent()
                )
                self.assertEqual(result["status"], "unsupported")
                self.assertIn(
                    result["reason"],
                    (
                        "unsupported:current-state-invalid",
                        "unsupported:next-state-invalid",
                    ),
                )
                self.assertEqual(journal.result_exit_code(result), 2)
        for evidence in (EVIDENCE[:-1], EVIDENCE.upper(), b"x" * 64, 5, 1.5):
            with self.subTest(evidence=evidence):
                observations = _gate_observations(
                    "activating", "rollback-intent"
                )
                observations["no-durable-claim"]["evidence_sha256"] = evidence
                result = journal.validate_transition(
                    "activating",
                    "rollback-intent",
                    activation_intent=_intent(),
                    gate_observations_by_type=observations,
                )
                self.assertEqual(
                    result["reason"],
                    "unsupported:gate-observation-invalid:no-durable-claim",
                )
        for evidence in (
            EQUALITY_EVIDENCE[:-1],
            EQUALITY_EVIDENCE.upper(),
            b"x" * 64,
            5,
            1.5,
        ):
            with self.subTest(equality_evidence=evidence):
                observations = _gate_observations(
                    "rollback-intent", "control-plane-rolled-back"
                )
                observations["protected-state-equality"][
                    "evidence_sha256"
                ] = evidence
                result = journal.validate_transition(
                    "rollback-intent",
                    "control-plane-rolled-back",
                    activation_intent=_intent(),
                    gate_observations_by_type=observations,
                )
                self.assertEqual(
                    result["reason"],
                    "unsupported:gate-observation-invalid:"
                    "protected-state-equality",
                )

        _HookDict.calls = []
        invalid_observation_maps = (
            [],
            _HookDict(
                _gate_observations("prepared", "quiesce-intent")
            ),
            {"unknown": {}},
            {7: {}},
        )
        for observation_map in invalid_observation_maps:
            with self.subTest(observation_map=type(observation_map)):
                result = journal.validate_transition(
                    "prepared",
                    "quiesce-intent",
                    activation_intent=_intent(),
                    gate_observations_by_type=observation_map,
                )
                self.assertEqual(
                    result["reason"],
                    "unsupported:gate-observation-map-invalid",
                )
        self.assertEqual(_HookDict.calls, [])

        malformed_documents = []
        for key, bad in (
            ("transaction_id", "transaction-" + _h("wrong")),
            ("from_state", "start"),
            ("to_state", "committed"),
            ("observation_type", "candidate-health"),
            ("observed_at", True),
            ("observed_state_entry_sha256", "f" * 63),
            ("host_nonce", "0" * 31),
            ("expires_at", 1700000100),
            ("minimum_authority_expires_at", 1700000100),
        ):
            observations = _gate_observations(
                "prepared", "quiesce-intent"
            )
            observations["host-authority"][key] = bad
            malformed_documents.append(observations)
        observations = _gate_observations("prepared", "quiesce-intent")
        observations["host-authority"] = 7
        malformed_documents.append(observations)
        observations = _gate_observations("prepared", "quiesce-intent")
        del observations["host-authority"]["evidence_sha256"]
        malformed_documents.append(observations)
        observations = _gate_observations("prepared", "quiesce-intent")
        observations["host-authority"]["extra"] = "x"
        malformed_documents.append(observations)
        observations = _gate_observations("prepared", "quiesce-intent")
        observations["host-authority"] = _HookDict(
            observations["host-authority"]
        )
        malformed_documents.append(observations)
        observations = _gate_observations("prepared", "quiesce-intent")
        observations["host-authority"]["evidence_sha256"] = _HookStr(
            observations["host-authority"]["evidence_sha256"]
        )
        malformed_documents.append(observations)
        for key, bad in (
            ("observed_at", 0),
            ("observed_at", 2**53 + 1),
            ("host_evidence_key_id", "rsa-" + _h("host-key")),
            ("issued_at", 1700000200),
            ("minimum_authority_expires_at", 1700001001),
        ):
            observations = _gate_observations(
                "prepared", "quiesce-intent"
            )
            observations["host-authority"][key] = bad
            malformed_documents.append(observations)
        for observations in malformed_documents:
            result = journal.validate_transition(
                "prepared",
                "quiesce-intent",
                activation_intent=_intent(),
                gate_observations_by_type=observations,
            )
            self.assertEqual(
                result["reason"],
                "unsupported:gate-observation-invalid:host-authority",
            )

        irrelevant = journal.validate_transition(
            "start",
            "prepared",
            activation_intent=_intent(),
            gate_observations_by_type={
                "candidate-health": _gate_observation(
                    "candidate-health", "start", "prepared"
                )
            },
        )
        self.assertEqual(
            irrelevant["reason"],
            "unsupported:gate-observation-not-applicable:candidate-health",
        )

        partial = journal.validate_transition(
            "prepared",
            "quiesce-intent",
            activation_intent=_intent(),
            gate_observations_by_type={
                "host-authority": _gate_observation(
                    "host-authority", "prepared", "quiesce-intent"
                )
            },
        )
        self.assertEqual(
            partial["reason"],
            "denied:gate-observation-required:recovery-readiness",
        )
        self.assertEqual(partial["intent"], _intent())
        self.assertEqual(
            set(partial["gate_observations_by_type"]),
            {"host-authority"},
        )
        self.assertEqual(
            partial["gate_observation_sha256_by_type"]["host-authority"],
            journal._gate_observation_sha256(
                partial["gate_observations_by_type"]["host-authority"]
            ),
        )
        self.assertEqual(journal.result_exit_code(partial), 3)
        self.assertEqual(json.loads(journal.render_result(partial)), partial)

        forged = dict(partial)
        forged["reason"] = (
            "denied:gate-observation-required:host-authority"
        )
        self.assertEqual(journal.result_exit_code(forged), 2)
        self.assertEqual(
            json.loads(journal.render_result(forged))["reason"],
            "unsupported:result-not-renderable",
        )

        recovery_document = _gate_observation(
            "recovery-readiness", "prepared", "quiesce-intent"
        )
        recovery_only = journal.validate_transition(
            "prepared",
            "quiesce-intent",
            activation_intent=_intent(),
            gate_observations_by_type={
                "recovery-readiness": recovery_document
            },
        )
        self.assertEqual(
            recovery_only["reason"],
            "denied:gate-observation-required:host-authority",
        )
        self.assertEqual(
            recovery_only["gate_observations_by_type"],
            {"recovery-readiness": recovery_document},
        )
        self.assertEqual(journal.result_exit_code(recovery_only), 3)

    def test_no_return_and_rollback_proofs_are_edge_scoped(self) -> None:
        manual = _validate("switch-intent", "manual-recovery-required")
        self.assertEqual(manual["status"], "valid")
        rollback = _validate("switch-intent", "rollback-intent")
        self.assertEqual(rollback["status"], "denied")
        self.assertEqual(rollback["reason"], "denied:illegal-transition")

        wrong_proof = journal.validate_transition(
            "activating",
            "rollback-intent",
            activation_intent=_intent(),
            gate_observations_by_type={
                "protected-state-equality": _gate_observation(
                    "protected-state-equality",
                    "activating",
                    "rollback-intent",
                )
            },
        )
        self.assertEqual(
            wrong_proof["reason"],
            "unsupported:gate-observation-not-applicable:"
            "protected-state-equality",
        )
        both_observations = _gate_observations(
            "activating", "rollback-intent"
        )
        both_observations["protected-state-equality"] = _gate_observation(
            "protected-state-equality", "activating", "rollback-intent"
        )
        both = journal.validate_transition(
            "activating",
            "rollback-intent",
            activation_intent=_intent(),
            gate_observations_by_type=both_observations,
        )
        self.assertEqual(
            both["reason"],
            "unsupported:gate-observation-not-applicable:"
            "protected-state-equality",
        )

        final_without_fresh_proof = journal.validate_transition(
            "rollback-intent",
            "control-plane-rolled-back",
            activation_intent=_intent(),
        )
        self.assertEqual(final_without_fresh_proof["status"], "denied")
        self.assertEqual(
            final_without_fresh_proof["reason"],
            "denied:gate-observation-required:protected-state-equality",
        )

    def test_every_observation_type_has_exact_failure_tokens(self) -> None:
        edge_by_type = {}
        for edge, observation_types in EXPECTED_EDGE_OBSERVATIONS.items():
            for observation_type in observation_types:
                edge_by_type.setdefault(observation_type, edge)
        self.assertEqual(
            set(edge_by_type), set(EXPECTED_GATE_OBSERVATION_TYPES)
        )

        for observation_type in EXPECTED_GATE_OBSERVATION_TYPES:
            with self.subTest(observation_type=observation_type):
                current, upcoming = edge_by_type[observation_type]
                observations = _gate_observations(current, upcoming)
                observations[observation_type]["evidence_sha256"] = "f" * 63
                invalid = journal.validate_transition(
                    current,
                    upcoming,
                    activation_intent=_intent(),
                    gate_observations_by_type=observations,
                )
                self.assertEqual(
                    invalid["reason"],
                    "unsupported:gate-observation-invalid:"
                    + observation_type,
                )

                irrelevant = journal.validate_transition(
                    "start",
                    "prepared",
                    activation_intent=_intent(),
                    gate_observations_by_type={
                        observation_type: _gate_observation(
                            observation_type, "start", "prepared"
                        )
                    },
                )
                self.assertEqual(
                    irrelevant["reason"],
                    "unsupported:gate-observation-not-applicable:"
                    + observation_type,
                )

    def test_illegal_and_terminal_edges_screen_gate_input_first(self) -> None:
        for current, upcoming in (
            ("start", "committed"),
            ("committed", "prepared"),
        ):
            with self.subTest(current=current, kind="malformed-map"):
                malformed = journal.validate_transition(
                    current,
                    upcoming,
                    activation_intent=_intent(),
                    gate_observations_by_type=[],
                )
                self.assertEqual(malformed["status"], "unsupported")
                self.assertEqual(
                    malformed["reason"],
                    "unsupported:gate-observation-map-invalid",
                )

            with self.subTest(current=current, kind="irrelevant-doc"):
                irrelevant = journal.validate_transition(
                    current,
                    upcoming,
                    activation_intent=_intent(),
                    gate_observations_by_type={
                        "candidate-health": _gate_observation(
                            "candidate-health", current, upcoming
                        )
                    },
                )
                self.assertEqual(irrelevant["status"], "unsupported")
                self.assertEqual(
                    irrelevant["reason"],
                    "unsupported:gate-observation-not-applicable:"
                    "candidate-health",
                )

            with self.subTest(current=current, kind="empty-map"):
                denied = journal.validate_transition(
                    current,
                    upcoming,
                    activation_intent=_intent(),
                    gate_observations_by_type={},
                )
                self.assertEqual(denied["status"], "denied")
                self.assertEqual(journal.result_exit_code(denied), 3)

    def test_post_pivot_field_is_history_safe_tristate(self) -> None:
        for current, upcoming in (
            ("switch-intent", "activating"),
            ("switch-intent", "manual-recovery-required"),
            ("activating", "manual-recovery-required"),
            ("candidate-healthy", "pivot-intent"),
            ("pivot-intent", "post-pivot-recovery-required"),
        ):
            with self.subTest(current=current, upcoming=upcoming):
                result = _validate(current, upcoming)
                self.assertEqual(result["status"], "valid")
                self.assertIsNone(result["post_pivot_forward_only"])
                self.assertEqual(journal.result_exit_code(result), 0)
                self.assertEqual(
                    json.loads(journal.render_result(result)), result
                )
        rolled_back = _validate("activating", "rollback-intent")
        self.assertIs(rolled_back["post_pivot_forward_only"], False)
        pivoted = _validate("pivot-intent", PIVOT)
        self.assertIs(pivoted["post_pivot_forward_only"], True)

    def test_rollback_dispositions_and_pivot(self) -> None:
        projection = journal.activation_contract_projection()
        dispositions = projection["rollback_policy"]["dispositions"]
        for state in PRE_PIVOT_EQUALITY:
            self.assertIn("equality-proof", dispositions[state])
        for state in RECONCILIATION:
            self.assertEqual(
                dispositions[state], "manual-pivot-reconciliation-required"
            )
        for state in POST_PIVOT:
            self.assertIn("forward-only", dispositions[state])
        pivot_entry = _validate("pivot-intent", PIVOT)
        self.assertIs(pivot_entry["post_pivot_forward_only"], True)
        self.assertIn("forward-only", pivot_entry["rollback_disposition"])
        for current in POST_PIVOT:
            for upcoming in EXPECTED_GRAPH[current]:
                result = _validate(current, upcoming)
                self.assertIs(result["post_pivot_forward_only"], True)
                self.assertIn(
                    "forward-only", result["rollback_disposition"]
                )


class IntentPlanTests(unittest.TestCase):
    def test_golden_plan(self) -> None:
        result = journal.plan_activation_intent(_intent())
        self.assertEqual(result["status"], "planned")
        self.assertEqual(
            result["reason"], "planned:activation-intent-bound"
        )
        self.assertEqual(result["transaction_id"], EXPECTED_TRANSACTION_ID)
        self.assertEqual(
            result, journal.plan_activation_intent(_intent())
        )
        payload = {
            "activation_contract_id": EXPECTED_ACTIVATION_CONTRACT_ID,
            "intent": _intent(),
        }
        digest = hashlib.sha256(
            b"SYNAPSE-S2\x00RELEASE-ACTIVATION-TRANSACTION\x00v1\x00"
            + _canonical(payload).encode("ascii")
        ).hexdigest()
        self.assertEqual(
            result["transaction_id"], "transaction-" + digest
        )
        self.assertEqual(result["declared_initial_state"], "prepared")
        self.assertEqual(result["intent"], _intent())
        intent_digest = hashlib.sha256(
            b"SYNAPSE-S2\x00RELEASE-ACTIVATION-INTENT\x00v1\x00"
            + _canonical(_intent()).encode("ascii")
        ).hexdigest()
        self.assertEqual(result["intent_sha256"], intent_digest)
        self.assertIs(result["post_pivot_forward_only"], False)
        self.assertIn("equality-proof", result["rollback_disposition"])
        self.assertEqual(set(result), set(RESULT_KEYS))

    def test_changed_field_changes_transaction_id(self) -> None:
        base = journal.plan_activation_intent(_intent())["transaction_id"]
        variants = (
            {"activation_nonce": "cd" * 16},
            {"idempotency_key_sha256": _h("idem2")},
            {"channel": "beta"},
            {"trust_generation": 4},
            {"prior_control_plane_projection_sha256": _h("prior2")},
        )
        for overrides in variants:
            with self.subTest(overrides=overrides):
                result = journal.plan_activation_intent(_intent(**overrides))
                self.assertEqual(result["status"], "planned")
                self.assertNotEqual(result["transaction_id"], base)

    def test_refreshable_observations_do_not_change_transaction(self) -> None:
        intent = _intent()
        transaction_id = journal.plan_activation_intent(intent)[
            "transaction_id"
        ]
        first = _gate_observations(
            "prepared", "quiesce-intent", intent=intent
        )
        second = _gate_observations(
            "prepared", "quiesce-intent", intent=intent
        )
        second["host-authority"]["observed_at"] = 1700000200
        second["host-authority"]["evidence_sha256"] = _h("fresh-host")
        first_result = journal.validate_transition(
            "prepared",
            "quiesce-intent",
            activation_intent=intent,
            gate_observations_by_type=first,
        )
        second_result = journal.validate_transition(
            "prepared",
            "quiesce-intent",
            activation_intent=intent,
            gate_observations_by_type=second,
        )
        self.assertEqual(first_result["status"], "valid")
        self.assertEqual(second_result["status"], "valid")
        self.assertEqual(first_result["transaction_id"], transaction_id)
        self.assertEqual(second_result["transaction_id"], transaction_id)
        self.assertNotEqual(
            first_result["gate_observation_sha256_by_type"][
                "host-authority"
            ],
            second_result["gate_observation_sha256_by_type"][
                "host-authority"
            ],
        )
        self.assertIs(first_result["gate_observation_evidence_verified"], False)

    def test_tamper_every_field(self) -> None:
        hex63 = "0" * 63
        tampered = {
            "schema": "synapse-s2.tampered.v1",
            "activation_nonce": "AB" * 16,
            "idempotency_key_sha256": hex63,
            "activation_policy_receipt_sha256": _h("x").upper(),
            "root_key_id": "rsa-" + _h("root"),
            "trust_generation": True,
            "trust_bundle_sha256": hex63,
            "release_envelope_sha256": _h("x") + "0",
            "compatibility_ticket_sha256": hex63,
            "compatibility_result_sha256": "zz" * 32,
            "channel": "Stable",
            "version": "-bad",
            "release_sequence": 7.0,
            "source_sha": "0" * 39,
            "inventory_policy_id": "inventory-" + _h("inv"),
            "current_source_build_id": "build-" + _h("cur")[:24],
            "candidate_source_build_id": "source-" + _h("cand")[:23],
            "current_product_id": "product-" + hex63,
            "candidate_product_id": _h("candp"),
            "current_dependency_component_id": "component-" + hex63,
            "candidate_dependency_component_id": "component",
            "surfaces_digest": hex63,
            "installed_floor_preimage_sha256": "",
            "incumbent_installed_record_sha256": None,
            "layout_schema": "synapse-s2.installed-layout-contract.v2",
            "layout_mode": "active-versioned-v1",
            "layout_contract_id": "layout-" + _h("lc"),
            "layout_id": "layout-contract-" + _h("lid"),
            "stage_result_sha256": ["a"],
            "stage_journal_head_sha256": {"a": 1},
            "staged_product_id": "product-" + hex63,
            "staged_source_build_id": "source-" + "G" * 24,
            "environment_receipt_sha256": hex63,
            "host_evidence_schema": "synapse-s2.host-evidence.v1",
            "host_evidence_purpose": "operator",
            "host_id_sha256": hex63,
            "prior_control_plane_projection_sha256": hex63,
            "desired_control_plane_projection_sha256": hex63,
        }
        self.assertEqual(sorted(tampered), sorted(INTENT_KEYS))
        for key, bad in tampered.items():
            with self.subTest(key=key):
                result = journal.plan_activation_intent(_intent(**{key: bad}))
                self.assertEqual(result["status"], "unsupported")
                self.assertEqual(
                    result["reason"],
                    "unsupported:intent-field-invalid:" + key,
                )
                self.assertIsNone(result["transaction_id"])

    def test_planned_result_valid_to_valid_tampering_is_rejected(self) -> None:
        original = journal.plan_activation_intent(_intent())
        mutations = []

        changed_transaction = dict(original)
        changed_transaction["transaction_id"] = "transaction-" + _h("other")
        mutations.append(changed_transaction)

        changed_product = dict(original)
        changed_product["candidate_product_id"] = "product-" + _h("other")
        mutations.append(changed_product)

        changed_sequence = dict(original)
        changed_sequence["release_sequence"] = 999
        mutations.append(changed_sequence)

        changed_intent_hash = dict(original)
        changed_intent_hash["intent_sha256"] = _h("other-intent")
        mutations.append(changed_intent_hash)

        changed_nested = dict(original)
        changed_nested["intent"] = dict(original["intent"])
        changed_nested["intent"]["candidate_product_id"] = (
            "product-" + _h("other")
        )
        mutations.append(changed_nested)

        coordinated = dict(original)
        coordinated["intent"] = dict(original["intent"])
        coordinated["intent"]["release_sequence"] = 999
        coordinated["release_sequence"] = 999
        coordinated["intent_sha256"] = hashlib.sha256(
            b"SYNAPSE-S2\x00RELEASE-ACTIVATION-INTENT\x00v1\x00"
            + _canonical(coordinated["intent"]).encode("ascii")
        ).hexdigest()
        mutations.append(coordinated)

        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                self.assertEqual(journal.result_exit_code(mutated), 2)
                rendered = json.loads(journal.render_result(mutated))
                self.assertEqual(rendered["status"], "unsupported")
                self.assertEqual(
                    rendered["reason"],
                    "unsupported:result-not-renderable",
                )

    def test_shape_and_cross_binding(self) -> None:
        missing = _intent()
        del missing["activation_nonce"]
        extra = _intent()
        extra["transaction_id"] = "transaction-" + _h("mine")
        cases = {
            "not-a-dict": [("schema", "x")],
            "none": None,
            "subclass": _HookDict(_intent()),
            "missing": missing,
            "extra": extra,
            "dependency-mismatch": _intent(
                candidate_dependency_component_id="component-" + _h("other")
            ),
            "staged-product-mismatch": _intent(
                staged_product_id="product-" + _h("other")
            ),
            "staged-build-mismatch": _intent(
                staged_source_build_id="source-" + _h("other")[:24]
            ),
            "unknown-layout-contract": _intent(
                layout_contract_id="layout-contract-" + "f" * 64
            ),
            "nan-int": _intent(release_sequence=float("nan")),
        }
        for label, bad_intent in cases.items():
            with self.subTest(label=label):
                result = journal.plan_activation_intent(bad_intent)
                self.assertEqual(result["status"], "unsupported")
                self.assertIsNone(result["transaction_id"])
        for field in REFRESHABLE_GATE_EVIDENCE_FIELDS:
            with self.subTest(late_gate_field=field):
                result = journal.plan_activation_intent(
                    _intent(**{field: _h("late:" + field)})
                )
                self.assertEqual(result["status"], "unsupported")
                self.assertIsNone(result["transaction_id"])
        binding_cases = {
            "current_dependency_component_id": _intent(
                candidate_dependency_component_id=(
                    "component-" + _h("other-dependency")
                )
            ),
            "staged_product_id": _intent(
                staged_product_id="product-" + _h("other-product")
            ),
            "staged_source_build_id": _intent(
                staged_source_build_id=(
                    "source-" + _h("other-build")[:24]
                )
            ),
        }
        for left, bad_intent in binding_cases.items():
            with self.subTest(binding_mismatch=left):
                result = journal.plan_activation_intent(bad_intent)
                self.assertEqual(
                    result["reason"],
                    "unsupported:intent-binding-mismatch:" + left,
                )

    def test_hooks_never_execute_and_oversize_rejected(self) -> None:
        _HookStr.calls = []
        result = journal.plan_activation_intent(
            _intent(channel=_HookStr("stable"))
        )
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(_HookStr.calls, [])
        _HookStr.calls = []
        hostile_key = _intent()
        hostile_key[_HookStr("evil-key")] = "x"
        self.assertEqual(
            journal.plan_activation_intent(hostile_key)["status"],
            "unsupported",
        )
        self.assertEqual(_HookStr.calls, [])
        _HookStr.calls = []
        oversized = _intent()
        for index in range(500):
            oversized[_HookStr("extra-" + str(index))] = "x"
        self.assertEqual(
            journal.plan_activation_intent(oversized)["status"],
            "unsupported",
        )
        self.assertEqual(_HookStr.calls, [])
        _HookDict.calls = []
        journal.plan_activation_intent(_HookDict(_intent()))
        self.assertEqual(_HookDict.calls, [])
        huge = journal.plan_activation_intent(_intent(channel="a" * 1000000))
        self.assertEqual(huge["status"], "unsupported")


class ResultShapeTests(unittest.TestCase):
    def _results(self) -> dict:
        return {
            "planned": journal.plan_activation_intent(_intent()),
            "valid": _validate("start", "prepared"),
            "denied": journal.validate_transition(
                "committed", "prepared", activation_intent=_intent()
            ),
            "unsupported-intent": journal.plan_activation_intent(None),
            "unsupported-state": journal.validate_transition(
                "x", "y", activation_intent=_intent()
            ),
        }

    def test_flags_nonclaims_and_closure_under_every_status(self) -> None:
        for label, result in self._results().items():
            with self.subTest(label=label):
                self.assertEqual(set(result), set(RESULT_KEYS))
                for flag in FALSE_FLAGS:
                    self.assertIs(result[flag], False)
                self.assertEqual(result["nonclaims"], list(NONCLAIMS))
                self.assertEqual(
                    result["activation_contract_id"],
                    EXPECTED_ACTIVATION_CONTRACT_ID,
                )
                self.assertEqual(result["pivot_state"], PIVOT)
                for value in result.values():
                    self.assertIn(
                        type(value), (str, int, bool, list, dict, type(None))
                    )
        unsupported = journal.plan_activation_intent(None)
        for field in ("transaction_id", "channel", "candidate_product_id"):
            self.assertIsNone(unsupported[field])

    def test_every_result_field_is_closed_before_render_or_exit(self) -> None:
        result = journal.plan_activation_intent(_intent())
        self.assertEqual(journal.result_exit_code(result), 0)
        for key in sorted(result):
            with self.subTest(key=key):
                mutated = dict(result)
                value = mutated[key]
                if type(value) is bool:
                    mutated[key] = not value
                elif type(value) is int:
                    mutated[key] = None
                elif type(value) is str:
                    mutated[key] = None
                elif type(value) is list:
                    mutated[key] = value[:-1]
                elif type(value) is dict:
                    mutated[key] = dict(value)
                    mutated[key].pop(next(iter(mutated[key])))
                elif value is None:
                    mutated[key] = "unexpected"
                else:
                    self.fail("unhandled result value type")
                self.assertEqual(journal.result_exit_code(mutated), 2)
                rendered = json.loads(journal.render_result(mutated))
                self.assertEqual(rendered["status"], "unsupported")
                self.assertEqual(
                    rendered["reason"],
                    "unsupported:result-not-renderable",
                )

    def test_denied_result_semantic_tampering_is_rejected(self) -> None:
        document = _gate_observation(
            "host-authority", "prepared", "quiesce-intent"
        )
        original = journal.validate_transition(
            "prepared",
            "quiesce-intent",
            activation_intent=_intent(),
            gate_observations_by_type={"host-authority": document},
        )
        self.assertEqual(original["status"], "denied")
        self.assertEqual(journal.result_exit_code(original), 3)
        mutations = []

        changed_reason = dict(original)
        changed_reason["reason"] = (
            "denied:gate-observation-required:host-authority"
        )
        mutations.append(changed_reason)

        changed_transaction = dict(original)
        changed_transaction["transaction_id"] = (
            "transaction-" + _h("other")
        )
        mutations.append(changed_transaction)

        changed_intent = dict(original)
        changed_intent["intent"] = dict(original["intent"])
        changed_intent["intent"]["release_sequence"] = 999
        mutations.append(changed_intent)

        changed_document = dict(original)
        changed_document["gate_observations_by_type"] = {
            "host-authority": dict(document)
        }
        changed_document["gate_observations_by_type"]["host-authority"][
            "evidence_sha256"
        ] = _h("other-evidence")
        mutations.append(changed_document)

        changed_digest = dict(original)
        changed_digest["gate_observation_sha256_by_type"] = {
            "host-authority": "f" * 64
        }
        mutations.append(changed_digest)

        dropped_partial = dict(original)
        dropped_partial["gate_observations_by_type"] = {}
        dropped_partial["gate_observation_sha256_by_type"] = {}
        mutations.append(dropped_partial)

        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                self.assertEqual(journal.result_exit_code(mutated), 2)
                self.assertEqual(
                    json.loads(journal.render_result(mutated))["reason"],
                    "unsupported:result-not-renderable",
                )

        for current, upcoming in (
            ("prepared", "committed"),
            ("committed", "prepared"),
        ):
            with self.subTest(current=current, upcoming=upcoming):
                denied = journal.validate_transition(
                    current, upcoming, activation_intent=_intent()
                )
                self.assertEqual(denied["intent"], _intent())
                self.assertIsNotNone(denied["transaction_id"])
                self.assertEqual(denied["gate_observations_by_type"], {})
                self.assertEqual(
                    denied["gate_observation_sha256_by_type"], {}
                )
                self.assertEqual(journal.result_exit_code(denied), 3)

    def test_valid_transition_result_semantic_tampering_is_rejected(self) -> None:
        original = _validate("prepared", "quiesce-intent")
        mutations = []

        changed_digest = dict(original)
        changed_digest["gate_observation_sha256_by_type"] = dict(
            original["gate_observation_sha256_by_type"]
        )
        changed_digest["gate_observation_sha256_by_type"][
            "host-authority"
        ] = "f" * 64
        mutations.append(changed_digest)

        changed_document = dict(original)
        changed_document["gate_observations_by_type"] = {
            key: dict(value)
            for key, value in original["gate_observations_by_type"].items()
        }
        changed_document["gate_observations_by_type"]["host-authority"][
            "evidence_sha256"
        ] = _h("changed")
        mutations.append(changed_document)

        changed_transaction = dict(original)
        changed_transaction["transaction_id"] = "transaction-" + _h("other")
        mutations.append(changed_transaction)

        changed_edge = dict(original)
        changed_edge["next_state"] = "aborted-pre-pivot"
        mutations.append(changed_edge)

        changed_reason = dict(original)
        changed_reason["reason"] = (
            "valid:rollback-intent-admitted-after-"
            "no-durable-claim-evidence"
        )
        mutations.append(changed_reason)

        changed_intent = dict(original)
        changed_intent["intent"] = dict(original["intent"])
        changed_intent["intent"]["release_sequence"] = 999
        mutations.append(changed_intent)

        changed_disposition = dict(original)
        changed_disposition["rollback_disposition"] = (
            "manual-pivot-reconciliation-required"
        )
        mutations.append(changed_disposition)

        changed_history = dict(original)
        changed_history["post_pivot_forward_only"] = True
        mutations.append(changed_history)

        missing_observation = dict(original)
        missing_observation["gate_observations_by_type"] = dict(
            original["gate_observations_by_type"]
        )
        del missing_observation["gate_observations_by_type"][
            "recovery-readiness"
        ]
        mutations.append(missing_observation)

        irrelevant_observation = dict(original)
        irrelevant_observation["gate_observations_by_type"] = {
            key: dict(value)
            for key, value in original["gate_observations_by_type"].items()
        }
        extra_document = _gate_observation(
            "candidate-health", "prepared", "quiesce-intent"
        )
        irrelevant_observation["gate_observations_by_type"][
            "candidate-health"
        ] = extra_document
        irrelevant_observation["gate_observation_sha256_by_type"] = dict(
            original["gate_observation_sha256_by_type"]
        )
        irrelevant_observation["gate_observation_sha256_by_type"][
            "candidate-health"
        ] = journal._gate_observation_sha256(extra_document)
        mutations.append(irrelevant_observation)

        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                self.assertEqual(journal.result_exit_code(mutated), 2)
                rendered = json.loads(journal.render_result(mutated))
                self.assertEqual(rendered["status"], "unsupported")
                self.assertEqual(
                    rendered["reason"],
                    "unsupported:result-not-renderable",
                )

    def test_observed_state_entry_is_shape_bound_but_not_history_verified(
        self,
    ) -> None:
        original = _validate("activating", "candidate-healthy")
        observations = _gate_observations(
            "activating", "candidate-healthy"
        )
        observations["candidate-health"][
            "observed_state_entry_sha256"
        ] = _h("different-valid-journal-tip")
        refreshed = journal.validate_transition(
            "activating",
            "candidate-healthy",
            activation_intent=_intent(),
            gate_observations_by_type=observations,
        )
        self.assertEqual(refreshed["status"], "valid")
        self.assertNotEqual(
            refreshed["gate_observation_sha256_by_type"],
            original["gate_observation_sha256_by_type"],
        )
        self.assertIs(
            refreshed["gate_observation_evidence_verified"], False
        )
        self.assertEqual(journal.result_exit_code(refreshed), 0)
        self.assertEqual(json.loads(journal.render_result(refreshed)), refreshed)


class RenderAndExitTests(unittest.TestCase):
    def test_render_canonical_bounded(self) -> None:
        result = journal.plan_activation_intent(_intent())
        rendered = journal.render_result(result)
        self.assertNotIn("\n", rendered)
        self.assertLessEqual(
            len(rendered.encode("ascii")), journal.MAX_RESULT_BYTES
        )
        self.assertEqual(json.loads(rendered), result)
        self.assertEqual(rendered, _canonical(result))
        projection = journal.activation_contract_projection()
        projected = journal.render_result(projection)
        self.assertEqual(json.loads(projected), projection)
        self.assertLessEqual(len(projected.encode("ascii")), 32768)

    def test_render_redacts_hostile_inputs(self) -> None:
        for hostile in (None, [], object(), {"a": object()}, {"a": 1.5e400}):
            with self.subTest(hostile=str(type(hostile))):
                rendered = journal.render_result(hostile)
                parsed = json.loads(rendered)
                self.assertEqual(parsed["status"], "unsupported")
                self.assertEqual(
                    parsed["reason"], "unsupported:result-not-renderable"
                )
        oversized = journal.render_result(
            {"status": "planned", "blob": "a" * 20000}
        )
        self.assertEqual(
            json.loads(oversized)["reason"],
            "unsupported:result-not-renderable",
        )
        nan = journal.render_result({"x": float("nan")})
        self.assertEqual(
            json.loads(nan)["reason"], "unsupported:result-not-renderable"
        )

    def test_render_and_exit_reject_spoofing_without_hooks(self) -> None:
        hostile = {
            "status": "planned",
            "path": "/private/recovery.db",
            "secret": "token-value",
        }
        rendered = journal.render_result(hostile)
        self.assertNotIn("/private/recovery.db", rendered)
        self.assertNotIn("token-value", rendered)
        self.assertEqual(journal.result_exit_code(hostile), 2)
        self.assertEqual(journal.result_exit_code({"status": "planned"}), 2)

        forged_refusal = journal.plan_activation_intent(None)
        forged_refusal["reason"] = "unsupported:token-value"
        refused = journal.render_result(forged_refusal)
        self.assertNotIn("token-value", refused)
        self.assertEqual(journal.result_exit_code(forged_refusal), 2)

        _HookList.calls = []
        nested_list = {"x": _HookList(["secret"])}
        self.assertNotIn('"x"', journal.render_result(nested_list))
        self.assertEqual(_HookList.calls, [])

        _HookDict.calls = []
        nested_dict = {"x": _HookDict({"secret": "value"})}
        self.assertNotIn('"x"', journal.render_result(nested_dict))
        self.assertNotIn('"secret":"value"', journal.render_result(nested_dict))
        self.assertEqual(_HookDict.calls, [])

    def test_unsupported_reasons_are_command_scoped(self) -> None:
        templates = {
            "plan-activation-intent": journal.plan_activation_intent(None),
            "validate-transition": journal.validate_transition(
                "invalid", "prepared", activation_intent=_intent()
            ),
            "render-result": json.loads(journal.render_result(None)),
        }
        dynamic_reasons = tuple(
            "unsupported:intent-field-invalid:" + key
            for key in INTENT_KEYS
        ) + tuple(
            "unsupported:intent-binding-mismatch:" + key
            for key in EXPECTED_INTENT_EQUALITY_LEFTS
        )
        expected_by_command = {
            command: set(fixed)
            | (
                set(dynamic_reasons)
                if command in (
                    "plan-activation-intent",
                    "validate-transition",
                )
                else set()
            )
            for command, fixed in (
                EXPECTED_UNSUPPORTED_FIXED_BY_COMMAND.items()
            )
        }
        all_reasons = set(dynamic_reasons)
        for reasons in EXPECTED_UNSUPPORTED_FIXED_BY_COMMAND.values():
            all_reasons.update(reasons)
        all_reasons.update(
            {
                "unsupported:intent-field-invalid:not-a-key",
                "unsupported:intent-binding-mismatch:candidate_product_id",
            }
        )

        for command, template in templates.items():
            for reason in sorted(all_reasons):
                with self.subTest(command=command, reason=reason):
                    forged = dict(template)
                    forged["reason"] = reason
                    rendered = json.loads(journal.render_result(forged))
                    if reason in expected_by_command[command]:
                        self.assertEqual(rendered, forged)
                    else:
                        self.assertEqual(
                            rendered["command"], "render-result"
                        )
                        self.assertEqual(
                            rendered["reason"],
                            "unsupported:result-not-renderable",
                        )
                    self.assertEqual(journal.result_exit_code(forged), 2)

    def test_internal_errors_are_command_local_and_redacted(self) -> None:
        def fail(*_args, **_kwargs):
            raise RuntimeError("/private/secret token-value")

        original_plan = journal._plan
        journal._plan = fail
        try:
            plan_result = journal.plan_activation_intent(_intent())
        finally:
            journal._plan = original_plan

        original_validate = journal._validate_transition
        journal._validate_transition = fail
        try:
            validate_result = journal.validate_transition(
                "start", "prepared", activation_intent=_intent()
            )
        finally:
            journal._validate_transition = original_validate

        for result, command in (
            (plan_result, "plan-activation-intent"),
            (validate_result, "validate-transition"),
        ):
            with self.subTest(command=command):
                self.assertEqual(result["command"], command)
                self.assertEqual(
                    result["reason"], "unsupported:internal-error"
                )
                rendered = journal.render_result(result)
                self.assertNotIn("/private/secret", rendered)
                self.assertNotIn("token-value", rendered)
                self.assertEqual(json.loads(rendered), result)
                self.assertEqual(journal.result_exit_code(result), 2)

    def test_exit_codes_total(self) -> None:
        self.assertEqual(
            journal.result_exit_code(
                journal.plan_activation_intent(_intent())
            ),
            0,
        )
        self.assertEqual(
            journal.result_exit_code(
                journal.activation_contract_projection()
            ),
            0,
        )
        self.assertEqual(
            journal.result_exit_code(
                journal.validate_transition(
                    "committed", "prepared", activation_intent=_intent()
                )
            ),
            3,
        )
        self.assertEqual(
            journal.result_exit_code(journal.plan_activation_intent(None)), 2
        )
        for garbage in (None, [], {}, object(), {"status": 7}, {"status": "x"}):
            self.assertEqual(journal.result_exit_code(garbage), 2)


class JournalContractAndResultTests(unittest.TestCase):
    def test_frozen_source_contract_projection_and_platform_policy(self) -> None:
        self.assertEqual(
            hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest(),
            EXPECTED_JOURNAL_SOURCE_SHA256,
        )
        projection = journal.journal_contract_projection()
        self.assertEqual(
            projection["journal_contract_id"], EXPECTED_JOURNAL_CONTRACT_ID
        )
        payload = {
            key: value
            for key, value in projection.items()
            if key not in ("status", "reason", "journal_contract_id")
        }
        digest = hashlib.sha256(
            b"SYNAPSE-S2\x00RELEASE-ACTIVATION-JOURNAL-CONTRACT\x00v1\x00"
            + _canonical(payload).encode("ascii")
        ).hexdigest()
        self.assertEqual(
            projection["journal_contract_id"],
            "activation-journal-contract-" + digest,
        )
        rendered = journal.render_journal_result(projection)
        self.assertEqual(json.loads(rendered), projection)
        self.assertEqual(journal.journal_result_exit_code(projection), 0)
        self.assertLessEqual(
            len(_canonical(projection)), journal.MAX_JOURNAL_PROJECTION_BYTES
        )
        self.assertGreaterEqual(
            journal.MAX_RESULT_BYTES - len(_canonical(projection)), 8192
        )

        storage = projection["storage"]
        self.assertEqual(storage["root_mode"], "0700")
        self.assertEqual(storage["subdirectory_mode"], "0700")
        self.assertEqual(storage["lock_mode"], "0600")
        self.assertEqual(storage["document_mode"], "0600")
        self.assertIs(storage["effective_uid_and_exact_posix_mode_only"], True)
        self.assertIs(storage["extended_acl_or_xattr_verified"], False)
        self.assertEqual(
            storage["required_platform_flags"],
            list(journal._JOURNAL_REQUIRED_OS_FLAGS),
        )
        self.assertEqual(
            storage["required_fcntl_capabilities"],
            list(journal._JOURNAL_REQUIRED_FCNTL_CAPABILITIES),
        )
        self.assertEqual(
            storage["required_os_callables"],
            list(journal._JOURNAL_REQUIRED_OS_CALLABLES),
        )
        self.assertIs(storage["root_bounds_checked_before_io"], True)
        self.assertEqual(storage["root_path_encoding"], "utf-8-strict")
        self.assertIs(storage["fd_scandir_required"], True)
        self.assertNotIn("fd_listdir_required", storage)
        self.assertIn("scandir", storage["required_os_callables"])
        self.assertNotIn("listdir", storage["required_os_callables"])
        self.assertEqual(
            projection["limits"],
            {
                "document_bytes": 32768,
                "entries": 256,
                "directory_names": 258,
                "scan_bytes": 8 * 1024 * 1024,
                "root_path_bytes": 4096,
                "root_components": 64,
                "rendered_result_bytes": 32768,
                "rendered_projection_bytes": 24576,
            },
        )
        self.assertIn(
            "close-or-unlock-failure-may-retain-fd-or-advisory-lock",
            projection["nonclaims"],
        )
        self.assertIn(
            "cleanup-failure-requires-caller-termination-or-manual-recovery",
            projection["nonclaims"],
        )
        self.assertIn(
            "no-extended-acl-or-xattr-verification",
            projection["nonclaims"],
        )
        self.assertIn(
            "extended_acl_verified",
            projection["result_policy"]["false_flags"],
        )
        self.assertNotIn(
            journal.COMMAND_JOURNAL_PROJECT,
            projection["result_policy"]["commands"],
        )
        self.assertNotIn(
            journal.JOURNAL_STATUS_PROJECTED,
            projection["result_policy"]["success_statuses"],
        )
        result_policy = projection["result_policy"]
        self.assertIs(
            result_policy["platform_precedes_intent_validation"], True
        )
        self.assertEqual(
            result_policy["failure_truth"]["render_fallback"],
            {
                "read_supported": True,
                "write_supported": True,
                "runtime_platform_support_required": True,
                "read": False,
                "write_attempted": False,
                "written": False,
            },
        )

    def test_platform_capability_precedence_and_render_fallback(self) -> None:
        variants = [
            (os, name, None)
            for name in journal._JOURNAL_REQUIRED_OS_FLAGS
        ]
        variants.extend(
            (os, name, None)
            for name in journal._JOURNAL_REQUIRED_OS_CALLABLES
        )
        variants.extend(
            (fcntl, name, None)
            for name in journal._JOURNAL_REQUIRED_FCNTL_CAPABILITIES
        )
        variants.extend(
            (
                (os, "supports_dir_fd", set()),
                (os, "supports_fd", set()),
            )
        )
        for index, (owner, name, replacement) in enumerate(variants):
            with self.subTest(owner=owner.__name__, capability=name):
                original = getattr(owner, name)
                setattr(owner, name, replacement)
                try:
                    module = _load(
                        f"journal_platform_missing_{index}", MODULE_PATH
                    )
                finally:
                    setattr(owner, name, original)
                self.assertIs(module._JOURNAL_PLATFORM_SUPPORTED, False)
                projection = module.journal_contract_projection()
                self.assertTrue(module._valid_journal_projection(projection))

                calls = []

                def tripwire(*args, **kwargs):
                    calls.append((args, kwargs))
                    raise AssertionError("operand validation or I/O attempted")

                module._validate_intent = tripwire
                module._JOURNAL_OPEN = tripwire
                module._JOURNAL_SCANDIR = tripwire
                module._JOURNAL_GETEUID = tripwire
                results = (
                    module.begin_activation_journal(
                        object(), activation_intent=object()
                    ),
                    module.append_activation_transition(
                        object(),
                        activation_intent=object(),
                        observed_state_entry_sha256=object(),
                        next_state=object(),
                        decision_at=object(),
                    ),
                    module.inspect_activation_journal(
                        object(), activation_intent=object()
                    ),
                )
                self.assertEqual(calls, [])
                for result in results:
                    self.assertEqual(
                        result["reason"],
                        "unsupported:journal-platform-unsupported",
                    )
                    self.assertTrue(
                        all(
                            result[key] is None
                            for key in (
                                "transaction_id",
                                "intent_sha256",
                                "request_sha256",
                                "entry_sha256",
                            )
                        )
                    )
                    self.assertIs(result["journal_read_supported"], False)
                    self.assertIs(result["journal_write_supported"], False)
                    self.assertIs(result["journal_read_performed"], False)
                    self.assertIs(result["journal_write_attempted"], False)
                    self.assertIs(result["journal_written"], False)
                    self.assertTrue(module._valid_journal_result(result))

                fallback = json.loads(
                    module.render_journal_result(object())
                )
                self.assertEqual(calls, [])
                self.assertEqual(
                    fallback["reason"],
                    "unsupported:journal-result-not-renderable",
                )
                self.assertIs(fallback["journal_read_supported"], False)
                self.assertIs(fallback["journal_write_supported"], False)
                self.assertTrue(module._valid_journal_result(fallback))
                self.assertEqual(module.journal_result_exit_code(fallback), 2)

    def test_4a_identity_and_fixture_transaction_are_unchanged(self) -> None:
        self.assertEqual(
            journal.activation_contract_projection()["activation_contract_id"],
            EXPECTED_ACTIVATION_CONTRACT_ID,
        )
        self.assertEqual(
            journal.plan_activation_intent(_intent())["transaction_id"],
            EXPECTED_TRANSACTION_ID,
        )

    def test_projected_reachable_entry_truth_is_exact(self) -> None:
        expected = {(0, "start", "prepared", False)}
        frontier = {(0, "prepared", False)}
        seen = set(frontier)
        while frontier:
            upcoming = set()
            for sequence, current, anchor in sorted(frontier):
                for next_state in EXPECTED_GRAPH[current]:
                    next_anchor = anchor or (
                        current == "prepared"
                        and next_state == "quiesce-intent"
                    )
                    row = (sequence + 1, current, next_state, next_anchor)
                    expected.add(row)
                    marker = (sequence + 1, next_state, next_anchor)
                    if marker not in seen:
                        seen.add(marker)
                        upcoming.add(marker)
            frontier = upcoming
        projected = {
            tuple(row)
            for row in journal.journal_contract_projection()["chain"][
                "reachable_entry_truth"
            ]
        }
        self.assertEqual(projected, expected)

    def test_reachable_success_history_anchor_and_prior_truth(self) -> None:
        transaction = "transaction-" + _h("journal-transaction")
        identity = _h("journal-intent")
        request = _h("journal-request")
        anchor = _h("journal-anchor")
        rows = journal._journal_reachable_entry_truth()
        for sequence, current, upcoming, anchor_present in rows:
            with self.subTest(sequence=sequence, edge=(current, upcoming)):
                fields = {
                    "transaction_id": transaction,
                    "intent_sha256": identity,
                    "request_sha256": request,
                    "entry_sha256": _h(
                        f"entry:{sequence}:{current}:{upcoming}"
                    ),
                    "prior_entry_sha256": (
                        None if sequence == 0 else _h(f"prior:{sequence}")
                    ),
                    "sequence": sequence,
                    "from_state": current,
                    "to_state": upcoming,
                    "tip_state": upcoming,
                    "protected_state_preimage_sha256": (
                        anchor if anchor_present else None
                    ),
                    "journal_read_performed": True,
                    "journal_write_attempted": True,
                    "journal_written": True,
                }
                command = journal.COMMAND_JOURNAL_BEGIN
                status = journal.JOURNAL_STATUS_INITIALIZED
                token = "journal-created"
                if sequence:
                    command = journal.COMMAND_JOURNAL_APPEND
                    status = journal.JOURNAL_STATUS_APPENDED
                    token = "transition-recorded"
                result = journal._journal_result(
                    command, status, token, **fields
                )
                self.assertTrue(journal._valid_journal_result(result))
                wrong_anchor = copy.deepcopy(result)
                wrong_anchor["protected_state_preimage_sha256"] = (
                    None if anchor_present else anchor
                )
                self.assertFalse(journal._valid_journal_result(wrong_anchor))
                if sequence:
                    self_prior = copy.deepcopy(result)
                    self_prior["prior_entry_sha256"] = result["entry_sha256"]
                    self.assertFalse(journal._valid_journal_result(self_prior))

        candidate = journal._journal_result(
            journal.COMMAND_JOURNAL_APPEND,
            journal.JOURNAL_STATUS_APPENDED,
            "transition-already-recorded",
            transaction_id=transaction,
            intent_sha256=identity,
            request_sha256=request,
            entry_sha256=_h("history-entry"),
            prior_entry_sha256=_h("history-prior"),
            sequence=1,
            from_state="prepared",
            to_state="quiesce-intent",
            tip_state="quiesce-intent",
            protected_state_preimage_sha256=anchor,
            journal_read_performed=True,
        )
        allowed = set(
            journal._journal_reachable_tip_states()["quiesce-intent"]
        )
        for state in EXPECTED_GRAPH:
            changed = copy.deepcopy(candidate)
            changed["tip_state"] = state
            self.assertEqual(
                journal._valid_journal_result(changed), state in allowed
            )

    def test_exact_reason_identity_cross_product_and_exit_truth(self) -> None:
        tip = {
            "transaction_id": "transaction-" + _h("matrix-transaction"),
            "intent_sha256": _h("matrix-intent"),
            "request_sha256": _h("matrix-request"),
            "entry_sha256": _h("matrix-entry"),
            "prior_entry_sha256": _h("matrix-prior"),
            "sequence": 1,
            "from_state": "prepared",
            "to_state": "quiesce-intent",
            "tip_state": "quiesce-intent",
            "protected_state_preimage_sha256": _h("matrix-anchor"),
        }
        populations = {
            "000": {},
            "100": {
                key: tip[key] for key in ("transaction_id", "intent_sha256")
            },
            "110": {
                key: tip[key]
                for key in (
                    "transaction_id",
                    "intent_sha256",
                    "request_sha256",
                )
            },
            "111": tip,
        }
        inhabited = set()
        for command, reasons in journal._JOURNAL_RESULT_REASONS.items():
            self.assertEqual(len(reasons), len(set(reasons)))
            for reason in reasons:
                if reason in journal._JOURNAL_SUCCESS_RESULT_TRUTH:
                    continue
                status, token = reason.split(":", 1)
                empty = journal._journal_result(command, status, token)
                truth_profile = journal._journal_failure_profile(empty)
                identity_profile = journal._journal_failure_identity_profile(
                    empty
                )
                self.assertIsNotNone(truth_profile, (command, reason))
                self.assertIsNotNone(identity_profile, (command, reason))
                policy = journal._JOURNAL_FAILURE_RESULT_TRUTH[truth_profile]
                allowed = set(
                    journal._JOURNAL_FAILURE_IDENTITY_SHAPES[
                        identity_profile
                    ]
                )
                for shape, fields in populations.items():
                    candidate_fields = dict(fields)
                    candidate_fields.update(
                        journal_read_supported=policy.get(
                            "read_supported", True
                        ),
                        journal_write_supported=policy.get(
                            "write_supported", True
                        ),
                        journal_read_performed=(
                            False
                            if policy.get("read") == "false-or-true"
                            else policy.get("read", True)
                        ),
                        journal_write_attempted=policy["write_attempted"],
                        journal_written=policy["written"],
                    )
                    candidate = journal._journal_result(
                        command, status, token, **candidate_fields
                    )
                    valid = journal._valid_journal_result(candidate)
                    self.assertEqual(
                        valid,
                        shape in allowed,
                        (command, reason, shape, identity_profile),
                    )
                    if valid:
                        inhabited.add((command, reason))
                        self.assertEqual(
                            json.loads(journal.render_journal_result(candidate)),
                            candidate,
                        )
                        expected_exit = (
                            4
                            if status == "outcome_unknown"
                            else 3
                            if status in ("blocked", "denied", "conflict")
                            else 2
                        )
                        self.assertEqual(
                            journal.journal_result_exit_code(candidate),
                            expected_exit,
                        )
        fixed_failures = {
            (command, reason)
            for command, reasons in journal._JOURNAL_RESULT_REASONS.items()
            for reason in reasons
            if reason not in journal._JOURNAL_SUCCESS_RESULT_TRUTH
        }
        self.assertEqual(inhabited, fixed_failures)

        dynamic = journal._journal_result(
            journal.COMMAND_JOURNAL_APPEND,
            journal.JOURNAL_STATUS_UNSUPPORTED,
            "intent-field-invalid:schema",
        )
        self.assertTrue(journal._valid_journal_result(dynamic))
        outcome = journal._journal_result(
            journal.COMMAND_JOURNAL_APPEND,
            journal.JOURNAL_STATUS_OUTCOME_UNKNOWN,
            "journal-write-outcome-unknown",
            **tip,
            journal_read_performed=True,
            journal_write_attempted=True,
            journal_written=None,
        )
        self.assertTrue(journal._valid_journal_result(outcome))
        bad_tip = copy.deepcopy(outcome)
        bad_tip["tip_state"] = "prepared"
        self.assertFalse(journal._valid_journal_result(bad_tip))
        self.assertEqual(journal.journal_result_exit_code(bad_tip), 2)


class JournalLifecycleTests(unittest.TestCase):
    def _begin(self, root: str, intent: dict | None = None) -> tuple[dict, dict]:
        stable_intent = _intent() if intent is None else intent
        result = journal.begin_activation_journal(
            root, activation_intent=stable_intent
        )
        self.assertEqual(result["reason"], "initialized:journal-created")
        self.assertTrue(journal._valid_journal_result(result))
        return stable_intent, result

    def test_begin_genesis_inspect_retry_conflict_and_redaction(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent, created = self._begin(root)
            self.assertEqual(created["sequence"], 0)
            self.assertEqual(created["from_state"], "start")
            self.assertEqual(created["to_state"], "prepared")
            self.assertEqual(created["tip_state"], "prepared")
            self.assertIsNone(created["prior_entry_sha256"])
            self.assertIsNone(created["protected_state_preimage_sha256"])
            self.assertIs(created["journal_write_attempted"], True)
            self.assertIs(created["journal_written"], True)

            inspected = journal.inspect_activation_journal(
                root, activation_intent=intent
            )
            retried = journal.begin_activation_journal(
                root, activation_intent=intent
            )
            self.assertEqual(inspected["reason"], "inspected:journal-consistent")
            self.assertEqual(
                retried["reason"], "initialized:journal-already-initialized"
            )
            self.assertEqual(_journal_tip_fields(inspected), _journal_tip_fields(created))
            self.assertIs(retried["journal_write_attempted"], False)
            self.assertIs(retried["journal_written"], False)

            other = _intent(activation_nonce="cd" * 16)
            conflict = journal.inspect_activation_journal(
                root, activation_intent=other
            )
            self.assertEqual(
                conflict["reason"], "conflict:activation-request-mismatch"
            )
            self.assertIsNone(conflict["request_sha256"])
            self.assertTrue(journal._valid_journal_result(conflict))

            for result in (created, inspected, retried, conflict):
                rendered = journal.render_journal_result(result)
                self.assertNotIn(root, rendered)
                self.assertNotIn("activation_intent", rendered)
                self.assertNotIn("gate_observations_by_type", rendered)
                self.assertTrue(all(result[flag] is False for flag in journal._JOURNAL_FALSE_FLAGS))

    def test_plan_result_and_invalid_intent_refuse_before_io(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            plan = journal.plan_activation_intent(_intent())
            calls = []
            original_open = journal._JOURNAL_OPEN

            def tripwire(*args, **kwargs):
                calls.append((args, kwargs))
                raise AssertionError("operand I/O attempted")

            journal._JOURNAL_OPEN = tripwire
            try:
                results = (
                    journal.begin_activation_journal(
                        root, activation_intent=plan
                    ),
                    journal.append_activation_transition(
                        root,
                        activation_intent=plan,
                        observed_state_entry_sha256="0" * 64,
                        next_state="aborted-pre-pivot",
                        decision_at=1,
                    ),
                    journal.inspect_activation_journal(
                        root, activation_intent=plan
                    ),
                )
            finally:
                journal._JOURNAL_OPEN = original_open
            self.assertEqual(calls, [])
            for result in results:
                self.assertTrue(result["reason"].startswith("unsupported:intent-"))
                self.assertIs(result["journal_read_performed"], False)
                self.assertIs(result["journal_write_attempted"], False)
                self.assertTrue(journal._valid_journal_result(result))
            self.assertFalse(_journal_directory(root).exists())

    def test_canonical_request_genesis_modes_links_and_hashes(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent, created = self._begin(root)
            request_path, entry_paths = _journal_request_and_entries(root)
            self.assertEqual(len(entry_paths), 1)
            paths = [
                _journal_directory(root) / journal.JOURNAL_LOCK_FILENAME,
                request_path,
                entry_paths[0],
            ]
            self.assertEqual(
                stat.S_IMODE(os.stat(_journal_directory(root)).st_mode), 0o700
            )
            for path in paths:
                metadata = os.stat(path)
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_uid, os.geteuid())
                self.assertEqual(metadata.st_nlink, 1)
            for path in (request_path, entry_paths[0]):
                raw = path.read_bytes()
                self.assertTrue(raw.endswith(b"\n"))
                self.assertFalse(raw.endswith(b"\n\n"))
                document = json.loads(raw[:-1].decode("ascii"))
                self.assertEqual(raw, (_canonical(document) + "\n").encode("ascii"))
                digest = path.name.split("-", 1)[1][:-5]
                hash_field = (
                    "request_sha256"
                    if path is request_path
                    else "entry_sha256"
                )
                domain = (
                    journal._JOURNAL_REQUEST_HASH_DOMAIN
                    if path is request_path
                    else journal._JOURNAL_ENTRY_HASH_DOMAIN
                )
                self.assertEqual(document[hash_field], digest)
                self.assertEqual(
                    journal._journal_self_hash(domain, document, hash_field),
                    digest,
                )
            request = json.loads(request_path.read_text(encoding="ascii"))
            root_stat = os.stat(root)
            self.assertEqual(request["journal_root_device"], root_stat.st_dev)
            self.assertEqual(request["journal_root_inode"], root_stat.st_ino)
            self.assertEqual(request["activation_intent"], intent)
            self.assertEqual(request["request_sha256"], created["request_sha256"])

    def test_append_immediate_and_progressed_history_retry(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent, genesis = self._begin(root)
            observations = _journal_observations(
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
            )
            first = _journal_append(
                root,
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
                observations=observations,
            )
            self.assertEqual(first["reason"], "appended:transition-recorded")
            self.assertEqual(
                first["protected_state_preimage_sha256"],
                _h("journal-protected-state"),
            )
            immediate = _journal_append(
                root,
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
                observations=observations,
                now_values=(),
            )
            self.assertEqual(
                immediate["reason"], "appended:transition-already-recorded"
            )
            self.assertEqual(immediate["tip_state"], "quiesce-intent")

            second_decision = JOURNAL_DECISION + 100
            second = _journal_append(
                root,
                first,
                "quiescent-observed",
                second_decision,
                intent=intent,
            )
            self.assertEqual(second["reason"], "appended:transition-recorded")
            progressed = _journal_append(
                root,
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
                observations=observations,
                now_values=(),
            )
            self.assertEqual(
                progressed["reason"], "appended:transition-already-recorded"
            )
            self.assertEqual(progressed["to_state"], "quiesce-intent")
            self.assertEqual(progressed["tip_state"], "quiescent-observed")
            self.assertTrue(journal._valid_journal_result(progressed))

    def test_stale_tip_observation_and_protected_lineage_denials(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent, genesis = self._begin(root)
            first = _journal_append(
                root,
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
            )
            stale = _journal_append(
                root,
                genesis,
                "aborted-pre-pivot",
                JOURNAL_DECISION + 1,
                intent=intent,
                observations={},
                now_values=(),
            )
            self.assertEqual(stale["reason"], "conflict:journal-tip-mismatch")
            self.assertEqual(stale["entry_sha256"], first["entry_sha256"])

            decision = JOURNAL_DECISION + 100
            wrong_tip = _journal_observations(
                first, "quiescent-observed", decision, intent=intent
            )
            wrong_tip["quiescence"]["observed_state_entry_sha256"] = _h(
                "wrong-tip"
            )
            denied = _journal_append(
                root,
                first,
                "quiescent-observed",
                decision,
                intent=intent,
                observations=wrong_tip,
                now_values=(),
            )
            self.assertEqual(denied["reason"], "denied:observation-tip-mismatch")
            self.assertEqual(denied["entry_sha256"], first["entry_sha256"])

            wrong_anchor = _journal_observations(
                first,
                "quiescent-observed",
                decision,
                intent=intent,
                protected_sha256=_h("wrong-anchor"),
            )
            denied = _journal_append(
                root,
                first,
                "quiescent-observed",
                decision,
                intent=intent,
                observations=wrong_anchor,
                now_values=(),
            )
            self.assertEqual(
                denied["reason"],
                "denied:protected-state-preimage-mismatch",
            )
            self.assertTrue(journal._valid_journal_result(denied))

        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent, genesis = self._begin(root)
            aborted = _journal_append(
                root,
                genesis,
                "aborted-pre-pivot",
                JOURNAL_DECISION,
                intent=intent,
                observations={},
            )
            self.assertEqual(aborted["reason"], "appended:transition-recorded")
            self.assertIsNone(aborted["protected_state_preimage_sha256"])

    def test_two_sample_clock_chronology_and_expiry(self) -> None:
        cases = (
            ("mismatch", (JOURNAL_DECISION + 1,), "denied:decision-clock-mismatch"),
            (
                "regression",
                (JOURNAL_DECISION, JOURNAL_DECISION - 1),
                "denied:decision-clock-regressed",
            ),
        )
        for label, samples, reason in cases:
            with self.subTest(label=label), _journal_root() as root:
                os.chmod(root, 0o700)
                intent, genesis = self._begin(root)
                result = _journal_append(
                    root,
                    genesis,
                    "aborted-pre-pivot",
                    JOURNAL_DECISION,
                    intent=intent,
                    observations={},
                    now_values=samples,
                )
                self.assertEqual(result["reason"], reason)
                self.assertIs(result["journal_write_attempted"], False)
                self.assertTrue(journal._valid_journal_result(result))

        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent, genesis = self._begin(root)
            observations = _journal_observations(
                genesis, "quiesce-intent", JOURNAL_DECISION, intent=intent
            )
            observations["host-authority"]["expires_at"] = JOURNAL_DECISION + 1
            observations["host-authority"][
                "minimum_authority_expires_at"
            ] = JOURNAL_DECISION + 1
            expired = _journal_append(
                root,
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
                observations=observations,
                now_values=(JOURNAL_DECISION, JOURNAL_DECISION + 1),
            )
            self.assertEqual(
                expired["reason"], "denied:host-authority-expired-at-decision"
            )

            observations = _journal_observations(
                genesis, "quiesce-intent", JOURNAL_DECISION, intent=intent
            )
            for document in observations.values():
                document["observed_at"] = JOURNAL_DECISION + 1
            chronology = _journal_append(
                root,
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
                observations=observations,
                now_values=(),
            )
            self.assertEqual(
                chronology["reason"], "denied:observation-time-invalid"
            )

    def test_internal_clock_failure_carries_complete_tip(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent, genesis = self._begin(root)
            first = _journal_append(
                root,
                genesis,
                "quiesce-intent",
                JOURNAL_DECISION,
                intent=intent,
            )
            original_now = journal._JOURNAL_NOW

            def boom():
                raise RuntimeError("clock unavailable")

            journal._JOURNAL_NOW = boom
            try:
                result = journal.append_activation_transition(
                    root,
                    activation_intent=intent,
                    observed_state_entry_sha256=first["entry_sha256"],
                    next_state="manual-recovery-required",
                    decision_at=JOURNAL_DECISION + 1,
                    gate_observations_by_type={},
                )
            finally:
                journal._JOURNAL_NOW = original_now
            self.assertEqual(result["reason"], "unsupported:internal-error")
            self.assertEqual(_journal_tip_fields(result), _journal_tip_fields(first))
            self.assertTrue(journal._valid_journal_result(result))
            self.assertEqual(json.loads(journal.render_journal_result(result)), result)
            self.assertEqual(journal.journal_result_exit_code(result), 2)

    def test_request_only_recovery_and_uninitialized_refusals(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent = _intent()
            handles = journal._journal_acquire(root, create=True)
            try:
                request = journal._journal_request_document(
                    journal._validate_intent(intent), handles.root_stat
                )
                journal._journal_publish_document(
                    handles.directory_fd,
                    journal.JOURNAL_REQUEST_PREFIX
                    + request["request_sha256"]
                    + journal.JOURNAL_DOCUMENT_SUFFIX,
                    request,
                )
            finally:
                journal._journal_release(handles)
            inspected = journal.inspect_activation_journal(
                root, activation_intent=intent
            )
            appended = journal.append_activation_transition(
                root,
                activation_intent=intent,
                observed_state_entry_sha256="0" * 64,
                next_state="aborted-pre-pivot",
                decision_at=1,
            )
            for result in (inspected, appended):
                self.assertEqual(result["reason"], "blocked:journal-request-only")
                self.assertIsNotNone(result["request_sha256"])
                self.assertIsNone(result["entry_sha256"])
                self.assertTrue(journal._valid_journal_result(result))
            resumed = journal.begin_activation_journal(
                root, activation_intent=intent
            )
            self.assertEqual(resumed["reason"], "initialized:journal-created")

        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent = _intent()
            for result in (
                journal.inspect_activation_journal(root, activation_intent=intent),
                journal.append_activation_transition(
                    root,
                    activation_intent=intent,
                    observed_state_entry_sha256="0" * 64,
                    next_state="aborted-pre-pivot",
                    decision_at=1,
                ),
            ):
                self.assertEqual(result["reason"], "blocked:journal-uninitialized")
                self.assertTrue(journal._valid_journal_result(result))


class JournalFilesystemAdversarialTests(unittest.TestCase):
    def _inspect_invalid(self, root: str, intent: dict) -> dict:
        result = journal.inspect_activation_journal(
            root, activation_intent=intent
        )
        self.assertEqual(result["reason"], "blocked:journal-integrity-invalid")
        self.assertTrue(journal._valid_journal_result(result))
        return result

    def _publish(self, root: str, filename: str, document: dict) -> None:
        handles = journal._journal_acquire(root, create=False)
        try:
            journal._journal_publish_document(
                handles.directory_fd, filename, document
            )
        finally:
            journal._journal_release(handles)

    def test_root_path_and_mode_refusals_are_prewrite(self) -> None:
        with _journal_root() as parent:
            os.chmod(parent, 0o700)
            real = Path(parent) / "real"
            real.mkdir(mode=0o700)
            link = Path(parent) / "link"
            link.symlink_to(real, target_is_directory=True)
            cases = (
                "relative-root",
                "/",
                str(real) + "/",
                str(real) + "/.",
                str(link),
            )
            for candidate in cases:
                with self.subTest(root=candidate):
                    result = journal.begin_activation_journal(
                        candidate, activation_intent=_intent()
                    )
                    self.assertEqual(
                        result["reason"], "blocked:journal-root-invalid"
                    )
                    self.assertIs(result["journal_read_performed"], False)
                    self.assertIs(result["journal_write_attempted"], False)
                    self.assertIs(result["journal_written"], False)
            os.chmod(real, 0o755)
            result = journal.begin_activation_journal(
                str(real), activation_intent=_intent()
            )
            self.assertEqual(result["reason"], "blocked:journal-root-invalid")
            self.assertFalse(
                (real / journal.JOURNAL_SUBDIRECTORY).exists()
            )

    def test_root_bounds_refuse_before_open(self) -> None:
        cases = {
            "huge-character-count": "/" + "x" * 5_000_000,
            "utf8-byte-count": "/" + "\N{LATIN SMALL LETTER E WITH ACUTE}" * 2048,
            "component-count": "/" + "/".join("x" for _ in range(65)),
        }
        intent = _intent()
        calls = []
        real_open = journal._JOURNAL_OPEN

        def tripwire(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("root open attempted")

        journal._JOURNAL_OPEN = tripwire
        try:
            for label, candidate in cases.items():
                with self.subTest(case=label):
                    result = journal.begin_activation_journal(
                        candidate, activation_intent=intent
                    )
                    self.assertEqual(
                        result["reason"], "blocked:journal-root-invalid"
                    )
                    self.assertIs(result["journal_read_performed"], False)
                    self.assertIs(result["journal_write_attempted"], False)
                    self.assertIs(result["journal_written"], False)
                    self.assertTrue(journal._valid_journal_result(result))
        finally:
            journal._JOURNAL_OPEN = real_open
        self.assertEqual(calls, [])

    def test_subdirectory_symlink_fifo_file_and_mode_attacks(self) -> None:
        for attack in ("symlink", "fifo", "file", "mode"):
            with self.subTest(attack=attack), _journal_root() as root:
                os.chmod(root, 0o700)
                target = _journal_directory(root)
                if attack == "symlink":
                    safe = Path(root) / "elsewhere"
                    safe.mkdir(mode=0o700)
                    target.symlink_to(safe, target_is_directory=True)
                elif attack == "fifo":
                    os.mkfifo(target, 0o600)
                elif attack == "file":
                    descriptor = os.open(
                        target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                    )
                    os.close(descriptor)
                else:
                    target.mkdir(mode=0o700)
                    os.chmod(target, 0o777)
                result = journal.begin_activation_journal(
                    root, activation_intent=_intent()
                )
                self.assertEqual(
                    result["reason"], "blocked:journal-integrity-invalid"
                )
                self.assertIs(result["journal_write_attempted"], False)

    def test_lock_symlink_fifo_directory_hardlink_and_mode_attacks(self) -> None:
        for attack in ("symlink", "fifo", "directory", "hardlink", "mode"):
            with self.subTest(attack=attack), _journal_root() as root:
                os.chmod(root, 0o700)
                directory = _journal_directory(root)
                directory.mkdir(mode=0o700)
                lock = directory / journal.JOURNAL_LOCK_FILENAME
                if attack == "symlink":
                    target = Path(root) / "lock-target"
                    target.write_bytes(b"")
                    os.chmod(target, 0o600)
                    lock.symlink_to(target)
                elif attack == "fifo":
                    os.mkfifo(lock, 0o600)
                elif attack == "directory":
                    lock.mkdir(mode=0o700)
                elif attack == "hardlink":
                    target = Path(root) / "lock-target"
                    target.write_bytes(b"")
                    os.chmod(target, 0o600)
                    os.link(target, lock)
                else:
                    lock.write_bytes(b"")
                    os.chmod(lock, 0o644)
                result = journal.begin_activation_journal(
                    root, activation_intent=_intent()
                )
                self.assertEqual(
                    result["reason"], "blocked:journal-integrity-invalid"
                )
                self.assertFalse(result["journal_written"])

    def test_document_symlink_fifo_hardlink_and_mode_attacks(self) -> None:
        for attack in ("symlink", "fifo", "hardlink", "mode"):
            with self.subTest(attack=attack), _journal_root() as root:
                os.chmod(root, 0o700)
                intent = _intent()
                created = journal.begin_activation_journal(
                    root, activation_intent=intent
                )
                self.assertEqual(created["status"], "initialized")
                request, _entries = _journal_request_and_entries(root)
                if attack == "symlink":
                    target = Path(root) / "request-target"
                    target.write_bytes(request.read_bytes())
                    os.chmod(target, 0o600)
                    request.unlink()
                    request.symlink_to(target)
                elif attack == "fifo":
                    request.unlink()
                    os.mkfifo(request, 0o600)
                elif attack == "hardlink":
                    os.link(request, Path(root) / "request-peer")
                else:
                    os.chmod(request, 0o644)
                self._inspect_invalid(root, intent)

    def test_corrupt_hash_filename_and_canonical_documents(self) -> None:
        for attack in (
            "request-json",
            "request-canonical",
            "entry-self-hash",
            "entry-filename-hash",
            "unknown-file",
        ):
            with self.subTest(attack=attack), _journal_root() as root:
                os.chmod(root, 0o700)
                intent = _intent()
                created = journal.begin_activation_journal(
                    root, activation_intent=intent
                )
                request, entries = _journal_request_and_entries(root)
                entry = entries[0]
                if attack == "request-json":
                    descriptor = os.open(request, os.O_WRONLY | os.O_TRUNC)
                    try:
                        os.write(descriptor, b"{not-json}\n")
                    finally:
                        os.close(descriptor)
                elif attack == "request-canonical":
                    document = json.loads(request.read_text(encoding="ascii"))
                    descriptor = os.open(request, os.O_WRONLY | os.O_TRUNC)
                    try:
                        os.write(
                            descriptor,
                            (json.dumps(document, indent=2) + "\n").encode(
                                "ascii"
                            ),
                        )
                    finally:
                        os.close(descriptor)
                elif attack == "entry-self-hash":
                    document = json.loads(entry.read_text(encoding="ascii"))
                    document["decision_at"] = 1
                    _rewrite_journal_document(entry, document)
                elif attack == "entry-filename-hash":
                    entry.rename(
                        entry.with_name(
                            journal.JOURNAL_ENTRY_PREFIX
                            + "0" * 64
                            + journal.JOURNAL_DOCUMENT_SUFFIX
                        )
                    )
                else:
                    (_journal_directory(root) / "unexpected").write_bytes(b"x")
                result = self._inspect_invalid(root, intent)
                self.assertEqual(result["entry_sha256"], None)
                self.assertEqual(created["status"], "initialized")

    def test_missing_fork_orphan_and_sequence_gap_are_rejected(self) -> None:
        for attack in ("missing-request", "missing-genesis"):
            with self.subTest(attack=attack), _journal_root() as root:
                os.chmod(root, 0o700)
                intent = _intent()
                genesis = journal.begin_activation_journal(
                    root, activation_intent=intent
                )
                if attack == "missing-genesis":
                    _journal_append(
                        root,
                        genesis,
                        "aborted-pre-pivot",
                        JOURNAL_DECISION,
                        intent=intent,
                        observations={},
                    )
                    _request, entries = _journal_request_and_entries(root)
                    genesis_path = next(
                        path
                        for path in entries
                        if json.loads(path.read_text(encoding="ascii"))[
                            "sequence"
                        ]
                        == 0
                    )
                    genesis_path.unlink()
                else:
                    request, _entries = _journal_request_and_entries(root)
                    request.unlink()
                self._inspect_invalid(root, intent)

        for attack in ("fork", "orphan", "gap"):
            with self.subTest(attack=attack), _journal_root() as root:
                os.chmod(root, 0o700)
                intent = _intent()
                genesis = journal.begin_activation_journal(
                    root, activation_intent=intent
                )
                request_path, _entries = _journal_request_and_entries(root)
                request = json.loads(request_path.read_text(encoding="ascii"))
                transition = journal._validate_transition(
                    "prepared", "aborted-pre-pivot", intent, {}
                )
                sequence = 1
                prior = genesis["entry_sha256"]
                if attack == "fork":
                    _journal_append(
                        root,
                        genesis,
                        "quiesce-intent",
                        JOURNAL_DECISION,
                        intent=intent,
                    )
                elif attack == "orphan":
                    sequence = 2
                    prior = _h("missing-predecessor")
                else:
                    sequence = 3
                candidate = journal._journal_entry_document(
                    request,
                    sequence=sequence,
                    prior_entry_sha256=prior,
                    from_state="prepared",
                    to_state="aborted-pre-pivot",
                    decision_at=JOURNAL_DECISION + 1,
                    gate_observations_by_type={},
                    transition_result=transition,
                    protected_state_preimage_sha256=None,
                )
                self._publish(
                    root,
                    journal.JOURNAL_ENTRY_PREFIX
                    + candidate["entry_sha256"]
                    + journal.JOURNAL_DOCUMENT_SUFFIX,
                    candidate,
                )
                self._inspect_invalid(root, intent)


class JournalWriteAndDescriptorFaultTests(unittest.TestCase):
    def _empty_infrastructure(self, root: str) -> None:
        handles = journal._journal_acquire(root, create=True)
        journal._journal_release(handles)

    def _assert_unknown(self, result: dict) -> None:
        self.assertEqual(
            result["reason"], "outcome_unknown:journal-write-outcome-unknown"
        )
        self.assertIs(result["journal_write_attempted"], True)
        self.assertIsNone(result["journal_written"])
        self.assertEqual(journal.journal_result_exit_code(result), 4)
        self.assertTrue(journal._valid_journal_result(result))

    def test_exclusive_create_collision_before_and_after_create(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            self._empty_infrastructure(root)
            real_open = journal._JOURNAL_OPEN

            def collide_request(path, flags, *args, **kwargs):
                if (
                    path.startswith(journal.JOURNAL_REQUEST_PREFIX)
                    and flags & os.O_EXCL
                ):
                    raise FileExistsError(errno.EEXIST, "collision")
                return real_open(path, flags, *args, **kwargs)

            journal._JOURNAL_OPEN = collide_request
            try:
                result = journal.begin_activation_journal(
                    root, activation_intent=_intent()
                )
            finally:
                journal._JOURNAL_OPEN = real_open
            self.assertEqual(result["reason"], "conflict:journal-tip-mismatch")
            self.assertIs(result["journal_write_attempted"], False)
            self.assertIs(result["journal_written"], False)
            self.assertTrue(journal._valid_journal_result(result))

        with _journal_root() as root:
            os.chmod(root, 0o700)
            self._empty_infrastructure(root)
            real_write = journal._JOURNAL_WRITE

            def postcreate_eexist(_fd, _data):
                raise FileExistsError(errno.EEXIST, "after create")

            journal._JOURNAL_WRITE = postcreate_eexist
            try:
                result = journal.begin_activation_journal(
                    root, activation_intent=_intent()
                )
            finally:
                journal._JOURNAL_WRITE = real_write
            self._assert_unknown(result)

    def test_short_write_zero_eintr_and_fsync_truth(self) -> None:
        for fault in ("partial", "zero", "eintr", "file-fsync", "dir-fsync"):
            with self.subTest(fault=fault), _journal_root() as root:
                os.chmod(root, 0o700)
                self._empty_infrastructure(root)
                real_write = journal._JOURNAL_WRITE
                real_fsync = journal._JOURNAL_FSYNC
                fsync_calls = [0]

                def writing(fd, data):
                    if fault == "partial":
                        return real_write(fd, data[:7])
                    if fault == "zero":
                        return 0
                    if fault == "eintr":
                        raise InterruptedError(errno.EINTR, "interrupted")
                    return real_write(fd, data)

                def syncing(fd):
                    fsync_calls[0] += 1
                    if fault == "file-fsync" and fsync_calls[0] == 1:
                        raise OSError(errno.EIO, "file fsync")
                    if fault == "dir-fsync" and fsync_calls[0] == 2:
                        raise OSError(errno.EIO, "directory fsync")
                    return real_fsync(fd)

                journal._JOURNAL_WRITE = writing
                journal._JOURNAL_FSYNC = syncing
                try:
                    result = journal.begin_activation_journal(
                        root, activation_intent=_intent()
                    )
                finally:
                    journal._JOURNAL_WRITE = real_write
                    journal._JOURNAL_FSYNC = real_fsync
                if fault == "partial":
                    self.assertEqual(
                        result["reason"], "initialized:journal-created"
                    )
                    self.assertIs(result["journal_written"], True)
                else:
                    self._assert_unknown(result)

    def test_bounded_scandir_and_strict_close_truth(self) -> None:
        class Entry:
            name = "x"

        class Endless:
            def __init__(self):
                self.next_calls = 0
                self.close_calls = 0

            def __iter__(self):
                return self

            def __next__(self):
                self.next_calls += 1
                return Entry()

            def close(self):
                self.close_calls += 1

        endless = Endless()
        real_scandir = journal._JOURNAL_SCANDIR
        journal._JOURNAL_SCANDIR = lambda _fd: endless
        try:
            with self.assertRaisesRegex(
                ValueError, "journal-directory-name-limit"
            ):
                journal._journal_directory_names(7)
        finally:
            journal._JOURNAL_SCANDIR = real_scandir
        self.assertEqual(
            endless.next_calls, journal.MAX_JOURNAL_DIRECTORY_NAMES + 1
        )
        self.assertEqual(endless.close_calls, 1)

        class CloseFailure:
            def __init__(self):
                self.close_calls = 0

            def __iter__(self):
                return iter(())

            def close(self):
                self.close_calls += 1
                raise OSError(errno.EIO, "scandir close")

        close_failure = CloseFailure()
        journal._JOURNAL_SCANDIR = lambda _fd: close_failure
        try:
            with self.assertRaisesRegex(OSError, "scandir close"):
                journal._journal_directory_names(8)
        finally:
            journal._JOURNAL_SCANDIR = real_scandir
        self.assertEqual(close_failure.close_calls, 1)

        journal._JOURNAL_SCANDIR = lambda _fd: iter(())
        try:
            with self.assertRaisesRegex(
                ValueError, "scandir-close-unavailable"
            ):
                journal._journal_directory_names(9)
        finally:
            journal._JOURNAL_SCANDIR = real_scandir

        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent = _intent()
            created = journal.begin_activation_journal(
                root, activation_intent=intent
            )
            self.assertEqual(created["status"], "initialized")
            failures = [0]

            class ReadCloseFailure:
                def __init__(self, iterator):
                    self.iterator = iterator

                def __iter__(self):
                    return self

                def __next__(self):
                    return next(self.iterator)

                def close(self):
                    failures[0] += 1
                    self.iterator.close()
                    raise OSError(errno.EIO, "scandir close")

            journal._JOURNAL_SCANDIR = lambda fd: ReadCloseFailure(
                real_scandir(fd)
            )
            try:
                refused = journal.inspect_activation_journal(
                    root, activation_intent=intent
                )
            finally:
                journal._JOURNAL_SCANDIR = real_scandir
            self.assertEqual(failures[0], 1)
            self.assertEqual(
                refused["reason"], "blocked:journal-integrity-invalid"
            )
            self.assertIs(refused["journal_write_attempted"], False)
            self.assertIs(refused["journal_written"], False)

        with _journal_root() as root:
            os.chmod(root, 0o700)
            self._empty_infrastructure(root)
            close_calls = [0]

            class PostwriteCloseFailure:
                def __init__(self, iterator):
                    self.iterator = iterator

                def __iter__(self):
                    return self

                def __next__(self):
                    return next(self.iterator)

                def close(self):
                    close_calls[0] += 1
                    self.iterator.close()
                    if close_calls[0] == 5:
                        raise OSError(errno.EIO, "postwrite scandir close")

            journal._JOURNAL_SCANDIR = lambda fd: PostwriteCloseFailure(
                real_scandir(fd)
            )
            try:
                unknown = journal.begin_activation_journal(
                    root, activation_intent=_intent()
                )
            finally:
                journal._JOURNAL_SCANDIR = real_scandir
            self.assertEqual(close_calls[0], 5)
            self._assert_unknown(unknown)
            self.assertEqual(
                len(list(_journal_directory(root).glob("request-*.json"))),
                1,
            )
            self.assertEqual(
                len(list(_journal_directory(root).glob("entry-*.json"))),
                0,
            )

    def test_close_reuse_read_refusal_and_postwrite_unknown(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent = _intent()
            created = journal.begin_activation_journal(
                root, activation_intent=intent
            )
            self.assertEqual(created["status"], "initialized")
            real_close = journal._JOURNAL_CLOSE
            real_read = journal._JOURNAL_READ
            state = {"reading": False, "read_closes": 0, "sentinel": None}

            def reading(fd, size):
                data = real_read(fd, size)
                state["reading"] = True
                return data

            def close_second_read_probe(fd):
                if state["reading"]:
                    state["read_closes"] += 1
                    if state["read_closes"] == 2:
                        state["reading"] = False
                        real_close(fd)
                        sentinel = os.open("/dev/null", os.O_RDONLY)
                        if sentinel != fd:
                            os.dup2(sentinel, fd)
                            os.close(sentinel)
                            sentinel = fd
                        state["sentinel"] = sentinel
                        raise OSError(errno.EIO, "ambiguous close")
                return real_close(fd)

            journal._JOURNAL_READ = reading
            journal._JOURNAL_CLOSE = close_second_read_probe
            try:
                result = journal.inspect_activation_journal(
                    root, activation_intent=intent
                )
            finally:
                journal._JOURNAL_READ = real_read
                journal._JOURNAL_CLOSE = real_close
            self.assertEqual(
                result["reason"], "blocked:journal-integrity-invalid"
            )
            self.assertEqual(state["read_closes"], 2)
            os.fstat(state["sentinel"])
            os.close(state["sentinel"])

        with _journal_root() as root:
            os.chmod(root, 0o700)
            self._empty_infrastructure(root)
            real_close = journal._JOURNAL_CLOSE
            real_write = journal._JOURNAL_WRITE
            state = {"written": False, "closes": 0, "sentinel": None}

            def writing(fd, data):
                state["written"] = True
                return real_write(fd, data)

            def close_after_write(fd):
                if state["written"]:
                    state["closes"] += 1
                    if state["closes"] == 1:
                        state["written"] = False
                        real_close(fd)
                        sentinel = os.open("/dev/null", os.O_RDONLY)
                        if sentinel != fd:
                            os.dup2(sentinel, fd)
                            os.close(sentinel)
                            sentinel = fd
                        state["sentinel"] = sentinel
                        raise OSError(errno.EIO, "ambiguous close")
                return real_close(fd)

            journal._JOURNAL_WRITE = writing
            journal._JOURNAL_CLOSE = close_after_write
            try:
                result = journal.begin_activation_journal(
                    root, activation_intent=_intent()
                )
            finally:
                journal._JOURNAL_WRITE = real_write
                journal._JOURNAL_CLOSE = real_close
            self._assert_unknown(result)
            self.assertEqual(state["closes"], 1)
            os.fstat(state["sentinel"])
            os.close(state["sentinel"])

    def test_callee_owned_descriptors_close_once_on_validation_faults(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            expected_root_opens = len(root.split(os.path.sep)[1:]) + 1
            for target in range(1, expected_root_opens + 1):
                module = _load(f"root_close_{target}", MODULE_PATH)
                opened = []
                closed = []
                real_open = module._JOURNAL_OPEN
                real_close = module._JOURNAL_CLOSE
                real_fstat = module._JOURNAL_FSTAT
                calls = [0]

                def opening(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                def closing(descriptor):
                    closed.append(descriptor)
                    return real_close(descriptor)

                def failing_fstat(descriptor):
                    calls[0] += 1
                    if calls[0] == target:
                        raise OSError(errno.EIO, "fstat")
                    return real_fstat(descriptor)

                module._JOURNAL_OPEN = opening
                module._JOURNAL_CLOSE = closing
                module._JOURNAL_FSTAT = failing_fstat
                with self.assertRaises(module._JournalRefusal):
                    module._journal_root_descriptor(root)
                self.assertEqual(sorted(opened), sorted(closed))
                self.assertTrue(all(closed.count(fd) == 1 for fd in closed))

        for target_kind in ("directory", "lock"):
            with self.subTest(target=target_kind), _journal_root() as root:
                os.chmod(root, 0o700)
                directory = _journal_directory(root)
                directory.mkdir(mode=0o700)
                if target_kind == "lock":
                    lock = directory / journal.JOURNAL_LOCK_FILENAME
                    lock.write_bytes(b"")
                    os.chmod(lock, 0o600)
                root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                directory_fd = None
                opened = []
                closed = []
                real_open = journal._JOURNAL_OPEN
                real_close = journal._JOURNAL_CLOSE
                real_fstat = journal._JOURNAL_FSTAT

                def opening(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                def closing(descriptor):
                    closed.append(descriptor)
                    return real_close(descriptor)

                journal._JOURNAL_OPEN = opening
                journal._JOURNAL_CLOSE = closing
                journal._JOURNAL_FSTAT = lambda _fd: (_ for _ in ()).throw(
                    OSError(errno.EIO, "fstat")
                )
                try:
                    if target_kind == "directory":
                        with self.assertRaises(journal._JournalRefusal):
                            journal._journal_open_private_directory(
                                root_fd, create=False
                            )
                    else:
                        directory_fd = os.open(
                            directory, os.O_RDONLY | os.O_DIRECTORY
                        )
                        with self.assertRaises(journal._JournalRefusal):
                            journal._journal_open_lock(
                                directory_fd,
                                create=False,
                                prior_written=False,
                            )
                finally:
                    journal._JOURNAL_OPEN = real_open
                    journal._JOURNAL_CLOSE = real_close
                    journal._JOURNAL_FSTAT = real_fstat
                    if directory_fd is not None:
                        os.close(directory_fd)
                    os.close(root_fd)
                self.assertEqual(opened, closed)
                self.assertEqual(len(closed), 1)

    def test_root_mode_baseline_and_visible_reproof_races(self) -> None:
        with _journal_root() as root:
            os.chmod(root, 0o700)
            intent = _intent()
            created = journal.begin_activation_journal(
                root, activation_intent=intent
            )
            self.assertEqual(created["status"], "initialized")
            target = os.stat(root)
            cases = (
                ((0o777, 0o700, 0o777), "blocked:journal-root-invalid"),
                ((0o700, 0o777), "blocked:journal-integrity-invalid"),
                (
                    (0o700, 0o700, 0o777),
                    "blocked:journal-integrity-invalid",
                ),
            )
            for modes, reason in cases:
                with self.subTest(modes=modes):
                    module = _load("root_mode_" + "_".join(map(str, modes)), MODULE_PATH)
                    real_fstat = module._JOURNAL_FSTAT
                    seen = [0]

                    def raced(descriptor):
                        metadata = real_fstat(descriptor)
                        if (
                            stat.S_ISDIR(metadata.st_mode)
                            and (metadata.st_dev, metadata.st_ino)
                            == (target.st_dev, target.st_ino)
                        ):
                            seen[0] += 1
                            if seen[0] <= len(modes):
                                values = list(metadata)
                                values[0] = (
                                    metadata.st_mode & ~0o777
                                ) | modes[seen[0] - 1]
                                return os.stat_result(values)
                        return metadata

                    module._JOURNAL_FSTAT = raced
                    result = module.inspect_activation_journal(
                        root, activation_intent=intent
                    )
                    self.assertEqual(result["reason"], reason)
                    self.assertTrue(module._valid_journal_result(result))


class AstPurityTests(unittest.TestCase):
    def test_imports_and_call_surfaces(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imports = sorted(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertEqual(
            imports,
            [
                "errno",
                "fcntl",
                "hashlib",
                "json",
                "os",
                "re",
                "stat",
                "time",
            ],
        )
        self.assertFalse(
            any(isinstance(node, ast.ImportFrom) for node in ast.walk(tree))
        )

        calls = []

        def tripwire(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("4A touched the 4B filesystem/clock lane")

        seam_names = (
            "_JOURNAL_OPEN",
            "_JOURNAL_READ",
            "_JOURNAL_WRITE",
            "_JOURNAL_FSTAT",
            "_JOURNAL_FCHMOD",
            "_JOURNAL_FSYNC",
            "_JOURNAL_CLOSE",
            "_JOURNAL_LISTDIR",
            "_JOURNAL_MKDIR",
            "_JOURNAL_SCANDIR",
            "_JOURNAL_FLOCK",
            "_JOURNAL_NOW",
        )
        originals = {name: getattr(journal, name) for name in seam_names}
        try:
            for name in seam_names:
                setattr(journal, name, tripwire)
            projection = journal.activation_contract_projection()
            planned = journal.plan_activation_intent(_intent())
            transition = journal.validate_transition(
                "start", "prepared", activation_intent=_intent()
            )
            for result in (projection, planned, transition):
                self.assertIsInstance(journal.render_result(result), str)
                self.assertEqual(journal.result_exit_code(result), 0)
        finally:
            for name, original in originals.items():
                setattr(journal, name, original)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()

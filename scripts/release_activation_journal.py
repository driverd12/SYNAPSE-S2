#!/usr/bin/env python3
"""Release-activation contract, planner, and dormant durable journal.

This module describes — and only describes — the governed activation journal
for SYNAPSE-S2 releases.  It binds a host-independent activation contract
identity, validates externally supplied activation intents, derives
transaction identities, and adjudicates journal state transitions on paper.

The 4A APIs remain pure and perform no filesystem access.  The separate 4B
APIs can write only immutable activation-journal documents below an explicit,
pre-existing, effective-UID-owned POSIX-0700 root.  Neither layer performs
activation or apply,
loads project or candidate code, touches the network, controls services,
publishes selectors/config, mutates a provenance floor, or accesses live
runtime state.  Public results are closed and redact paths, evidence content,
signatures, exception text, hostnames, users, and secrets.
"""

import errno
import hashlib
import json
import os
import re
import stat
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by platform-gate tests.
    fcntl = None


CONTRACT_SCHEMA = "synapse-s2.release-activation-contract.v1"
INTENT_SCHEMA = "synapse-s2.release-activation-intent.v1"
RESULT_SCHEMA = "synapse-s2.release-activation-plan.v1"
MODE = "dormant-source-only"

PROFILE = "exact-build-only"
PROFILE_VERSION = 1
HOST_EVIDENCE_POLICY = "required-later"
MIGRATION_POLICY = "blocked"
DOWNGRADE_POLICY = "blocked"

# Pinned sibling vocabulary, restated byte-for-byte and never imported.
LAYOUT_SCHEMA = "synapse-s2.installed-layout-contract.v1"
LAYOUT_MODE = "inactive-versioned-v1"
HOST_EVIDENCE_RECEIPT_SCHEMA = "synapse-s2.host-evidence-receipt.v1"
HOST_EVIDENCE_PURPOSE = "release-activation"
GATE_OBSERVATION_SCHEMA = (
    "synapse-s2.release-activation-gate-observation.v1"
)
GATE_OBSERVATION_TYPES = (
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
EXPECTED_LAYOUT_CONTRACT_ID = (
    "layout-contract-"
    "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
)

COMMAND_PLAN = "plan-activation-intent"
COMMAND_VALIDATE = "validate-transition"
COMMAND_RENDER = "render-result"

STATUS_PROJECTED = "projected"
STATUS_PLANNED = "planned"
STATUS_VALID = "valid"
STATUS_DENIED = "denied"
STATUS_UNSUPPORTED = "unsupported"

STATE_START = "start"
STATE_PREPARED = "prepared"
STATE_QUIESCE_INTENT = "quiesce-intent"
STATE_QUIESCENT_OBSERVED = "quiescent-observed"
STATE_SWITCH_INTENT = "switch-intent"
STATE_ACTIVATING = "activating"
STATE_ROLLBACK_INTENT = "rollback-intent"
STATE_CANDIDATE_HEALTHY = "candidate-healthy"
STATE_PIVOT_INTENT = "pivot-intent"
STATE_PIVOT = "state-pivot-committed-writer-fenced"
STATE_POST_UPDATE_EQUIVALENT = "post-update-equivalent"
STATE_CLIENTS_PUBLISH_INTENT = "clients-publish-intent"
STATE_CLIENTS_CONVERGED = "clients-converged"
STATE_RELEASE_COMMIT_INTENT = "release-commit-intent"
STATE_FLOOR_RECORDED = "floor-recorded"
STATE_COMMITTED = "committed"
STATE_ABORTED_PRE_PIVOT = "aborted-pre-pivot"
STATE_CONTROL_PLANE_ROLLED_BACK = "control-plane-rolled-back"
STATE_MANUAL_RECOVERY_REQUIRED = "manual-recovery-required"
STATE_POST_PIVOT_RECOVERY_REQUIRED = "post-pivot-recovery-required"

# Closed successor map.  Empty tuple means terminal: no successors, ever.
STATE_GRAPH = {
    STATE_START: (STATE_PREPARED,),
    STATE_PREPARED: (STATE_QUIESCE_INTENT, STATE_ABORTED_PRE_PIVOT),
    STATE_QUIESCE_INTENT: (
        STATE_QUIESCENT_OBSERVED,
        STATE_ROLLBACK_INTENT,
        STATE_MANUAL_RECOVERY_REQUIRED,
    ),
    STATE_QUIESCENT_OBSERVED: (
        STATE_SWITCH_INTENT,
        STATE_ROLLBACK_INTENT,
        STATE_MANUAL_RECOVERY_REQUIRED,
    ),
    STATE_SWITCH_INTENT: (
        STATE_ACTIVATING,
        STATE_MANUAL_RECOVERY_REQUIRED,
    ),
    STATE_ACTIVATING: (
        STATE_ROLLBACK_INTENT,
        STATE_CANDIDATE_HEALTHY,
        STATE_MANUAL_RECOVERY_REQUIRED,
    ),
    STATE_CANDIDATE_HEALTHY: (
        STATE_PIVOT_INTENT,
        STATE_ROLLBACK_INTENT,
        STATE_MANUAL_RECOVERY_REQUIRED,
    ),
    STATE_PIVOT_INTENT: (
        STATE_PIVOT,
        STATE_POST_PIVOT_RECOVERY_REQUIRED,
    ),
    STATE_ROLLBACK_INTENT: (
        STATE_CONTROL_PLANE_ROLLED_BACK,
        STATE_MANUAL_RECOVERY_REQUIRED,
    ),
    STATE_PIVOT: (
        STATE_POST_UPDATE_EQUIVALENT,
        STATE_POST_PIVOT_RECOVERY_REQUIRED,
    ),
    STATE_POST_UPDATE_EQUIVALENT: (
        STATE_CLIENTS_PUBLISH_INTENT,
        STATE_POST_PIVOT_RECOVERY_REQUIRED,
    ),
    STATE_CLIENTS_PUBLISH_INTENT: (
        STATE_CLIENTS_CONVERGED,
        STATE_POST_PIVOT_RECOVERY_REQUIRED,
    ),
    STATE_CLIENTS_CONVERGED: (
        STATE_RELEASE_COMMIT_INTENT,
        STATE_POST_PIVOT_RECOVERY_REQUIRED,
    ),
    STATE_RELEASE_COMMIT_INTENT: (
        STATE_FLOOR_RECORDED,
        STATE_POST_PIVOT_RECOVERY_REQUIRED,
    ),
    STATE_FLOOR_RECORDED: (
        STATE_COMMITTED,
        STATE_POST_PIVOT_RECOVERY_REQUIRED,
    ),
    STATE_ABORTED_PRE_PIVOT: (),
    STATE_CONTROL_PLANE_ROLLED_BACK: (),
    STATE_MANUAL_RECOVERY_REQUIRED: (),
    STATE_COMMITTED: (),
    STATE_POST_PIVOT_RECOVERY_REQUIRED: (),
}

# The declared journal origin.  Planning declares it; nothing here ever
# authorizes entering it.
INITIAL_STATE = STATE_PREPARED

# The pivot is the first candidate-owned durable authority/write claim.
# Crossing it makes rollback and downgrade permanently forward-only.
# release-commit-intent is later final publication/floor intent and never
# weakens this earlier boundary.
PIVOT_STATE = STATE_PIVOT
NO_RETURN_STATE = STATE_SWITCH_INTENT
POST_PIVOT_STATES = (
    STATE_PIVOT,
    STATE_POST_UPDATE_EQUIVALENT,
    STATE_CLIENTS_PUBLISH_INTENT,
    STATE_CLIENTS_CONVERGED,
    STATE_RELEASE_COMMIT_INTENT,
    STATE_FLOOR_RECORDED,
    STATE_COMMITTED,
    STATE_POST_PIVOT_RECOVERY_REQUIRED,
)

# switch-intent and activating mean the durable claim outcome is unknown and
# needs reconciliation before any rollback decision.
RECONCILIATION_STATES = (
    STATE_SWITCH_INTENT,
    STATE_ACTIVATING,
    STATE_PIVOT_INTENT,
)

# These edges have crossed the durable no-return intent, but do not prove
# whether the candidate obtained the first durable authority/write claim.
# The public post-pivot field is therefore null until reconciliation proves
# either the pivot or its absence.
UNKNOWN_PIVOT_OUTCOME_EDGES = (
    (STATE_SWITCH_INTENT, STATE_ACTIVATING),
    (STATE_SWITCH_INTENT, STATE_MANUAL_RECOVERY_REQUIRED),
    (STATE_ACTIVATING, STATE_MANUAL_RECOVERY_REQUIRED),
    (STATE_CANDIDATE_HEALTHY, STATE_PIVOT_INTENT),
    (STATE_PIVOT_INTENT, STATE_POST_PIVOT_RECOVERY_REQUIRED),
)

EVIDENCE_NO_DURABLE_CLAIM = "no-durable-claim"
EVIDENCE_PROTECTED_STATE_EQUALITY = "protected-state-equality"
GUARDED_EDGES = {
    (STATE_QUIESCE_INTENT, STATE_ROLLBACK_INTENT): (
        EVIDENCE_PROTECTED_STATE_EQUALITY,
    ),
    (STATE_QUIESCENT_OBSERVED, STATE_ROLLBACK_INTENT): (
        EVIDENCE_PROTECTED_STATE_EQUALITY,
    ),
    (STATE_ACTIVATING, STATE_ROLLBACK_INTENT): (
        EVIDENCE_NO_DURABLE_CLAIM,
    ),
    (STATE_CANDIDATE_HEALTHY, STATE_ROLLBACK_INTENT): (
        EVIDENCE_NO_DURABLE_CLAIM,
    ),
    (STATE_ROLLBACK_INTENT, STATE_CONTROL_PLANE_ROLLED_BACK): (
        EVIDENCE_PROTECTED_STATE_EQUALITY,
    ),
}

# Refreshable, externally verified observations are not part of the stable
# activation request.  A later durable journal entry must bind exactly these
# typed observation digests before recording the corresponding edge.  This
# pure module validates only their closed shape and edge association; it does
# not authenticate the referenced receipts.
EDGE_OBSERVATION_REQUIREMENTS = {
    (STATE_PREPARED, STATE_QUIESCE_INTENT): (
        "host-authority",
        "recovery-readiness",
    ),
    (STATE_QUIESCE_INTENT, STATE_QUIESCENT_OBSERVED): (
        "quiescence",
    ),
    (STATE_QUIESCENT_OBSERVED, STATE_SWITCH_INTENT): (
        "host-authority",
    ),
    (STATE_ACTIVATING, STATE_CANDIDATE_HEALTHY): (
        "candidate-health",
    ),
    (STATE_CANDIDATE_HEALTHY, STATE_PIVOT_INTENT): (
        "host-authority",
    ),
    (STATE_PIVOT_INTENT, STATE_PIVOT): (
        "binding-published",
    ),
    (STATE_PIVOT, STATE_POST_UPDATE_EQUIVALENT): (
        "memory-equivalence",
    ),
    (STATE_POST_UPDATE_EQUIVALENT, STATE_CLIENTS_PUBLISH_INTENT): (
        "host-authority",
    ),
    (STATE_CLIENTS_PUBLISH_INTENT, STATE_CLIENTS_CONVERGED): (
        "clients-converged",
    ),
    (STATE_CLIENTS_CONVERGED, STATE_RELEASE_COMMIT_INTENT): (
        "host-authority",
    ),
    (STATE_RELEASE_COMMIT_INTENT, STATE_FLOOR_RECORDED): (
        "floor-recorded",
    ),
    (STATE_QUIESCE_INTENT, STATE_ROLLBACK_INTENT): (
        EVIDENCE_PROTECTED_STATE_EQUALITY,
    ),
    (STATE_QUIESCENT_OBSERVED, STATE_ROLLBACK_INTENT): (
        EVIDENCE_PROTECTED_STATE_EQUALITY,
    ),
    (STATE_ACTIVATING, STATE_ROLLBACK_INTENT): (
        EVIDENCE_NO_DURABLE_CLAIM,
    ),
    (STATE_CANDIDATE_HEALTHY, STATE_ROLLBACK_INTENT): (
        EVIDENCE_NO_DURABLE_CLAIM,
    ),
    (STATE_ROLLBACK_INTENT, STATE_CONTROL_PLANE_ROLLED_BACK): (
        EVIDENCE_PROTECTED_STATE_EQUALITY,
    ),
}

NO_RETURN_POLICY = (
    "switch-intent-durable-before-launchctl-bootstrap-or-candidate-start",
    "candidate-starts-writer-fenced",
    "automatic-predecessor-restart-forbidden-after-switch-intent",
    "automatic-predecessor-reinstall-forbidden-after-switch-intent",
    "automatic-predecessor-republication-forbidden-after-switch-intent",
    "automatic-predecessor-fallback-forbidden-after-switch-intent",
    "pre-pivot-rollback-after-switch-is-cleanup-only-after-reconciliation",
    "pivot-is-first-candidate-owned-durable-authority-write-claim",
    "candidate-health-precedes-pivot-intent",
    "pivot-precedes-post-update-equivalence",
    "post-update-equivalence-precedes-client-convergence",
    "client-publication-intent-precedes-client-convergence",
    "client-convergence-precedes-release-commit-intent",
    "release-commit-intent-precedes-floor-record",
    "floor-record-precedes-complete",
    "post-pivot-recovery-is-forward-only",
)

DISPOSITION_EQUALITY_PROOF = (
    "control-plane-rollback-eligible-only-after-"
    "exact-protected-state-equality-proof"
)
DISPOSITION_MANUAL_RECONCILIATION = "manual-pivot-reconciliation-required"
DISPOSITION_FORWARD_ONLY = (
    "forward-only-roll-forward-recover-existing-"
    "or-newer-admitted-release-only"
)

ROLLBACK_DISPOSITIONS = {
    STATE_START: DISPOSITION_EQUALITY_PROOF,
    STATE_PREPARED: DISPOSITION_EQUALITY_PROOF,
    STATE_QUIESCE_INTENT: DISPOSITION_EQUALITY_PROOF,
    STATE_QUIESCENT_OBSERVED: DISPOSITION_EQUALITY_PROOF,
    STATE_ABORTED_PRE_PIVOT: DISPOSITION_EQUALITY_PROOF,
    STATE_CONTROL_PLANE_ROLLED_BACK: DISPOSITION_EQUALITY_PROOF,
    STATE_SWITCH_INTENT: DISPOSITION_MANUAL_RECONCILIATION,
    STATE_ACTIVATING: DISPOSITION_MANUAL_RECONCILIATION,
    STATE_CANDIDATE_HEALTHY: DISPOSITION_MANUAL_RECONCILIATION,
    STATE_PIVOT_INTENT: DISPOSITION_MANUAL_RECONCILIATION,
    STATE_ROLLBACK_INTENT: DISPOSITION_MANUAL_RECONCILIATION,
    STATE_MANUAL_RECOVERY_REQUIRED: DISPOSITION_MANUAL_RECONCILIATION,
    STATE_PIVOT: DISPOSITION_FORWARD_ONLY,
    STATE_POST_UPDATE_EQUIVALENT: DISPOSITION_FORWARD_ONLY,
    STATE_CLIENTS_PUBLISH_INTENT: DISPOSITION_FORWARD_ONLY,
    STATE_CLIENTS_CONVERGED: DISPOSITION_FORWARD_ONLY,
    STATE_RELEASE_COMMIT_INTENT: DISPOSITION_FORWARD_ONLY,
    STATE_FLOOR_RECORDED: DISPOSITION_FORWARD_ONLY,
    STATE_COMMITTED: DISPOSITION_FORWARD_ONLY,
    STATE_POST_PIVOT_RECOVERY_REQUIRED: DISPOSITION_FORWARD_ONLY,
}

# Rollback never restores, deletes, rewrites, copies, or replaces any of
# these.  Data rollback is a nonclaim in every phase.
ROLLBACK_NEVER_RESTORES = (
    "captures",
    "learned-state",
    "media",
    "memory-database",
    "namespaces",
    "neurons",
    "recovery-artifacts",
    "relationships",
    "request-journal",
    "runtime-history",
)

ALWAYS_FALSE_FLAGS = (
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

REQUIREMENTS = (
    "candidate-starts-writer-fenced",
    "external-governed-executor-required",
    "forward-only-after-state-pivot",
    "fresh-host-authority-observation-before-quiesce-switch-pivot-clients-and-commit",
    "edge-specific-gate-observation-digests-required",
    "host-evidence-verification-required-later",
    "manual-pivot-reconciliation-before-rollback-decision",
    "no-durable-claim-evidence-before-rollback-intent",
    "no-return-intent-before-launchctl-bootstrap-or-candidate-start",
    "no-automatic-predecessor-fallback-after-no-return-intent",
    "protected-state-equality-proof-before-pre-pivot-rollback",
    "protected-state-equality-proof-before-control-plane-rollback-record",
    "quiescence-observation-produced-after-quiesce-intent",
    "recovery-readiness-observation-before-quiesce-intent",
    "refreshable-gate-evidence-excluded-from-transaction-id",
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

MAX_INT = 2**53
MAX_INTENT_STRING_CHARS = 128
MAX_STATE_CHARS = 64
MAX_RESULT_BYTES = 32768
MAX_OUTPUT_DEPTH = 12
MAX_OUTPUT_ITEMS = 4096
MAX_OUTPUT_STRING_CHARS = 4096

_ACTIVATION_CONTRACT_ID_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-CONTRACT\x00v1\x00"
)
_TRANSACTION_ID_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-TRANSACTION\x00v1\x00"
)
_INTENT_HASH_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-INTENT\x00v1\x00"
)
_GATE_OBSERVATION_HASH_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-GATE-OBSERVATION\x00v1\x00"
)

_HEX32_PATTERN = re.compile(r"\A[0-9a-f]{32}\Z")
_HEX64_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
_KEY_ID_PATTERN = re.compile(r"\Aed25519-[0-9a-f]{64}\Z")
_SOURCE_SHA_PATTERN = re.compile(r"\A[0-9a-f]{40}\Z")
_SOURCE_BUILD_ID_PATTERN = re.compile(r"\Asource-[0-9a-f]{24}\Z")
_PRODUCT_ID_PATTERN = re.compile(r"\Aproduct-[0-9a-f]{64}\Z")
_COMPONENT_ID_PATTERN = re.compile(r"\Acomponent-[0-9a-f]{64}\Z")
_INVENTORY_POLICY_ID_PATTERN = re.compile(
    r"\Ainventory-policy-[0-9a-f]{64}\Z"
)
_CHANNEL_PATTERN = re.compile(r"\A[a-z][a-z0-9-]{0,31}\Z")
_VERSION_PATTERN = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
_LAYOUT_ID_PATTERN = re.compile(r"\Alayout-[0-9a-f]{64}\Z")
_TRANSACTION_ID_PATTERN = re.compile(r"\Atransaction-[0-9a-f]{64}\Z")
_REASON_PATTERN = re.compile(r"\A[a-z][a-z0-9:_-]{0,191}\Z")

_GATE_COMMON_FIELDS = (
    "schema",
    "transaction_id",
    "from_state",
    "to_state",
    "observation_type",
    "observed_at",
    "observed_state_entry_sha256",
    "evidence_sha256",
)
_GATE_HOST_AUTHORITY_FIELDS = (
    "host_evidence_key_id",
    "host_nonce",
    "issued_at",
    "expires_at",
    "minimum_authority_expires_at",
)
_GATE_PROTECTED_STATE_FIELDS = (
    "protected_state_preimage_sha256",
)
_GATE_PROTECTED_STATE_TYPES = (
    "protected-state-equality",
    "quiescence",
    "recovery-readiness",
)
_GATE_OBSERVATION_STRING_PATTERNS = {
    "evidence_sha256": _HEX64_PATTERN,
    "host_evidence_key_id": _KEY_ID_PATTERN,
    "host_nonce": _HEX32_PATTERN,
    "observed_state_entry_sha256": _HEX64_PATTERN,
    "protected_state_preimage_sha256": _HEX64_PATTERN,
}

# Exactly pinned intent values.
_INTENT_FIXED = {
    "schema": INTENT_SCHEMA,
    "layout_schema": LAYOUT_SCHEMA,
    "layout_mode": LAYOUT_MODE,
    "layout_contract_id": EXPECTED_LAYOUT_CONTRACT_ID,
    "host_evidence_schema": HOST_EVIDENCE_RECEIPT_SCHEMA,
    "host_evidence_purpose": HOST_EVIDENCE_PURPOSE,
}

# Grammar-bounded intent strings: identifiers and digests only.
_INTENT_PATTERNS = {
    "activation_nonce": _HEX32_PATTERN,
    "idempotency_key_sha256": _HEX64_PATTERN,
    "activation_policy_receipt_sha256": _HEX64_PATTERN,
    "root_key_id": _KEY_ID_PATTERN,
    "trust_bundle_sha256": _HEX64_PATTERN,
    "release_envelope_sha256": _HEX64_PATTERN,
    "compatibility_ticket_sha256": _HEX64_PATTERN,
    "compatibility_result_sha256": _HEX64_PATTERN,
    "channel": _CHANNEL_PATTERN,
    "version": _VERSION_PATTERN,
    "source_sha": _SOURCE_SHA_PATTERN,
    "inventory_policy_id": _INVENTORY_POLICY_ID_PATTERN,
    "current_source_build_id": _SOURCE_BUILD_ID_PATTERN,
    "candidate_source_build_id": _SOURCE_BUILD_ID_PATTERN,
    "current_product_id": _PRODUCT_ID_PATTERN,
    "candidate_product_id": _PRODUCT_ID_PATTERN,
    "current_dependency_component_id": _COMPONENT_ID_PATTERN,
    "candidate_dependency_component_id": _COMPONENT_ID_PATTERN,
    "surfaces_digest": _HEX64_PATTERN,
    "installed_floor_preimage_sha256": _HEX64_PATTERN,
    "incumbent_installed_record_sha256": _HEX64_PATTERN,
    "layout_id": _LAYOUT_ID_PATTERN,
    "stage_result_sha256": _HEX64_PATTERN,
    "stage_journal_head_sha256": _HEX64_PATTERN,
    "staged_product_id": _PRODUCT_ID_PATTERN,
    "staged_source_build_id": _SOURCE_BUILD_ID_PATTERN,
    "environment_receipt_sha256": _HEX64_PATTERN,
    "host_id_sha256": _HEX64_PATTERN,
    "prior_control_plane_projection_sha256": _HEX64_PATTERN,
    "desired_control_plane_projection_sha256": _HEX64_PATTERN,
}

_INTENT_INTEGER_KEYS = (
    "trust_generation",
    "release_sequence",
)

# Exact-build-only cross-bindings inside one intent.
_INTENT_EQUALITY_REQUIREMENTS = (
    ("current_dependency_component_id", "candidate_dependency_component_id"),
    ("staged_product_id", "candidate_product_id"),
    ("staged_source_build_id", "candidate_source_build_id"),
)

_RESULT_IDENTITY_FIELDS = (
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
)

_PLAN_RESULT_BINDINGS = {
    "activation_nonce": "activation_nonce",
    "candidate_product_id": "candidate_product_id",
    "candidate_source_build_id": "candidate_source_build_id",
    "channel": "channel",
    "compatibility_result_sha256": "compatibility_result_sha256",
    "compatibility_ticket_sha256": "compatibility_ticket_sha256",
    "current_product_id": "current_product_id",
    "current_source_build_id": "current_source_build_id",
    "idempotency_key_sha256": "idempotency_key_sha256",
    "inventory_policy_id": "inventory_policy_id",
    "layout_contract_id": "layout_contract_id",
    "layout_id": "layout_id",
    "release_envelope_sha256": "release_envelope_sha256",
    "release_sequence": "release_sequence",
    "source_sha": "source_sha",
    "surfaces_digest": "surfaces_digest",
    "trust_bundle_sha256": "trust_bundle_sha256",
    "trust_generation": "trust_generation",
    "version": "version",
}

_RESULT_BASE_FIELDS = (
    "schema",
    "mode",
    "command",
    "status",
    "reason",
    "activation_contract_id",
    "pivot_state",
)

_RESULT_TRAILER_FIELDS = ("requirements", "nonclaims")

_COMMAND_STATUS_POLICY = {
    COMMAND_PLAN: (STATUS_PLANNED, STATUS_UNSUPPORTED),
    COMMAND_VALIDATE: (STATUS_VALID, STATUS_DENIED, STATUS_UNSUPPORTED),
    COMMAND_RENDER: (STATUS_UNSUPPORTED,),
}

_SUCCESS_STATUSES = (STATUS_PROJECTED, STATUS_PLANNED, STATUS_VALID)
_EXIT_CODE_POLICY = {
    STATUS_PROJECTED: 0,
    STATUS_PLANNED: 0,
    STATUS_VALID: 0,
    STATUS_DENIED: 3,
    STATUS_UNSUPPORTED: 2,
}

_EXACT_REASONS = (
    "planned:activation-intent-bound",
    "projected:activation-contract",
    "valid:control-plane-rollback-recorded-after-protected-state-equality-evidence",
    "valid:rollback-intent-admitted-after-no-durable-claim-evidence",
    "valid:rollback-intent-admitted-after-protected-state-equality-evidence",
    "valid:transition-allowed",
)

_DENIAL_REASONS = (
    "denied:illegal-transition",
    "denied:terminal-state",
) + tuple(
    "denied:gate-observation-required:" + observation_type
    for observation_type in GATE_OBSERVATION_TYPES
)

_INTENT_UNSUPPORTED_FIXED_REASONS = (
    "unsupported:intent-key-count-invalid",
    "unsupported:intent-key-type-invalid",
    "unsupported:intent-keys-invalid",
    "unsupported:intent-type-invalid",
    "unsupported:internal-error",
)

_VALIDATE_UNSUPPORTED_FIXED_REASONS = (
    "unsupported:current-state-invalid",
) + _INTENT_UNSUPPORTED_FIXED_REASONS + (
    "unsupported:next-state-invalid",
    "unsupported:gate-observation-map-invalid",
) + tuple(
    "unsupported:gate-observation-not-applicable:" + observation_type
    for observation_type in GATE_OBSERVATION_TYPES
) + tuple(
    "unsupported:gate-observation-invalid:" + observation_type
    for observation_type in GATE_OBSERVATION_TYPES
)

_RENDER_UNSUPPORTED_FIXED_REASONS = (
    "unsupported:output-oversize",
    "unsupported:result-not-renderable",
)

_UNSUPPORTED_FIXED_REASONS_BY_COMMAND = {
    COMMAND_PLAN: _INTENT_UNSUPPORTED_FIXED_REASONS,
    COMMAND_VALIDATE: _VALIDATE_UNSUPPORTED_FIXED_REASONS,
    COMMAND_RENDER: _RENDER_UNSUPPORTED_FIXED_REASONS,
}


class _Unsupported(Exception):
    """Fail-closed refusal carrying only a fixed public token."""

    def __init__(self, token):
        super().__init__(token)
        self.token = token


class _Denied(Exception):
    """Illegal but well-formed transition, carrying only fixed tokens."""

    def __init__(self, token, current_state, next_state, fields=None):
        super().__init__(token)
        self.token = token
        self.current_state = current_state
        self.next_state = next_state
        self.fields = {} if fields is None else fields


def _state_constant_map():
    """Return every runtime state alias for contract-identity binding."""
    return {
        "STATE_ABORTED_PRE_PIVOT": STATE_ABORTED_PRE_PIVOT,
        "STATE_ACTIVATING": STATE_ACTIVATING,
        "STATE_CANDIDATE_HEALTHY": STATE_CANDIDATE_HEALTHY,
        "STATE_CLIENTS_PUBLISH_INTENT": STATE_CLIENTS_PUBLISH_INTENT,
        "STATE_CLIENTS_CONVERGED": STATE_CLIENTS_CONVERGED,
        "STATE_COMMITTED": STATE_COMMITTED,
        "STATE_CONTROL_PLANE_ROLLED_BACK": STATE_CONTROL_PLANE_ROLLED_BACK,
        "STATE_FLOOR_RECORDED": STATE_FLOOR_RECORDED,
        "STATE_MANUAL_RECOVERY_REQUIRED": STATE_MANUAL_RECOVERY_REQUIRED,
        "STATE_PIVOT": STATE_PIVOT,
        "STATE_PIVOT_INTENT": STATE_PIVOT_INTENT,
        "STATE_POST_UPDATE_EQUIVALENT": STATE_POST_UPDATE_EQUIVALENT,
        "STATE_POST_PIVOT_RECOVERY_REQUIRED": (
            STATE_POST_PIVOT_RECOVERY_REQUIRED
        ),
        "STATE_PREPARED": STATE_PREPARED,
        "STATE_QUIESCE_INTENT": STATE_QUIESCE_INTENT,
        "STATE_QUIESCENT_OBSERVED": STATE_QUIESCENT_OBSERVED,
        "STATE_RELEASE_COMMIT_INTENT": STATE_RELEASE_COMMIT_INTENT,
        "STATE_ROLLBACK_INTENT": STATE_ROLLBACK_INTENT,
        "STATE_START": STATE_START,
        "STATE_SWITCH_INTENT": STATE_SWITCH_INTENT,
    }


def _evidence_field_constant_map():
    """Return runtime evidence aliases for contract-identity binding."""
    return {
        "EVIDENCE_NO_DURABLE_CLAIM": EVIDENCE_NO_DURABLE_CLAIM,
        "EVIDENCE_PROTECTED_STATE_EQUALITY": (
            EVIDENCE_PROTECTED_STATE_EQUALITY
        ),
    }


def _canonical(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _contract_payload():
    graph = {}
    terminal_states = []
    for state in sorted(STATE_GRAPH):
        graph[state] = list(STATE_GRAPH[state])
        if len(STATE_GRAPH[state]) == 0:
            terminal_states.append(state)
    guarded_edges = []
    for edge in sorted(GUARDED_EDGES):
        guarded_edges.append(
            [edge[0], edge[1], list(GUARDED_EDGES[edge])]
        )
    observation_edges = []
    for edge in sorted(EDGE_OBSERVATION_REQUIREMENTS):
        observation_edges.append(
            [
                edge[0],
                edge[1],
                list(EDGE_OBSERVATION_REQUIREMENTS[edge]),
            ]
        )
    return {
        "schema": CONTRACT_SCHEMA,
        "result_schema": RESULT_SCHEMA,
        "intent_schema": INTENT_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "policies": {
            "host_evidence_policy": HOST_EVIDENCE_POLICY,
            "migration_policy": MIGRATION_POLICY,
            "downgrade_policy": DOWNGRADE_POLICY,
            "layout_schema": LAYOUT_SCHEMA,
            "layout_mode": LAYOUT_MODE,
            "expected_layout_contract_id": EXPECTED_LAYOUT_CONTRACT_ID,
            "host_evidence_receipt_schema": HOST_EVIDENCE_RECEIPT_SCHEMA,
            "host_evidence_purpose": HOST_EVIDENCE_PURPOSE,
        },
        "state_policy": {
            "state_constants": _state_constant_map(),
            "initial_state": INITIAL_STATE,
            "initial_state_authorized": False,
            "graph": graph,
            "terminal_states": terminal_states,
            "pivot_state": PIVOT_STATE,
            "pivot_semantics": (
                "first-candidate-owned-durable-authority-write-claim"
            ),
            "release_commit_semantics": (
                "final-publication-floor-intent-never-weakens-pivot"
            ),
            "post_pivot_states": list(POST_PIVOT_STATES),
            "reconciliation_states": list(RECONCILIATION_STATES),
            "unknown_pivot_outcome_edges": [
                list(edge) for edge in UNKNOWN_PIVOT_OUTCOME_EDGES
            ],
            "post_pivot_forward_only_semantics": {
                "true": "next-state-is-post-pivot",
                "false": "pivot-absence-proven-or-pre-no-return",
                "null": "pivot-outcome-unknown-reconciliation-required",
            },
            "guarded_edges": guarded_edges,
        },
        "no_return_policy": {
            "state": NO_RETURN_STATE,
            "rules": list(NO_RETURN_POLICY),
            "candidate_writer_fenced": True,
            "automatic_predecessor_fallback_after_state": False,
        },
        "rollback_policy": {
            "dispositions": {
                state: ROLLBACK_DISPOSITIONS[state]
                for state in sorted(ROLLBACK_DISPOSITIONS)
            },
            "forward_only_after_pivot": True,
            "never_restores": list(ROLLBACK_NEVER_RESTORES),
        },
        "intent_policy": {
            "keys": sorted(_intent_key_set()),
            "fixed_values": {
                key: _INTENT_FIXED[key] for key in sorted(_INTENT_FIXED)
            },
            "grammars": {
                key: {
                    "pattern": _INTENT_PATTERNS[key].pattern,
                    "flags": int(_INTENT_PATTERNS[key].flags),
                }
                for key in sorted(_INTENT_PATTERNS)
            },
            "integer_keys": sorted(_INTENT_INTEGER_KEYS),
            "integer_minimum": 1,
            "integer_maximum": MAX_INT,
            "equality_requirements": [
                [left, right]
                for left, right in _INTENT_EQUALITY_REQUIREMENTS
            ],
            "max_string_chars": MAX_INTENT_STRING_CHARS,
            "ascii_only": True,
            "exact_builtin_types_required": True,
            "ids_and_digests_only": True,
            "refreshable_gate_evidence_excluded": [
                "host_evidence_expires_at",
                "host_evidence_issued_at",
                "host_evidence_key_id",
                "host_evidence_sha256",
                "host_nonce",
                "minimum_authority_expires_at",
                "quiescence_evidence_sha256",
                "recovery_evidence_sha256",
                "protected_state_preimage_sha256",
            ],
        },
        "late_gate_observation_policy": {
            "schema": GATE_OBSERVATION_SCHEMA,
            "types": list(GATE_OBSERVATION_TYPES),
            "common_fields": list(_GATE_COMMON_FIELDS),
            "host_authority_fields": list(_GATE_HOST_AUTHORITY_FIELDS),
            "protected_state_fields": list(_GATE_PROTECTED_STATE_FIELDS),
            "protected_state_types": list(_GATE_PROTECTED_STATE_TYPES),
            "fields_by_type": {
                observation_type: sorted(
                    _gate_observation_key_set(observation_type)
                )
                for observation_type in GATE_OBSERVATION_TYPES
            },
            "string_grammars": {
                key: {
                    "pattern": pattern.pattern,
                    "flags": int(pattern.flags),
                }
                for key, pattern in sorted(
                    _GATE_OBSERVATION_STRING_PATTERNS.items()
                )
            },
            "host_authority_rules": [
                "expires_at>observed_at>=issued_at",
                "minimum_authority_expires_at>observed_at",
                "minimum_authority_expires_at<=expires_at",
            ],
            "host_authority_required_before_states": [
                STATE_QUIESCE_INTENT,
                STATE_SWITCH_INTENT,
                STATE_PIVOT_INTENT,
                STATE_CLIENTS_PUBLISH_INTENT,
                STATE_RELEASE_COMMIT_INTENT,
            ],
            "quiescence_fields": [
                *_GATE_PROTECTED_STATE_FIELDS,
            ],
            "quiescence_produced_after_state": STATE_QUIESCE_INTENT,
            "quiescence_required_before_state": STATE_QUIESCENT_OBSERVED,
            "recovery_readiness_fields": [
                *_GATE_PROTECTED_STATE_FIELDS,
            ],
            "recovery_readiness_required_before_state": (
                STATE_QUIESCE_INTENT
            ),
            "candidate_health_required_before_state": (
                STATE_CANDIDATE_HEALTHY
            ),
            "binding_publication_required_before_state": PIVOT_STATE,
            "memory_equivalence_required_before_state": (
                STATE_POST_UPDATE_EQUIVALENT
            ),
            "client_convergence_required_before_state": (
                STATE_CLIENTS_CONVERGED
            ),
            "floor_record_required_before_state": STATE_FLOOR_RECORDED,
            "edge_observation_requirements": observation_edges,
            "observation_hash_domain": (
                _GATE_OBSERVATION_HASH_DOMAIN.decode("ascii")
            ),
            "observation_hash_form": "sha256-hex",
            "transaction_and_edge_bound": True,
            "observed_state_entry_bound": True,
            "public_results_include_validated_metadata_and_digests": True,
            "journal_must_persist_exact_observation_documents": True,
            "journal_must_revalidate_observation_before_append": True,
            "host_authority_observation_must_immediately_precede_edge": True,
            "cross_entry_protected_state_rule": (
                "recovery-readiness-and-quiescence-and-rollback-"
                "equality-preimages-must-match"
            ),
            "protected_state_lineage_policy": {
                "field": "protected_state_preimage_sha256",
                "types": list(_GATE_PROTECTED_STATE_TYPES),
                "journal_must_compare_prior_observations": True,
            },
            "shape_validation_is_not_evidence_verification": True,
            "refresh_preserves_transaction_id": True,
            "persisted_as_typed_journal_entries": True,
        },
        "limits": {
            "max_int": MAX_INT,
            "max_result_bytes": MAX_RESULT_BYTES,
            "max_state_chars": MAX_STATE_CHARS,
            "max_output_depth": MAX_OUTPUT_DEPTH,
            "max_output_items": MAX_OUTPUT_ITEMS,
            "max_output_string_chars": MAX_OUTPUT_STRING_CHARS,
        },
        "canonicalization": {
            "hash_algorithm": "sha256",
            "rule": "json-sorted-keys-compact-ascii",
        },
        "transaction_policy": {
            "domain": _TRANSACTION_ID_DOMAIN.decode("ascii"),
            "form": "transaction-<sha256-hex>",
            "caller_selected": False,
            "binds": ["activation_contract_id", "intent"],
            "intent_hash_domain": _INTENT_HASH_DOMAIN.decode("ascii"),
            "intent_hash_form": "sha256-hex",
        },
        "contract_id_domain": (
            _ACTIVATION_CONTRACT_ID_DOMAIN.decode("ascii")
        ),
        "transition_input_policy": {
            "evidence_field_constants": _evidence_field_constant_map(),
            "guarded_edges": guarded_edges,
            "edge_observation_requirements": observation_edges,
            "gate_observation_types": list(GATE_OBSERVATION_TYPES),
            "gate_observation_map_policy": {
                "exact_builtin_dict_required": True,
                "exact_builtin_string_keys_required": True,
                "input_values_are_exact_builtin_documents": True,
                "output_digest_grammar": {
                    "pattern": _HEX64_PATTERN.pattern,
                    "flags": int(_HEX64_PATTERN.flags),
                },
                "input_values_are_typed_observation_documents": True,
                "output_values_are_recomputed_observation_digests": True,
                "missing_required_status": STATUS_DENIED,
                "malformed_or_irrelevant_status": STATUS_UNSUPPORTED,
            },
            "missing_required_evidence_status": STATUS_DENIED,
            "malformed_or_irrelevant_evidence_status": STATUS_UNSUPPORTED,
            "exact_builtin_types_required": True,
        },
        "result_policy": {
            "command_constants": [
                COMMAND_PLAN,
                COMMAND_VALIDATE,
                COMMAND_RENDER,
            ],
            "status_constants": [
                STATUS_PROJECTED,
                STATUS_PLANNED,
                STATUS_VALID,
                STATUS_DENIED,
                STATUS_UNSUPPORTED,
            ],
            "base_fields": list(_RESULT_BASE_FIELDS),
            "identity_fields": list(_RESULT_IDENTITY_FIELDS),
            "false_flag_fields": list(ALWAYS_FALSE_FLAGS),
            "trailer_fields": list(_RESULT_TRAILER_FIELDS),
            "keys": sorted(_result_key_set()),
            "commands": {
                command: list(_COMMAND_STATUS_POLICY[command])
                for command in sorted(_COMMAND_STATUS_POLICY)
            },
            "statuses": sorted(_EXIT_CODE_POLICY),
            "success_statuses": list(_SUCCESS_STATUSES),
            "exit_codes": {
                status: _EXIT_CODE_POLICY[status]
                for status in sorted(_EXIT_CODE_POLICY)
            },
            "exact_reasons": list(_EXACT_REASONS),
            "denial_reasons": list(_DENIAL_REASONS),
            "unsupported_reason_grammar": {
                "pattern": _REASON_PATTERN.pattern,
                "flags": int(_REASON_PATTERN.flags),
            },
            "unsupported_reason_policy": {
                "fixed_by_command": {
                    command: list(
                        _UNSUPPORTED_FIXED_REASONS_BY_COMMAND[command]
                    )
                    for command in sorted(
                        _UNSUPPORTED_FIXED_REASONS_BY_COMMAND
                    )
                },
                "dynamic": [
                    {
                        "prefix": "unsupported:intent-field-invalid:",
                        "commands": [COMMAND_PLAN, COMMAND_VALIDATE],
                        "suffixes": sorted(_intent_key_set()),
                    },
                    {
                        "prefix": "unsupported:intent-binding-mismatch:",
                        "commands": [COMMAND_PLAN, COMMAND_VALIDATE],
                        "suffixes": sorted(
                            left
                            for left, _right in (
                                _INTENT_EQUALITY_REQUIREMENTS
                            )
                        ),
                    },
                ],
                "exact_command_match_required": True,
            },
            "transaction_id_grammar": {
                "pattern": _TRANSACTION_ID_PATTERN.pattern,
                "flags": int(_TRANSACTION_ID_PATTERN.flags),
            },
            "planned_result_bindings": {
                key: _PLAN_RESULT_BINDINGS[key]
                for key in sorted(_PLAN_RESULT_BINDINGS)
            },
            "planned_result_recomputes": [
                "intent_sha256",
                "transaction_id",
            ],
            "projection_renderable": True,
            "closed_native_shape_required": True,
            "unknown_fields_rejected": True,
            "invalid_output_redacted": True,
            "status_field_policy": {
                "planned": (
                    "stable-intent-and-derived-identities;transition-"
                    "fields-null;initial-and-disposition-pinned"
                ),
                "valid": (
                    "stable-intent-and-derived-transaction;legal-edge;"
                    "typed-observation-metadata-and-digests;"
                    "reason-disposition-and-"
                    "post-pivot-tristate-derived"
                ),
                "denied": (
                    "stable-intent-and-derived-transaction;current-next;"
                    "validated-partial-typed-observation-metadata-and-"
                    "digests;exact-denial-recomputed"
                ),
                "unsupported": (
                    "all-identities-null;command-scoped-bounded-token-"
                    "reason"
                ),
            },
        },
        "always_false_flags": list(ALWAYS_FALSE_FLAGS),
        "requirements": list(REQUIREMENTS),
        "nonclaims": list(NONCLAIMS),
    }


def _activation_contract_id():
    payload = _contract_payload()
    digest = hashlib.sha256(
        _ACTIVATION_CONTRACT_ID_DOMAIN + _canonical(payload).encode("ascii")
    ).hexdigest()
    return "activation-contract-" + digest


def activation_contract_projection():
    """Return the closed deterministic activation contract projection."""
    projection = _contract_payload()
    projection["status"] = STATUS_PROJECTED
    projection["reason"] = "projected:activation-contract"
    projection["activation_contract_id"] = _activation_contract_id()
    return projection


def _result(command, status, reason, **fields):
    result = {
        "schema": RESULT_SCHEMA,
        "mode": MODE,
        "command": command,
        "status": status,
        "reason": reason,
        "activation_contract_id": _activation_contract_id(),
        "pivot_state": PIVOT_STATE,
    }
    for key in _RESULT_IDENTITY_FIELDS:
        result[key] = fields.get(key)
    for flag in ALWAYS_FALSE_FLAGS:
        result[flag] = False
    result["requirements"] = list(REQUIREMENTS)
    result["nonclaims"] = list(NONCLAIMS)
    return result


def _guard(command, work):
    try:
        try:
            return work()
        except _Unsupported:
            raise
        except _Denied:
            raise
        except Exception:
            raise _Unsupported("internal-error")
    except _Denied as denial:
        fields = dict(denial.fields)
        fields["current_state"] = denial.current_state
        fields["next_state"] = denial.next_state
        return _result(
            command,
            STATUS_DENIED,
            "denied:" + denial.token,
            **fields,
        )
    except _Unsupported as refusal:
        return _result(
            command, STATUS_UNSUPPORTED, "unsupported:" + refusal.token
        )


def _intent_key_set():
    keys = set(_INTENT_INTEGER_KEYS)
    for key in _INTENT_FIXED:
        keys.add(key)
    for key in _INTENT_PATTERNS:
        keys.add(key)
    return keys


def _result_key_set():
    keys = set(_RESULT_BASE_FIELDS)
    keys.update(_RESULT_IDENTITY_FIELDS)
    keys.update(ALWAYS_FALSE_FLAGS)
    keys.update(_RESULT_TRAILER_FIELDS)
    return keys


def _intent_string(value, key):
    if type(value) is not str:
        raise _Unsupported("intent-field-invalid:" + key)
    if len(value) > MAX_INTENT_STRING_CHARS:
        raise _Unsupported("intent-field-invalid:" + key)
    if not value.isascii():
        raise _Unsupported("intent-field-invalid:" + key)
    return value


def _intent_integer(value, key):
    if type(value) is not int:
        raise _Unsupported("intent-field-invalid:" + key)
    if value < 1 or value > MAX_INT:
        raise _Unsupported("intent-field-invalid:" + key)
    return value


def _validate_intent(intent):
    if type(intent) is not dict:
        raise _Unsupported("intent-type-invalid")
    expected_count = (
        len(_INTENT_FIXED) + len(_INTENT_PATTERNS) + len(_INTENT_INTEGER_KEYS)
    )
    # Cardinality gate before any key scan: oversized inputs are rejected
    # without iteration and without executing subclass hooks.
    if len(intent) != expected_count:
        raise _Unsupported("intent-key-count-invalid")
    for key in intent:
        if type(key) is not str:
            raise _Unsupported("intent-key-type-invalid")
    if set(intent) != _intent_key_set():
        raise _Unsupported("intent-keys-invalid")
    validated = {}
    for key in sorted(_intent_key_set()):
        value = intent[key]
        if key in _INTENT_INTEGER_KEYS:
            validated[key] = _intent_integer(value, key)
            continue
        text = _intent_string(value, key)
        if key in _INTENT_FIXED:
            if text != _INTENT_FIXED[key]:
                raise _Unsupported("intent-field-invalid:" + key)
        elif _INTENT_PATTERNS[key].fullmatch(text) is None:
            raise _Unsupported("intent-field-invalid:" + key)
        validated[key] = text
    for left, right in _INTENT_EQUALITY_REQUIREMENTS:
        if validated[left] != validated[right]:
            raise _Unsupported("intent-binding-mismatch:" + left)
    return validated


def _transaction_id(contract_id, validated_intent):
    payload = {
        "activation_contract_id": contract_id,
        "intent": validated_intent,
    }
    digest = hashlib.sha256(
        _TRANSACTION_ID_DOMAIN + _canonical(payload).encode("ascii")
    ).hexdigest()
    return "transaction-" + digest


def _intent_sha256(validated_intent):
    return hashlib.sha256(
        _INTENT_HASH_DOMAIN + _canonical(validated_intent).encode("ascii")
    ).hexdigest()


def _plan(intent):
    validated = _validate_intent(intent)
    contract_id = _activation_contract_id()
    transaction = _transaction_id(contract_id, validated)
    return _result(
        COMMAND_PLAN,
        STATUS_PLANNED,
        "planned:activation-intent-bound",
        transaction_id=transaction,
        intent_sha256=_intent_sha256(validated),
        intent=validated,
        activation_nonce=validated["activation_nonce"],
        idempotency_key_sha256=validated["idempotency_key_sha256"],
        channel=validated["channel"],
        version=validated["version"],
        release_sequence=validated["release_sequence"],
        trust_generation=validated["trust_generation"],
        source_sha=validated["source_sha"],
        inventory_policy_id=validated["inventory_policy_id"],
        current_source_build_id=validated["current_source_build_id"],
        candidate_source_build_id=validated["candidate_source_build_id"],
        current_product_id=validated["current_product_id"],
        candidate_product_id=validated["candidate_product_id"],
        layout_contract_id=validated["layout_contract_id"],
        layout_id=validated["layout_id"],
        trust_bundle_sha256=validated["trust_bundle_sha256"],
        release_envelope_sha256=validated["release_envelope_sha256"],
        compatibility_ticket_sha256=validated["compatibility_ticket_sha256"],
        compatibility_result_sha256=validated["compatibility_result_sha256"],
        surfaces_digest=validated["surfaces_digest"],
        declared_initial_state=INITIAL_STATE,
        rollback_disposition=ROLLBACK_DISPOSITIONS[INITIAL_STATE],
        post_pivot_forward_only=False,
    )


def plan_activation_intent(intent):
    """Bind an activation intent to a derived transaction identity."""
    return _guard(COMMAND_PLAN, lambda: _plan(intent))


def _state(value, token):
    if type(value) is not str:
        raise _Unsupported(token)
    if len(value) > MAX_STATE_CHARS:
        raise _Unsupported(token)
    if value not in STATE_GRAPH:
        raise _Unsupported(token)
    return value


def _gate_observation_key_set(observation_type):
    keys = set(_GATE_COMMON_FIELDS)
    if observation_type == "host-authority":
        keys.update(_GATE_HOST_AUTHORITY_FIELDS)
    if observation_type in _GATE_PROTECTED_STATE_TYPES:
        keys.update(_GATE_PROTECTED_STATE_FIELDS)
    return keys


def _gate_observation_integer(value, observation_type):
    if type(value) is not int or value < 1 or value > MAX_INT:
        raise _Unsupported(
            "gate-observation-invalid:" + observation_type
        )
    return value


def _validate_gate_observation(
    document,
    observation_type,
    transaction_id,
    current_state,
    next_state,
):
    token = "gate-observation-invalid:" + observation_type
    if type(document) is not dict:
        raise _Unsupported(token)
    expected_keys = _gate_observation_key_set(observation_type)
    if len(document) != len(expected_keys):
        raise _Unsupported(token)
    for key in document:
        if type(key) is not str:
            raise _Unsupported(token)
    if set(document) != expected_keys:
        raise _Unsupported(token)
    if type(document["schema"]) is not str:
        raise _Unsupported(token)
    if document["schema"] != GATE_OBSERVATION_SCHEMA:
        raise _Unsupported(token)
    fixed_strings = {
        "transaction_id": transaction_id,
        "from_state": current_state,
        "to_state": next_state,
        "observation_type": observation_type,
    }
    for key, expected in fixed_strings.items():
        if type(document[key]) is not str or document[key] != expected:
            raise _Unsupported(token)
    for key in ("evidence_sha256", "observed_state_entry_sha256"):
        value = document[key]
        if type(value) is not str:
            raise _Unsupported(token)
        if _GATE_OBSERVATION_STRING_PATTERNS[key].fullmatch(value) is None:
            raise _Unsupported(token)
    observed_at = _gate_observation_integer(
        document["observed_at"], observation_type
    )
    if observation_type == "host-authority":
        key_id = document["host_evidence_key_id"]
        nonce = document["host_nonce"]
        if type(key_id) is not str:
            raise _Unsupported(token)
        if (
            _GATE_OBSERVATION_STRING_PATTERNS[
                "host_evidence_key_id"
            ].fullmatch(key_id)
            is None
        ):
            raise _Unsupported(token)
        if type(nonce) is not str:
            raise _Unsupported(token)
        if (
            _GATE_OBSERVATION_STRING_PATTERNS["host_nonce"].fullmatch(
                nonce
            )
            is None
        ):
            raise _Unsupported(token)
        issued_at = _gate_observation_integer(
            document["issued_at"], observation_type
        )
        expires_at = _gate_observation_integer(
            document["expires_at"], observation_type
        )
        minimum_expires_at = _gate_observation_integer(
            document["minimum_authority_expires_at"], observation_type
        )
        if not (
            issued_at <= observed_at < expires_at
            and observed_at < minimum_expires_at <= expires_at
        ):
            raise _Unsupported(token)
    if observation_type in _GATE_PROTECTED_STATE_TYPES:
        preimage = document["protected_state_preimage_sha256"]
        if type(preimage) is not str:
            raise _Unsupported(token)
        if (
            _GATE_OBSERVATION_STRING_PATTERNS[
                "protected_state_preimage_sha256"
            ].fullmatch(preimage)
            is None
        ):
            raise _Unsupported(token)
    return {key: document[key] for key in sorted(expected_keys)}


def _gate_observation_sha256(validated_observation):
    return hashlib.sha256(
        _GATE_OBSERVATION_HASH_DOMAIN
        + _canonical(validated_observation).encode("ascii")
    ).hexdigest()


def _transition_observations(
    value,
    required_types,
    transaction_id,
    current_state,
    next_state,
):
    if value is None:
        value = {}
    if type(value) is not dict:
        raise _Unsupported("gate-observation-map-invalid")
    if len(value) > len(GATE_OBSERVATION_TYPES):
        raise _Unsupported("gate-observation-map-invalid")
    for key in value:
        if type(key) is not str:
            raise _Unsupported("gate-observation-map-invalid")
    allowed = set(GATE_OBSERVATION_TYPES)
    provided_types = set(value)
    if not provided_types.issubset(allowed):
        raise _Unsupported("gate-observation-map-invalid")
    required_set = set(required_types)
    irrelevant = provided_types - required_set
    if irrelevant:
        raise _Unsupported(
            "gate-observation-not-applicable:" + sorted(irrelevant)[0]
        )
    documents = {}
    digests = {}
    for observation_type in sorted(provided_types):
        validated = _validate_gate_observation(
            value[observation_type],
            observation_type,
            transaction_id,
            current_state,
            next_state,
        )
        documents[observation_type] = validated
        digests[observation_type] = _gate_observation_sha256(validated)
    missing = required_set - provided_types
    if missing:
        raise _Denied(
            "gate-observation-required:" + sorted(missing)[0],
            current_state,
            next_state,
            fields={
                "gate_observations_by_type": documents,
                "gate_observation_sha256_by_type": digests,
            },
        )
    return documents, digests


def _post_pivot_forward_only_value(current_state, next_state):
    if (current_state, next_state) in UNKNOWN_PIVOT_OUTCOME_EDGES:
        return None
    if next_state in POST_PIVOT_STATES:
        return True
    return False


def _transition_reason(current_state, next_state):
    required = GUARDED_EDGES.get((current_state, next_state), ())
    if required == (EVIDENCE_NO_DURABLE_CLAIM,):
        return (
            "valid:rollback-intent-admitted-after-no-durable-claim-evidence"
        )
    if required == (EVIDENCE_PROTECTED_STATE_EQUALITY,):
        if next_state == STATE_CONTROL_PLANE_ROLLED_BACK:
            return (
                "valid:control-plane-rollback-recorded-after-"
                "protected-state-equality-evidence"
            )
        return (
            "valid:rollback-intent-admitted-after-"
            "protected-state-equality-evidence"
        )
    return "valid:transition-allowed"


def _validate_transition(
    current_state,
    next_state,
    activation_intent,
    gate_observations_by_type,
):
    validated_intent = _validate_intent(activation_intent)
    contract_id = _activation_contract_id()
    transaction_id = _transaction_id(contract_id, validated_intent)
    current = _state(current_state, "current-state-invalid")
    upcoming = _state(next_state, "next-state-invalid")
    edge = (current, upcoming)
    denial_fields = {
        "transaction_id": transaction_id,
        "intent_sha256": _intent_sha256(validated_intent),
        "intent": validated_intent,
        "gate_observations_by_type": {},
        "gate_observation_sha256_by_type": {},
    }
    successors = STATE_GRAPH[current]
    legal_edge = upcoming in successors
    try:
        observation_documents, observation_digests = (
            _transition_observations(
                gate_observations_by_type,
                (
                    EDGE_OBSERVATION_REQUIREMENTS.get(edge, ())
                    if legal_edge
                    else ()
                ),
                transaction_id,
                current,
                upcoming,
            )
        )
    except _Denied as denial:
        fields = dict(denial_fields)
        fields.update(denial.fields)
        denial.fields = fields
        raise
    denial_fields["gate_observations_by_type"] = observation_documents
    denial_fields["gate_observation_sha256_by_type"] = observation_digests
    if len(successors) == 0:
        raise _Denied(
            "terminal-state", current, upcoming, fields=denial_fields
        )
    if not legal_edge:
        raise _Denied(
            "illegal-transition", current, upcoming, fields=denial_fields
        )
    reason = _transition_reason(current, upcoming)
    return _result(
        COMMAND_VALIDATE,
        STATUS_VALID,
        reason,
        transaction_id=transaction_id,
        intent_sha256=_intent_sha256(validated_intent),
        intent=validated_intent,
        current_state=current,
        next_state=upcoming,
        rollback_disposition=ROLLBACK_DISPOSITIONS[upcoming],
        post_pivot_forward_only=_post_pivot_forward_only_value(
            current, upcoming
        ),
        gate_observations_by_type=observation_documents,
        gate_observation_sha256_by_type=observation_digests,
    )


def validate_transition(
    current_state,
    next_state,
    *,
    activation_intent=None,
    gate_observations_by_type=None,
):
    """Adjudicate one journal edge on paper; authorizes nothing."""
    return _guard(
        COMMAND_VALIDATE,
        lambda: _validate_transition(
            current_state,
            next_state,
            activation_intent,
            gate_observations_by_type,
        ),
    )


def _closed_native_json(value, *, depth=0, budget=None):
    if budget is None:
        budget = [MAX_OUTPUT_ITEMS]
    if depth > MAX_OUTPUT_DEPTH or budget[0] < 1:
        return False
    budget[0] -= 1
    value_type = type(value)
    if value is None or value_type is bool:
        return True
    if value_type is int:
        return -MAX_INT <= value <= MAX_INT
    if value_type is str:
        return (
            len(value) <= MAX_OUTPUT_STRING_CHARS and value.isascii()
        )
    if value_type is list:
        if len(value) > MAX_OUTPUT_ITEMS:
            return False
        for item in value:
            if not _closed_native_json(
                item, depth=depth + 1, budget=budget
            ):
                return False
        return True
    if value_type is dict:
        if len(value) > MAX_OUTPUT_ITEMS:
            return False
        for key in value:
            if type(key) is not str:
                return False
            if (
                len(key) > MAX_OUTPUT_STRING_CHARS
                or not key.isascii()
                or budget[0] < 1
            ):
                return False
            budget[0] -= 1
        for key in value:
            if not _closed_native_json(
                value[key], depth=depth + 1, budget=budget
            ):
                return False
        return True
    return False


def _matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _result_identity_valid(key, value):
    if value is None:
        return True
    if key == "intent":
        try:
            return _validate_intent(value) == value
        except _Unsupported:
            return False
    if key == "intent_sha256":
        return _matches(_HEX64_PATTERN, value)
    if key == "gate_observations_by_type":
        return type(value) is dict
    if key == "gate_observation_sha256_by_type":
        if type(value) is not dict:
            return False
        if len(value) > len(GATE_OBSERVATION_TYPES):
            return False
        for observation_type in value:
            if type(observation_type) is not str:
                return False
        if not set(value).issubset(set(GATE_OBSERVATION_TYPES)):
            return False
        digests = []
        for observation_type in value:
            digest = value[observation_type]
            if not _matches(_HEX64_PATTERN, digest):
                return False
            digests.append(digest)
        return len(digests) == len(set(digests))
    if key == "transaction_id":
        return _matches(_TRANSACTION_ID_PATTERN, value)
    if key in _INTENT_PATTERNS:
        return _matches(_INTENT_PATTERNS[key], value)
    if key in _INTENT_FIXED:
        return type(value) is str and value == _INTENT_FIXED[key]
    if key in _INTENT_INTEGER_KEYS:
        return type(value) is int and 1 <= value <= MAX_INT
    if key == "declared_initial_state":
        return type(value) is str and value == INITIAL_STATE
    if key in ("current_state", "next_state"):
        return type(value) is str and value in STATE_GRAPH
    if key == "rollback_disposition":
        return type(value) is str and value in set(
            ROLLBACK_DISPOSITIONS.values()
        )
    if key == "post_pivot_forward_only":
        return type(value) is bool
    return False


def _valid_result_reason(command, status, reason):
    if type(reason) is not str or len(reason) > 192:
        return False
    if _REASON_PATTERN.fullmatch(reason) is None:
        return False
    if status == STATUS_PLANNED:
        return command == COMMAND_PLAN and reason == _EXACT_REASONS[0]
    if status == STATUS_VALID:
        return command == COMMAND_VALIDATE and reason in _EXACT_REASONS
    if status == STATUS_DENIED:
        return command == COMMAND_VALIDATE and reason in _DENIAL_REASONS
    if status == STATUS_UNSUPPORTED:
        if reason in _UNSUPPORTED_FIXED_REASONS_BY_COMMAND[command]:
            return True
        if command not in (COMMAND_PLAN, COMMAND_VALIDATE):
            return False
        field_prefix = "unsupported:intent-field-invalid:"
        if reason.startswith(field_prefix):
            return reason[len(field_prefix) :] in _intent_key_set()
        binding_prefix = "unsupported:intent-binding-mismatch:"
        if reason.startswith(binding_prefix):
            allowed = {
                left for left, _right in _INTENT_EQUALITY_REQUIREMENTS
            }
            return reason[len(binding_prefix) :] in allowed
        return False
    return False


def _valid_result_document(result):
    if type(result) is not dict:
        return False
    if len(result) != len(_result_key_set()):
        return False
    for key in result:
        if type(key) is not str:
            return False
    if set(result) != _result_key_set():
        return False
    if not _closed_native_json(result):
        return False
    if result["schema"] != RESULT_SCHEMA or result["mode"] != MODE:
        return False
    if result["activation_contract_id"] != _activation_contract_id():
        return False
    if result["pivot_state"] != PIVOT_STATE:
        return False
    if result["requirements"] != list(REQUIREMENTS):
        return False
    if result["nonclaims"] != list(NONCLAIMS):
        return False
    for flag in ALWAYS_FALSE_FLAGS:
        if result[flag] is not False:
            return False
    command = result["command"]
    status = result["status"]
    if type(command) is not str or command not in _COMMAND_STATUS_POLICY:
        return False
    if type(status) is not str:
        return False
    if status not in _COMMAND_STATUS_POLICY[command]:
        return False
    if not _valid_result_reason(command, status, result["reason"]):
        return False
    for key in _RESULT_IDENTITY_FIELDS:
        if not _result_identity_valid(key, result[key]):
            return False
    populated = {
        key for key in _RESULT_IDENTITY_FIELDS if result[key] is not None
    }
    if status == STATUS_UNSUPPORTED:
        return not populated
    if status == STATUS_DENIED:
        expected_result = _guard(
            COMMAND_VALIDATE,
            lambda: _validate_transition(
                result["current_state"],
                result["next_state"],
                result["intent"],
                result["gate_observations_by_type"],
            ),
        )
        return (
            expected_result["status"] == STATUS_DENIED
            and result == expected_result
        )
    if status == STATUS_PLANNED:
        expected = set(_RESULT_IDENTITY_FIELDS) - {
            "current_state",
            "next_state",
            "gate_observations_by_type",
            "gate_observation_sha256_by_type",
        }
        intent = result["intent"]
        try:
            validated_intent = _validate_intent(intent)
        except _Unsupported:
            return False
        if validated_intent != intent:
            return False
        if result["intent_sha256"] != _intent_sha256(validated_intent):
            return False
        if result["transaction_id"] != _transaction_id(
            _activation_contract_id(), validated_intent
        ):
            return False
        for result_key, intent_key in _PLAN_RESULT_BINDINGS.items():
            if result[result_key] != validated_intent[intent_key]:
                return False
        return (
            populated == expected
            and result["declared_initial_state"] == INITIAL_STATE
            and result["rollback_disposition"]
            == ROLLBACK_DISPOSITIONS[INITIAL_STATE]
            and result["post_pivot_forward_only"] is False
        )
    if status == STATUS_VALID:
        try:
            expected_result = _validate_transition(
                result["current_state"],
                result["next_state"],
                result["intent"],
                result["gate_observations_by_type"],
            )
        except (_Unsupported, _Denied, KeyError, TypeError):
            return False
        return result == expected_result
    return False


def _valid_projection_document(result):
    if type(result) is not dict or not _closed_native_json(result):
        return False
    expected = activation_contract_projection()
    if len(result) != len(expected):
        return False
    for key in result:
        if type(key) is not str:
            return False
    return result == expected


def render_result(result):
    """Render a result as bounded canonical one-line JSON; never raises."""
    token = "result-not-renderable"
    if _valid_result_document(result) or _valid_projection_document(result):
        try:
            rendered = _canonical(result)
        except Exception:
            rendered = None
        if rendered is not None:
            if len(rendered) <= MAX_RESULT_BYTES and "\n" not in rendered:
                return rendered
            token = "output-oversize"
    fallback = _result(
        COMMAND_RENDER, STATUS_UNSUPPORTED, "unsupported:" + token
    )
    return _canonical(fallback)


def result_exit_code(result):
    """Total fail-closed exit-code mapping: 0 success, 3 denied, 2 other."""
    if _valid_projection_document(result):
        return _EXIT_CODE_POLICY[STATUS_PROJECTED]
    if not _valid_result_document(result):
        return 2
    return _EXIT_CODE_POLICY.get(result["status"], 2)


# ---------------------------------------------------------------------------
# 4B: dormant durable activation journal.
#
# This storage layer deliberately has its own contract, result vocabulary, and
# hash domains.  Nothing below is referenced by the frozen 4A projection or
# identity calculation above.

JOURNAL_CONTRACT_SCHEMA = (
    "synapse-s2.release-activation-journal-contract.v1"
)
JOURNAL_REQUEST_SCHEMA = (
    "synapse-s2.release-activation-journal-request.v1"
)
JOURNAL_ENTRY_SCHEMA = "synapse-s2.release-activation-journal-entry.v1"
JOURNAL_RESULT_SCHEMA = "synapse-s2.release-activation-journal-result.v1"
JOURNAL_MODE = "dormant-storage-only"

JOURNAL_SUBDIRECTORY = ".release-activation-journal-v1"
JOURNAL_LOCK_FILENAME = ".owner.lock"
JOURNAL_REQUEST_PREFIX = "request-"
JOURNAL_ENTRY_PREFIX = "entry-"
JOURNAL_DOCUMENT_SUFFIX = ".json"

MAX_JOURNAL_DOCUMENT_BYTES = 32768
MAX_JOURNAL_ENTRIES = 256
MAX_JOURNAL_SCAN_BYTES = 8 * 1024 * 1024
MAX_JOURNAL_PROJECTION_BYTES = MAX_RESULT_BYTES - 8192
MAX_JOURNAL_ROOT_BYTES = 4096
MAX_JOURNAL_ROOT_COMPONENTS = 64
MAX_JOURNAL_DIRECTORY_NAMES = MAX_JOURNAL_ENTRIES + 2

COMMAND_JOURNAL_PROJECT = "journal-contract-projection"
COMMAND_JOURNAL_BEGIN = "begin-activation-journal"
COMMAND_JOURNAL_APPEND = "append-activation-transition"
COMMAND_JOURNAL_INSPECT = "inspect-activation-journal"
COMMAND_JOURNAL_RENDER = "render-journal-result"

JOURNAL_STATUS_PROJECTED = "projected"
JOURNAL_STATUS_INITIALIZED = "initialized"
JOURNAL_STATUS_APPENDED = "appended"
JOURNAL_STATUS_INSPECTED = "inspected"
JOURNAL_STATUS_BLOCKED = "blocked"
JOURNAL_STATUS_DENIED = "denied"
JOURNAL_STATUS_CONFLICT = "conflict"
JOURNAL_STATUS_OUTCOME_UNKNOWN = "outcome_unknown"
JOURNAL_STATUS_UNSUPPORTED = "unsupported"

_JOURNAL_CONTRACT_ID_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-JOURNAL-CONTRACT\x00v1\x00"
)
_JOURNAL_REQUEST_HASH_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-JOURNAL-REQUEST\x00v1\x00"
)
_JOURNAL_ENTRY_HASH_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-JOURNAL-ENTRY\x00v1\x00"
)
_JOURNAL_TRANSITION_RESULT_HASH_DOMAIN = (
    b"SYNAPSE-S2\x00RELEASE-ACTIVATION-JOURNAL-TRANSITION-RESULT\x00v1\x00"
)

_JOURNAL_REQUIREMENTS = (
    "explicit-pre-existing-canonical-absolute-effective-uid-owned-0700-root",
    "root-path-byte-and-component-bounds-checked-before-io",
    "fixed-private-effective-uid-owned-0700-subdirectory",
    "descriptor-anchored-no-follow-file-access",
    "nonblocking-exclusive-effective-uid-owned-0600-lock",
    "one-exact-content-addressed-request-per-root",
    "immutable-exclusive-create-request-and-entry-files",
    "canonical-ascii-json-with-one-trailing-newline",
    "full-bounded-chain-rescan-before-and-after-publish",
    "unique-genesis-linear-chain-and-tip",
    "caller-and-observation-tip-equality",
    "strict-decision-and-observation-chronology",
    "host-authority-valid-through-decision",
    "protected-state-preimage-lineage",
    "directory-and-file-fsync-before-success",
    "possible-write-ambiguity-reported-as-outcome-unknown",
    "caller-allocates-one-root-per-activation-transaction",
    "global-active-transaction-exclusion-required-later",
)

_JOURNAL_NONCLAIMS = (
    "no-activation",
    "no-apply",
    "no-candidate-import-or-execution",
    "no-config-or-plist-publication",
    "close-or-unlock-failure-may-retain-fd-or-advisory-lock",
    "cleanup-failure-requires-caller-termination-or-manual-recovery",
    "no-data-rollback",
    "no-host-evidence-authentication",
    "no-cross-root-active-transaction-exclusion",
    "no-external-clock-attestation",
    "no-extended-acl-or-xattr-verification",
    "no-live-state-access",
    "no-malicious-preexisting-journal-authenticity",
    "no-memory-content-access",
    "no-memory-equivalence-verification",
    "no-network",
    "no-physical-storage-durability-proof",
    "no-owner-exclusivity-beyond-posix-mode-bits",
    "no-provenance-floor-mutation",
    "no-secret-access",
    "no-selector-or-binding-change",
    "no-service-control",
    "no-writer-quiescence",
)

_JOURNAL_FALSE_FLAGS = (
    "activation_supported",
    "activation_performed",
    "apply_supported",
    "apply_performed",
    "live_state_accessed",
    "live_state_modified",
    "service_modified",
    "config_modified",
    "selector_modified",
    "provenance_floor_modified",
    "rollback_performed",
    "host_evidence_verified",
    "memory_equivalence_verified",
    "extended_acl_verified",
)

_JOURNAL_RESULT_FIELDS = (
    "schema",
    "mode",
    "command",
    "status",
    "reason",
    "journal_contract_id",
    "activation_contract_id",
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
    "journal_read_supported",
    "journal_write_supported",
    "journal_read_performed",
    "journal_write_attempted",
    "journal_written",
) + _JOURNAL_FALSE_FLAGS + (
    "requirements",
    "nonclaims",
)

_JOURNAL_SUCCESS_STATUSES = (
    JOURNAL_STATUS_INITIALIZED,
    JOURNAL_STATUS_APPENDED,
    JOURNAL_STATUS_INSPECTED,
)

_JOURNAL_RESULT_REASONS = {
    COMMAND_JOURNAL_BEGIN: (
        "initialized:journal-created",
        "initialized:journal-already-initialized",
        "blocked:journal-busy",
        "blocked:journal-integrity-invalid",
        "blocked:journal-root-invalid",
        "conflict:activation-request-mismatch",
        "conflict:journal-tip-mismatch",
        "outcome_unknown:journal-write-outcome-unknown",
        "unsupported:internal-error",
        "unsupported:journal-platform-unsupported",
    ) + tuple(
        reason for reason in _INTENT_UNSUPPORTED_FIXED_REASONS
        if reason != "unsupported:internal-error"
    ),
    COMMAND_JOURNAL_APPEND: (
        "appended:transition-recorded",
        "appended:transition-already-recorded",
        "blocked:journal-busy",
        "blocked:journal-entry-limit",
        "blocked:journal-integrity-invalid",
        "blocked:journal-root-invalid",
        "blocked:journal-uninitialized",
        "blocked:journal-request-only",
        "conflict:activation-request-mismatch",
        "conflict:journal-tip-mismatch",
        "denied:host-authority-expired-at-decision",
        "denied:decision-clock-mismatch",
        "denied:decision-clock-regressed",
        "denied:observation-time-invalid",
        "denied:observation-tip-mismatch",
        "denied:protected-state-preimage-mismatch",
        "outcome_unknown:journal-write-outcome-unknown",
        "unsupported:decision-at-invalid",
        "unsupported:internal-error",
        "unsupported:journal-platform-unsupported",
        "unsupported:observed-state-entry-sha256-invalid",
    ) + tuple(
        "denied:" + reason[len("denied:") :]
        for reason in _DENIAL_REASONS
    ) + tuple(
        reason for reason in _VALIDATE_UNSUPPORTED_FIXED_REASONS
        if reason not in (
            "unsupported:current-state-invalid",
            "unsupported:internal-error",
        )
    ),
    COMMAND_JOURNAL_INSPECT: (
        "inspected:journal-consistent",
        "blocked:journal-busy",
        "blocked:journal-integrity-invalid",
        "blocked:journal-root-invalid",
        "blocked:journal-uninitialized",
        "blocked:journal-request-only",
        "conflict:activation-request-mismatch",
        "unsupported:internal-error",
        "unsupported:journal-platform-unsupported",
    ) + tuple(
        reason for reason in _INTENT_UNSUPPORTED_FIXED_REASONS
        if reason != "unsupported:internal-error"
    ),
    COMMAND_JOURNAL_RENDER: (
        "unsupported:journal-output-oversize",
        "unsupported:journal-result-not-renderable",
    ),
}

_JOURNAL_SUCCESS_RESULT_TRUTH = {
    "initialized:journal-created": {
        "profile": "genesis-tip",
        "read": True,
        "write_attempted": True,
        "written": True,
    },
    "initialized:journal-already-initialized": {
        "profile": "entry-tip",
        "read": True,
        "write_attempted": False,
        "written": False,
    },
    "appended:transition-recorded": {
        "profile": "positive-sequence-entry-tip",
        "read": True,
        "write_attempted": True,
        "written": True,
    },
    "appended:transition-already-recorded": {
        "profile": "positive-sequence-entry-history",
        "read": True,
        "write_attempted": False,
        "written": False,
    },
    "inspected:journal-consistent": {
        "profile": "entry-tip",
        "read": True,
        "write_attempted": False,
        "written": False,
    },
}

_JOURNAL_FAILURE_RESULT_TRUTH = {
    "default": {
        "write_attempted": False,
        "written": False,
    },
    "outcome_unknown": {
        "read": True,
        "write_attempted": True,
        "written": None,
    },
    "platform_unsupported": {
        "read_supported": False,
        "write_supported": False,
        "read": False,
        "write_attempted": False,
        "written": False,
    },
    "render_fallback": {
        "read_supported": True,
        "write_supported": True,
        "runtime_platform_support_required": True,
        "read": False,
        "write_attempted": False,
        "written": False,
    },
    "invalid_intent": {
        "read": False,
        "write_attempted": False,
        "written": False,
    },
    "root_invalid": {
        "read": False,
        "write_attempted": False,
        "written": False,
    },
    "request_only": {
        "read": True,
        "write_attempted": False,
        "written": False,
    },
    "internal_error": {
        "read": "false-or-true",
        "write_attempted": False,
        "written": False,
    },
}

_JOURNAL_IDENTITY_POPULATION_POLICY = {
    "transaction_and_intent": "both-null-or-both-populated",
    "request_requires_transaction_and_intent": True,
    "entry_requires_request": True,
    "entry_requires_sequence_from_to_tip": True,
    "no_entry_requires_entry_fields_null": True,
    "genesis_sequence": 0,
    "genesis_prior": None,
    "genesis_from": STATE_START,
    "genesis_to": STATE_PREPARED,
    "genesis_preimage": None,
    "positive_sequence_requires_prior": True,
    "positive_sequence_prior_differs_from_entry": True,
    "entry_requires_reachable_genesis_triple": True,
    "entry_requires_exact_protected_anchor_presence": True,
}

_JOURNAL_FAILURE_IDENTITY_SHAPES = {
    "none": ("000",),
    "intent": ("100",),
    "request": ("110",),
    "tip": ("111",),
    "none-or-intent": ("000", "100"),
    "intent-or-tip": ("100", "111"),
    "outcome": ("100", "110", "111"),
}

# The selector, value, optional command scope, and identity-shape profile are
# projected verbatim.  These rules take precedence over the compact per-command
# defaults and exceptions below.
_JOURNAL_FAILURE_IDENTITY_SPECIAL_RULES = (
    ("command", COMMAND_JOURNAL_RENDER, None, "none"),
    (
        "reason",
        "unsupported:journal-platform-unsupported",
        None,
        "none",
    ),
    ("status", JOURNAL_STATUS_OUTCOME_UNKNOWN, None, "outcome"),
    ("reason-prefix", "unsupported:intent-", None, "none"),
    ("reason", "blocked:journal-root-invalid", None, "intent"),
    ("reason", "blocked:journal-request-only", None, "request"),
    (
        "reason",
        "unsupported:internal-error",
        COMMAND_JOURNAL_BEGIN,
        "none-or-intent",
    ),
    (
        "reason",
        "unsupported:internal-error",
        COMMAND_JOURNAL_APPEND,
        "intent-or-tip",
    ),
    (
        "reason",
        "unsupported:internal-error",
        COMMAND_JOURNAL_INSPECT,
        "none-or-intent",
    ),
)

_JOURNAL_FAILURE_IDENTITY_DEFAULTS = {
    COMMAND_JOURNAL_BEGIN: "intent",
    COMMAND_JOURNAL_APPEND: "tip",
    COMMAND_JOURNAL_INSPECT: "intent",
}

_JOURNAL_FAILURE_IDENTITY_REASON_EXCEPTIONS = {
    COMMAND_JOURNAL_APPEND: {
        "intent": (
            "blocked:journal-busy",
            "blocked:journal-integrity-invalid",
            "blocked:journal-uninitialized",
            "conflict:activation-request-mismatch",
            "unsupported:decision-at-invalid",
            "unsupported:observed-state-entry-sha256-invalid",
        ),
        "intent-or-tip": (
            "conflict:journal-tip-mismatch",
        ),
    },
}

_JOURNAL_FAILURE_PROFILE_RULES = (
    {
        "profile": "render_fallback",
        "commands": [COMMAND_JOURNAL_RENDER],
    },
    {
        "profile": "platform_unsupported",
        "exact_reason": "unsupported:journal-platform-unsupported",
    },
    {
        "profile": "outcome_unknown",
        "status": JOURNAL_STATUS_OUTCOME_UNKNOWN,
    },
    {
        "profile": "invalid_intent",
        "reason_prefix": "unsupported:intent-",
    },
    {
        "profile": "root_invalid",
        "exact_reason": "blocked:journal-root-invalid",
    },
    {
        "profile": "request_only",
        "exact_reason": "blocked:journal-request-only",
    },
    {
        "profile": "internal_error",
        "exact_reason": "unsupported:internal-error",
    },
    {
        "profile": "default",
    },
)

_JOURNAL_REQUEST_FIELDS = (
    "schema",
    "journal_contract_id",
    "activation_contract_id",
    "transaction_id",
    "intent_sha256",
    "activation_intent",
    "journal_root_device",
    "journal_root_inode",
    "request_sha256",
)

_JOURNAL_ENTRY_FIELDS = (
    "schema",
    "journal_contract_id",
    "activation_contract_id",
    "transaction_id",
    "request_sha256",
    "sequence",
    "prior_entry_sha256",
    "from_state",
    "to_state",
    "decision_at",
    "gate_observations_by_type",
    "gate_observation_sha256_by_type",
    "transition_result_sha256",
    "protected_state_preimage_sha256",
    "entry_sha256",
)


class _JournalRefusal(Exception):
    """Closed storage refusal with explicit read/write truth values."""

    def __init__(
        self,
        status,
        token,
        *,
        read_performed=False,
        write_attempted=False,
        written=False,
        fields=None,
    ):
        super().__init__(token)
        self.status = status
        self.token = token
        self.read_performed = read_performed
        self.write_attempted = write_attempted
        self.written = written
        self.fields = {} if fields is None else fields


class _JournalWriteUnknown(_JournalRefusal):
    """A write may have become visible or durable; never guess otherwise."""

    def __init__(self, *, read_performed, fields=None):
        super().__init__(
            JOURNAL_STATUS_OUTCOME_UNKNOWN,
            "journal-write-outcome-unknown",
            read_performed=read_performed,
            write_attempted=True,
            written=None,
            fields=fields,
        )


def _journal_reachable_entry_truth():
    truth = {(0, STATE_START, STATE_PREPARED, False)}
    frontier = {(0, STATE_PREPARED, False)}
    seen = set(frontier)
    while frontier:
        upcoming_frontier = set()
        for sequence, current_state, anchor_present in sorted(frontier):
            next_sequence = sequence + 1
            if next_sequence >= MAX_JOURNAL_ENTRIES:
                continue
            for next_state in STATE_GRAPH[current_state]:
                next_anchor = anchor_present or (
                    current_state == STATE_PREPARED
                    and next_state == STATE_QUIESCE_INTENT
                )
                truth.add(
                    (
                        next_sequence,
                        current_state,
                        next_state,
                        next_anchor,
                    )
                )
                marker = (next_sequence, next_state, next_anchor)
                if marker not in seen:
                    seen.add(marker)
                    upcoming_frontier.add(marker)
        frontier = upcoming_frontier
    return tuple(sorted(truth))


def _journal_strict_descendants():
    descendants = {}
    for origin in sorted(STATE_GRAPH):
        reached = set()
        frontier = list(STATE_GRAPH[origin])
        while frontier:
            state = frontier.pop()
            if state == origin or state in reached:
                continue
            reached.add(state)
            frontier.extend(STATE_GRAPH[state])
        descendants[origin] = tuple(sorted(reached))
    return descendants


def _journal_reachable_tip_states():
    return {
        state: tuple(sorted((state,) + _journal_strict_descendants()[state]))
        for state in sorted(STATE_GRAPH)
    }


def _journal_contract_payload():
    edges = []
    for current in sorted(STATE_GRAPH):
        for upcoming in STATE_GRAPH[current]:
            edges.append([current, upcoming])
    return {
        "schema": JOURNAL_CONTRACT_SCHEMA,
        "mode": JOURNAL_MODE,
        "activation_contract_id": _activation_contract_id(),
        "document_schemas": {
            "request": JOURNAL_REQUEST_SCHEMA,
            "entry": JOURNAL_ENTRY_SCHEMA,
            "result": JOURNAL_RESULT_SCHEMA,
        },
        "storage": {
            "subdirectory": JOURNAL_SUBDIRECTORY,
            "lock_filename": JOURNAL_LOCK_FILENAME,
            "root_mode": "0700",
            "subdirectory_mode": "0700",
            "lock_mode": "0600",
            "document_mode": "0600",
            "request_filename": (
                JOURNAL_REQUEST_PREFIX + "<sha256>" + JOURNAL_DOCUMENT_SUFFIX
            ),
            "entry_filename": (
                JOURNAL_ENTRY_PREFIX + "<sha256>" + JOURNAL_DOCUMENT_SUFFIX
            ),
            "authoritative_mutable_head": False,
            "exclusive_create": True,
            "no_follow": True,
            "effective_uid_and_exact_posix_mode_only": True,
            "extended_acl_or_xattr_verified": False,
            "root_bounds_checked_before_io": True,
            "root_path_encoding": "utf-8-strict",
            "file_link_count": 1,
            "file_fsync": True,
            "directory_fsync": True,
            "canonical_ascii_json": True,
            "trailing_newline_bytes": 1,
            "required_platform_flags": list(
                _JOURNAL_REQUIRED_OS_FLAGS
            ),
            "required_platform_flag_type": "exact-int",
            "required_fcntl_capabilities": list(
                _JOURNAL_REQUIRED_FCNTL_CAPABILITIES
            ),
            "required_fcntl_lock_type": "exact-int",
            "required_fcntl_flock_callable": True,
            "required_os_callables": list(
                _JOURNAL_REQUIRED_OS_CALLABLES
            ),
            "dir_fd_open_required": True,
            "dir_fd_mkdir_required": True,
            "fd_scandir_required": True,
        },
        "hash_domains": {
            "contract": _JOURNAL_CONTRACT_ID_DOMAIN.decode("ascii"),
            "request": _JOURNAL_REQUEST_HASH_DOMAIN.decode("ascii"),
            "entry": _JOURNAL_ENTRY_HASH_DOMAIN.decode("ascii"),
            "transition_result": (
                _JOURNAL_TRANSITION_RESULT_HASH_DOMAIN.decode("ascii")
            ),
        },
        "limits": {
            "document_bytes": MAX_JOURNAL_DOCUMENT_BYTES,
            "entries": MAX_JOURNAL_ENTRIES,
            "directory_names": MAX_JOURNAL_DIRECTORY_NAMES,
            "scan_bytes": MAX_JOURNAL_SCAN_BYTES,
            "root_path_bytes": MAX_JOURNAL_ROOT_BYTES,
            "root_components": MAX_JOURNAL_ROOT_COMPONENTS,
            "rendered_result_bytes": MAX_RESULT_BYTES,
            "rendered_projection_bytes": MAX_JOURNAL_PROJECTION_BYTES,
        },
        "chain": {
            "genesis": [STATE_START, STATE_PREPARED],
            "genesis_sequence": 0,
            "genesis_decision_at": 0,
            "legal_edges": edges,
            "one_request": True,
            "one_genesis": True,
            "linear": True,
            "unique_child": True,
            "unique_tip": True,
            "orphan_allowed": False,
            "fork_allowed": False,
            "cycle_allowed": False,
            "full_rescan_each_operation": True,
            "reachable_entry_truth": [
                list(row) for row in _journal_reachable_entry_truth()
            ],
        },
        "temporal_policy": {
            "decision_strictly_increases": True,
            "new_decision_equals_initial_trusted_unix_time": True,
            "final_trusted_time_not_before_initial": True,
            "observation_after_prior_decision": True,
            "observation_not_after_decision": True,
            "host_decision_before_minimum_expiry": True,
            "host_authority_valid_through_final_trusted_time": True,
            "historical_rescan_uses_stored_chronology_only": True,
            "observation_binds_exact_prior_entry": True,
            "protected_state_anchor_type": "recovery-readiness",
            "protected_state_carried_across_entries": True,
        },
        "write_outcome_policy": {
            "not_attempted": False,
            "completed": True,
            "possibly_visible_or_durable": None,
        },
        "document_policy": {
            "request_fields": list(_JOURNAL_REQUEST_FIELDS),
            "entry_fields": list(_JOURNAL_ENTRY_FIELDS),
            "exact_builtin_types_required": True,
            "unknown_fields_rejected": True,
            "self_hash_and_filename_hash_required": True,
            "filename_grammars": {
                "request": {
                    "pattern": _JOURNAL_REQUEST_FILENAME_PATTERN.pattern,
                    "flags": int(_JOURNAL_REQUEST_FILENAME_PATTERN.flags),
                },
                "entry": {
                    "pattern": _JOURNAL_ENTRY_FILENAME_PATTERN.pattern,
                    "flags": int(_JOURNAL_ENTRY_FILENAME_PATTERN.flags),
                },
            },
            "root_identity_integer_minimum": 0,
            "root_identity_integer_maximum": MAX_INT,
        },
        "result_policy": {
            "fields": list(_JOURNAL_RESULT_FIELDS),
            "commands": sorted(_JOURNAL_RESULT_REASONS),
            "reasons_by_command": {
                command: list(_JOURNAL_RESULT_REASONS[command])
                for command in sorted(_JOURNAL_RESULT_REASONS)
            },
            "dynamic_reason_policy": [
                {
                    "prefix": "unsupported:intent-field-invalid:",
                    "commands": [
                        COMMAND_JOURNAL_APPEND,
                        COMMAND_JOURNAL_BEGIN,
                        COMMAND_JOURNAL_INSPECT,
                    ],
                    "suffixes": sorted(_intent_key_set()),
                },
                {
                    "prefix": "unsupported:intent-binding-mismatch:",
                    "commands": [
                        COMMAND_JOURNAL_APPEND,
                        COMMAND_JOURNAL_BEGIN,
                        COMMAND_JOURNAL_INSPECT,
                    ],
                    "suffixes": sorted(
                        left for left, _right in (
                            _INTENT_EQUALITY_REQUIREMENTS
                        )
                    ),
                },
            ],
            "success_statuses": list(_JOURNAL_SUCCESS_STATUSES),
            "success_truth": {
                reason: dict(_JOURNAL_SUCCESS_RESULT_TRUTH[reason])
                for reason in sorted(_JOURNAL_SUCCESS_RESULT_TRUTH)
            },
            "failure_truth": {
                profile: dict(_JOURNAL_FAILURE_RESULT_TRUTH[profile])
                for profile in sorted(_JOURNAL_FAILURE_RESULT_TRUTH)
            },
            "identity_population_policy": dict(
                _JOURNAL_IDENTITY_POPULATION_POLICY
            ),
            "failure_profile_rules": [
                dict(rule) for rule in _JOURNAL_FAILURE_PROFILE_RULES
            ],
            "failure_identity_policy": {
                "shapes": {
                    profile: list(shapes)
                    for profile, shapes in sorted(
                        _JOURNAL_FAILURE_IDENTITY_SHAPES.items()
                    )
                },
                "special_rules": [
                    list(rule)
                    for rule in _JOURNAL_FAILURE_IDENTITY_SPECIAL_RULES
                ],
                "command_defaults": dict(
                    _JOURNAL_FAILURE_IDENTITY_DEFAULTS
                ),
                "reason_exceptions": {
                    command: {
                        profile: list(reasons)
                        for profile, reasons in sorted(profiles.items())
                    }
                    for command, profiles in sorted(
                        _JOURNAL_FAILURE_IDENTITY_REASON_EXCEPTIONS.items()
                    )
                },
                "resolution_order": [
                    "special-rules",
                    "reason-exceptions",
                    "command-defaults",
                ],
            },
            "history_tip_policy": {
                "reflexive_descendant_required": True,
                "equality_allowed_for_immediate_retry": True,
                "reachable_tip_states": {
                    state: list(reachable)
                    for state, reachable in (
                        _journal_reachable_tip_states().items()
                    )
                },
            },
            "entry_truth_policy": {
                "success_requires_reachable_entry_triple": True,
                "success_requires_exact_protected_anchor_presence": True,
                "scanned_tip_failure_requires_reachable_entry_triple": True,
                "populated_failure_entry_requires_tip_equals_to": True,
                "outcome_unknown_may_carry_partial_snapshot": True,
            },
            "false_flags": list(_JOURNAL_FALSE_FLAGS),
            "exit_codes": {
                "success": 0,
                "unsupported-or-invalid": 2,
                "blocked-denied-conflict": 3,
                "outcome_unknown": 4,
            },
            "closed_native_shape_required": True,
            "reason_specific_truth_required": True,
            "platform_precedes_intent_validation": True,
            "invalid_output_redacted": True,
        },
        "requirements": list(_JOURNAL_REQUIREMENTS),
        "nonclaims": list(_JOURNAL_NONCLAIMS),
    }


def _journal_contract_id():
    digest = hashlib.sha256(
        _JOURNAL_CONTRACT_ID_DOMAIN
        + _canonical(_journal_contract_payload()).encode("ascii")
    ).hexdigest()
    return "activation-journal-contract-" + digest


def journal_contract_projection():
    """Return the compact deterministic durable-journal contract."""
    result = _journal_contract_payload()
    result["status"] = JOURNAL_STATUS_PROJECTED
    result["reason"] = "projected:journal-contract"
    result["journal_contract_id"] = _journal_contract_id()
    return result


def _journal_result(command, status, token, **fields):
    result = {
        "schema": JOURNAL_RESULT_SCHEMA,
        "mode": JOURNAL_MODE,
        "command": command,
        "status": status,
        "reason": status + ":" + token,
        "journal_contract_id": _journal_contract_id(),
        "activation_contract_id": _activation_contract_id(),
        "transaction_id": fields.get("transaction_id"),
        "intent_sha256": fields.get("intent_sha256"),
        "request_sha256": fields.get("request_sha256"),
        "entry_sha256": fields.get("entry_sha256"),
        "prior_entry_sha256": fields.get("prior_entry_sha256"),
        "sequence": fields.get("sequence"),
        "from_state": fields.get("from_state"),
        "to_state": fields.get("to_state"),
        "tip_state": fields.get("tip_state"),
        "protected_state_preimage_sha256": fields.get(
            "protected_state_preimage_sha256"
        ),
        "journal_read_supported": fields.get(
            "journal_read_supported", True
        ),
        "journal_write_supported": fields.get(
            "journal_write_supported", True
        ),
        "journal_read_performed": fields.get(
            "journal_read_performed", False
        ),
        "journal_write_attempted": fields.get(
            "journal_write_attempted", False
        ),
        "journal_written": fields.get("journal_written", False),
    }
    for flag in _JOURNAL_FALSE_FLAGS:
        result[flag] = False
    result["requirements"] = list(_JOURNAL_REQUIREMENTS)
    result["nonclaims"] = list(_JOURNAL_NONCLAIMS)
    return result


def _journal_identity_fields(validated_intent):
    if validated_intent is None:
        return {}
    return {
        "transaction_id": _transaction_id(
            _activation_contract_id(), validated_intent
        ),
        "intent_sha256": _intent_sha256(validated_intent),
    }


def _valid_journal_projection(value):
    if type(value) is not dict or not _closed_native_json(value):
        return False
    expected = journal_contract_projection()
    return value == expected and len(_canonical(value)) <= (
        MAX_JOURNAL_PROJECTION_BYTES
    )


def _journal_identity_population_valid(value):
    identity_pair = (
        value["transaction_id"] is not None,
        value["intent_sha256"] is not None,
    )
    if identity_pair not in ((False, False), (True, True)):
        return False
    request_present = value["request_sha256"] is not None
    entry_present = value["entry_sha256"] is not None
    if request_present and not identity_pair[0]:
        return False
    if entry_present and not request_present:
        return False
    entry_shape_fields = (
        "sequence",
        "from_state",
        "to_state",
        "tip_state",
    )
    if not entry_present:
        if any(value[key] is not None for key in entry_shape_fields):
            return False
        if value["prior_entry_sha256"] is not None:
            return False
        if value["protected_state_preimage_sha256"] is not None:
            return False
        return True
    if any(value[key] is None for key in entry_shape_fields):
        return False
    if value["sequence"] == 0:
        if value["prior_entry_sha256"] is not None:
            return False
        if value["from_state"] != STATE_START:
            return False
        if value["to_state"] != STATE_PREPARED:
            return False
        if value["protected_state_preimage_sha256"] is not None:
            return False
    else:
        if value["prior_entry_sha256"] is None:
            return False
        if value["prior_entry_sha256"] == value["entry_sha256"]:
            return False
    truth_marker = (
        value["sequence"],
        value["from_state"],
        value["to_state"],
        value["protected_state_preimage_sha256"] is not None,
    )
    if truth_marker not in _journal_reachable_entry_truth():
        return False
    return True


def _journal_success_truth_valid(value):
    policy = _JOURNAL_SUCCESS_RESULT_TRUTH.get(value["reason"])
    if policy is None:
        return False
    if value["journal_read_supported"] is not True:
        return False
    if value["journal_write_supported"] is not True:
        return False
    if value["journal_read_performed"] is not policy["read"]:
        return False
    if value["journal_write_attempted"] is not policy["write_attempted"]:
        return False
    if value["journal_written"] is not policy["written"]:
        return False
    if value["transaction_id"] is None or value["intent_sha256"] is None:
        return False
    if value["request_sha256"] is None or value["entry_sha256"] is None:
        return False
    profile = policy["profile"]
    if profile == "genesis-tip":
        return (
            value["sequence"] == 0
            and value["from_state"] == STATE_START
            and value["to_state"] == STATE_PREPARED
            and value["tip_state"] == STATE_PREPARED
            and value["prior_entry_sha256"] is None
            and value["protected_state_preimage_sha256"] is None
        )
    if profile in (
        "positive-sequence-entry-tip",
        "positive-sequence-entry-history",
    ) and (value["sequence"] is None or value["sequence"] < 1):
        return False
    if profile in ("genesis-tip", "entry-tip", "positive-sequence-entry-tip"):
        return value["tip_state"] == value["to_state"]
    if profile == "positive-sequence-entry-history":
        return value["tip_state"] in _journal_reachable_tip_states()[
            value["to_state"]
        ]
    return False


def _journal_failure_profile(value):
    for rule in _JOURNAL_FAILURE_PROFILE_RULES:
        if "commands" in rule and value["command"] not in rule["commands"]:
            continue
        if "exact_reason" in rule and value["reason"] != rule[
            "exact_reason"
        ]:
            continue
        if "status" in rule and value["status"] != rule["status"]:
            continue
        if "reason_prefix" in rule and not value["reason"].startswith(
            rule["reason_prefix"]
        ):
            continue
        return rule["profile"]
    return None


def _journal_failure_identity_profile(value):
    for selector, expected, command, profile in (
        _JOURNAL_FAILURE_IDENTITY_SPECIAL_RULES
    ):
        if command is not None and value["command"] != command:
            continue
        if selector == "command":
            matched = value["command"] == expected
        elif selector == "reason":
            matched = value["reason"] == expected
        elif selector == "status":
            matched = value["status"] == expected
        elif selector == "reason-prefix":
            matched = value["reason"].startswith(expected)
        else:
            return None
        if matched:
            return profile
    profiles = _JOURNAL_FAILURE_IDENTITY_REASON_EXCEPTIONS.get(
        value["command"], {}
    )
    for profile, reasons in profiles.items():
        if value["reason"] in reasons:
            return profile
    return _JOURNAL_FAILURE_IDENTITY_DEFAULTS.get(value["command"])


def _journal_failure_identity_valid(value, profile):
    shapes = _JOURNAL_FAILURE_IDENTITY_SHAPES.get(profile)
    if shapes is None:
        return False
    shape = "".join(
        "1" if value[key] is not None else "0"
        for key in (
            "transaction_id",
            "request_sha256",
            "entry_sha256",
        )
    )
    return shape in shapes


def _journal_failure_truth_valid(value):
    profile = _journal_failure_profile(value)
    if profile is None:
        return False
    identity_profile = _journal_failure_identity_profile(value)
    if identity_profile is None:
        return False
    if not _journal_failure_identity_valid(value, identity_profile):
        return False
    policy = _JOURNAL_FAILURE_RESULT_TRUTH[profile]
    read_supported = policy.get("read_supported", True)
    write_supported = policy.get("write_supported", True)
    if policy.get("runtime_platform_support_required") is True:
        read_supported = _JOURNAL_PLATFORM_SUPPORTED
        write_supported = _JOURNAL_PLATFORM_SUPPORTED
    if value["journal_read_supported"] is not read_supported:
        return False
    if value["journal_write_supported"] is not write_supported:
        return False
    if (
        value["entry_sha256"] is not None
        and value["tip_state"] != value["to_state"]
    ):
        return False
    read_policy = policy.get("read", True)
    if (
        read_policy != "false-or-true"
        and value["journal_read_performed"] is not read_policy
    ):
        return False
    if value["journal_write_attempted"] is not policy["write_attempted"]:
        return False
    if value["journal_written"] is not policy["written"]:
        return False
    return True


def _valid_journal_result(value):
    if type(value) is not dict:
        return False
    if len(value) != len(_JOURNAL_RESULT_FIELDS):
        return False
    for key in value:
        if type(key) is not str:
            return False
    if set(value) != set(_JOURNAL_RESULT_FIELDS):
        return False
    if not _closed_native_json(value):
        return False
    if value["schema"] != JOURNAL_RESULT_SCHEMA:
        return False
    if value["mode"] != JOURNAL_MODE:
        return False
    if value["journal_contract_id"] != _journal_contract_id():
        return False
    if value["activation_contract_id"] != _activation_contract_id():
        return False
    if type(value["command"]) is not str:
        return False
    if type(value["status"]) is not str:
        return False
    if type(value["reason"]) is not str:
        return False
    command = value["command"]
    if command not in _JOURNAL_RESULT_REASONS:
        return False
    if value["reason"] not in _JOURNAL_RESULT_REASONS[command]:
        if not (
            command in (COMMAND_JOURNAL_BEGIN, COMMAND_JOURNAL_APPEND,
                        COMMAND_JOURNAL_INSPECT)
            and value["reason"].startswith("unsupported:intent-")
            and value["reason"][len("unsupported:") :]
            in tuple(
                reason[len("unsupported:") :]
                for reason in _INTENT_UNSUPPORTED_FIXED_REASONS
            )
            + tuple(
                "intent-field-invalid:" + key
                for key in sorted(_intent_key_set())
            )
            + tuple(
                "intent-binding-mismatch:" + left
                for left, _right in _INTENT_EQUALITY_REQUIREMENTS
            )
        ):
            return False
    if not value["reason"].startswith(value["status"] + ":"):
        return False
    for key in (
        "transaction_id",
        "intent_sha256",
        "request_sha256",
        "entry_sha256",
        "prior_entry_sha256",
        "protected_state_preimage_sha256",
    ):
        item = value[key]
        if item is not None and not _matches(
            _TRANSACTION_ID_PATTERN if key == "transaction_id"
            else _HEX64_PATTERN,
            item,
        ):
            return False
    sequence = value["sequence"]
    if sequence is not None and (
        type(sequence) is not int
        or sequence < 0
        or sequence >= MAX_JOURNAL_ENTRIES
    ):
        return False
    for key in ("from_state", "to_state", "tip_state"):
        state_value = value[key]
        if state_value is not None and (
            type(state_value) is not str or state_value not in STATE_GRAPH
        ):
            return False
    for key in (
        "journal_read_supported",
        "journal_write_supported",
        "journal_read_performed",
        "journal_write_attempted",
    ):
        if type(value[key]) is not bool:
            return False
    if value["journal_written"] not in (False, True, None):
        return False
    if value["journal_written"] is True and not value[
        "journal_write_attempted"
    ]:
        return False
    if value["journal_written"] is None and not value[
        "journal_write_attempted"
    ]:
        return False
    if value["status"] == JOURNAL_STATUS_OUTCOME_UNKNOWN and value[
        "journal_written"
    ] is not None:
        return False
    for flag in _JOURNAL_FALSE_FLAGS:
        if value[flag] is not False:
            return False
    if value["requirements"] != list(_JOURNAL_REQUIREMENTS):
        return False
    if value["nonclaims"] != list(_JOURNAL_NONCLAIMS):
        return False
    if not _journal_identity_population_valid(value):
        return False
    if value["reason"] in _JOURNAL_SUCCESS_RESULT_TRUTH:
        if not _journal_success_truth_valid(value):
            return False
    elif not _journal_failure_truth_valid(value):
        return False
    return len(_canonical(value)) <= MAX_RESULT_BYTES


def render_journal_result(result):
    """Render a closed journal result/projection as canonical one-line JSON."""
    token = "journal-result-not-renderable"
    if _valid_journal_result(result) or _valid_journal_projection(result):
        try:
            rendered = _canonical(result)
        except Exception:
            rendered = None
        if rendered is not None and len(rendered) <= MAX_RESULT_BYTES:
            return rendered
        token = "journal-output-oversize"
    return _canonical(
        _journal_result(
            COMMAND_JOURNAL_RENDER,
            JOURNAL_STATUS_UNSUPPORTED,
            token,
            journal_read_supported=_JOURNAL_PLATFORM_SUPPORTED,
            journal_write_supported=_JOURNAL_PLATFORM_SUPPORTED,
        )
    )


def journal_result_exit_code(result):
    """Map durable-journal outcomes without mistaking ambiguity for success."""
    if _valid_journal_projection(result):
        return 0
    if not _valid_journal_result(result):
        return 2
    if result["status"] in _JOURNAL_SUCCESS_STATUSES:
        return 0
    if result["status"] == JOURNAL_STATUS_OUTCOME_UNKNOWN:
        return 4
    if result["status"] in (
        JOURNAL_STATUS_BLOCKED,
        JOURNAL_STATUS_DENIED,
        JOURNAL_STATUS_CONFLICT,
    ):
        return 3
    return 2


_JOURNAL_REQUIRED_OS_FLAGS = (
    "O_CLOEXEC",
    "O_CREAT",
    "O_DIRECTORY",
    "O_EXCL",
    "O_NOFOLLOW",
    "O_NONBLOCK",
    "O_RDONLY",
    "O_RDWR",
    "O_WRONLY",
)
_JOURNAL_REQUIRED_FCNTL_CAPABILITIES = (
    "flock",
    "LOCK_EX",
    "LOCK_NB",
    "LOCK_UN",
)
_JOURNAL_REQUIRED_OS_CALLABLES = (
    "close",
    "fchmod",
    "fstat",
    "fsync",
    "geteuid",
    "mkdir",
    "open",
    "read",
    "scandir",
    "write",
)

# Syscall and clock seams are private and injectable for failpoint testing.
# Production callers must not replace them.  Safe lookup keeps the projection
# and unsupported-platform results importable when a required capability is
# absent.
_JOURNAL_OPEN = getattr(os, "open", None)
_JOURNAL_READ = getattr(os, "read", None)
_JOURNAL_WRITE = getattr(os, "write", None)
_JOURNAL_FSTAT = getattr(os, "fstat", None)
_JOURNAL_FCHMOD = getattr(os, "fchmod", None)
_JOURNAL_FSYNC = getattr(os, "fsync", None)
_JOURNAL_CLOSE = getattr(os, "close", None)
_JOURNAL_MKDIR = getattr(os, "mkdir", None)
_JOURNAL_SCANDIR = getattr(os, "scandir", None)
# Retained only as a dormant 4A purity-test tripwire; journal scans never use
# listdir or materialize an unbounded directory listing.
_JOURNAL_LISTDIR = None
_JOURNAL_GETEUID = getattr(os, "geteuid", None)
_JOURNAL_FLOCK = (
    None if fcntl is None else getattr(fcntl, "flock", None)
)
_JOURNAL_LOCK_EX = (
    None if fcntl is None else getattr(fcntl, "LOCK_EX", None)
)
_JOURNAL_LOCK_NB = (
    None if fcntl is None else getattr(fcntl, "LOCK_NB", None)
)
_JOURNAL_LOCK_UN = (
    None if fcntl is None else getattr(fcntl, "LOCK_UN", None)
)
_JOURNAL_NOW = lambda: int(time.time())

_JOURNAL_PLATFORM_SUPPORTED = (
    fcntl is not None
    and all(
        hasattr(fcntl, item)
        for item in _JOURNAL_REQUIRED_FCNTL_CAPABILITIES
    )
    and callable(getattr(fcntl, "flock", None))
    and all(
        type(getattr(fcntl, item, None)) is int
        for item in ("LOCK_EX", "LOCK_NB", "LOCK_UN")
    )
    and all(
        type(getattr(os, flag, None)) is int
        for flag in _JOURNAL_REQUIRED_OS_FLAGS
    )
    and all(
        callable(getattr(os, item, None))
        for item in _JOURNAL_REQUIRED_OS_CALLABLES
    )
    and _JOURNAL_OPEN in getattr(os, "supports_dir_fd", set())
    and _JOURNAL_MKDIR in getattr(os, "supports_dir_fd", set())
    and _JOURNAL_SCANDIR in getattr(os, "supports_fd", set())
)
if _JOURNAL_PLATFORM_SUPPORTED:
    _JOURNAL_FILE_FLAGS = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    _JOURNAL_DIRECTORY_FLAGS = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    _JOURNAL_CREATE_FLAGS = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    _JOURNAL_LOCK_OPEN_FLAGS = (
        os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
else:
    _JOURNAL_FILE_FLAGS = 0
    _JOURNAL_DIRECTORY_FLAGS = 0
    _JOURNAL_CREATE_FLAGS = 0
    _JOURNAL_LOCK_OPEN_FLAGS = 0

_JOURNAL_REQUEST_FILENAME_PATTERN = re.compile(
    r"\Arequest-([0-9a-f]{64})\.json\Z"
)
_JOURNAL_ENTRY_FILENAME_PATTERN = re.compile(
    r"\Aentry-([0-9a-f]{64})\.json\Z"
)


class _JournalHandles:
    def __init__(
        self,
        root_chain_fds,
        root_components,
        root_fingerprints,
        directory_fd,
        directory_fingerprint,
        lock_fd,
        lock_fingerprint,
        root_stat,
        written,
    ):
        self.root_chain_fds = root_chain_fds
        self.root_components = root_components
        self.root_fingerprints = root_fingerprints
        self.root_fd = root_chain_fds[-1]
        self.directory_fd = directory_fd
        self.directory_fingerprint = directory_fingerprint
        self.lock_fd = lock_fd
        self.lock_fingerprint = lock_fingerprint
        self.root_stat = root_stat
        self.infrastructure_written = written


def _journal_close_fd(fd):
    if fd is None:
        return
    try:
        _JOURNAL_CLOSE(fd)
    except Exception:
        pass


def _journal_release(handles):
    if handles is None:
        return
    if handles.lock_fd is not None:
        try:
            _JOURNAL_FLOCK(handles.lock_fd, _JOURNAL_LOCK_UN)
        except Exception:
            pass
    _journal_close_fd(handles.lock_fd)
    _journal_close_fd(handles.directory_fd)
    for descriptor in reversed(handles.root_chain_fds):
        _journal_close_fd(descriptor)


def _journal_fingerprint(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1000000000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1000000000)),
    )


def _journal_identity_fingerprint(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _journal_file_identity_fingerprint(metadata):
    return _journal_identity_fingerprint(metadata) + (metadata.st_nlink,)


def _journal_mode_owner_valid(metadata, expected_mode, *, directory):
    kind_valid = (
        stat.S_ISDIR(metadata.st_mode)
        if directory
        else stat.S_ISREG(metadata.st_mode)
    )
    return (
        kind_valid
        and metadata.st_uid == _JOURNAL_GETEUID()
        and stat.S_IMODE(metadata.st_mode) == expected_mode
        and (directory or metadata.st_nlink == 1)
    )


def _journal_root_descriptor(journal_root):
    if not _JOURNAL_PLATFORM_SUPPORTED:
        raise _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED, "journal-platform-unsupported",
            fields={
                "journal_read_supported": False,
                "journal_write_supported": False,
            },
        )
    if type(journal_root) is not str:
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED, "journal-root-invalid"
        )
    if len(journal_root) > MAX_JOURNAL_ROOT_BYTES:
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED, "journal-root-invalid"
        )
    try:
        encoded_root = journal_root.encode("utf-8", "strict")
        canonical = (
            journal_root != os.path.sep
            and os.path.isabs(journal_root)
            and os.path.normpath(journal_root) == journal_root
            and "\x00" not in journal_root
        )
    except Exception:
        canonical = False
    if not canonical:
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED, "journal-root-invalid"
        )
    components = journal_root.split(os.path.sep)[1:]
    if (
        len(encoded_root) > MAX_JOURNAL_ROOT_BYTES
        or len(components) > MAX_JOURNAL_ROOT_COMPONENTS
        or not components
        or any(component in ("", ".", "..") for component in components)
    ):
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED, "journal-root-invalid"
        )
    chain_fds = []
    fingerprints = []
    try:
        descriptor = _JOURNAL_OPEN(os.path.sep, _JOURNAL_DIRECTORY_FLAGS)
        chain_fds.append(descriptor)
        root_component_metadata = _JOURNAL_FSTAT(descriptor)
        fingerprints.append(
            _journal_identity_fingerprint(root_component_metadata)
        )
        metadata = None
        for index, component in enumerate(components):
            descriptor = _JOURNAL_OPEN(
                component,
                _JOURNAL_DIRECTORY_FLAGS,
                dir_fd=chain_fds[-1],
            )
            chain_fds.append(descriptor)
            component_metadata = _JOURNAL_FSTAT(descriptor)
            if index == len(components) - 1:
                metadata = component_metadata
                if not _journal_mode_owner_valid(
                    metadata, 0o700, directory=True
                ):
                    raise ValueError("journal-root-policy-invalid")
                if (
                    type(metadata.st_dev) is not int
                    or type(metadata.st_ino) is not int
                    or metadata.st_dev < 0
                    or metadata.st_ino < 0
                    or metadata.st_dev > MAX_INT
                    or metadata.st_ino > MAX_INT
                ):
                    raise ValueError("journal-root-identity-invalid")
            fingerprints.append(
                _journal_identity_fingerprint(component_metadata)
            )
    except Exception:
        for descriptor in reversed(chain_fds):
            _journal_close_fd(descriptor)
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED, "journal-root-invalid"
        )
    return chain_fds, components, fingerprints, metadata


def _journal_reprove_root(handles):
    if len(handles.root_chain_fds) != len(handles.root_fingerprints):
        return False
    for index, descriptor in enumerate(handles.root_chain_fds):
        probe = None
        try:
            held_metadata = _JOURNAL_FSTAT(descriptor)
            if index == len(handles.root_chain_fds) - 1 and not (
                _journal_mode_owner_valid(
                    held_metadata, 0o700, directory=True
                )
            ):
                return False
            if _journal_identity_fingerprint(
                held_metadata
            ) != handles.root_fingerprints[index]:
                return False
            if index == 0:
                continue
            probe = _JOURNAL_OPEN(
                handles.root_components[index - 1],
                _JOURNAL_DIRECTORY_FLAGS,
                dir_fd=handles.root_chain_fds[index - 1],
            )
            visible_metadata = _JOURNAL_FSTAT(probe)
            if index == len(handles.root_chain_fds) - 1 and not (
                _journal_mode_owner_valid(
                    visible_metadata, 0o700, directory=True
                )
            ):
                return False
            visible = _journal_identity_fingerprint(visible_metadata)
            if visible != handles.root_fingerprints[index]:
                return False
            closing_fd = probe
            probe = None
            _JOURNAL_CLOSE(closing_fd)
        except Exception:
            return False
        finally:
            _journal_close_fd(probe)
    return True


def _journal_private_directory_metadata(directory_fd):
    metadata = _JOURNAL_FSTAT(directory_fd)
    if not _journal_mode_owner_valid(metadata, 0o700, directory=True):
        raise ValueError("journal-directory-policy-invalid")
    return metadata


def _journal_open_private_directory(root_fd, *, create):
    directory_fd = None
    try:
        directory_fd = _JOURNAL_OPEN(
            JOURNAL_SUBDIRECTORY,
            _JOURNAL_DIRECTORY_FLAGS,
            dir_fd=root_fd,
        )
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-integrity-invalid",
                read_performed=True,
            )
    except Exception:
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-integrity-invalid",
            read_performed=True,
        )
    else:
        try:
            metadata = _journal_private_directory_metadata(directory_fd)
            fingerprint = _journal_identity_fingerprint(metadata)
        except Exception:
            closing_fd = directory_fd
            directory_fd = None
            _journal_close_fd(closing_fd)
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-integrity-invalid",
                read_performed=True,
            )
        transferred_fd = directory_fd
        directory_fd = None
        return transferred_fd, fingerprint, False
    if not create:
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-uninitialized",
            read_performed=True,
        )

    attempted = False
    try:
        _JOURNAL_MKDIR(JOURNAL_SUBDIRECTORY, 0o700, dir_fd=root_fd)
        attempted = True
    except FileExistsError:
        attempted = False
    except Exception:
        raise _JournalWriteUnknown(read_performed=True)
    if attempted:
        try:
            _JOURNAL_FSYNC(root_fd)
        except Exception:
            raise _JournalWriteUnknown(read_performed=True)
    directory_fd = None
    try:
        directory_fd = _JOURNAL_OPEN(
            JOURNAL_SUBDIRECTORY,
            _JOURNAL_DIRECTORY_FLAGS,
            dir_fd=root_fd,
        )
        metadata = _journal_private_directory_metadata(directory_fd)
        fingerprint = _journal_identity_fingerprint(metadata)
    except Exception:
        closing_fd = directory_fd
        directory_fd = None
        _journal_close_fd(closing_fd)
        if attempted:
            raise _JournalWriteUnknown(read_performed=True)
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-integrity-invalid",
            read_performed=True,
        )
    transferred_fd = directory_fd
    directory_fd = None
    return transferred_fd, fingerprint, attempted


def _journal_open_lock(directory_fd, *, create, prior_written):
    lock_fd = None
    created = False
    try:
        lock_fd = _JOURNAL_OPEN(
            JOURNAL_LOCK_FILENAME,
            _JOURNAL_LOCK_OPEN_FLAGS,
            dir_fd=directory_fd,
        )
    except OSError as error:
        if error.errno != errno.ENOENT:
            if prior_written:
                raise _JournalWriteUnknown(read_performed=True)
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-integrity-invalid",
                read_performed=True,
            )
    except Exception:
        if prior_written:
            raise _JournalWriteUnknown(read_performed=True)
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-integrity-invalid",
            read_performed=True,
        )

    if lock_fd is None:
        if not create:
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-integrity-invalid",
                read_performed=True,
            )
        try:
            lock_fd = _JOURNAL_OPEN(
                JOURNAL_LOCK_FILENAME,
                _JOURNAL_LOCK_OPEN_FLAGS | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            created = True
        except FileExistsError:
            closing_fd = lock_fd
            lock_fd = None
            _journal_close_fd(closing_fd)
            try:
                lock_fd = _JOURNAL_OPEN(
                    JOURNAL_LOCK_FILENAME,
                    _JOURNAL_LOCK_OPEN_FLAGS,
                    dir_fd=directory_fd,
                )
            except Exception:
                if prior_written:
                    raise _JournalWriteUnknown(read_performed=True)
                raise _JournalRefusal(
                    JOURNAL_STATUS_BLOCKED,
                    "journal-integrity-invalid",
                    read_performed=True,
                )
        except Exception:
            closing_fd = lock_fd
            lock_fd = None
            _journal_close_fd(closing_fd)
            raise _JournalWriteUnknown(read_performed=True)
        if created:
            try:
                _JOURNAL_FCHMOD(lock_fd, 0o600)
                _JOURNAL_FSYNC(lock_fd)
                _JOURNAL_FSYNC(directory_fd)
            except Exception:
                closing_fd = lock_fd
                lock_fd = None
                _journal_close_fd(closing_fd)
                raise _JournalWriteUnknown(read_performed=True)

    try:
        metadata = _JOURNAL_FSTAT(lock_fd)
        if not _journal_mode_owner_valid(
            metadata, 0o600, directory=False
        ):
            raise ValueError("journal-lock-policy-invalid")
        fingerprint = _journal_file_identity_fingerprint(metadata)
    except Exception:
        closing_fd = lock_fd
        lock_fd = None
        _journal_close_fd(closing_fd)
        if prior_written or created:
            raise _JournalWriteUnknown(read_performed=True)
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-integrity-invalid",
            read_performed=True,
        )
    try:
        _JOURNAL_FLOCK(lock_fd, _JOURNAL_LOCK_EX | _JOURNAL_LOCK_NB)
    except OSError as error:
        closing_fd = lock_fd
        lock_fd = None
        _journal_close_fd(closing_fd)
        if error.errno in (errno.EACCES, errno.EAGAIN):
            if prior_written or created:
                raise _JournalWriteUnknown(read_performed=True)
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-busy",
                read_performed=True,
                write_attempted=False,
                written=False,
            )
        if prior_written or created:
            raise _JournalWriteUnknown(read_performed=True)
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-integrity-invalid",
            read_performed=True,
        )
    except Exception:
        closing_fd = lock_fd
        lock_fd = None
        _journal_close_fd(closing_fd)
        if prior_written or created:
            raise _JournalWriteUnknown(read_performed=True)
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-integrity-invalid",
            read_performed=True,
        )
    transferred_fd = lock_fd
    lock_fd = None
    return (
        transferred_fd,
        fingerprint,
        (prior_written or created),
    )


def _journal_reprove_private(handles):
    if not _journal_reprove_root(handles):
        return False
    probe_directory = None
    probe_lock = None
    try:
        directory_metadata = _JOURNAL_FSTAT(handles.directory_fd)
        if not _journal_mode_owner_valid(
            directory_metadata, 0o700, directory=True
        ):
            return False
        if _journal_identity_fingerprint(
            directory_metadata
        ) != handles.directory_fingerprint:
            return False
        probe_directory = _JOURNAL_OPEN(
            JOURNAL_SUBDIRECTORY,
            _JOURNAL_DIRECTORY_FLAGS,
            dir_fd=handles.root_fd,
        )
        probe_directory_metadata = _JOURNAL_FSTAT(probe_directory)
        if not _journal_mode_owner_valid(
            probe_directory_metadata, 0o700, directory=True
        ):
            return False
        if _journal_identity_fingerprint(
            probe_directory_metadata
        ) != handles.directory_fingerprint:
            return False
        closing_fd = probe_directory
        probe_directory = None
        _JOURNAL_CLOSE(closing_fd)
        lock_metadata = _JOURNAL_FSTAT(handles.lock_fd)
        if not _journal_mode_owner_valid(
            lock_metadata, 0o600, directory=False
        ):
            return False
        if _journal_file_identity_fingerprint(
            lock_metadata
        ) != handles.lock_fingerprint:
            return False
        probe_lock = _JOURNAL_OPEN(
            JOURNAL_LOCK_FILENAME,
            _JOURNAL_LOCK_OPEN_FLAGS,
            dir_fd=handles.directory_fd,
        )
        probe_lock_metadata = _JOURNAL_FSTAT(probe_lock)
        if not _journal_mode_owner_valid(
            probe_lock_metadata, 0o600, directory=False
        ):
            return False
        if _journal_file_identity_fingerprint(
            probe_lock_metadata
        ) != handles.lock_fingerprint:
            return False
        closing_fd = probe_lock
        probe_lock = None
        _JOURNAL_CLOSE(closing_fd)
        return True
    except Exception:
        return False
    finally:
        _journal_close_fd(probe_lock)
        _journal_close_fd(probe_directory)


def _journal_acquire(journal_root, *, create):
    root_chain_fds = []
    directory_fd = None
    lock_fd = None
    root_stat = None
    try:
        (
            root_chain_fds,
            root_components,
            root_fingerprints,
            root_stat,
        ) = _journal_root_descriptor(journal_root)
        root_fd = root_chain_fds[-1]
        (
            directory_fd,
            directory_fingerprint,
            infrastructure_written,
        ) = _journal_open_private_directory(root_fd, create=create)
        (
            lock_fd,
            lock_fingerprint,
            infrastructure_written,
        ) = _journal_open_lock(
            directory_fd,
            create=create,
            prior_written=infrastructure_written,
        )
        handles = _JournalHandles(
            root_chain_fds,
            root_components,
            root_fingerprints,
            directory_fd,
            directory_fingerprint,
            lock_fd,
            lock_fingerprint,
            root_stat,
            infrastructure_written,
        )
        if not _journal_reprove_private(handles):
            if infrastructure_written:
                raise _JournalWriteUnknown(read_performed=True)
            raise _journal_integrity_refusal()
        return handles
    except Exception:
        _journal_close_fd(lock_fd)
        _journal_close_fd(directory_fd)
        for descriptor in reversed(root_chain_fds):
            _journal_close_fd(descriptor)
        raise


def _journal_read_exact_file(file_fd, size):
    remaining = size
    chunks = []
    while remaining:
        chunk = _JOURNAL_READ(file_fd, min(remaining, 65536))
        if not chunk:
            raise ValueError("short-document-read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if _JOURNAL_READ(file_fd, 1) != b"":
        raise ValueError("document-grew-during-read")
    return b"".join(chunks)


def _journal_read_document(directory_fd, filename):
    file_fd = None
    probe_fd = None
    try:
        file_fd = _JOURNAL_OPEN(
            filename, _JOURNAL_FILE_FLAGS, dir_fd=directory_fd
        )
        before = _JOURNAL_FSTAT(file_fd)
        if not _journal_mode_owner_valid(before, 0o600, directory=False):
            raise ValueError("invalid-document-metadata")
        if before.st_size < 3 or before.st_size > (
            MAX_JOURNAL_DOCUMENT_BYTES
        ):
            raise ValueError("invalid-document-size")
        raw = _journal_read_exact_file(file_fd, before.st_size)
        after = _JOURNAL_FSTAT(file_fd)
        if _journal_fingerprint(before) != _journal_fingerprint(after):
            raise ValueError("document-changed-during-read")
        closing_fd = file_fd
        file_fd = None
        _JOURNAL_CLOSE(closing_fd)
        probe_fd = _JOURNAL_OPEN(
            filename, _JOURNAL_FILE_FLAGS, dir_fd=directory_fd
        )
        probe_before = _JOURNAL_FSTAT(probe_fd)
        if _journal_fingerprint(probe_before) != _journal_fingerprint(after):
            raise ValueError("document-name-identity-changed")
        probe_raw = _journal_read_exact_file(probe_fd, probe_before.st_size)
        probe_after = _JOURNAL_FSTAT(probe_fd)
        if _journal_fingerprint(probe_before) != _journal_fingerprint(
            probe_after
        ):
            raise ValueError("document-changed-during-reproof")
        if probe_raw != raw:
            raise ValueError("document-bytes-changed-during-reproof")
        closing_fd = probe_fd
        probe_fd = None
        _JOURNAL_CLOSE(closing_fd)
    finally:
        _journal_close_fd(file_fd)
        _journal_close_fd(probe_fd)
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise ValueError("document-newline-invalid")
    try:
        document = json.loads(raw[:-1].decode("ascii"))
    except Exception as error:
        raise ValueError("document-json-invalid") from error
    if type(document) is not dict:
        raise ValueError("document-type-invalid")
    if (_canonical(document) + "\n").encode("ascii") != raw:
        raise ValueError("document-not-canonical")
    return document, after.st_size


def _journal_self_hash(domain, document, field):
    payload = dict(document)
    payload.pop(field, None)
    return hashlib.sha256(
        domain + (_canonical(payload) + "\n").encode("ascii")
    ).hexdigest()


def _journal_document_bytes(document):
    encoded = (_canonical(document) + "\n").encode("ascii")
    if len(encoded) > MAX_JOURNAL_DOCUMENT_BYTES:
        raise _JournalRefusal(
            JOURNAL_STATUS_BLOCKED,
            "journal-integrity-invalid",
            read_performed=True,
        )
    return encoded


def _journal_publish_document(directory_fd, filename, document):
    encoded = _journal_document_bytes(document)
    file_fd = None
    created = False
    try:
        file_fd = _JOURNAL_OPEN(
            filename,
            _JOURNAL_CREATE_FLAGS,
            0o600,
            dir_fd=directory_fd,
        )
        created = True
        _JOURNAL_FCHMOD(file_fd, 0o600)
        offset = 0
        while offset < len(encoded):
            written = _JOURNAL_WRITE(file_fd, encoded[offset:])
            if type(written) is not int or written < 1:
                raise OSError(errno.EIO, "short-write")
            offset += written
        _JOURNAL_FSYNC(file_fd)
        metadata = _JOURNAL_FSTAT(file_fd)
        if not _journal_mode_owner_valid(metadata, 0o600, directory=False):
            raise OSError(errno.EIO, "published-metadata-invalid")
        if metadata.st_size != len(encoded):
            raise OSError(errno.EIO, "published-size-invalid")
        closing_fd = file_fd
        file_fd = None
        _JOURNAL_CLOSE(closing_fd)
        _JOURNAL_FSYNC(directory_fd)
        verified, verified_size = _journal_read_document(
            directory_fd, filename
        )
        if verified != document or verified_size != len(encoded):
            raise OSError(errno.EIO, "published-document-reproof-failed")
        return True
    except FileExistsError:
        if created:
            raise _JournalWriteUnknown(read_performed=True)
        raise _JournalRefusal(
            JOURNAL_STATUS_CONFLICT,
            "journal-tip-mismatch",
            read_performed=True,
            write_attempted=False,
            written=False,
        )
    except Exception:
        if created:
            raise _JournalWriteUnknown(read_performed=True)
        raise _JournalWriteUnknown(read_performed=True)
    finally:
        _journal_close_fd(file_fd)


def _journal_request_document(validated_intent, root_stat):
    transaction_id = _transaction_id(
        _activation_contract_id(), validated_intent
    )
    document = {
        "schema": JOURNAL_REQUEST_SCHEMA,
        "journal_contract_id": _journal_contract_id(),
        "activation_contract_id": _activation_contract_id(),
        "transaction_id": transaction_id,
        "intent_sha256": _intent_sha256(validated_intent),
        "activation_intent": validated_intent,
        "journal_root_device": root_stat.st_dev,
        "journal_root_inode": root_stat.st_ino,
    }
    document["request_sha256"] = _journal_self_hash(
        _JOURNAL_REQUEST_HASH_DOMAIN, document, "request_sha256"
    )
    _journal_document_bytes(document)
    return document


def _journal_transition_result_sha256(transition_result):
    return hashlib.sha256(
        _JOURNAL_TRANSITION_RESULT_HASH_DOMAIN
        + (_canonical(transition_result) + "\n").encode("ascii")
    ).hexdigest()


def _journal_entry_document(
    request,
    *,
    sequence,
    prior_entry_sha256,
    from_state,
    to_state,
    decision_at,
    gate_observations_by_type,
    transition_result,
    protected_state_preimage_sha256,
):
    document = {
        "schema": JOURNAL_ENTRY_SCHEMA,
        "journal_contract_id": _journal_contract_id(),
        "activation_contract_id": _activation_contract_id(),
        "transaction_id": request["transaction_id"],
        "request_sha256": request["request_sha256"],
        "sequence": sequence,
        "prior_entry_sha256": prior_entry_sha256,
        "from_state": from_state,
        "to_state": to_state,
        "decision_at": decision_at,
        "gate_observations_by_type": gate_observations_by_type,
        "gate_observation_sha256_by_type": transition_result[
            "gate_observation_sha256_by_type"
        ],
        "transition_result_sha256": (
            _journal_transition_result_sha256(transition_result)
        ),
        "protected_state_preimage_sha256": (
            protected_state_preimage_sha256
        ),
    }
    document["entry_sha256"] = _journal_self_hash(
        _JOURNAL_ENTRY_HASH_DOMAIN, document, "entry_sha256"
    )
    _journal_document_bytes(document)
    return document


def _journal_genesis_document(request, validated_intent):
    transition_result = _validate_transition(
        STATE_START,
        STATE_PREPARED,
        validated_intent,
        {},
    )
    return _journal_entry_document(
        request,
        sequence=0,
        prior_entry_sha256=None,
        from_state=STATE_START,
        to_state=STATE_PREPARED,
        decision_at=0,
        gate_observations_by_type={},
        transition_result=transition_result,
        protected_state_preimage_sha256=None,
    )


def _journal_request_valid(document, filename_digest, root_stat):
    if type(document) is not dict:
        return False
    if len(document) != len(_JOURNAL_REQUEST_FIELDS):
        return False
    for key in document:
        if type(key) is not str:
            return False
    if set(document) != set(_JOURNAL_REQUEST_FIELDS):
        return False
    if document["schema"] != JOURNAL_REQUEST_SCHEMA:
        return False
    if document["journal_contract_id"] != _journal_contract_id():
        return False
    if document["activation_contract_id"] != _activation_contract_id():
        return False
    try:
        validated = _validate_intent(document["activation_intent"])
    except Exception:
        return False
    if validated != document["activation_intent"]:
        return False
    if document["intent_sha256"] != _intent_sha256(validated):
        return False
    if document["transaction_id"] != _transaction_id(
        _activation_contract_id(), validated
    ):
        return False
    for key, expected in (
        ("journal_root_device", root_stat.st_dev),
        ("journal_root_inode", root_stat.st_ino),
    ):
        if type(document[key]) is not int or document[key] != expected:
            return False
        if document[key] < 0 or document[key] > MAX_INT:
            return False
    expected_hash = _journal_self_hash(
        _JOURNAL_REQUEST_HASH_DOMAIN, document, "request_sha256"
    )
    return (
        _matches(_HEX64_PATTERN, document["request_sha256"])
        and document["request_sha256"] == expected_hash
        and filename_digest == expected_hash
    )


def _journal_entry_shape_valid(document, filename_digest, request):
    if type(document) is not dict:
        return False
    if len(document) != len(_JOURNAL_ENTRY_FIELDS):
        return False
    for key in document:
        if type(key) is not str:
            return False
    if set(document) != set(_JOURNAL_ENTRY_FIELDS):
        return False
    fixed = {
        "schema": JOURNAL_ENTRY_SCHEMA,
        "journal_contract_id": _journal_contract_id(),
        "activation_contract_id": _activation_contract_id(),
        "transaction_id": request["transaction_id"],
        "request_sha256": request["request_sha256"],
    }
    for key, expected in fixed.items():
        if type(document[key]) is not str or document[key] != expected:
            return False
    sequence = document["sequence"]
    if type(sequence) is not int:
        return False
    if sequence < 0 or sequence >= MAX_JOURNAL_ENTRIES:
        return False
    prior = document["prior_entry_sha256"]
    if prior is not None and not _matches(_HEX64_PATTERN, prior):
        return False
    for key in ("from_state", "to_state"):
        if type(document[key]) is not str or document[key] not in STATE_GRAPH:
            return False
    decision_at = document["decision_at"]
    if type(decision_at) is not int:
        return False
    if decision_at < 0 or decision_at > MAX_INT:
        return False
    if type(document["gate_observations_by_type"]) is not dict:
        return False
    if type(document["gate_observation_sha256_by_type"]) is not dict:
        return False
    if not _matches(
        _HEX64_PATTERN, document["transition_result_sha256"]
    ):
        return False
    preimage = document["protected_state_preimage_sha256"]
    if preimage is not None and not _matches(_HEX64_PATTERN, preimage):
        return False
    expected_hash = _journal_self_hash(
        _JOURNAL_ENTRY_HASH_DOMAIN, document, "entry_sha256"
    )
    return (
        _matches(_HEX64_PATTERN, document["entry_sha256"])
        and document["entry_sha256"] == expected_hash
        and filename_digest == expected_hash
    )


def _journal_integrity_refusal():
    return _JournalRefusal(
        JOURNAL_STATUS_BLOCKED,
        "journal-integrity-invalid",
        read_performed=True,
    )


def _journal_validate_entry_semantics(
    entry,
    request,
    validated_intent,
    prior_entry,
    protected_anchor,
):
    sequence = entry["sequence"]
    if sequence == 0:
        expected = _journal_genesis_document(request, validated_intent)
        if entry != expected or prior_entry is not None:
            raise _journal_integrity_refusal()
        return None
    if prior_entry is None:
        raise _journal_integrity_refusal()
    if sequence != prior_entry["sequence"] + 1:
        raise _journal_integrity_refusal()
    if entry["prior_entry_sha256"] != prior_entry["entry_sha256"]:
        raise _journal_integrity_refusal()
    if entry["from_state"] != prior_entry["to_state"]:
        raise _journal_integrity_refusal()
    if entry["decision_at"] <= prior_entry["decision_at"]:
        raise _journal_integrity_refusal()
    try:
        transition_result = _validate_transition(
            entry["from_state"],
            entry["to_state"],
            validated_intent,
            entry["gate_observations_by_type"],
        )
    except Exception:
        raise _journal_integrity_refusal()
    if transition_result["status"] != STATUS_VALID:
        raise _journal_integrity_refusal()
    if entry["gate_observation_sha256_by_type"] != transition_result[
        "gate_observation_sha256_by_type"
    ]:
        raise _journal_integrity_refusal()
    if entry["transition_result_sha256"] != (
        _journal_transition_result_sha256(transition_result)
    ):
        raise _journal_integrity_refusal()
    observations = transition_result["gate_observations_by_type"]
    for observation in observations.values():
        if observation["observed_state_entry_sha256"] != prior_entry[
            "entry_sha256"
        ]:
            raise _journal_integrity_refusal()
        if not (
            prior_entry["decision_at"] < observation["observed_at"]
            <= entry["decision_at"]
        ):
            raise _journal_integrity_refusal()
    for observation_type in sorted(observations):
        observation = observations[observation_type]
        if observation_type == "host-authority":
            if not (
                entry["decision_at"]
                < observation["minimum_authority_expires_at"]
            ):
                raise _journal_integrity_refusal()
        if observation_type in _GATE_PROTECTED_STATE_TYPES:
            observed_preimage = observation[
                "protected_state_preimage_sha256"
            ]
            if observation_type == "recovery-readiness":
                if protected_anchor is None:
                    protected_anchor = observed_preimage
                elif protected_anchor != observed_preimage:
                    raise _journal_integrity_refusal()
            elif (
                protected_anchor is None
                or protected_anchor != observed_preimage
            ):
                raise _journal_integrity_refusal()
    if entry["protected_state_preimage_sha256"] != protected_anchor:
        raise _journal_integrity_refusal()
    return protected_anchor


def _journal_directory_names(directory_fd):
    iterator = None
    close_iterator = None
    try:
        iterator = _JOURNAL_SCANDIR(directory_fd)
        close_iterator = getattr(iterator, "close", None)
        if not callable(close_iterator):
            raise ValueError("scandir-close-unavailable")
        names = []
        for entry in iterator:
            if len(names) >= MAX_JOURNAL_DIRECTORY_NAMES:
                raise ValueError("journal-directory-name-limit")
            name = getattr(entry, "name", None)
            if type(name) is not str:
                raise ValueError("journal-directory-name-invalid")
            names.append(name)
        closing = close_iterator
        iterator = None
        close_iterator = None
        closing()
        return names
    except Exception:
        if iterator is not None:
            iterator = None
            closing = close_iterator
            close_iterator = None
            if callable(closing):
                try:
                    closing()
                except Exception:
                    pass
        raise


def _journal_scan(directory_fd, root_stat, validated_intent):
    try:
        names = _journal_directory_names(directory_fd)
    except Exception:
        raise _journal_integrity_refusal()
    if type(names) is not list or len(names) > MAX_JOURNAL_DIRECTORY_NAMES:
        raise _journal_integrity_refusal()
    if any(type(name) is not str for name in names):
        raise _journal_integrity_refusal()
    initial_names = sorted(names)
    if JOURNAL_LOCK_FILENAME not in names:
        raise _journal_integrity_refusal()
    request_files = []
    entry_files = []
    for name in names:
        if type(name) is not str or not name.isascii():
            raise _journal_integrity_refusal()
        if name == JOURNAL_LOCK_FILENAME:
            continue
        request_match = _JOURNAL_REQUEST_FILENAME_PATTERN.fullmatch(name)
        if request_match is not None:
            request_files.append((name, request_match.group(1)))
            continue
        entry_match = _JOURNAL_ENTRY_FILENAME_PATTERN.fullmatch(name)
        if entry_match is not None:
            entry_files.append((name, entry_match.group(1)))
            continue
        raise _journal_integrity_refusal()
    if len(request_files) > 1 or len(entry_files) > MAX_JOURNAL_ENTRIES:
        raise _journal_integrity_refusal()
    if not request_files:
        if entry_files:
            raise _journal_integrity_refusal()
        try:
            if sorted(_journal_directory_names(directory_fd)) != initial_names:
                raise _journal_integrity_refusal()
        except _JournalRefusal:
            raise
        except Exception:
            raise _journal_integrity_refusal()
        return {
            "state": "empty",
            "request": None,
            "entries": [],
            "entry_by_sha256": {},
            "tip": None,
            "protected_state_preimage_sha256": None,
            "total_bytes": 0,
        }

    total_bytes = 0
    try:
        request, size = _journal_read_document(
            directory_fd, request_files[0][0]
        )
    except Exception:
        raise _journal_integrity_refusal()
    total_bytes += size
    if total_bytes > MAX_JOURNAL_SCAN_BYTES:
        raise _journal_integrity_refusal()
    if not _journal_request_valid(
        request, request_files[0][1], root_stat
    ):
        raise _journal_integrity_refusal()
    expected_request = _journal_request_document(validated_intent, root_stat)
    if request != expected_request:
        raise _JournalRefusal(
            JOURNAL_STATUS_CONFLICT,
            "activation-request-mismatch",
            read_performed=True,
        )
    if not entry_files:
        try:
            if sorted(_journal_directory_names(directory_fd)) != initial_names:
                raise _journal_integrity_refusal()
        except _JournalRefusal:
            raise
        except Exception:
            raise _journal_integrity_refusal()
        return {
            "state": "request-only",
            "request": request,
            "entries": [],
            "entry_by_sha256": {},
            "tip": None,
            "protected_state_preimage_sha256": None,
            "total_bytes": total_bytes,
        }

    entry_by_sha256 = {}
    for filename, filename_digest in sorted(entry_files):
        try:
            entry, size = _journal_read_document(directory_fd, filename)
        except Exception:
            raise _journal_integrity_refusal()
        total_bytes += size
        if total_bytes > MAX_JOURNAL_SCAN_BYTES:
            raise _journal_integrity_refusal()
        if not _journal_entry_shape_valid(
            entry, filename_digest, request
        ):
            raise _journal_integrity_refusal()
        digest = entry["entry_sha256"]
        if digest in entry_by_sha256:
            raise _journal_integrity_refusal()
        entry_by_sha256[digest] = entry

    genesis_entries = [
        entry for entry in entry_by_sha256.values()
        if entry["sequence"] == 0
    ]
    if len(genesis_entries) != 1:
        raise _journal_integrity_refusal()
    genesis = genesis_entries[0]
    children = {}
    for entry in entry_by_sha256.values():
        if entry is genesis:
            continue
        prior = entry["prior_entry_sha256"]
        if prior not in entry_by_sha256:
            raise _journal_integrity_refusal()
        children.setdefault(prior, []).append(entry)
        if len(children[prior]) != 1:
            raise _journal_integrity_refusal()

    ordered = []
    seen = set()
    current = genesis
    protected_anchor = None
    prior_entry = None
    while current is not None:
        digest = current["entry_sha256"]
        if digest in seen:
            raise _journal_integrity_refusal()
        seen.add(digest)
        protected_anchor = _journal_validate_entry_semantics(
            current,
            request,
            validated_intent,
            prior_entry,
            protected_anchor,
        )
        ordered.append(current)
        successors = children.get(digest, [])
        current = successors[0] if successors else None
        prior_entry = ordered[-1]
    if len(seen) != len(entry_by_sha256):
        raise _journal_integrity_refusal()
    tip = ordered[-1]
    try:
        if sorted(_journal_directory_names(directory_fd)) != initial_names:
            raise _journal_integrity_refusal()
    except _JournalRefusal:
        raise
    except Exception:
        raise _journal_integrity_refusal()
    return {
        "state": "ready",
        "request": request,
        "entries": ordered,
        "entry_by_sha256": entry_by_sha256,
        "tip": tip,
        "protected_state_preimage_sha256": protected_anchor,
        "total_bytes": total_bytes,
    }


def _journal_snapshot_fields(snapshot):
    request = snapshot.get("request")
    tip = snapshot.get("tip")
    fields = {}
    if request is not None:
        fields.update(
            transaction_id=request["transaction_id"],
            intent_sha256=request["intent_sha256"],
            request_sha256=request["request_sha256"],
        )
    if tip is not None:
        fields.update(
            entry_sha256=tip["entry_sha256"],
            prior_entry_sha256=tip["prior_entry_sha256"],
            sequence=tip["sequence"],
            from_state=tip["from_state"],
            to_state=tip["to_state"],
            tip_state=tip["to_state"],
            protected_state_preimage_sha256=tip[
                "protected_state_preimage_sha256"
            ],
        )
    return fields


def _journal_result_from_refusal(command, refusal, base_fields):
    fields = dict(base_fields)
    fields.update(refusal.fields)
    fields.update(
        journal_read_performed=refusal.read_performed,
        journal_write_attempted=refusal.write_attempted,
        journal_written=refusal.written,
    )
    return _journal_result(
        command, refusal.status, refusal.token, **fields
    )


def _journal_platform_preflight_result(command):
    if _JOURNAL_PLATFORM_SUPPORTED:
        return None
    return _journal_result(
        command,
        JOURNAL_STATUS_UNSUPPORTED,
        "journal-platform-unsupported",
        journal_read_supported=False,
        journal_write_supported=False,
        journal_read_performed=False,
        journal_write_attempted=False,
        journal_written=False,
    )


def _journal_reprove_or_refuse(handles, *, possible_write=False):
    if _journal_reprove_private(handles):
        return
    if possible_write:
        raise _JournalWriteUnknown(read_performed=True)
    raise _journal_integrity_refusal()


def _journal_sample_now(snapshot):
    try:
        value = _JOURNAL_NOW()
    except Exception:
        raise _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            "internal-error",
            read_performed=True,
            fields=_journal_snapshot_fields(snapshot),
        )
    if type(value) is not int or value < 1 or value > MAX_INT:
        raise _JournalRefusal(
            JOURNAL_STATUS_DENIED,
            "decision-clock-regressed",
            read_performed=True,
            fields=_journal_snapshot_fields(snapshot),
        )
    return value


def _journal_host_minimum_expiries(candidate):
    observations = candidate["gate_observations_by_type"]
    return [
        observation["minimum_authority_expires_at"]
        for observation_type, observation in observations.items()
        if observation_type == "host-authority"
    ]


def _journal_scan_with_reproof(handles, validated_intent, *, possible_write=False):
    _journal_reprove_or_refuse(handles, possible_write=possible_write)
    try:
        snapshot = _journal_scan(
            handles.directory_fd, handles.root_stat, validated_intent
        )
    except Exception:
        if possible_write:
            raise _JournalWriteUnknown(read_performed=True)
        raise
    _journal_reprove_or_refuse(handles, possible_write=possible_write)
    return snapshot


def _journal_validate_append_inputs(
    snapshot,
    validated_intent,
    observed_state_entry_sha256,
    next_state,
    decision_at,
    gate_observations_by_type,
):
    if not _matches(_HEX64_PATTERN, observed_state_entry_sha256):
        raise _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            "observed-state-entry-sha256-invalid",
            read_performed=True,
        )
    if type(decision_at) is not int or decision_at < 1 or decision_at > MAX_INT:
        raise _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            "decision-at-invalid",
            read_performed=True,
        )
    reference = snapshot["entry_by_sha256"].get(
        observed_state_entry_sha256
    )
    current_tip = snapshot["tip"]
    if reference is None:
        raise _JournalRefusal(
            JOURNAL_STATUS_CONFLICT,
            "journal-tip-mismatch",
            read_performed=True,
            fields=_journal_snapshot_fields(snapshot),
        )
    try:
        transition_result = _validate_transition(
            reference["to_state"],
            next_state,
            validated_intent,
            gate_observations_by_type,
        )
    except _Denied as denial:
        raise _JournalRefusal(
            JOURNAL_STATUS_DENIED,
            denial.token,
            read_performed=True,
            fields=_journal_snapshot_fields(snapshot),
        )
    except _Unsupported as refusal:
        raise _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            refusal.token,
            read_performed=True,
            fields=_journal_snapshot_fields(snapshot),
        )
    observations = transition_result["gate_observations_by_type"]
    for observation in observations.values():
        if observation["observed_state_entry_sha256"] != (
            observed_state_entry_sha256
        ):
            raise _JournalRefusal(
                JOURNAL_STATUS_DENIED,
                "observation-tip-mismatch",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        if not (
            reference["decision_at"] < observation["observed_at"]
            <= decision_at
        ):
            raise _JournalRefusal(
                JOURNAL_STATUS_DENIED,
                "observation-time-invalid",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
    if decision_at <= reference["decision_at"]:
        raise _JournalRefusal(
            JOURNAL_STATUS_DENIED,
            "observation-time-invalid",
            read_performed=True,
            fields=_journal_snapshot_fields(snapshot),
        )
    anchor = reference["protected_state_preimage_sha256"]
    for observation_type in sorted(observations):
        observation = observations[observation_type]
        if observation_type == "host-authority" and not (
            decision_at < observation["minimum_authority_expires_at"]
        ):
            raise _JournalRefusal(
                JOURNAL_STATUS_DENIED,
                "host-authority-expired-at-decision",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        if observation_type in _GATE_PROTECTED_STATE_TYPES:
            candidate = observation["protected_state_preimage_sha256"]
            if observation_type == "recovery-readiness" and anchor is None:
                anchor = candidate
            elif anchor is None or anchor != candidate:
                raise _JournalRefusal(
                    JOURNAL_STATUS_DENIED,
                    "protected-state-preimage-mismatch",
                    read_performed=True,
                    fields=_journal_snapshot_fields(snapshot),
                )
    request = snapshot["request"]
    candidate_entry = _journal_entry_document(
        request,
        sequence=reference["sequence"] + 1,
        prior_entry_sha256=reference["entry_sha256"],
        from_state=reference["to_state"],
        to_state=transition_result["next_state"],
        decision_at=decision_at,
        gate_observations_by_type=observations,
        transition_result=transition_result,
        protected_state_preimage_sha256=anchor,
    )
    if reference is not current_tip:
        existing_children = [
            entry for entry in snapshot["entries"]
            if entry["prior_entry_sha256"] == reference["entry_sha256"]
        ]
        if len(existing_children) == 1 and existing_children[0] == (
            candidate_entry
        ):
            return candidate_entry, True
        raise _JournalRefusal(
            JOURNAL_STATUS_CONFLICT,
            "journal-tip-mismatch",
            read_performed=True,
            fields=_journal_snapshot_fields(snapshot),
        )
    return candidate_entry, False


def begin_activation_journal(journal_root, *, activation_intent):
    """Create or resume one immutable request and deterministic genesis."""
    command = COMMAND_JOURNAL_BEGIN
    platform_result = _journal_platform_preflight_result(command)
    if platform_result is not None:
        return platform_result
    handles = None
    validated_intent = None
    base_fields = {}
    write_completed = False
    try:
        validated_intent = _validate_intent(activation_intent)
        base_fields.update(_journal_identity_fields(validated_intent))
        handles = _journal_acquire(journal_root, create=True)
        if handles.infrastructure_written:
            write_completed = True
        snapshot = _journal_scan_with_reproof(handles, validated_intent)
        if snapshot["state"] == "empty":
            request = _journal_request_document(
                validated_intent, handles.root_stat
            )
            before = _journal_scan_with_reproof(handles, validated_intent)
            if before["state"] != "empty":
                raise _journal_integrity_refusal()
            _journal_publish_document(
                handles.directory_fd,
                JOURNAL_REQUEST_PREFIX
                + request["request_sha256"]
                + JOURNAL_DOCUMENT_SUFFIX,
                request,
            )
            write_completed = True
            snapshot = _journal_scan_with_reproof(
                handles, validated_intent, possible_write=True
            )
            if snapshot["state"] != "request-only":
                raise _JournalWriteUnknown(read_performed=True)
        if snapshot["state"] == "request-only":
            genesis = _journal_genesis_document(
                snapshot["request"], validated_intent
            )
            before = _journal_scan_with_reproof(handles, validated_intent)
            if before["state"] != "request-only":
                if write_completed:
                    raise _JournalWriteUnknown(read_performed=True)
                raise _journal_integrity_refusal()
            _journal_publish_document(
                handles.directory_fd,
                JOURNAL_ENTRY_PREFIX
                + genesis["entry_sha256"]
                + JOURNAL_DOCUMENT_SUFFIX,
                genesis,
            )
            write_completed = True
            snapshot = _journal_scan_with_reproof(
                handles, validated_intent, possible_write=True
            )
            if (
                snapshot["state"] != "ready"
                or snapshot["tip"] != genesis
            ):
                raise _JournalWriteUnknown(read_performed=True)
            fields = _journal_snapshot_fields(snapshot)
            fields.update(
                journal_read_performed=True,
                journal_write_attempted=True,
                journal_written=True,
            )
            return _journal_result(
                command,
                JOURNAL_STATUS_INITIALIZED,
                "journal-created",
                **fields,
            )
        if snapshot["state"] != "ready":
            raise _journal_integrity_refusal()
        if handles.infrastructure_written:
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-integrity-invalid",
                read_performed=True,
                write_attempted=True,
                written=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        fields = _journal_snapshot_fields(snapshot)
        fields.update(
            journal_read_performed=True,
            journal_write_attempted=False,
            journal_written=False,
        )
        return _journal_result(
            command,
            JOURNAL_STATUS_INITIALIZED,
            "journal-already-initialized",
            **fields,
        )
    except _Unsupported as refusal:
        journal_refusal = _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            refusal.token,
            read_performed=False,
        )
        return _journal_result_from_refusal(
            command, journal_refusal, base_fields
        )
    except _JournalRefusal as refusal:
        if write_completed and refusal.status != (
            JOURNAL_STATUS_OUTCOME_UNKNOWN
        ):
            refusal = _JournalWriteUnknown(
                read_performed=refusal.read_performed,
                fields=refusal.fields,
            )
        return _journal_result_from_refusal(command, refusal, base_fields)
    except Exception:
        if write_completed:
            refusal = _JournalWriteUnknown(read_performed=True)
        else:
            refusal = _JournalRefusal(
                JOURNAL_STATUS_UNSUPPORTED,
                "internal-error",
                read_performed=handles is not None,
            )
        return _journal_result_from_refusal(command, refusal, base_fields)
    finally:
        _journal_release(handles)


def append_activation_transition(
    journal_root,
    *,
    activation_intent,
    observed_state_entry_sha256,
    next_state,
    decision_at,
    gate_observations_by_type=None,
):
    """Validate and append one immutable transition to the unique journal tip."""
    command = COMMAND_JOURNAL_APPEND
    platform_result = _journal_platform_preflight_result(command)
    if platform_result is not None:
        return platform_result
    handles = None
    validated_intent = None
    base_fields = {}
    write_started = False
    try:
        validated_intent = _validate_intent(activation_intent)
        base_fields.update(_journal_identity_fields(validated_intent))
        handles = _journal_acquire(journal_root, create=False)
        snapshot = _journal_scan_with_reproof(handles, validated_intent)
        if snapshot["state"] == "empty":
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-uninitialized",
                read_performed=True,
            )
        if snapshot["state"] == "request-only":
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-request-only",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        if snapshot["state"] != "ready":
            raise _journal_integrity_refusal()
        candidate, idempotent = _journal_validate_append_inputs(
            snapshot,
            validated_intent,
            observed_state_entry_sha256,
            next_state,
            decision_at,
            gate_observations_by_type,
        )
        if idempotent:
            fields = _journal_snapshot_fields(snapshot)
            fields.update(
                entry_sha256=candidate["entry_sha256"],
                prior_entry_sha256=candidate["prior_entry_sha256"],
                sequence=candidate["sequence"],
                from_state=candidate["from_state"],
                to_state=candidate["to_state"],
                tip_state=snapshot["tip"]["to_state"],
                protected_state_preimage_sha256=candidate[
                    "protected_state_preimage_sha256"
                ],
                journal_read_performed=True,
                journal_write_attempted=False,
                journal_written=False,
            )
            return _journal_result(
                command,
                JOURNAL_STATUS_APPENDED,
                "transition-already-recorded",
                **fields,
            )
        initial_now = _journal_sample_now(snapshot)
        if decision_at != initial_now:
            raise _JournalRefusal(
                JOURNAL_STATUS_DENIED,
                "decision-clock-mismatch",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        for minimum_expiry in _journal_host_minimum_expiries(candidate):
            if initial_now >= minimum_expiry:
                raise _JournalRefusal(
                    JOURNAL_STATUS_DENIED,
                    "host-authority-expired-at-decision",
                    read_performed=True,
                    fields=_journal_snapshot_fields(snapshot),
                )
        if len(snapshot["entries"]) >= MAX_JOURNAL_ENTRIES:
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-entry-limit",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        before = _journal_scan_with_reproof(handles, validated_intent)
        if (
            before["state"] != "ready"
            or before["tip"] != snapshot["tip"]
            or before["entries"] != snapshot["entries"]
        ):
            raise _journal_integrity_refusal()
        final_now = _journal_sample_now(snapshot)
        if final_now < initial_now:
            raise _JournalRefusal(
                JOURNAL_STATUS_DENIED,
                "decision-clock-regressed",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        for minimum_expiry in _journal_host_minimum_expiries(candidate):
            if final_now >= minimum_expiry:
                raise _JournalRefusal(
                    JOURNAL_STATUS_DENIED,
                    "host-authority-expired-at-decision",
                    read_performed=True,
                    fields=_journal_snapshot_fields(snapshot),
                )
        _journal_publish_document(
            handles.directory_fd,
            JOURNAL_ENTRY_PREFIX
            + candidate["entry_sha256"]
            + JOURNAL_DOCUMENT_SUFFIX,
            candidate,
        )
        write_started = True
        after = _journal_scan_with_reproof(
            handles, validated_intent, possible_write=True
        )
        if after["state"] != "ready" or after["tip"] != candidate:
            raise _JournalWriteUnknown(read_performed=True)
        fields = _journal_snapshot_fields(after)
        fields.update(
            journal_read_performed=True,
            journal_write_attempted=True,
            journal_written=True,
        )
        return _journal_result(
            command,
            JOURNAL_STATUS_APPENDED,
            "transition-recorded",
            **fields,
        )
    except _Unsupported as refusal:
        journal_refusal = _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            refusal.token,
            read_performed=False,
        )
        return _journal_result_from_refusal(
            command, journal_refusal, base_fields
        )
    except _JournalRefusal as refusal:
        if write_started and refusal.written is False:
            refusal = _JournalWriteUnknown(
                read_performed=True, fields=refusal.fields
            )
        return _journal_result_from_refusal(command, refusal, base_fields)
    except Exception:
        refusal = (
            _JournalWriteUnknown(read_performed=True)
            if write_started
            else _JournalRefusal(
                JOURNAL_STATUS_UNSUPPORTED,
                "internal-error",
                read_performed=handles is not None,
            )
        )
        return _journal_result_from_refusal(command, refusal, base_fields)
    finally:
        _journal_release(handles)


def inspect_activation_journal(journal_root, *, activation_intent):
    """Read and prove the one complete request chain without mutating it."""
    command = COMMAND_JOURNAL_INSPECT
    platform_result = _journal_platform_preflight_result(command)
    if platform_result is not None:
        return platform_result
    handles = None
    validated_intent = None
    base_fields = {}
    try:
        validated_intent = _validate_intent(activation_intent)
        base_fields.update(_journal_identity_fields(validated_intent))
        handles = _journal_acquire(journal_root, create=False)
        snapshot = _journal_scan_with_reproof(handles, validated_intent)
        if snapshot["state"] == "empty":
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-uninitialized",
                read_performed=True,
            )
        if snapshot["state"] == "request-only":
            raise _JournalRefusal(
                JOURNAL_STATUS_BLOCKED,
                "journal-request-only",
                read_performed=True,
                fields=_journal_snapshot_fields(snapshot),
            )
        if snapshot["state"] != "ready":
            raise _journal_integrity_refusal()
        fields = _journal_snapshot_fields(snapshot)
        fields.update(
            journal_read_performed=True,
            journal_write_attempted=False,
            journal_written=False,
        )
        return _journal_result(
            command,
            JOURNAL_STATUS_INSPECTED,
            "journal-consistent",
            **fields,
        )
    except _Unsupported as refusal:
        journal_refusal = _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            refusal.token,
            read_performed=False,
        )
        return _journal_result_from_refusal(
            command, journal_refusal, base_fields
        )
    except _JournalRefusal as refusal:
        return _journal_result_from_refusal(command, refusal, base_fields)
    except Exception:
        refusal = _JournalRefusal(
            JOURNAL_STATUS_UNSUPPORTED,
            "internal-error",
            read_performed=handles is not None,
        )
        return _journal_result_from_refusal(command, refusal, base_fields)
    finally:
        _journal_release(handles)

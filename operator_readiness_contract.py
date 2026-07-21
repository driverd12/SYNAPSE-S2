"""Versioned operator-readiness and local quiescence contracts.

This module is deliberately dependency-free so the readiness producer and its
cutover consumers can validate the same immutable policy without importing one
another.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


OPERATOR_READINESS_PROOF_CONTRACT_SCHEMA = (
    "synapse-s2.operator-readiness-proof-contract.v2"
)
OPERATOR_READINESS_PROOF_CONTRACT_VERSION = 2
OPERATOR_READINESS_REQUIRED_PROOF_IDS = (
    "runtime_build_identity",
    "client_config",
    "local_launcher",
    "mcp_connect",
    "mcp_status_call",
    "mcp_contract_probe",
    "neural_embedding",
    "doctor",
    "start_work",
    "memory_write",
    "recall",
    "app_preview",
    "wrap_session",
    "capture_inbox",
    "authority_guard",
    "guarded_quiescence",
    "capture_ledger_audit",
    "recovery_backup",
    "recovery_verify",
    "recovery_restore",
    "dashboard",
)


def ready_operator_proof_contract() -> dict[str, Any]:
    """Return the only proof-contract summary accepted for a ready pack."""

    return {
        "schema": OPERATOR_READINESS_PROOF_CONTRACT_SCHEMA,
        "version": OPERATOR_READINESS_PROOF_CONTRACT_VERSION,
        "required_proof_ids": list(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
        "valid": True,
        "missing": [],
        "duplicates": [],
    }


QUIESCENCE_POLICY_SCHEMA = "synapse-s2.local-quiescence-policy.v1"
QUIESCENCE_POLICY_VERSION = 1


@dataclass(frozen=True)
class LaunchAgentQuiescenceRule:
    """One exact launchd service rule in the reviewed cutover policy."""

    category: str
    label: str
    require_disabled_when_unloaded: bool = False


QUIESCENCE_LAUNCH_AGENT_RULES = (
    LaunchAgentQuiescenceRule(
        category="capture",
        label="aero.boom.synapse-s2.capture-daemon",
    ),
    LaunchAgentQuiescenceRule(
        category="dashboard",
        label="aero.boom.synapse-s2.dashboard",
    ),
    LaunchAgentQuiescenceRule(
        category="core",
        label="aero.boom.synapse-s2.core",
    ),
    # This external worker is a persistent writer respawner. Merely observing
    # it unloaded is insufficient: cutover requires positive disabled-state
    # evidence so launchd cannot recreate a writer after the process snapshot.
    LaunchAgentQuiescenceRule(
        category="master_mold_capture_respawner",
        label="com.master-mold.imprint.inboxworker",
        require_disabled_when_unloaded=True,
    ),
)


def quiescence_launch_agent_rules() -> dict[str, LaunchAgentQuiescenceRule]:
    """Return the reviewed rules keyed by their stable inventory category."""

    return {rule.category: rule for rule in QUIESCENCE_LAUNCH_AGENT_RULES}


def quiescence_policy_contract() -> dict[str, Any]:
    """Return the exact, versioned machine-quiescence policy."""

    return {
        "schema": QUIESCENCE_POLICY_SCHEMA,
        "version": QUIESCENCE_POLICY_VERSION,
        "launch_agents": [
            {
                "category": rule.category,
                "label": rule.label,
                "require_disabled_when_unloaded": (
                    rule.require_disabled_when_unloaded
                ),
            }
            for rule in QUIESCENCE_LAUNCH_AGENT_RULES
        ],
    }


def quiescence_policy_digest() -> str:
    """Bind evidence to the exact ordered policy contract."""

    canonical = json.dumps(
        quiescence_policy_contract(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


REPLAY_DEBT_COUNTERS = (
    "missing_authoritative_ledger_count",
    "replay_required_capture_count",
    "replay_required_file_count",
    "identifierless_replay_file_count",
    "unclassified_file_count",
)

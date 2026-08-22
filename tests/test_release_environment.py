"""Tests for the Phase-5A candidate-environment document contract.

Goldens here are independently pinned: literal schemas, domain bytes, key
tuples, and a test-local canonical/hash helper that never calls back into
module internals for its expectations.
"""

import ast
import builtins
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SOURCE = os.path.join(_REPO, "scripts", "release_environment.py")
_JOURNAL = os.path.join(_REPO, "scripts", "release_activation_journal.py")
_COMPATIBILITY = os.path.join(_REPO, "scripts", "release_compatibility.py")
_SIGNER = os.path.join(_REPO, "scripts", "sign_release_provenance.py")
sys.path.insert(0, os.path.join(_REPO, "scripts"))

import release_environment as re_mod  # noqa: E402


def _load_activation_fixture():
    spec = importlib.util.spec_from_file_location(
        "release_environment_activation_fixture",
        os.path.join(_REPO, "tests", "test_release_activation_journal.py"),
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("activation fixture unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


activation_fixture = _load_activation_fixture()

# ---------------------------------------------------------------------------
# Independently pinned literals (never derived from the module under test).
# ---------------------------------------------------------------------------

PINNED_ACTIVATION_ID = (
    "activation-contract-"
    "db5a82b45bfc11d9a56a81fb7f0710e95d429fdfd313aac3743bd6d31abad276"
)
PINNED_JOURNAL_SHA256 = (
    "36f8b4befcf2783608be4e3c95911ead8176bfab35b8bcf9593301f8e0bcc3df"
)
PINNED_JOURNAL_CONTRACT_ID = (
    "activation-journal-contract-"
    "bc13294365c58271c141eebf3bfc9496b79991ec9e50e27f998ffd130070194a"
)
PINNED_BASE_ACTIVATION_TRANSACTION_ID = (
    "transaction-"
    "6677a3e9c08b9b4ed73b5778e6f76014b7af44c77c9bbf17d8437a5875ada819"
)
PINNED_RECEIPT_ACTIVATION_TRANSACTION_ID = (
    "transaction-"
    "a103634774aab7df3355ed32894d013537f6d0538dd1909c4c3fe684761034d4"
)
PINNED_ENVIRONMENT_CONTRACT_ID = (
    "environment-contract-"
    "fec40398c01456d33b1bf5980b737987d1825fea8194d102af7d0afd939cfe3e"
)
PINNED_REQUEST_SHA256 = (
    "47c1f028ca4ef32022f1e4d7525b23f54c28d01b16b8ab1f623f075fe88dfcfd"
)
PINNED_OBSERVATION_SHA256 = (
    "1dcc8bdd5e5a3d40c6ac4ea21f378ebf6d04788d24541ab4f9ec8659ef7ead55"
)
PINNED_ENVIRONMENT_ID = (
    "environment-"
    "2d1eadb13e970bbcaba8599ea42ab700c45fe05d13691d2b6d0e930ffd84ab88"
)
PINNED_RECEIPT_SHA256 = (
    "6902e660750b24cc830a43bf41c659fc4640315ca5e274b5b8a80e0b3ead2923"
)
PINNED_PLANNED_RESULT_SHA256 = (
    "84911265abdd30e504a3c20a8fa6c7eee22c58fe326d33aaaf53e7293d17d80d"
)
PINNED_VALID_RESULT_SHA256 = (
    "d65f6f0f6e98abc68c5cdf100fc51c8411f4fdb82aeea82be5927a2d22b2e21e"
)
PINNED_PLANNED_RENDER = (
    '{"blocker_5_complete":false,"command":"plan-release-environment",'
    '"environment_contract_id":"environment-contract-fec40398c01456d33b1bf5980b737987d1825fea8194d102af7d0afd939cfe3e",'
    '"environment_id":"","environment_receipt_sha256":"",'
    '"evidence_verified":false,"observation_sha256":"",'
    '"reason":"planned-document-only-not-evidence-verified",'
    '"request_sha256":"47c1f028ca4ef32022f1e4d7525b23f54c28d01b16b8ab1f623f075fe88dfcfd",'
    '"schema":"synapse-s2.release-environment-render.v1",'
    '"status":"planned"}'
)
PINNED_VALID_RENDER = (
    '{"blocker_5_complete":false,'
    '"command":"validate-candidate-environment-receipt",'
    '"environment_contract_id":"environment-contract-fec40398c01456d33b1bf5980b737987d1825fea8194d102af7d0afd939cfe3e",'
    '"environment_id":"environment-2d1eadb13e970bbcaba8599ea42ab700c45fe05d13691d2b6d0e930ffd84ab88",'
    '"environment_receipt_sha256":"6902e660750b24cc830a43bf41c659fc4640315ca5e274b5b8a80e0b3ead2923",'
    '"evidence_verified":false,'
    '"observation_sha256":"1dcc8bdd5e5a3d40c6ac4ea21f378ebf6d04788d24541ab4f9ec8659ef7ead55",'
    '"reason":"document-valid-not-evidence-verified",'
    '"request_sha256":"47c1f028ca4ef32022f1e4d7525b23f54c28d01b16b8ab1f623f075fe88dfcfd",'
    '"schema":"synapse-s2.release-environment-render.v1",'
    '"status":"document_valid"}'
)

PROJECTION_KEYS = (
    "schema", "mode", "profile", "profile_version",
    "compatibility_profile_version", "compatibility_profile_disposition",
    "activation_contract_id", "schemas",
    "domains_hex", "identity_prefixes", "request_keys", "binding_keys",
    "observation_keys", "receipt_keys", "result_keys", "render_keys",
    "request_fixed", "binding_fixed", "observation_fixed", "receipt_fixed",
    "derived_fixed_fields", "field_patterns", "observed_bindings",
    "observation_digests", "observation_digest_pattern",
    "environment_id_pattern", "int_fields", "equality_requirements",
    "forbidden_keys", "forbidden_key_pattern", "key_pattern", "limits",
    "canonicalization", "hash_bindings", "result_policy", "flags",
    "nonclaims", "fallback_line", "evidence_verified",
    "blocker_5_complete", "environment_contract_id", "contract_sha256",
)

CONTRACT_SCHEMA = "synapse-s2.release-environment-contract.v1"
REQUEST_SCHEMA = "synapse-s2.release-environment-request.v1"
OBSERVATION_SCHEMA = "synapse-s2.release-environment-observation.v1"
RECEIPT_SCHEMA = "synapse-s2.candidate-environment-receipt.v1"
RESULT_SCHEMA = "synapse-s2.release-environment-result.v1"
RENDER_SCHEMA = "synapse-s2.release-environment-render.v1"

MODE = "dormant-source-only-environment-contract"
PROFILE = "exact-build-only"

PLAN_COMMAND = "plan-release-environment"
VALIDATE_COMMAND = "validate-candidate-environment-receipt"
PLANNED_REASON = "planned-document-only-not-evidence-verified"
DOCUMENT_VALID_REASON = "document-valid-not-evidence-verified"
UNSUPPORTED_PLAN_REASON = "unsupported-request-document"
UNSUPPORTED_VALIDATE_REASON = "unsupported-receipt-document"
MAX_INT = 2**53

NONCLAIMS = [
    "document-validation-is-not-evidence-verification",
    "blocker-5-remains-incomplete",
    "no-filesystem-or-held-root-observation",
    "no-clock-freshness-or-process-environment-observation",
    "no-network",
    "no-profile-3-ticket-or-result-verification-in-this-module",
    "no-release-compatibility-or-stage-document-verification",
    "no-stage-tree-verification-or-stage-journal-authority",
    "no-environment-build-install-or-materialization",
    "no-dependency-lock-install-import-origin-or-runtime-proof",
    "no-model-manifest-cache-content-load-or-inference-proof",
    "no-provider-model-or-target-abi-support-validation",
    "no-observation-evidence-document-schema-or-content-verification",
    "no-activation-policy-or-environment-policy-verification",
    "no-receipt-authentication-ownership-durability-or-immutability",
    "no-host-evidence-verification-or-candidate-execution",
    "no-live-state-service-config-selector-or-floor-mutation",
    "no-activation-journal-write",
    "no-rollback-equivalence-migration-or-downgrade",
    "phase-5b-held-root-evidence-verification-required",
]

BINDING_KEYS = (
    "activation_policy_receipt_sha256", "root_key_id", "trust_generation",
    "trust_bundle_sha256", "release_envelope_sha256",
    "compatibility_ticket_sha256", "compatibility_result_sha256", "channel",
    "version", "release_sequence", "source_sha", "candidate_source_build_id",
    "candidate_product_id", "inventory_policy_id",
    "candidate_dependency_component_id", "surfaces_digest", "layout_schema",
    "layout_mode", "layout_contract_id", "layout_id", "stage_result_sha256",
    "stage_journal_head_sha256", "staged_product_id",
    "staged_source_build_id", "host_id_sha256", "core_config_fingerprint",
    "embedding_space_identity", "embedding_provider", "model_id",
    "model_revision", "embedding_runtime_config_sha256",
    "expected_model_snapshot_sha256", "dependency_lock_sha256",
    "project_metadata_sha256", "environment_policy_id", "target_system",
    "target_machine", "target_python_implementation", "target_python_abi",
    "target_base_executable_sha256",
)
REQUEST_KEYS = (
    "schema", "mode", "profile", "profile_version",
    "environment_contract_id", "activation_contract_id",
    "compatibility_profile_version",
) + BINDING_KEYS
OBSERVED_KEYS = (
    "observed_system", "observed_machine", "observed_python_implementation",
    "observed_python_abi", "observed_base_executable_sha256",
    "observed_dependency_lock_sha256", "observed_project_metadata_sha256",
    "observed_embedding_provider", "observed_model_id",
    "observed_model_revision", "observed_embedding_runtime_config_sha256",
    "observed_model_snapshot_sha256",
)
OBSERVATION_DIGESTS = (
    "environment_manifest_sha256", "installed_distribution_manifest_sha256",
    "native_file_manifest_sha256", "dependency_probe_sha256",
    "interpreter_observation_sha256", "toolchain_observation_sha256",
    "model_manifest_sha256", "model_probe_sha256",
)
OBSERVATION_KEYS = (
    "schema", "mode", "profile", "profile_version",
    "environment_contract_id", "request_sha256",
) + OBSERVED_KEYS + OBSERVATION_DIGESTS
RECEIPT_KEYS = (
    "schema", "mode", "profile", "profile_version",
    "environment_contract_id", "request", "request_sha256", "observation",
    "observation_sha256", "environment_id",
)
RESULT_KEYS = (
    "schema", "command", "status", "reason", "environment_contract_id",
    "request", "receipt", "request_sha256", "observation_sha256",
    "environment_receipt_sha256", "environment_id", "evidence_verified",
    "blocker_5_complete", "flags", "nonclaims", "result_sha256",
)
RENDER_KEYS = (
    "schema", "command", "status", "reason", "environment_contract_id",
    "request_sha256", "observation_sha256", "environment_receipt_sha256",
    "environment_id", "evidence_verified", "blocker_5_complete",
)
FALSE_FLAGS = (
    "filesystem_verified", "access_verified", "build_verified",
    "materialization_verified", "stage_authority_verified",
    "dependency_proof_verified", "model_proof_verified",
    "authentication_verified", "host_evidence_verified",
    "candidate_execution_verified", "activation_performed",
    "apply_performed", "journal_written", "service_started",
    "config_mutated", "selector_updated", "floor_engaged",
    "live_traffic_served", "memory_written", "equivalence_verified",
    "migration_performed", "downgrade_performed",
)

FALLBACK_LINE = (
    '{"blocker_5_complete":false,"evidence_verified":false,'
    '"schema":"synapse-s2.release-environment-render.v1",'
    '"status":"unsupported","valid":false}'
)


def dom(name):
    """Test-local pinned domain bytes."""
    return (
        b"SYNAPSE-S2\x00RELEASE-ENVIRONMENT-"
        + name.encode("ascii")
        + b"\x00v1\x00"
    )


def canon(value):
    """Test-local canonical JSON, independent of the module under test."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def h(name, value):
    """Test-local domain-separated digest."""
    return hashlib.sha256(dom(name) + canon(value).encode("ascii")).hexdigest()


def valid_bindings():
    return {
        "activation_policy_receipt_sha256": "1a" * 32,
        "root_key_id": "ed25519-" + "2b" * 32,
        "trust_generation": 4,
        "trust_bundle_sha256": "3c" * 32,
        "release_envelope_sha256": "4d" * 32,
        "compatibility_ticket_sha256": "5e" * 32,
        "compatibility_result_sha256": "6f" * 32,
        "channel": "stable",
        "version": "2.14.0",
        "release_sequence": 12,
        "source_sha": "7a" * 20,
        "candidate_source_build_id": "source-" + "8b" * 12,
        "candidate_product_id": "product-" + "9c" * 32,
        "inventory_policy_id": "inventory-policy-" + "0d" * 32,
        "candidate_dependency_component_id": "component-" + "1e" * 32,
        "surfaces_digest": "2f" * 32,
        "layout_schema": "synapse-s2.installed-layout-contract.v1",
        "layout_mode": "inactive-versioned-v1",
        "layout_contract_id": (
            "layout-contract-"
            "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
        ),
        "layout_id": "layout-" + "4b" * 32,
        "stage_result_sha256": "5c" * 32,
        "stage_journal_head_sha256": "6d" * 32,
        "staged_product_id": "product-" + "9c" * 32,
        "staged_source_build_id": "source-" + "8b" * 12,
        "host_id_sha256": "7e" * 32,
        "core_config_fingerprint": "8f" * 32,
        "embedding_space_identity": "synapse-s2/embedding-space.v3",
        "embedding_provider": "voyage",
        "model_id": "voyage-3-large",
        "model_revision": "9a" * 20,
        "embedding_runtime_config_sha256": "0b" * 32,
        "expected_model_snapshot_sha256": "1c" * 32,
        "dependency_lock_sha256": "2d" * 32,
        "project_metadata_sha256": "3e" * 32,
        "environment_policy_id": "environment-policy-" + "4f" * 32,
        "target_system": "darwin",
        "target_machine": "arm64",
        "target_python_implementation": "cpython",
        "target_python_abi": "cp312",
        "target_base_executable_sha256": "5a" * 32,
    }


def valid_request():
    request = {
        "schema": REQUEST_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": 1,
        "environment_contract_id": PINNED_ENVIRONMENT_CONTRACT_ID,
        "activation_contract_id": PINNED_ACTIVATION_ID,
        "compatibility_profile_version": 3,
    }
    request.update(valid_bindings())
    return request


def valid_observation(request, request_sha256):
    observation = {
        "schema": OBSERVATION_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": 1,
        "environment_contract_id": PINNED_ENVIRONMENT_CONTRACT_ID,
        "request_sha256": request_sha256,
        "observed_system": request["target_system"],
        "observed_machine": request["target_machine"],
        "observed_python_implementation":
            request["target_python_implementation"],
        "observed_python_abi": request["target_python_abi"],
        "observed_base_executable_sha256":
            request["target_base_executable_sha256"],
        "observed_dependency_lock_sha256": request["dependency_lock_sha256"],
        "observed_project_metadata_sha256":
            request["project_metadata_sha256"],
        "observed_embedding_provider": request["embedding_provider"],
        "observed_model_id": request["model_id"],
        "observed_model_revision": request["model_revision"],
        "observed_embedding_runtime_config_sha256":
            request["embedding_runtime_config_sha256"],
        "observed_model_snapshot_sha256":
            request["expected_model_snapshot_sha256"],
    }
    for index, name in enumerate(OBSERVATION_DIGESTS):
        observation[name] = ("%02x" % (0xB0 + index)) * 32
    return observation


def environment_identity(request_sha256, observation_sha256):
    return "environment-" + h(
        "IDENTITY",
        {
            "environment_contract_id": PINNED_ENVIRONMENT_CONTRACT_ID,
            "request_sha256": request_sha256,
            "observation_sha256": observation_sha256,
        },
    )


def valid_receipt():
    request = valid_request()
    request_sha = h("REQUEST", request)
    observation = valid_observation(request, request_sha)
    observation_sha = h("OBSERVATION", observation)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": 1,
        "environment_contract_id": PINNED_ENVIRONMENT_CONTRACT_ID,
        "request": request,
        "request_sha256": request_sha,
        "observation": observation,
        "observation_sha256": observation_sha,
        "environment_id": environment_identity(request_sha,
                                               observation_sha),
    }
    return request, receipt


def rehash_result(result):
    """Coordinated forgery helper: recompute result_sha256 like an attacker."""
    body = {k: v for k, v in result.items() if k != "result_sha256"}
    result["result_sha256"] = h("RESULT", body)
    return result


class AlwaysEqual:
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    def __hash__(self):
        return 0


class SystemExitBomb:
    def __eq__(self, other):
        raise SystemExit(3)

    def __hash__(self):
        return 0

    def __str__(self):
        raise SystemExit(3)


class EvilDict(dict):
    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0

    def keys(self):
        raise SystemExit(3)


class RaisingStr(str):
    def __eq__(self, other):
        raise SystemExit(3)

    def __hash__(self):
        return 0


class TestPins(unittest.TestCase):
    def test_schema_mode_profile_literals(self):
        self.assertEqual(re_mod.CONTRACT_SCHEMA, CONTRACT_SCHEMA)
        self.assertEqual(re_mod.REQUEST_SCHEMA, REQUEST_SCHEMA)
        self.assertEqual(re_mod.OBSERVATION_SCHEMA, OBSERVATION_SCHEMA)
        self.assertEqual(re_mod.RECEIPT_SCHEMA, RECEIPT_SCHEMA)
        self.assertEqual(re_mod.RESULT_SCHEMA, RESULT_SCHEMA)
        self.assertEqual(re_mod.RENDER_SCHEMA, RENDER_SCHEMA)
        self.assertEqual(re_mod.MODE, MODE)
        self.assertEqual(re_mod.PROFILE, PROFILE)
        self.assertEqual(re_mod.PROFILE_VERSION, 1)
        self.assertEqual(re_mod.COMPATIBILITY_PROFILE_VERSION, 3)
        self.assertEqual(
            re_mod.COMPATIBILITY_PROFILE_DISPOSITION,
            "current-profile-3-external-verification-required",
        )
        self.assertEqual(re_mod.ACTIVATION_CONTRACT_ID, PINNED_ACTIVATION_ID)
        self.assertEqual(
            re_mod.ENVIRONMENT_CONTRACT_ID,
            PINNED_ENVIRONMENT_CONTRACT_ID,
        )
        self.assertEqual(re_mod.MAX_INT, MAX_INT)
        self.assertEqual(re_mod._FALLBACK_LINE, FALLBACK_LINE)
        self.assertEqual(tuple(re_mod.BINDING_KEYS), BINDING_KEYS)
        self.assertEqual(tuple(re_mod.REQUEST_KEYS), REQUEST_KEYS)
        self.assertEqual(tuple(re_mod.OBSERVATION_KEYS), OBSERVATION_KEYS)
        self.assertEqual(tuple(re_mod.RECEIPT_KEYS), RECEIPT_KEYS)
        self.assertEqual(tuple(re_mod.RESULT_KEYS), RESULT_KEYS)
        self.assertEqual(tuple(re_mod.RENDER_KEYS), RENDER_KEYS)
        self.assertEqual(tuple(re_mod.FALSE_FLAGS), FALSE_FLAGS)
        self.assertEqual(list(re_mod.NONCLAIMS), NONCLAIMS)

    def test_profile_disposition_matches_current_ticket_siblings(self):
        for path in (_COMPATIBILITY, _SIGNER):
            with self.subTest(path=path):
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                matches = re.findall(
                    r"(?m)^PROFILE_VERSION = ([0-9]+)$", text
                )
                self.assertEqual(matches, ["3"])
        self.assertEqual(re_mod.COMPATIBILITY_PROFILE_VERSION, 3)
        self.assertEqual(
            re_mod.COMPATIBILITY_PROFILE_DISPOSITION,
            "current-profile-3-external-verification-required",
        )
        self.assertIn(
            "no-profile-3-ticket-or-result-verification-in-this-module",
            re_mod.NONCLAIMS,
        )

    def test_domain_literals(self):
        for name in ("CONTRACT", "REQUEST", "OBSERVATION", "IDENTITY",
                     "RECEIPT", "RESULT"):
            self.assertEqual(re_mod._DOMAINS[name], dom(name), name)
            probe = {"probe": name.lower()}
            self.assertEqual(re_mod._digest(name, probe), h(name, probe))
        self.assertEqual(set(re_mod._DOMAINS),
                         {"CONTRACT", "REQUEST", "OBSERVATION", "IDENTITY",
                          "RECEIPT", "RESULT"})

    def test_activation_journal_pinned(self):
        with open(_JOURNAL, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        self.assertEqual(digest, PINNED_JOURNAL_SHA256)

    def test_receipt_digest_plugs_into_frozen_activation_intent(self):
        journal = activation_fixture.journal
        self.assertEqual(
            journal.activation_contract_projection()["activation_contract_id"],
            PINNED_ACTIVATION_ID,
        )
        self.assertEqual(
            journal.journal_contract_projection()["journal_contract_id"],
            PINNED_JOURNAL_CONTRACT_ID,
        )
        self.assertEqual(
            journal.plan_activation_intent(
                activation_fixture._intent()
            )["transaction_id"],
            PINNED_BASE_ACTIVATION_TRANSACTION_ID,
        )

        request, receipt = valid_receipt()
        self.assertEqual(
            re_mod.candidate_environment_receipt_sha256(receipt),
            PINNED_RECEIPT_SHA256,
        )
        intent = activation_fixture._intent()
        for name in (
            "activation_policy_receipt_sha256",
            "root_key_id",
            "trust_generation",
            "trust_bundle_sha256",
            "release_envelope_sha256",
            "compatibility_ticket_sha256",
            "compatibility_result_sha256",
            "channel",
            "version",
            "release_sequence",
            "source_sha",
            "inventory_policy_id",
            "candidate_source_build_id",
            "candidate_product_id",
            "candidate_dependency_component_id",
            "surfaces_digest",
            "layout_schema",
            "layout_mode",
            "layout_contract_id",
            "layout_id",
            "stage_result_sha256",
            "stage_journal_head_sha256",
            "staged_product_id",
            "staged_source_build_id",
            "host_id_sha256",
        ):
            intent[name] = request[name]
        intent["current_dependency_component_id"] = request[
            "candidate_dependency_component_id"
        ]
        intent["environment_receipt_sha256"] = PINNED_RECEIPT_SHA256

        planned = journal.plan_activation_intent(intent)
        self.assertEqual(planned["status"], "planned")
        self.assertEqual(
            planned["transaction_id"],
            PINNED_RECEIPT_ACTIVATION_TRANSACTION_ID,
        )
        self.assertFalse(planned["execution_supported"])
        self.assertFalse(planned["journal_write_supported"])
        self.assertFalse(planned["host_evidence_verified"])

    def test_contract_id_replayed_with_test_local_hash(self):
        projection = re_mod.environment_contract_projection()
        self.assertEqual(tuple(projection), PROJECTION_KEYS)
        body = {k: v for k, v in projection.items()
                if k not in ("environment_contract_id", "contract_sha256")}
        contract_sha = h("CONTRACT", body)
        self.assertEqual(
            contract_sha,
            PINNED_ENVIRONMENT_CONTRACT_ID.removeprefix(
                "environment-contract-"
            ),
        )
        self.assertEqual(projection["contract_sha256"], contract_sha)
        self.assertEqual(projection["environment_contract_id"],
                         "environment-contract-" + contract_sha)
        self.assertEqual(re_mod.ENVIRONMENT_CONTRACT_ID,
                         PINNED_ENVIRONMENT_CONTRACT_ID)
        self.assertEqual(projection["activation_contract_id"],
                         PINNED_ACTIVATION_ID)

    def test_contract_binds_grammars_and_limits(self):
        projection = re_mod.environment_contract_projection()
        self.assertEqual(projection["request_keys"], list(REQUEST_KEYS))
        self.assertEqual(projection["observation_keys"],
                         list(OBSERVATION_KEYS))
        self.assertEqual(projection["receipt_keys"], list(RECEIPT_KEYS))
        self.assertEqual(projection["result_keys"], list(RESULT_KEYS))
        self.assertEqual(projection["render_keys"], list(RENDER_KEYS))
        self.assertEqual(projection["flags"], list(FALSE_FLAGS))
        self.assertEqual(projection["nonclaims"], NONCLAIMS)
        self.assertEqual(projection["fallback_line"], FALLBACK_LINE)
        self.assertEqual(
            projection["compatibility_profile_disposition"],
            "current-profile-3-external-verification-required",
        )
        self.assertEqual(
            projection["binding_fixed"],
            {
                "layout_schema":
                    "synapse-s2.installed-layout-contract.v1",
                "layout_mode": "inactive-versioned-v1",
                "layout_contract_id": (
                    "layout-contract-"
                    "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
                ),
                "target_system": "darwin",
                "target_machine": "arm64",
                "target_python_implementation": "cpython",
            },
        )
        self.assertEqual(
            projection["domains_hex"],
            {name.lower(): dom(name).hex()
             for name in ("CONTRACT", "REQUEST", "OBSERVATION", "IDENTITY",
                          "RECEIPT", "RESULT")})
        self.assertEqual(
            set(projection["field_patterns"]),
            set(BINDING_KEYS) - {"trust_generation", "release_sequence"})
        for spec in projection["field_patterns"].values():
            self.assertEqual(set(spec), {"pattern", "flags"})
            self.assertEqual(spec["flags"], 0)
        self.assertEqual(projection["field_patterns"]["source_sha"],
                         {"pattern": r"\A[0-9a-f]{40}\Z", "flags": 0})
        self.assertEqual(projection["field_patterns"]["channel"],
                         {"pattern": r"\A[a-z][a-z0-9-]{0,31}\Z",
                          "flags": 0})
        self.assertEqual(
            projection["field_patterns"]["version"],
            {"pattern": r"\A[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z",
             "flags": 0},
        )
        self.assertEqual(
            projection["field_patterns"]["model_revision"],
            {"pattern": r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z",
             "flags": 0})
        self.assertEqual(projection["int_fields"],
                         {"trust_generation": [1, MAX_INT],
                          "release_sequence": [1, MAX_INT]})
        self.assertEqual(projection["equality_requirements"],
                         [["staged_product_id", "candidate_product_id"],
                          ["staged_source_build_id",
                           "candidate_source_build_id"]])
        self.assertEqual(
            projection["observed_bindings"],
            {"observed_system": "target_system",
             "observed_machine": "target_machine",
             "observed_python_implementation":
                 "target_python_implementation",
             "observed_python_abi": "target_python_abi",
             "observed_base_executable_sha256":
                 "target_base_executable_sha256",
             "observed_dependency_lock_sha256": "dependency_lock_sha256",
             "observed_project_metadata_sha256": "project_metadata_sha256",
             "observed_embedding_provider": "embedding_provider",
             "observed_model_id": "model_id",
             "observed_model_revision": "model_revision",
             "observed_embedding_runtime_config_sha256":
                 "embedding_runtime_config_sha256",
             "observed_model_snapshot_sha256":
                 "expected_model_snapshot_sha256"})
        self.assertIn("forbidden_key_pattern", projection)
        self.assertEqual(
            projection["limits"],
            {
                "max_canonical_bytes": 32768,
                "max_depth": 8,
                "max_integer_abs": MAX_INT,
                "max_keys": 64,
                "max_render_bytes": 1024,
                "max_string_chars": 1024,
            },
        )
        self.assertEqual(
            projection["canonicalization"],
            {
                "format": "json",
                "hash_algorithm": "sha256",
                "byte_encoding": "ascii",
                "sort_keys": True,
                "separators": [",", ":"],
                "ensure_ascii": True,
                "allow_nan": False,
                "trailing_newline": False,
                "exact_builtin_types": True,
            },
        )
        self.assertEqual(
            projection["hash_bindings"],
            {
                "environment_contract_id": {
                    "domain": "CONTRACT",
                    "prefix": "environment-contract-",
                    "preimage": "canonical-contract-body",
                    "excluded_fields": [
                        "environment_contract_id", "contract_sha256"
                    ],
                },
                "request_sha256": {
                    "domain": "REQUEST",
                    "preimage": "canonical-complete-request",
                },
                "observation_sha256": {
                    "domain": "OBSERVATION",
                    "preimage": "canonical-complete-observation",
                },
                "environment_id": {
                    "domain": "IDENTITY",
                    "prefix": "environment-",
                    "preimage_fields": [
                        "environment_contract_id",
                        "request_sha256",
                        "observation_sha256",
                    ],
                },
                "environment_receipt_sha256": {
                    "domain": "RECEIPT",
                    "preimage": "canonical-complete-receipt",
                    "receipt_self_hash_field": "absent",
                },
                "result_sha256": {
                    "domain": "RESULT",
                    "preimage":
                        "canonical-result-without-result-sha256",
                    "excluded_fields": ["result_sha256"],
                },
            },
        )
        self.assertEqual(
            projection["result_policy"],
            {
                "plan": {
                    "command": PLAN_COMMAND,
                    "planned": {
                        "reason": PLANNED_REASON,
                        "populated_document_fields": ["request"],
                        "populated_identity_fields": ["request_sha256"],
                        "exit_code": 0,
                    },
                    "unsupported": {
                        "reason": UNSUPPORTED_PLAN_REASON,
                        "populated_document_fields": [],
                        "populated_identity_fields": [],
                        "exit_code": 1,
                    },
                },
                "validate": {
                    "command": VALIDATE_COMMAND,
                    "document_valid": {
                        "reason": DOCUMENT_VALID_REASON,
                        "populated_document_fields": ["receipt"],
                        "populated_identity_fields": [
                            "request_sha256",
                            "observation_sha256",
                            "environment_receipt_sha256",
                            "environment_id",
                        ],
                        "exit_code": 0,
                    },
                    "unsupported": {
                        "reason": UNSUPPORTED_VALIDATE_REASON,
                        "populated_document_fields": [],
                        "populated_identity_fields": [],
                        "exit_code": 1,
                    },
                },
                "invalid_or_nonrenderable_exit_code": 1,
                "replay": (
                    "recompute-all-populated-documents-identities-and-"
                    "result-digest-and-require-exact-native-population"
                ),
            },
        )
        self.assertEqual(projection["evidence_verified"], False)
        self.assertEqual(projection["blocker_5_complete"], False)
        self.assertEqual(projection,
                         re_mod.environment_contract_projection())


class TestPlanVector(unittest.TestCase):
    def test_plan_matches_test_local_vector(self):
        result = re_mod.plan_environment_request(**valid_bindings())
        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["command"], PLAN_COMMAND)
        self.assertEqual(result["reason"], PLANNED_REASON)
        self.assertEqual(tuple(sorted(result)), tuple(sorted(RESULT_KEYS)))
        self.assertEqual(result["request"], valid_request())
        self.assertEqual(result["request_sha256"],
                         h("REQUEST", valid_request()))
        self.assertEqual(result["request_sha256"], PINNED_REQUEST_SHA256)
        for name in ("receipt", "observation_sha256",
                     "environment_receipt_sha256", "environment_id"):
            self.assertEqual(result[name], "")
        self.assertIs(result["evidence_verified"], False)
        self.assertIs(result["blocker_5_complete"], False)
        self.assertEqual(result["nonclaims"], NONCLAIMS)
        self.assertEqual(tuple(sorted(result["flags"])),
                         tuple(sorted(FALSE_FLAGS)))
        for value in result["flags"].values():
            self.assertIs(value, False)
        body = {k: v for k, v in result.items() if k != "result_sha256"}
        self.assertEqual(result["result_sha256"], h("RESULT", body))
        self.assertEqual(
            result["result_sha256"], PINNED_PLANNED_RESULT_SHA256
        )
        self.assertEqual(re_mod.environment_result_exit_code(result), 0)

    def test_plan_render_exact_keys_and_no_leakage(self):
        result = re_mod.plan_environment_request(**valid_bindings())
        line = re_mod.render_environment_result(result)
        self.assertNotEqual(line, FALLBACK_LINE)
        self.assertEqual(line, PINNED_PLANNED_RENDER)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertLessEqual(len(line), 1024)
        parsed = json.loads(line)
        self.assertEqual(set(parsed), set(RENDER_KEYS))
        self.assertEqual(parsed["schema"], RENDER_SCHEMA)
        self.assertEqual(parsed["status"], "planned")
        self.assertEqual(parsed["reason"], PLANNED_REASON)
        self.assertEqual(parsed["request_sha256"], result["request_sha256"])
        self.assertIs(parsed["evidence_verified"], False)
        self.assertIs(parsed["blocker_5_complete"], False)
        for leaked in {
            value for value in valid_bindings().values()
            if type(value) is str
        }:
            self.assertNotIn(leaked, line, leaked)


class TestReceiptVector(unittest.TestCase):
    def test_receipt_matches_test_local_vector(self):
        request, receipt = valid_receipt()
        result = re_mod.validate_environment_receipt_document(request,
                                                              receipt)
        self.assertEqual(result["status"], "document_valid")
        self.assertEqual(result["command"], VALIDATE_COMMAND)
        self.assertEqual(result["reason"], DOCUMENT_VALID_REASON)
        self.assertEqual(result["request"], "")
        self.assertEqual(result["receipt"], receipt)
        self.assertEqual(result["request_sha256"], h("REQUEST", request))
        self.assertEqual(result["request_sha256"], PINNED_REQUEST_SHA256)
        self.assertEqual(result["observation_sha256"],
                         h("OBSERVATION", receipt["observation"]))
        self.assertEqual(
            result["observation_sha256"], PINNED_OBSERVATION_SHA256
        )
        self.assertEqual(result["environment_receipt_sha256"],
                         h("RECEIPT", receipt))
        self.assertEqual(
            result["environment_receipt_sha256"], PINNED_RECEIPT_SHA256
        )
        self.assertEqual(result["environment_id"],
                         receipt["environment_id"])
        self.assertEqual(result["environment_id"], PINNED_ENVIRONMENT_ID)
        self.assertEqual(
            result["result_sha256"], PINNED_VALID_RESULT_SHA256
        )
        self.assertEqual(
            re_mod.candidate_environment_receipt_sha256(receipt),
            h("RECEIPT", receipt))
        self.assertEqual(re_mod.environment_result_exit_code(result), 0)
        line = re_mod.render_environment_result(result)
        self.assertEqual(line, PINNED_VALID_RENDER)
        self.assertEqual(set(json.loads(line)), set(RENDER_KEYS))
        self.assertIn(result["environment_receipt_sha256"], line)
        self.assertIn(result["environment_id"], line)
        for leaked in {
            value
            for document in (request, receipt["observation"])
            for value in document.values()
            if type(value) is str
            and value not in {
                PINNED_REQUEST_SHA256,
                PINNED_OBSERVATION_SHA256,
                PINNED_RECEIPT_SHA256,
                PINNED_ENVIRONMENT_ID,
                PINNED_ENVIRONMENT_CONTRACT_ID,
            }
        }:
            self.assertNotIn(leaked, line, leaked)

    def test_receipt_digest_is_external_no_transaction_fields(self):
        _, receipt = valid_receipt()
        self.assertEqual(tuple(sorted(receipt)), tuple(sorted(RECEIPT_KEYS)))
        for key in ("environment_receipt_sha256", "transaction_id",
                    "intent_sha256", "timestamp", "nonce", "host_evidence",
                    "gate_evidence"):
            self.assertNotIn(key, receipt)
            self.assertNotIn(key, receipt["request"])
            self.assertNotIn(key, receipt["observation"])

    def test_receipt_extra_or_forbidden_keys_rejected(self):
        for key in ("environment_receipt_sha256", "transaction_id",
                    "intent_sha256", "timestamp", "timestamps", "nonce",
                    "nonces", "session_token", "created_at",
                    "host_evidence", "gate_evidence"):
            request, receipt = valid_receipt()
            receipt[key] = "0" * 64
            result = re_mod.validate_environment_receipt_document(request,
                                                                  receipt)
            self.assertEqual(result["status"], "unsupported", key)
            self.assertEqual(result["request"], "")
            self.assertEqual(result["receipt"], "")
            self.assertEqual(result["environment_id"], "")
            with self.assertRaises(ValueError):
                re_mod.candidate_environment_receipt_sha256(receipt)

    def test_deleted_key_mutants_rejected(self):
        for name in RECEIPT_KEYS:
            request, receipt = valid_receipt()
            del receipt[name]
            result = re_mod.validate_environment_receipt_document(request,
                                                                  receipt)
            self.assertEqual(result["status"], "unsupported", name)
        for name in OBSERVATION_KEYS:
            request, receipt = valid_receipt()
            del receipt["observation"][name]
            result = re_mod.validate_environment_receipt_document(request,
                                                                  receipt)
            self.assertEqual(result["status"], "unsupported", name)
        for name in REQUEST_KEYS:
            request, receipt = valid_receipt()
            del receipt["request"][name]
            result = re_mod.validate_environment_receipt_document(request,
                                                                  receipt)
            self.assertEqual(result["status"], "unsupported", name)

    def test_fixed_fields_and_digest_grammars(self):
        fixed_bad = {
            "schema": "wrong-schema.v1",
            "mode": "wrong-mode",
            "profile": "wrong-profile",
            "profile_version": 2,
            "environment_contract_id": "environment-contract-" + "f" * 64,
        }
        for name, bad in fixed_bad.items():
            request, receipt = valid_receipt()
            receipt[name] = bad
            self.assertEqual(
                re_mod.validate_environment_receipt_document(
                    request, receipt
                )["status"],
                "unsupported",
                ("receipt", name),
            )
            request, receipt = valid_receipt()
            receipt["observation"][name] = bad
            observation_sha = h("OBSERVATION", receipt["observation"])
            receipt["observation_sha256"] = observation_sha
            receipt["environment_id"] = environment_identity(
                receipt["request_sha256"], observation_sha
            )
            self.assertEqual(
                re_mod.validate_environment_receipt_document(
                    request, receipt
                )["status"],
                "unsupported",
                ("observation", name),
            )
        for name in OBSERVATION_DIGESTS:
            request, receipt = valid_receipt()
            receipt["observation"][name] = "g" * 64
            observation_sha = h("OBSERVATION", receipt["observation"])
            receipt["observation_sha256"] = observation_sha
            receipt["environment_id"] = environment_identity(
                receipt["request_sha256"], observation_sha
            )
            self.assertEqual(
                re_mod.validate_environment_receipt_document(
                    request, receipt
                )["status"],
                "unsupported",
                name,
            )

    def test_canonical_json_round_trip(self):
        request, receipt = valid_receipt()
        round_tripped = json.loads(canon(receipt))
        self.assertEqual(round_tripped, receipt)
        self.assertEqual(
            re_mod.candidate_environment_receipt_sha256(round_tripped),
            PINNED_RECEIPT_SHA256,
        )
        result = re_mod.validate_environment_receipt_document(
            request, round_tripped
        )
        self.assertEqual(result["status"], "document_valid")
        self.assertEqual(
            json.loads(canon(result)), result
        )
        self.assertEqual(
            re_mod.render_environment_result(json.loads(canon(result))),
            PINNED_VALID_RENDER,
        )


class TestClosedRejections(unittest.TestCase):
    def test_plan_is_closed_never_raises(self):
        base = valid_bindings()
        for name in BINDING_KEYS:
            for bad in (123.5, None, [], {}, "\x01", "x" * 513, True,
                        AlwaysEqual(), SystemExitBomb(), EvilDict()):
                mutated = dict(base)
                mutated[name] = bad
                result = re_mod.plan_environment_request(**mutated)
                self.assertEqual(result["status"], "unsupported", name)
                self.assertEqual(result["request"], "")
                self.assertEqual(result["request_sha256"], "")
                self.assertEqual(re_mod.environment_result_exit_code(result),
                                 1, name)
            missing = dict(base)
            del missing[name]
            self.assertEqual(
                re_mod.plan_environment_request(**missing)["status"],
                "unsupported", name)
        extra = dict(base)
        extra["extra_field"] = "x"
        self.assertEqual(re_mod.plan_environment_request(**extra)["status"],
                         "unsupported")

    def test_grammar_specifics(self):
        cases = (
            ("source_sha", "7a" * 32), ("source_sha", "Z" * 40),
            ("root_key_id", "ed25519-" + "g" * 64),
            ("root_key_id", "2b" * 32),
            ("candidate_source_build_id", "source-" + "8b" * 32),
            ("candidate_product_id", "9c" * 32),
            ("inventory_policy_id", "inventory-" + "0d" * 32),
            ("layout_id", "layout-contract-" + "3a" * 32),
            ("environment_policy_id", "environment-" + "4f" * 32),
            ("channel", "Nightly"), ("channel", "x" * 33),
            ("version", "-2.14.0"), ("version", "x" * 65),
            ("model_revision", "9a" * 25),
            ("model_id", "x" * 200), ("target_system", "Darwin"),
            ("trust_generation", 0), ("trust_generation", MAX_INT + 1),
            ("release_sequence", 0), ("release_sequence", MAX_INT + 1),
            ("trust_generation", True), ("release_sequence", 2.0),
        )
        for name, bad in cases:
            mutated = valid_bindings()
            mutated[name] = bad
            result = re_mod.plan_environment_request(**mutated)
            self.assertEqual(result["status"], "unsupported", (name, bad))

    def test_sibling_grammar_and_integer_boundaries(self):
        for name, good in (
            ("channel", "nightly"),
            ("channel", "stable-hotfix"),
            ("version", "2.14"),
            ("version", "v2.14.0"),
            ("version", "2.14.0-rc1+arm64"),
            ("trust_generation", MAX_INT),
            ("release_sequence", MAX_INT),
        ):
            mutated = valid_bindings()
            mutated[name] = good
            self.assertEqual(
                re_mod.plan_environment_request(**mutated)["status"],
                "planned",
                (name, good),
            )

    def test_exact_layout_and_canonical_host_values(self):
        for name, bad in (
            ("layout_schema", "wrong-layout.v1"),
            ("layout_mode", "active-versioned-v1"),
            ("layout_contract_id", "layout-contract-" + "f" * 64),
            ("target_system", "linux"),
            ("target_machine", "x86_64"),
            ("target_python_implementation", "pypy"),
        ):
            mutated = valid_bindings()
            mutated[name] = bad
            self.assertEqual(
                re_mod.plan_environment_request(**mutated)["status"],
                "unsupported",
                name,
            )

    def test_staged_must_equal_candidate(self):
        mutated = valid_bindings()
        mutated["staged_product_id"] = "product-" + "0a" * 32
        self.assertEqual(re_mod.plan_environment_request(**mutated)["status"],
                         "unsupported")
        mutated = valid_bindings()
        mutated["staged_source_build_id"] = "source-" + "0a" * 12
        self.assertEqual(re_mod.plan_environment_request(**mutated)["status"],
                         "unsupported")

    def test_fixed_field_tampering_rejected(self):
        for name, bad in (("schema", "release-environment-request/v1"),
                          ("mode", "active"),
                          ("profile", "any-build"),
                          ("profile_version", 2),
                          ("profile_version", True),
                          ("compatibility_profile_version", 2),
                          ("compatibility_profile_version", True),
                          ("activation_contract_id",
                           "activation-contract-" + "0" * 64),
                          ("environment_contract_id",
                           "environment-contract-" + "0" * 64)):
            request, receipt = valid_receipt()
            request[name] = bad
            receipt["request"] = dict(request)
            result = re_mod.validate_environment_receipt_document(request,
                                                                  receipt)
            self.assertEqual(result["status"], "unsupported", name)

    def test_cross_binding_forgery_rejected_even_when_rehashed(self):
        forgeries = (
            ("observed_model_revision", "0f" * 20),
            ("observed_model_id", "other-model"),
            ("observed_embedding_provider", "other-provider"),
            ("observed_dependency_lock_sha256", "0f" * 32),
            ("observed_model_snapshot_sha256", "0f" * 32),
            ("observed_project_metadata_sha256", "0f" * 32),
            ("observed_base_executable_sha256", "0f" * 32),
            ("observed_system", "linux"),
            ("observed_machine", "x86_64"),
            ("observed_python_implementation", "pypy"),
            ("observed_python_abi", "cp311"),
            ("observed_embedding_runtime_config_sha256", "0f" * 32),
        )
        for name, bad in forgeries:
            request, receipt = valid_receipt()
            observation = dict(receipt["observation"])
            observation[name] = bad
            # Coordinated attacker: rehash observation, identity and receipt.
            observation_sha = h("OBSERVATION", observation)
            receipt["observation"] = observation
            receipt["observation_sha256"] = observation_sha
            receipt["environment_id"] = environment_identity(
                receipt["request_sha256"], observation_sha)
            result = re_mod.validate_environment_receipt_document(request,
                                                                  receipt)
            self.assertEqual(result["status"], "unsupported", name)
            with self.assertRaises(ValueError):
                re_mod.candidate_environment_receipt_sha256(receipt)

    def test_observation_wrong_request_binding_rejected(self):
        request, receipt = valid_receipt()
        receipt["observation"] = dict(receipt["observation"])
        receipt["observation"]["request_sha256"] = "0f" * 32
        receipt["observation_sha256"] = h("OBSERVATION",
                                          receipt["observation"])
        receipt["environment_id"] = environment_identity(
            receipt["request_sha256"], receipt["observation_sha256"])
        result = re_mod.validate_environment_receipt_document(request,
                                                              receipt)
        self.assertEqual(result["status"], "unsupported")


class TestResultReplay(unittest.TestCase):
    def test_rehash_forgery_planned_to_document_valid(self):
        result = re_mod.plan_environment_request(**valid_bindings())
        forged = copy.deepcopy(result)
        forged["command"] = VALIDATE_COMMAND
        forged["status"] = "document_valid"
        forged["reason"] = DOCUMENT_VALID_REASON
        forged["environment_id"] = "environment-" + "a" * 64
        forged["observation_sha256"] = "b" * 64
        forged["environment_receipt_sha256"] = "c" * 64
        rehash_result(forged)
        self.assertEqual(re_mod.render_environment_result(forged),
                         FALLBACK_LINE)
        self.assertEqual(re_mod.environment_result_exit_code(forged), 1)

    def test_rehash_forgery_arbitrary_environment_id_on_planned(self):
        result = re_mod.plan_environment_request(**valid_bindings())
        forged = copy.deepcopy(result)
        forged["environment_id"] = "a" * 64
        rehash_result(forged)
        self.assertEqual(re_mod.environment_result_exit_code(forged), 1)

    def test_rehash_forgery_swapped_receipt_identity(self):
        request, receipt = valid_receipt()
        result = re_mod.validate_environment_receipt_document(request,
                                                              receipt)
        for name, bad in (("environment_id", "environment-" + "a" * 64),
                          ("environment_receipt_sha256", "a" * 64),
                          ("observation_sha256", "a" * 64),
                          ("request_sha256", "a" * 64)):
            forged = copy.deepcopy(result)
            forged[name] = bad
            rehash_result(forged)
            self.assertEqual(re_mod.environment_result_exit_code(forged), 1,
                             name)

    def test_rehash_forgery_tampered_embedded_documents(self):
        request, receipt = valid_receipt()
        result = re_mod.validate_environment_receipt_document(request,
                                                              receipt)
        forged = copy.deepcopy(result)
        forged["receipt"]["request"]["model_id"] = "other-model"
        forged["request_sha256"] = h("REQUEST", forged["receipt"]["request"])
        rehash_result(forged)
        self.assertEqual(re_mod.environment_result_exit_code(forged), 1)
        planned = re_mod.plan_environment_request(**valid_bindings())
        forged = copy.deepcopy(planned)
        forged["request"]["channel"] = "beta"
        rehash_result(forged)
        self.assertEqual(re_mod.environment_result_exit_code(forged), 1)

    def test_forged_flags_and_nonclaims_rejected(self):
        base = re_mod.plan_environment_request(**valid_bindings())
        for name in FALSE_FLAGS:
            forged = copy.deepcopy(base)
            forged["flags"][name] = True
            rehash_result(forged)
            self.assertEqual(re_mod.environment_result_exit_code(forged), 1,
                             name)
        for key in ("evidence_verified", "blocker_5_complete"):
            forged = copy.deepcopy(base)
            forged[key] = True
            rehash_result(forged)
            self.assertEqual(re_mod.environment_result_exit_code(forged), 1)
        forged = copy.deepcopy(base)
        forged["nonclaims"] = []
        rehash_result(forged)
        self.assertEqual(re_mod.environment_result_exit_code(forged), 1)
        forged = copy.deepcopy(base)
        forged["nonclaims"] = ["evidence-verified", NONCLAIMS[1]]
        rehash_result(forged)
        self.assertEqual(re_mod.environment_result_exit_code(forged), 1)

    def test_unsupported_results_never_exit_zero(self):
        for result, command, reason in (
            (
                re_mod.plan_environment_request(),
                PLAN_COMMAND,
                UNSUPPORTED_PLAN_REASON,
            ),
            (
                re_mod.validate_environment_receipt_document({}, {}),
                VALIDATE_COMMAND,
                UNSUPPORTED_VALIDATE_REASON,
            ),
        ):
            self.assertEqual(result["status"], "unsupported")
            self.assertEqual(result["command"], command)
            self.assertEqual(result["reason"], reason)
            for name in (
                "request", "receipt", "request_sha256",
                "observation_sha256", "environment_receipt_sha256",
                "environment_id",
            ):
                self.assertEqual(result[name], "")
            rendered = re_mod.render_environment_result(result)
            self.assertNotEqual(rendered, FALLBACK_LINE)
            self.assertEqual(
                json.loads(rendered),
                {
                    "schema": RENDER_SCHEMA,
                    "command": command,
                    "status": "unsupported",
                    "reason": reason,
                    "environment_contract_id": re_mod.ENVIRONMENT_CONTRACT_ID,
                    "request_sha256": "",
                    "observation_sha256": "",
                    "environment_receipt_sha256": "",
                    "environment_id": "",
                    "evidence_verified": False,
                    "blocker_5_complete": False,
                },
            )
            self.assertEqual(re_mod.environment_result_exit_code(result), 1)
            for name in (
                "request", "receipt", "request_sha256",
                "observation_sha256", "environment_receipt_sha256",
                "environment_id",
            ):
                forged = copy.deepcopy(result)
                forged[name] = "a" * 64
                rehash_result(forged)
                self.assertEqual(
                    re_mod.render_environment_result(forged), FALLBACK_LINE
                )
                self.assertEqual(
                    re_mod.environment_result_exit_code(forged), 1
                )

    def test_status_command_cross_forgery(self):
        planned = re_mod.plan_environment_request(**valid_bindings())
        for name, bad in (("status", "document_valid"),
                          ("status", "verified"),
                          ("status", "activated"),
                          ("command", VALIDATE_COMMAND),
                          ("reason", DOCUMENT_VALID_REASON),
                          ("schema", RESULT_SCHEMA + ".forged"),
                          ("environment_contract_id",
                           "environment-contract-" + "0" * 64)):
            forged = copy.deepcopy(planned)
            forged[name] = bad
            rehash_result(forged)
            self.assertEqual(re_mod.environment_result_exit_code(forged), 1,
                             name)
        hostile = copy.deepcopy(planned)
        hostile["transaction_id"] = "x"
        self.assertEqual(re_mod.environment_result_exit_code(hostile), 1)


class TestHostileObjectsAndTotality(unittest.TestCase):
    def test_renderer_total_for_hostile_objects(self):
        planned = re_mod.plan_environment_request(**valid_bindings())
        hostiles = (AlwaysEqual(), SystemExitBomb(), EvilDict(),
                    RaisingStr("planned"))
        for name in RESULT_KEYS:
            for hostile in hostiles:
                forged = copy.deepcopy(planned)
                forged[name] = hostile
                self.assertEqual(re_mod.render_environment_result(forged),
                                 FALLBACK_LINE, name)
                self.assertEqual(re_mod.environment_result_exit_code(forged),
                                 1, name)
        for garbage in (None, [], {}, "x", 0, 1.5, object(), EvilDict(),
                        SystemExitBomb(), AlwaysEqual(),
                        {"schema": RESULT_SCHEMA}):
            self.assertEqual(re_mod.render_environment_result(garbage),
                             FALLBACK_LINE)
            self.assertEqual(re_mod.environment_result_exit_code(garbage), 1)

    def test_hostile_objects_inside_documents(self):
        request, receipt = valid_receipt()
        for name in ("schema", "request_sha256", "observation_sha256",
                     "environment_id", "profile_version"):
            tampered = dict(receipt)
            tampered[name] = AlwaysEqual()
            result = re_mod.validate_environment_receipt_document(request,
                                                                  tampered)
            self.assertEqual(result["status"], "unsupported", name)
            tampered = dict(receipt)
            tampered[name] = SystemExitBomb()
            result = re_mod.validate_environment_receipt_document(request,
                                                                  tampered)
            self.assertEqual(result["status"], "unsupported", name)
        evil = EvilDict(receipt)
        result = re_mod.validate_environment_receipt_document(request, evil)
        self.assertEqual(result["status"], "unsupported")
        with self.assertRaises(ValueError):
            re_mod.candidate_environment_receipt_sha256(evil)
        with self.assertRaises(ValueError):
            re_mod.candidate_environment_receipt_sha256(SystemExitBomb())
        evil_request = EvilDict(request)
        result = re_mod.validate_environment_receipt_document(evil_request,
                                                              receipt)
        self.assertEqual(result["status"], "unsupported")

    def test_circular_and_oversize_values(self):
        circular = {}
        circular["self"] = circular
        mutated = valid_bindings()
        mutated["layout_mode"] = circular
        self.assertEqual(re_mod.plan_environment_request(**mutated)["status"],
                         "unsupported")
        result = re_mod.plan_environment_request(**valid_bindings())
        forged = dict(result)
        forged["request"] = circular
        self.assertEqual(re_mod.render_environment_result(forged),
                         FALLBACK_LINE)
        with self.assertRaises(ValueError):
            re_mod._canonical(2**80)
        with self.assertRaises(ValueError):
            re_mod._canonical(1.5)
        deep = "leaf"
        for _ in range(20):
            deep = {"d": deep}
        with self.assertRaises(ValueError):
            re_mod._canonical(deep)
        with self.assertRaises(ValueError):
            re_mod._canonical("x" * 2000)


class TestCardinalityFirstBounds(unittest.TestCase):
    def test_wrong_cardinality_is_rejected_before_unbounded_scan_or_sort(self):
        calls = {"search": 0, "sorted": 0}
        real_search = re_mod.re.search

        def counted_search(*args, **kwargs):
            calls["search"] += 1
            return real_search(*args, **kwargs)

        def counted_sorted(*args, **kwargs):
            calls["sorted"] += 1
            raise AssertionError("hostile mapping reached sorted")

        re_mod.re.search = counted_search
        re_mod.sorted = counted_sorted
        try:
            huge = {"extra_%05d" % index: "x" for index in range(20000)}
            self.assertEqual(
                re_mod.plan_environment_request(**huge)["status"],
                "unsupported",
            )
            self.assertEqual(calls, {"search": 0, "sorted": 0})

            request, _ = valid_receipt()
            result = re_mod.validate_environment_receipt_document(
                request, huge
            )
            self.assertEqual(result["status"], "unsupported")
            self.assertLessEqual(calls["search"], len(REQUEST_KEYS))
            self.assertEqual(calls["sorted"], 0)

            forged = dict(huge)
            self.assertEqual(
                re_mod.render_environment_result(forged), FALLBACK_LINE
            )
            self.assertEqual(calls["sorted"], 0)
        finally:
            re_mod.re.search = real_search
            del re_mod.sorted


class TestMutationClosure(unittest.TestCase):
    def _projection_id(self):
        return re_mod.environment_contract_projection()[
            "environment_contract_id"]

    def test_runtime_grammar_and_limit_mutations_move_contract_id(self):
        baseline = self._projection_id()
        self.assertEqual(baseline, re_mod.ENVIRONMENT_CONTRACT_ID)
        saved_patterns = dict(re_mod._PATTERNS)
        saved_ints = dict(re_mod._INT_FIELDS)
        saved_binding_fixed = dict(re_mod._BINDING_FIXED)
        saved_observed_bindings = dict(re_mod._OBSERVED_BINDINGS)
        saved = {name: getattr(re_mod, name) for name in
                 ("CONTRACT_SCHEMA", "REQUEST_SCHEMA", "OBSERVATION_SCHEMA",
                  "RECEIPT_SCHEMA", "RESULT_SCHEMA", "RENDER_SCHEMA",
                  "FALSE_FLAGS", "BINDING_KEYS", "REQUEST_KEYS",
                  "OBSERVATION_KEYS", "RECEIPT_KEYS", "RESULT_KEYS",
                  "RENDER_KEYS", "NONCLAIMS", "MAX_INT", "_MAX_DEPTH",
                  "_MAX_KEYS", "_MAX_STRING_CHARS", "_MAX_RENDER_BYTES",
                  "_MAX_CANONICAL_BYTES", "_FALLBACK_LINE",
                  "_FORBIDDEN_KEY_PATTERN", "_KEY_PATTERN", "MODE",
                  "PROFILE", "PLANNED_REASON", "DOCUMENT_VALID_REASON",
                  "UNSUPPORTED_PLAN_REASON", "UNSUPPORTED_VALIDATE_REASON",
                  "COMPATIBILITY_PROFILE_VERSION",
                  "COMPATIBILITY_PROFILE_DISPOSITION")}
        mutations = (
            lambda: re_mod._PATTERNS.update(
                {"channel": r"\A[a-z]{1,32}\Z"}),
            lambda: re_mod._PATTERNS.pop("channel"),
            lambda: re_mod._INT_FIELDS.update(
                {"trust_generation": (0, MAX_INT)}),
            lambda: re_mod._BINDING_FIXED.update({"target_system": "linux"}),
            lambda: re_mod._OBSERVED_BINDINGS.pop("observed_machine"),
            lambda: setattr(re_mod, "CONTRACT_SCHEMA", "contract.v2"),
            lambda: setattr(re_mod, "REQUEST_SCHEMA", "request.v2"),
            lambda: setattr(re_mod, "FALSE_FLAGS", re_mod.FALSE_FLAGS[:-1]),
            lambda: setattr(re_mod, "BINDING_KEYS", re_mod.BINDING_KEYS[:-1]),
            lambda: setattr(re_mod, "REQUEST_KEYS", re_mod.REQUEST_KEYS[:-1]),
            lambda: setattr(
                re_mod, "OBSERVATION_KEYS", re_mod.OBSERVATION_KEYS[:-1]
            ),
            lambda: setattr(re_mod, "RECEIPT_KEYS", re_mod.RECEIPT_KEYS[:-1]),
            lambda: setattr(re_mod, "RESULT_KEYS", re_mod.RESULT_KEYS[:-1]),
            lambda: setattr(re_mod, "RENDER_KEYS",
                            re_mod.RENDER_KEYS + ("model_id",)),
            lambda: setattr(re_mod, "NONCLAIMS", ("weakened",)),
            lambda: setattr(re_mod, "MAX_INT", MAX_INT - 1),
            lambda: setattr(re_mod, "_MAX_DEPTH", 9),
            lambda: setattr(re_mod, "_MAX_KEYS", 63),
            lambda: setattr(re_mod, "_MAX_STRING_CHARS", 2048),
            lambda: setattr(re_mod, "_MAX_RENDER_BYTES", 99999),
            lambda: setattr(re_mod, "_MAX_CANONICAL_BYTES", 999999),
            lambda: setattr(re_mod, "_FALLBACK_LINE", "{}"),
            lambda: setattr(re_mod, "_FORBIDDEN_KEY_PATTERN", "^never$"),
            lambda: setattr(re_mod, "_KEY_PATTERN", r"\A.+\Z"),
            lambda: setattr(re_mod, "MODE", "live"),
            lambda: setattr(re_mod, "PROFILE", "any-build"),
            lambda: setattr(re_mod, "PLANNED_REASON", "planned-weakened"),
            lambda: setattr(
                re_mod, "UNSUPPORTED_PLAN_REASON", "unsupported-weakened"
            ),
            lambda: setattr(re_mod, "COMPATIBILITY_PROFILE_VERSION", 4),
            lambda: setattr(
                re_mod,
                "COMPATIBILITY_PROFILE_DISPOSITION",
                "current-profile-accepted",
            ),
        )
        for index, mutate in enumerate(mutations):
            try:
                mutate()
                try:
                    mutated_id = self._projection_id()
                except Exception:
                    continue  # fail-closed is acceptable
                self.assertNotEqual(mutated_id, baseline, index)
            finally:
                re_mod._PATTERNS.clear()
                re_mod._PATTERNS.update(saved_patterns)
                re_mod._INT_FIELDS.clear()
                re_mod._INT_FIELDS.update(saved_ints)
                re_mod._BINDING_FIXED.clear()
                re_mod._BINDING_FIXED.update(saved_binding_fixed)
                re_mod._OBSERVED_BINDINGS.clear()
                re_mod._OBSERVED_BINDINGS.update(saved_observed_bindings)
                for name, value in saved.items():
                    setattr(re_mod, name, value)
        self.assertEqual(self._projection_id(), baseline)

    def test_domain_overlay_mutants_fail_closed(self):
        request, receipt = valid_receipt()
        result = re_mod.validate_environment_receipt_document(request,
                                                              receipt)
        self.assertEqual(re_mod.environment_result_exit_code(result), 0)
        saved_domains = dict(re_mod._DOMAINS)
        baseline = self._projection_id()
        try:
            re_mod._DOMAINS["RESULT"] = dom("RESULT") + b"X"
            self.assertEqual(re_mod.environment_result_exit_code(result), 1)
            self.assertEqual(re_mod.render_environment_result(result),
                             FALLBACK_LINE)
        finally:
            re_mod._DOMAINS.clear()
            re_mod._DOMAINS.update(saved_domains)
        try:
            re_mod._DOMAINS["CONTRACT"] = dom("CONTRACT") + b"X"
            self.assertNotEqual(self._projection_id(), baseline)
        finally:
            re_mod._DOMAINS.clear()
            re_mod._DOMAINS.update(saved_domains)
        try:
            del re_mod._DOMAINS["RECEIPT"]
            out = re_mod.validate_environment_receipt_document(request,
                                                               receipt)
            self.assertEqual(out["status"], "unsupported")
            with self.assertRaises(ValueError):
                re_mod.candidate_environment_receipt_sha256(receipt)
        finally:
            re_mod._DOMAINS.clear()
            re_mod._DOMAINS.update(saved_domains)
        self.assertEqual(re_mod.environment_result_exit_code(result), 0)


class TestPurity(unittest.TestCase):
    def test_ast_imports_and_safe_call_allowlist(self):
        with open(_SOURCE, "r", encoding="ascii") as handle:
            source = handle.read()
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {"hashlib", "json", "re"})
        allowed_names = {
            "len", "all", "ord", "abs", "type", "tuple", "sorted", "list",
            "set",
            "range", "_Reject", "_check_key", "_check_value", "_canonical",
            "_digest", "_check_document_keys", "_request_fixed",
            "_check_fixed", "_validate_request", "_validate_observation",
            "_environment_identity", "_validate_receipt", "_result",
            "_unsupported", "_contract_body", "_require_empty",
            "_validate_result", "render_environment_result",
        }
        allowed_attrs = {
            "sha256", "hexdigest", "encode", "hex", "lower", "dumps",
            "fullmatch", "search", "items", "__init__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    self.assertIn(func.id, allowed_names, func.id)
                elif isinstance(func, ast.Attribute):
                    self.assertIn(func.attr, allowed_attrs, func.attr)
                else:
                    self.fail("unsupported call form")
            if isinstance(node, ast.Name):
                self.assertNotIn(node.id,
                                 {"open", "eval", "exec", "input",
                                  "__import__", "compile", "getattr",
                                  "setattr", "globals", "locals", "vars",
                                  "os", "sys", "time", "datetime", "socket",
                                  "subprocess", "release_activation_journal"})

    def test_every_public_api_under_traps(self):
        with open(_SOURCE, "r", encoding="ascii") as handle:
            source = handle.read()
        real_import = builtins.__import__

        def trapped_import(name, *args, **kwargs):
            if name.split(".")[0] not in ("hashlib", "json", "re",
                                          "_sha256", "_hashlib"):
                raise AssertionError("forbidden import: " + name)
            return real_import(name, *args, **kwargs)

        def trap(*_args, **_kwargs):
            raise AssertionError("forbidden runtime capability used")

        safe_builtins = dict(vars(builtins))
        safe_builtins["__import__"] = trapped_import
        for name in ("open", "eval", "exec", "input", "compile"):
            safe_builtins[name] = trap
        namespace = {"__builtins__": safe_builtins,
                     "__name__": "release_environment_trapped"}
        exec(compile(source, _SOURCE, "exec"), namespace)

        projection = namespace["environment_contract_projection"]()
        self.assertEqual(projection["environment_contract_id"],
                         re_mod.ENVIRONMENT_CONTRACT_ID)
        planned = namespace["plan_environment_request"](**valid_bindings())
        self.assertEqual(planned["status"], "planned")
        hostile_bindings = valid_bindings()
        hostile_bindings["model_id"] = SystemExitBomb()
        self.assertEqual(
            namespace["plan_environment_request"](
                **hostile_bindings)["status"],
            "unsupported")
        request, receipt = valid_receipt()
        validated = namespace["validate_environment_receipt_document"](
            request, receipt)
        self.assertEqual(validated["status"], "document_valid")
        self.assertEqual(
            namespace["validate_environment_receipt_document"](
                request, EvilDict(receipt))["status"],
            "unsupported")
        self.assertEqual(
            namespace["candidate_environment_receipt_sha256"](receipt),
            h("RECEIPT", receipt))
        with self.assertRaises(ValueError):
            namespace["candidate_environment_receipt_sha256"](
                SystemExitBomb())
        self.assertNotEqual(
            namespace["render_environment_result"](planned), FALLBACK_LINE)
        self.assertEqual(
            namespace["environment_result_exit_code"](validated), 0)
        forged = copy.deepcopy(planned)
        forged["environment_id"] = "environment-" + "a" * 64
        rehash_result(forged)
        self.assertEqual(
            namespace["environment_result_exit_code"](forged), 1)
        self.assertEqual(
            namespace["render_environment_result"](SystemExitBomb()),
            FALLBACK_LINE)
        self.assertEqual(
            namespace["environment_result_exit_code"](EvilDict()), 1)


if __name__ == "__main__":
    unittest.main()

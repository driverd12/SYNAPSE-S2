"""Phase-5A candidate-environment document contract (pure, dormant).

Closed canonical ASCII JSON document schemas (contract/request/observation/
receipt/result, all v1). Planning and document validation only: success here
means "planned" or "document_valid", explicitly NOT evidence verification,
and Blocker 5 remains incomplete. No I/O, no time, no environment, no
network. Every field is exact-type-checked with built-in types before any
equality or regex runs, so attacker-controlled __eq__/__hash__ hooks never
execute; the renderer and exit code are total even for BaseException-raising
objects and replay the full public operation instead of trusting any
self-embedded hash.
"""

import hashlib
import json
import re

CONTRACT_SCHEMA = "synapse-s2.release-environment-contract.v1"
REQUEST_SCHEMA = "synapse-s2.release-environment-request.v1"
OBSERVATION_SCHEMA = "synapse-s2.release-environment-observation.v1"
RECEIPT_SCHEMA = "synapse-s2.candidate-environment-receipt.v1"
RESULT_SCHEMA = "synapse-s2.release-environment-result.v1"
RENDER_SCHEMA = "synapse-s2.release-environment-render.v1"

MODE = "dormant-source-only-environment-contract"
PROFILE = "exact-build-only"
PROFILE_VERSION = 1
COMPATIBILITY_PROFILE_VERSION = 3
COMPATIBILITY_PROFILE_DISPOSITION = (
    "current-profile-3-external-verification-required"
)

ACTIVATION_CONTRACT_ID = (
    "activation-contract-"
    "db5a82b45bfc11d9a56a81fb7f0710e95d429fdfd313aac3743bd6d31abad276"
)

PLAN_COMMAND = "plan-release-environment"
VALIDATE_COMMAND = "validate-candidate-environment-receipt"
PLANNED_REASON = "planned-document-only-not-evidence-verified"
DOCUMENT_VALID_REASON = "document-valid-not-evidence-verified"
UNSUPPORTED_PLAN_REASON = "unsupported-request-document"
UNSUPPORTED_VALIDATE_REASON = "unsupported-receipt-document"

NONCLAIMS = (
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
)

_DOMAIN_NAMES = (
    "CONTRACT",
    "REQUEST",
    "OBSERVATION",
    "IDENTITY",
    "RECEIPT",
    "RESULT",
)
_DOMAINS = {
    name: b"SYNAPSE-S2\x00RELEASE-ENVIRONMENT-"
    + name.encode("ascii")
    + b"\x00v1\x00"
    for name in _DOMAIN_NAMES
}

MAX_INT = 2**53

_SHA64_PATTERN = r"\A[0-9a-f]{64}\Z"
_ROOT_KEY_PATTERN = r"\Aed25519-[0-9a-f]{64}\Z"
_SOURCE_SHA_PATTERN = r"\A[0-9a-f]{40}\Z"
_SOURCE_BUILD_PATTERN = r"\Asource-[0-9a-f]{24}\Z"
_PRODUCT_PATTERN = r"\Aproduct-[0-9a-f]{64}\Z"
_COMPONENT_PATTERN = r"\Acomponent-[0-9a-f]{64}\Z"
_INVENTORY_POLICY_PATTERN = r"\Ainventory-policy-[0-9a-f]{64}\Z"
_LAYOUT_CONTRACT_PATTERN = r"\Alayout-contract-[0-9a-f]{64}\Z"
_LAYOUT_PATTERN = r"\Alayout-[0-9a-f]{64}\Z"
_ENVIRONMENT_POLICY_PATTERN = r"\Aenvironment-policy-[0-9a-f]{64}\Z"
_CHANNEL_PATTERN = r"\A[a-z][a-z0-9-]{0,31}\Z"
_VERSION_PATTERN = r"\A[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z"
_REVISION_PATTERN = r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z"
_LABEL_PATTERN = r"\A[A-Za-z0-9][A-Za-z0-9._/+-]{0,127}\Z"
_NAME_PATTERN = r"\A[a-z0-9][a-z0-9._-]{0,63}\Z"
_ENVIRONMENT_ID_PATTERN = r"\Aenvironment-[0-9a-f]{64}\Z"
_KEY_PATTERN = r"\A[a-z][a-z0-9_]{0,63}\Z"

# Exact per-field grammar for every non-fixed, non-integer request binding.
_PATTERNS = {
    "activation_policy_receipt_sha256": _SHA64_PATTERN,
    "root_key_id": _ROOT_KEY_PATTERN,
    "trust_bundle_sha256": _SHA64_PATTERN,
    "release_envelope_sha256": _SHA64_PATTERN,
    "compatibility_ticket_sha256": _SHA64_PATTERN,
    "compatibility_result_sha256": _SHA64_PATTERN,
    "channel": _CHANNEL_PATTERN,
    "version": _VERSION_PATTERN,
    "source_sha": _SOURCE_SHA_PATTERN,
    "candidate_source_build_id": _SOURCE_BUILD_PATTERN,
    "candidate_product_id": _PRODUCT_PATTERN,
    "inventory_policy_id": _INVENTORY_POLICY_PATTERN,
    "candidate_dependency_component_id": _COMPONENT_PATTERN,
    "surfaces_digest": _SHA64_PATTERN,
    "layout_schema": _NAME_PATTERN,
    "layout_mode": _NAME_PATTERN,
    "layout_contract_id": _LAYOUT_CONTRACT_PATTERN,
    "layout_id": _LAYOUT_PATTERN,
    "stage_result_sha256": _SHA64_PATTERN,
    "stage_journal_head_sha256": _SHA64_PATTERN,
    "staged_product_id": _PRODUCT_PATTERN,
    "staged_source_build_id": _SOURCE_BUILD_PATTERN,
    "host_id_sha256": _SHA64_PATTERN,
    "core_config_fingerprint": _SHA64_PATTERN,
    "embedding_space_identity": _LABEL_PATTERN,
    "embedding_provider": _LABEL_PATTERN,
    "model_id": _LABEL_PATTERN,
    "model_revision": _REVISION_PATTERN,
    "embedding_runtime_config_sha256": _SHA64_PATTERN,
    "expected_model_snapshot_sha256": _SHA64_PATTERN,
    "dependency_lock_sha256": _SHA64_PATTERN,
    "project_metadata_sha256": _SHA64_PATTERN,
    "environment_policy_id": _ENVIRONMENT_POLICY_PATTERN,
    "target_system": _NAME_PATTERN,
    "target_machine": _NAME_PATTERN,
    "target_python_implementation": _NAME_PATTERN,
    "target_python_abi": _NAME_PATTERN,
    "target_base_executable_sha256": _SHA64_PATTERN,
}

_INT_FIELDS = {
    "trust_generation": (1, MAX_INT),
    "release_sequence": (1, MAX_INT),
}

_BINDING_FIXED = {
    "layout_schema": "synapse-s2.installed-layout-contract.v1",
    "layout_mode": "inactive-versioned-v1",
    "layout_contract_id": (
        "layout-contract-"
        "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
    ),
    "target_system": "darwin",
    "target_machine": "arm64",
    "target_python_implementation": "cpython",
}

BINDING_KEYS = (
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
    "candidate_source_build_id",
    "candidate_product_id",
    "inventory_policy_id",
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
    "core_config_fingerprint",
    "embedding_space_identity",
    "embedding_provider",
    "model_id",
    "model_revision",
    "embedding_runtime_config_sha256",
    "expected_model_snapshot_sha256",
    "dependency_lock_sha256",
    "project_metadata_sha256",
    "environment_policy_id",
    "target_system",
    "target_machine",
    "target_python_implementation",
    "target_python_abi",
    "target_base_executable_sha256",
)

REQUEST_FIXED_KEYS = (
    "schema",
    "mode",
    "profile",
    "profile_version",
    "environment_contract_id",
    "activation_contract_id",
    "compatibility_profile_version",
)
REQUEST_KEYS = REQUEST_FIXED_KEYS + BINDING_KEYS

# Every observed_* value must equal its expected request counterpart.
_OBSERVED_BINDINGS = {
    "observed_system": "target_system",
    "observed_machine": "target_machine",
    "observed_python_implementation": "target_python_implementation",
    "observed_python_abi": "target_python_abi",
    "observed_base_executable_sha256": "target_base_executable_sha256",
    "observed_dependency_lock_sha256": "dependency_lock_sha256",
    "observed_project_metadata_sha256": "project_metadata_sha256",
    "observed_embedding_provider": "embedding_provider",
    "observed_model_id": "model_id",
    "observed_model_revision": "model_revision",
    "observed_embedding_runtime_config_sha256":
        "embedding_runtime_config_sha256",
    "observed_model_snapshot_sha256": "expected_model_snapshot_sha256",
}

OBSERVATION_DIGESTS = (
    "environment_manifest_sha256",
    "installed_distribution_manifest_sha256",
    "native_file_manifest_sha256",
    "dependency_probe_sha256",
    "interpreter_observation_sha256",
    "toolchain_observation_sha256",
    "model_manifest_sha256",
    "model_probe_sha256",
)

OBSERVATION_FIXED_KEYS = (
    "schema",
    "mode",
    "profile",
    "profile_version",
    "environment_contract_id",
    "request_sha256",
)
OBSERVATION_KEYS = (
    OBSERVATION_FIXED_KEYS
    + (
        "observed_system",
        "observed_machine",
        "observed_python_implementation",
        "observed_python_abi",
        "observed_base_executable_sha256",
        "observed_dependency_lock_sha256",
        "observed_project_metadata_sha256",
        "observed_embedding_provider",
        "observed_model_id",
        "observed_model_revision",
        "observed_embedding_runtime_config_sha256",
        "observed_model_snapshot_sha256",
    )
    + OBSERVATION_DIGESTS
)

RECEIPT_KEYS = (
    "schema",
    "mode",
    "profile",
    "profile_version",
    "environment_contract_id",
    "request",
    "request_sha256",
    "observation",
    "observation_sha256",
    "environment_id",
)

RESULT_KEYS = (
    "schema",
    "command",
    "status",
    "reason",
    "environment_contract_id",
    "request",
    "receipt",
    "request_sha256",
    "observation_sha256",
    "environment_receipt_sha256",
    "environment_id",
    "evidence_verified",
    "blocker_5_complete",
    "flags",
    "nonclaims",
    "result_sha256",
)

RENDER_KEYS = (
    "schema",
    "command",
    "status",
    "reason",
    "environment_contract_id",
    "request_sha256",
    "observation_sha256",
    "environment_receipt_sha256",
    "environment_id",
    "evidence_verified",
    "blocker_5_complete",
)

# Every execution/authority flag is structurally false in Phase 5A.
FALSE_FLAGS = (
    "filesystem_verified",
    "access_verified",
    "build_verified",
    "materialization_verified",
    "stage_authority_verified",
    "dependency_proof_verified",
    "model_proof_verified",
    "authentication_verified",
    "host_evidence_verified",
    "candidate_execution_verified",
    "activation_performed",
    "apply_performed",
    "journal_written",
    "service_started",
    "config_mutated",
    "selector_updated",
    "floor_engaged",
    "live_traffic_served",
    "memory_written",
    "equivalence_verified",
    "migration_performed",
    "downgrade_performed",
)

_FORBIDDEN_KEYS = (
    "transaction_id",
    "intent_sha256",
    "environment_receipt_sha256",
    "timestamp",
    "timestamps",
    "nonce",
    "nonces",
    "host_evidence",
    "gate_evidence",
)
_FORBIDDEN_KEY_PATTERN = (
    "(?:^|_)(?:transaction|intent|timestamp|timestamps|nonce|nonces|token|"
    "session)(?:$|_)|_at$|^receipt_sha256$|^environment_receipt_sha256$"
)

_MAX_CANONICAL_BYTES = 32768
_MAX_DEPTH = 8
_MAX_KEYS = 64
_MAX_STRING_CHARS = 1024
_MAX_RENDER_BYTES = 1024

_FALLBACK_LINE = (
    '{"blocker_5_complete":false,"evidence_verified":false,'
    '"schema":"synapse-s2.release-environment-render.v1",'
    '"status":"unsupported","valid":false}'
)


class _Reject(ValueError):
    """Internal closed rejection carrying a fixed, value-free reason code."""

    def __init__(self, code):
        ValueError.__init__(self, code)
        self.code = code


def _check_key(key):
    if type(key) is not str or len(key) > 64 or not re.fullmatch(
        _KEY_PATTERN, key
    ):
        raise _Reject("invalid-document-key")


def _check_value(value, depth):
    if depth > _MAX_DEPTH:
        raise _Reject("document-too-deep")
    kind = type(value)
    if kind is str:
        if len(value) > _MAX_STRING_CHARS or not all(
            0x20 <= ord(c) <= 0x7E for c in value
        ):
            raise _Reject("invalid-string-value")
    elif kind is bool:
        pass
    elif kind is int:
        if value < -MAX_INT or value > MAX_INT:
            raise _Reject("integer-out-of-bounds")
    elif kind is dict:
        if len(value) > _MAX_KEYS:
            raise _Reject("too-many-keys")
        for key, item in value.items():
            _check_key(key)
            _check_value(item, depth + 1)
    elif kind is list:
        if len(value) > _MAX_KEYS:
            raise _Reject("list-too-long")
        for item in value:
            _check_value(item, depth + 1)
    else:
        raise _Reject("unsupported-value-type")


def _canonical(value):
    _check_value(value, 0)
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if len(text) > _MAX_CANONICAL_BYTES:
        raise _Reject("canonical-document-oversize")
    return text


def _digest(domain, value):
    return hashlib.sha256(
        _DOMAINS[domain] + _canonical(value).encode("ascii")
    ).hexdigest()


def _check_document_keys(document, expected_keys, code, forbid=True):
    if type(document) is not dict:
        raise _Reject(code)
    # Cardinality is an O(1) gate.  Never scan, hash, or sort an
    # attacker-sized mapping before proving it has the closed size.
    if len(document) != len(expected_keys):
        raise _Reject(code)
    for key in document:
        try:
            _check_key(key)
        except BaseException:
            raise _Reject(code)
        if forbid and (
            key in _FORBIDDEN_KEYS
            or re.search(_FORBIDDEN_KEY_PATTERN, key)
        ):
            raise _Reject("forbidden-document-key")
    if set(document) != set(expected_keys):
        raise _Reject(code)


def _request_fixed():
    return {
        "schema": REQUEST_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "environment_contract_id": ENVIRONMENT_CONTRACT_ID,
        "activation_contract_id": ACTIVATION_CONTRACT_ID,
        "compatibility_profile_version": COMPATIBILITY_PROFILE_VERSION,
    }


def _check_fixed(document, fixed, code_prefix):
    for name, expected in fixed.items():
        value = document[name]
        if type(value) is not type(expected) or value != expected:
            raise _Reject(code_prefix + name)


def _validate_request(request):
    _check_document_keys(request, REQUEST_KEYS, "request-key-set-mismatch")
    _check_fixed(request, _request_fixed(), "invalid-request-field:")
    for name, pattern in _PATTERNS.items():
        value = request[name]
        if type(value) is not str or not re.fullmatch(pattern, value):
            raise _Reject("invalid-request-field:" + name)
    for name, bounds in _INT_FIELDS.items():
        value = request[name]
        if type(value) is not int or not bounds[0] <= value <= bounds[1]:
            raise _Reject("invalid-request-field:" + name)
    _check_fixed(request, _BINDING_FIXED, "invalid-request-field:")
    if request["staged_product_id"] != request["candidate_product_id"]:
        raise _Reject("staged-product-differs-from-candidate")
    if (
        request["staged_source_build_id"]
        != request["candidate_source_build_id"]
    ):
        raise _Reject("staged-build-differs-from-candidate")
    return _digest("REQUEST", request)


def _validate_observation(observation, request, request_sha256):
    _check_document_keys(
        observation, OBSERVATION_KEYS, "observation-key-set-mismatch"
    )
    fixed = {
        "schema": OBSERVATION_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "environment_contract_id": ENVIRONMENT_CONTRACT_ID,
        "request_sha256": request_sha256,
    }
    _check_fixed(observation, fixed, "invalid-observation-field:")
    for name, source in _OBSERVED_BINDINGS.items():
        value = observation[name]
        if type(value) is not str or value != request[source]:
            raise _Reject("observation-differs-from-expected:" + name)
    for name in OBSERVATION_DIGESTS:
        value = observation[name]
        if type(value) is not str or not re.fullmatch(_SHA64_PATTERN, value):
            raise _Reject("invalid-observation-field:" + name)
    return _digest("OBSERVATION", observation)


def _environment_identity(request_sha256, observation_sha256):
    return "environment-" + _digest(
        "IDENTITY",
        {
            "environment_contract_id": ENVIRONMENT_CONTRACT_ID,
            "request_sha256": request_sha256,
            "observation_sha256": observation_sha256,
        },
    )


def _validate_receipt(receipt):
    _check_document_keys(receipt, RECEIPT_KEYS, "receipt-key-set-mismatch")
    fixed = {
        "schema": RECEIPT_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "environment_contract_id": ENVIRONMENT_CONTRACT_ID,
    }
    _check_fixed(receipt, fixed, "invalid-receipt-field:")
    request_sha256 = _validate_request(receipt["request"])
    bound_request_sha = receipt["request_sha256"]
    if type(bound_request_sha) is not str or (
        bound_request_sha != request_sha256
    ):
        raise _Reject("receipt-request-digest-mismatch")
    observation_sha256 = _validate_observation(
        receipt["observation"], receipt["request"], request_sha256
    )
    bound_observation_sha = receipt["observation_sha256"]
    if type(bound_observation_sha) is not str or (
        bound_observation_sha != observation_sha256
    ):
        raise _Reject("receipt-observation-digest-mismatch")
    environment_id = _environment_identity(request_sha256, observation_sha256)
    bound_environment_id = receipt["environment_id"]
    if type(bound_environment_id) is not str or (
        bound_environment_id != environment_id
    ):
        raise _Reject("receipt-environment-id-mismatch")
    receipt_sha256 = _digest("RECEIPT", receipt)
    return request_sha256, observation_sha256, receipt_sha256, environment_id


def _result(
    command,
    status,
    reason,
    request,
    receipt,
    request_sha256,
    observation_sha256,
    environment_receipt_sha256,
    environment_id,
):
    body = {
        "schema": RESULT_SCHEMA,
        "command": command,
        "status": status,
        "reason": reason,
        "environment_contract_id": ENVIRONMENT_CONTRACT_ID,
        "request": request,
        "receipt": receipt,
        "request_sha256": request_sha256,
        "observation_sha256": observation_sha256,
        "environment_receipt_sha256": environment_receipt_sha256,
        "environment_id": environment_id,
        "evidence_verified": False,
        "blocker_5_complete": False,
        "flags": {name: False for name in FALSE_FLAGS},
        "nonclaims": list(NONCLAIMS),
    }
    body["result_sha256"] = _digest("RESULT", body)
    return body


def _unsupported(command, _exc):
    reason = (
        UNSUPPORTED_PLAN_REASON
        if command == PLAN_COMMAND
        else UNSUPPORTED_VALIDATE_REASON
    )
    return _result(command, "unsupported", reason, "", "", "", "", "", "")


def _contract_body():
    return {
        "schema": CONTRACT_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "compatibility_profile_version": COMPATIBILITY_PROFILE_VERSION,
        "compatibility_profile_disposition": (
            COMPATIBILITY_PROFILE_DISPOSITION
        ),
        "activation_contract_id": ACTIVATION_CONTRACT_ID,
        "schemas": [
            CONTRACT_SCHEMA,
            REQUEST_SCHEMA,
            OBSERVATION_SCHEMA,
            RECEIPT_SCHEMA,
            RESULT_SCHEMA,
            RENDER_SCHEMA,
        ],
        "domains_hex": {
            name.lower(): _DOMAINS[name].hex() for name in sorted(_DOMAINS)
        },
        "identity_prefixes": {
            "environment_contract_id": "environment-contract-",
            "environment_id": "environment-",
        },
        "request_keys": list(REQUEST_KEYS),
        "binding_keys": list(BINDING_KEYS),
        "observation_keys": list(OBSERVATION_KEYS),
        "receipt_keys": list(RECEIPT_KEYS),
        "result_keys": list(RESULT_KEYS),
        "render_keys": list(RENDER_KEYS),
        "request_fixed": {
            "schema": REQUEST_SCHEMA,
            "mode": MODE,
            "profile": PROFILE,
            "profile_version": PROFILE_VERSION,
            "activation_contract_id": ACTIVATION_CONTRACT_ID,
            "compatibility_profile_version": COMPATIBILITY_PROFILE_VERSION,
        },
        "binding_fixed": {
            name: _BINDING_FIXED[name] for name in sorted(_BINDING_FIXED)
        },
        "observation_fixed": {
            "schema": OBSERVATION_SCHEMA,
            "mode": MODE,
            "profile": PROFILE,
            "profile_version": PROFILE_VERSION,
        },
        "receipt_fixed": {
            "schema": RECEIPT_SCHEMA,
            "mode": MODE,
            "profile": PROFILE,
            "profile_version": PROFILE_VERSION,
        },
        "derived_fixed_fields": ["environment_contract_id"],
        "field_patterns": {
            name: {"pattern": _PATTERNS[name], "flags": 0}
            for name in sorted(_PATTERNS)
        },
        "observed_bindings": {
            name: _OBSERVED_BINDINGS[name]
            for name in sorted(_OBSERVED_BINDINGS)
        },
        "observation_digests": list(OBSERVATION_DIGESTS),
        "observation_digest_pattern": {
            "pattern": _SHA64_PATTERN,
            "flags": 0,
        },
        "environment_id_pattern": {
            "pattern": _ENVIRONMENT_ID_PATTERN,
            "flags": 0,
        },
        "int_fields": {
            name: [_INT_FIELDS[name][0], _INT_FIELDS[name][1]]
            for name in sorted(_INT_FIELDS)
        },
        "equality_requirements": [
            ["staged_product_id", "candidate_product_id"],
            ["staged_source_build_id", "candidate_source_build_id"],
        ],
        "forbidden_keys": sorted(_FORBIDDEN_KEYS),
        "forbidden_key_pattern": {
            "pattern": _FORBIDDEN_KEY_PATTERN,
            "flags": 0,
        },
        "key_pattern": {"pattern": _KEY_PATTERN, "flags": 0},
        "limits": {
            "max_canonical_bytes": _MAX_CANONICAL_BYTES,
            "max_depth": _MAX_DEPTH,
            "max_integer_abs": MAX_INT,
            "max_keys": _MAX_KEYS,
            "max_string_chars": _MAX_STRING_CHARS,
            "max_render_bytes": _MAX_RENDER_BYTES,
        },
        "canonicalization": {
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
        "hash_bindings": {
            "environment_contract_id": {
                "domain": "CONTRACT",
                "prefix": "environment-contract-",
                "preimage": "canonical-contract-body",
                "excluded_fields": [
                    "environment_contract_id",
                    "contract_sha256",
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
                "preimage": "canonical-result-without-result-sha256",
                "excluded_fields": ["result_sha256"],
            },
        },
        "result_policy": {
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
                "recompute-all-populated-documents-identities-and-result-"
                "digest-and-require-exact-native-population"
            ),
        },
        "flags": list(FALSE_FLAGS),
        "nonclaims": list(NONCLAIMS),
        "fallback_line": _FALLBACK_LINE,
        "evidence_verified": False,
        "blocker_5_complete": False,
    }


ENVIRONMENT_CONTRACT_ID = (
    "environment-contract-" + _digest("CONTRACT", _contract_body())
)


def environment_contract_projection():
    """Closed, deterministic projection of the Phase-5A contract."""
    body = _contract_body()
    contract_sha256 = _digest("CONTRACT", body)
    body["environment_contract_id"] = (
        "environment-contract-" + contract_sha256
    )
    body["contract_sha256"] = contract_sha256
    return body


def candidate_environment_receipt_sha256(receipt):
    """Canonical domain-separated digest of a fully valid receipt document.

    This is the digest Blocker 6 later binds. Raises ValueError for any
    document that does not validate exactly; never runs attacker hooks.
    """
    try:
        digests = _validate_receipt(receipt)
    except BaseException:
        raise _Reject("unsupported-receipt-document") from None
    return digests[2]


def plan_environment_request(**bindings):
    """Build and pin a candidate-environment request document.

    Success is only "planned": nothing on the host has been read, built,
    verified, or activated. Returns a closed result; never raises.
    """
    try:
        _check_document_keys(
            bindings, BINDING_KEYS, "binding-key-set-mismatch"
        )
        request = _request_fixed()
        for name in BINDING_KEYS:
            request[name] = bindings[name]
        request_sha256 = _validate_request(request)
        return _result(
            PLAN_COMMAND,
            "planned",
            PLANNED_REASON,
            request,
            "",
            request_sha256,
            "",
            "",
            "",
        )
    except BaseException as exc:
        return _unsupported(PLAN_COMMAND, exc)


def validate_environment_receipt_document(request, receipt):
    """Validate a receipt document against its request.

    The receipt never embeds its own hash; its canonical digest is returned
    in the result as environment_receipt_sha256. Validity is documentary
    only, never evidence verification. Returns a closed result; never
    raises.
    """
    try:
        request_sha256 = _validate_request(request)
        digests = _validate_receipt(receipt)
        if digests[0] != request_sha256 or (
            _canonical(request) != _canonical(receipt["request"])
        ):
            raise _Reject("receipt-request-mismatch")
        return _result(
            VALIDATE_COMMAND,
            "document_valid",
            DOCUMENT_VALID_REASON,
            "",
            receipt,
            digests[0],
            digests[1],
            digests[2],
            digests[3],
        )
    except BaseException as exc:
        return _unsupported(VALIDATE_COMMAND, exc)


def _require_empty(value, code):
    if type(value) is not str or value != "":
        raise _Reject(code)


def _validate_result(value):
    _check_document_keys(
        value, RESULT_KEYS, "result-key-set-mismatch", forbid=False
    )
    fixed = {
        "schema": RESULT_SCHEMA,
        "environment_contract_id": ENVIRONMENT_CONTRACT_ID,
    }
    _check_fixed(value, fixed, "invalid-result-field:")
    command = value["command"]
    status = value["status"]
    reason = value["reason"]
    for item in (command, status, reason):
        if type(item) is not str:
            raise _Reject("invalid-result-field:command")
    if (
        command == PLAN_COMMAND
        and status == "planned"
        and reason == PLANNED_REASON
    ):
        result_kind = "planned"
    elif (
        command == VALIDATE_COMMAND
        and status == "document_valid"
        and reason == DOCUMENT_VALID_REASON
    ):
        result_kind = "document_valid"
    elif (
        command == PLAN_COMMAND
        and status == "unsupported"
        and reason == UNSUPPORTED_PLAN_REASON
    ) or (
        command == VALIDATE_COMMAND
        and status == "unsupported"
        and reason == UNSUPPORTED_VALIDATE_REASON
    ):
        result_kind = "unsupported"
    else:
        raise _Reject("result-not-replayable")
    if value["evidence_verified"] is not False:
        raise _Reject("evidence-verified-can-never-be-true")
    if value["blocker_5_complete"] is not False:
        raise _Reject("blocker-5-can-never-be-complete")
    flags = value["flags"]
    _check_document_keys(
        flags, FALSE_FLAGS, "flag-key-set-mismatch", forbid=False
    )
    for name in FALSE_FLAGS:
        if flags[name] is not False:
            raise _Reject("impossible-truth-flag:" + name)
    nonclaims = value["nonclaims"]
    if type(nonclaims) is not list or len(nonclaims) != len(NONCLAIMS):
        raise _Reject("nonclaim-set-mismatch")
    for index in range(len(NONCLAIMS)):
        item = nonclaims[index]
        if type(item) is not str or item != NONCLAIMS[index]:
            raise _Reject("nonclaim-set-mismatch")
    if result_kind == "planned":
        _require_empty(value["receipt"], "planned-result-carries-receipt")
        _require_empty(
            value["observation_sha256"],
            "planned-result-carries-observation-digest",
        )
        _require_empty(
            value["environment_receipt_sha256"],
            "planned-result-carries-receipt-digest",
        )
        _require_empty(
            value["environment_id"],
            "planned-result-carries-environment-id",
        )
        request_sha256 = _validate_request(value["request"])
        bound = value["request_sha256"]
        if type(bound) is not str or bound != request_sha256:
            raise _Reject("result-request-digest-mismatch")
    elif result_kind == "document_valid":
        _require_empty(
            value["request"], "receipt-result-carries-loose-request"
        )
        digests = _validate_receipt(value["receipt"])
        replayed = (
            ("request_sha256", digests[0]),
            ("observation_sha256", digests[1]),
            ("environment_receipt_sha256", digests[2]),
            ("environment_id", digests[3]),
        )
        for name, expected in replayed:
            bound = value[name]
            if type(bound) is not str or bound != expected:
                raise _Reject("result-replay-mismatch:" + name)
    else:
        for name in (
            "request",
            "receipt",
            "request_sha256",
            "observation_sha256",
            "environment_receipt_sha256",
            "environment_id",
        ):
            _require_empty(
                value[name], "unsupported-result-carries-identity:" + name
            )
    body = {
        key: value[key] for key in RESULT_KEYS if key != "result_sha256"
    }
    bound_result_sha = value["result_sha256"]
    if type(bound_result_sha) is not str or (
        bound_result_sha != _digest("RESULT", body)
    ):
        raise _Reject("result-digest-mismatch")
    return value


def render_environment_result(value):
    """Total renderer: one bounded redacted canonical line, or a fallback.

    Replays the full public operation (request/observation/receipt/identity
    and result digests) and requires exact equality with the native
    recomputation; a self-embedded hash is never trusted on its own.
    """
    try:
        result = _validate_result(value)
        line = _canonical(
            {
                "schema": RENDER_SCHEMA,
                "command": result["command"],
                "status": result["status"],
                "reason": result["reason"],
                "environment_contract_id": (
                    result["environment_contract_id"]
                ),
                "request_sha256": result["request_sha256"],
                "observation_sha256": result["observation_sha256"],
                "environment_receipt_sha256": (
                    result["environment_receipt_sha256"]
                ),
                "environment_id": result["environment_id"],
                "evidence_verified": False,
                "blocker_5_complete": False,
            }
        )
        if len(line) > _MAX_RENDER_BYTES or "\n" in line:
            return _FALLBACK_LINE
        return line
    except BaseException:
        return _FALLBACK_LINE


def environment_result_exit_code(value):
    """0 only for a fully replayed planned/document_valid result."""
    try:
        result = _validate_result(value)
        if result["status"] == "unsupported":
            return 1
        return (
            0
            if render_environment_result(result) != _FALLBACK_LINE
            else 1
        )
    except BaseException:
        return 1

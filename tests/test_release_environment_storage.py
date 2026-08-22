"""Phase-5B1 first-tranche tests for release_environment_storage.

Pure contracts, frozen bridges, platform gating, and result totality only.
Every expected hash is recomputed with test-local canonical JSON and literal
domain bytes; module-private hash helpers are never used for expectations.
No temp directories and no filesystem publication in this tranche.
"""

import ast
import errno
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from scripts import installed_layout  # noqa: E402
from scripts import release_environment  # noqa: E402
from scripts import release_environment_storage as rs  # noqa: E402

import fcntl  # noqa: E402

_REAL_OS = os

# The storage boundary deliberately ignores already-imported sibling modules.
# Unit-level validator tests therefore use fresh namespaces compiled from the
# exact held, hash-pinned sibling bytes, matching the public entry points.
_PHASE5A_PRIVATE, _INSTALLED_LAYOUT_PRIVATE = (
    rs._verify_frozen_sibling_sources()
)


def validate_request(document, phase5a=None):
    return rs._validate_request(
        document, _PHASE5A_PRIVATE if phase5a is None else phase5a
    )


def validate_layout_plan(document, request, stage_result, namespace=None):
    return rs._validate_layout_plan(
        document,
        request,
        stage_result,
        _INSTALLED_LAYOUT_PRIVATE if namespace is None else namespace,
    )

# ---------------------------------------------------------------------------
# Independently pinned literals (never derived from the module under test).
# ---------------------------------------------------------------------------

PINNED_STORAGE_CONTRACT_ID = (
    "environment-storage-contract-"
    "9d10496d94003ad2d46905f19155de31c48a3834914c60469a739a73298c20aa"
)
PINNED_STORAGE_SOURCE_SHA256 = (
    "6a7fb7bfa2f0a0d321a424a535d3310d2f37d1f4c7a2b16017d1b12fc5e3f206"
)
PINNED_PHASE5A_SOURCE_SHA256 = (
    "42da38a8710ebdeaaabf11741859f4822a943df3d6b9d8deff2236fa64672308"
)
PINNED_PHASE5A_CONTRACT_ID = (
    "environment-contract-"
    "fec40398c01456d33b1bf5980b737987d1825fea8194d102af7d0afd939cfe3e"
)
PINNED_INSTALLED_LAYOUT_SOURCE_SHA256 = (
    "7c4e3069f225488a76f261b1e2fff37bb5ad163aef731364ac86f433d138ba12"
)
PINNED_ACTIVATION_JOURNAL_SOURCE_SHA256 = (
    "36f8b4befcf2783608be4e3c95911ead8176bfab35b8bcf9593301f8e0bcc3df"
)
PINNED_LAYOUT_CONTRACT_ID = (
    "layout-contract-"
    "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
)

CONTRACT_SCHEMA = "synapse-s2.release-environment-storage-contract.v1"
REQUEST_RECORD_SCHEMA = "synapse-s2.release-environment-storage-request.v1"
TREE_MANIFEST_SCHEMA = "synapse-s2.release-environment-tree-manifest.v1"
PREPARE_SCHEMA = "synapse-s2.release-environment-storage-prepare.v1"
RESULT_SCHEMA = "synapse-s2.release-environment-storage-result.v1"
RENDER_SCHEMA = "synapse-s2.release-environment-storage-render.v1"

CONTRACT_DOMAIN = "SYNAPSE-S2\x00RELEASE-ENVIRONMENT-STORAGE-CONTRACT\x00v1\x00"
REQUEST_DOMAIN = "SYNAPSE-S2\x00RELEASE-ENVIRONMENT-STORAGE-REQUEST\x00v1\x00"
TREE_MANIFEST_DOMAIN = (
    "SYNAPSE-S2\x00RELEASE-ENVIRONMENT-STORAGE-TREE-MANIFEST\x00v1\x00"
)
PREPARE_DOMAIN = "SYNAPSE-S2\x00RELEASE-ENVIRONMENT-STORAGE-PREPARE\x00v1\x00"
RESULT_DOMAIN = "SYNAPSE-S2\x00RELEASE-ENVIRONMENT-STORAGE-RESULT\x00v1\x00"
STORAGE_DIGEST_DOMAIN = (
    "SYNAPSE-S2\x00RELEASE-ENVIRONMENT-STORAGE-DIGEST\x00v1\x00"
)
STAGE_JOURNAL_DOMAIN = "SYNAPSE-S2\x00RELEASE-STAGE-JOURNAL\x00v1\x00"
LAYOUT_ID_DOMAIN = "SYNAPSE-S2\x00INSTALLED-LAYOUT-PLAN\x00v1\x00"

PHASE5A_REQUEST_DOMAIN_BYTES = b"SYNAPSE-S2\x00RELEASE-ENVIRONMENT-REQUEST\x00v1\x00"

PHASE5A_BINDING_KEYS = (
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
PHASE5A_REQUEST_KEYS = (
    "schema", "mode", "profile", "profile_version",
    "environment_contract_id", "activation_contract_id",
    "compatibility_profile_version",
) + PHASE5A_BINDING_KEYS

LAYOUT_PLAN_KEYS = (
    "schema", "mode", "status", "reason", "layout_id", "layout_contract_id",
    "product_id", "inventory_policy_id", "install_root", "code_root",
    "environment_root", "data_root", "release_root", "updater_state_root",
    "legacy_checkout_root", "data_root_retained_under_legacy_checkout",
    "adapters", "activation_eligibility", "requirements", "stage_associated",
    "stage_association", "activation_supported", "apply_supported",
    "apply_performed", "live_state_modified", "physical_separation_verified",
    "provenance_verified", "nonclaims",
)
LAYOUT_PLAN_FALSE_FLAGS = (
    "activation_supported", "apply_supported", "apply_performed",
    "live_state_modified", "physical_separation_verified",
    "provenance_verified",
)
LAYOUT_PLAN_NONCLAIMS = (
    "no-activation", "no-apply", "no-current-or-latest-selector",
    "no-filesystem-access", "no-live-state-access", "no-migration",
    "no-physical-alias-resolution", "no-physical-separation-verification",
    "no-provenance-verification", "no-stage-result-authority",
)
LAYOUT_ID_BINDING_KEYS = (
    "schema", "mode", "layout_contract_id", "product_id",
    "inventory_policy_id", "install_root", "code_root", "environment_root",
    "data_root", "release_root", "updater_state_root", "legacy_checkout_root",
    "adapters",
)
LAYOUT_ADAPTER_TABLE = (
    ("python-interpreter", "environment", "bin/python"),
    ("core-service", "code", "core_service.py"),
    ("mcp-entrypoint", "code", "mcp_client_wrapper.py"),
    ("mcp-server", "code", "mcp_server.py"),
    ("dashboard-server", "code", "dashboard_server.py"),
    ("dashboard-auth", "data", "dashboard-auth.json"),
    ("memory-store", "data", "memory.sqlite3"),
    ("runtime-state", "data", "runtime_state.json"),
    ("core-request-journal", "data", "core/requests.sqlite3"),
    ("client-config-journal", "data", "client-config-publication.journal.json"),
    ("readiness-evidence", "data", "evidence_packs"),
)

STAGE_RESULT_SCHEMA = "synapse-s2.release-stage-result.v1"
STAGE_RESULT_MODE = "incumbent-inactive-source-stage"
STAGE_RESULT_KEYS = (
    "schema", "mode", "status", "reason", "product_id", "inventory_policy_id",
    "source_staged", "identity_pin_verified", "journal_committed", "resumed",
    "reconciled", "environment_stage_supported", "environment_built",
    "activation_supported", "activation_performed", "live_state_modified",
    "nonclaims",
)
STAGE_RESULT_TRUE_PROOFS = (
    "source_staged", "identity_pin_verified", "journal_committed",
)
STAGE_RESULT_FALSE_FLAGS = (
    "environment_stage_supported", "environment_built",
    "activation_supported", "activation_performed", "live_state_modified",
)
STAGE_RESULT_ACCEPTED = (
    ("staged", "source-staged-inactive", False),
    ("already-staged", "identity-already-staged", True),
)
STAGE_RESULT_NONCLAIMS = (
    "no-activation", "no-current-or-latest-selector", "no-environment-build",
    "no-data-root-access", "no-live-state-access", "no-migration",
    "no-provenance-authentication-inside-stager",
    "no-post-stage-immutability-claim", "no-orphan-operation-reclamation",
)
STAGE_JOURNAL_SCHEMA = "synapse-s2.release-stage-journal-entry.v1"
STAGE_JOURNAL_KEYS = (
    "schema", "sequence", "previous_hash", "product_id",
    "inventory_policy_id", "release_state", "entry_hash",
)

TREE_MANIFEST_KEYS = (
    "schema", "storage_contract_id", "request_sha256", "operation_id",
    "product_id", "inventory_policy_id", "entry_count", "total_bytes",
    "entries",
)
TREE_ENTRY_KEYS = ("path", "kind", "mode", "size", "sha256")
FINGERPRINT_KEYS = ("device", "inode", "mode", "nlink")
FULL_STAT_FINGERPRINT_KEYS = (
    "device", "inode", "uid", "mode", "nlink", "size", "mtime_ns", "ctime_ns",
)
STORAGE_REQUEST_RECORD_KEYS = (
    "schema", "storage_contract_id", "phase5a_contract_id", "request",
    "request_sha256", "layout_id", "layout_plan_sha256",
    "stage_result_sha256", "stage_journal_entry_sha256", "operation_id",
    "environment_preimage_fingerprint", "operation_fingerprint",
    "request_record_sha256",
)
STORAGE_PREPARE_RECORD_KEYS = (
    "schema", "storage_contract_id", "request_record_sha256",
    "request_sha256", "operation_id", "layout_id", "manifest_sha256",
    "manifest_entry_count", "manifest_total_bytes",
    "environment_preimage_fingerprint", "operation_fingerprint",
    "stage_result_sha256", "stage_journal_entry_sha256", "prepare_sha256",
)

COMMAND_FINALIZE = "finalize-prebuilt-environment-stage"
COMMAND_INSPECT = "inspect-prebuilt-environment-stage"

SUCCESS_REASONS = (
    "tree_published:prebuilt-environment-published",
    "tree_published:prebuilt-environment-already-present",
    "tree_published:prebuilt-environment-publication-reconciled",
    "inspected:prebuilt-environment-tree-consistent",
)
BLOCKED_FINALIZE_REASON = "blocked:environment-storage-finalization-refused"
BLOCKED_INSPECT_REASON = "blocked:environment-storage-inspection-refused"
UNKNOWN_FINALIZE_REASON = (
    "outcome_unknown:environment-storage-finalization-ambiguous"
)
UNSUPPORTED_READ_REASONS = frozenset({
    "unsupported:platform-not-darwin",
    "unsupported:missing-nofollow-directory-open",
    "unsupported:missing-os-callable",
    "unsupported:missing-flock",
    "unsupported:platform-gate-error",
})
UNSUPPORTED_WRITE_REASONS = UNSUPPORTED_READ_REASONS | frozenset({
    "unsupported:missing-write-open-flags",
    "unsupported:missing-renameatx-np-swap-capability",
})

RESULT_DIGEST_KEYS = (
    "request_sha256", "manifest_sha256", "prepare_sha256", "storage_digest",
)
RESULT_IDENTITY_KEYS = (
    "operation_id", "layout_plan_id", "product_id", "policy_id",
)
RESULT_FLAG_KEYS = (
    "storage_read_supported", "storage_write_supported",
    "storage_read_performed", "storage_write_attempted", "storage_written",
    "stage_authority_verified", "stage_correlation_verified",
    "filesystem_verified", "access_verified", "environment_tree_verified",
    "environment_tree_published", "reconciled", "dependency_proof_verified",
    "model_proof_verified", "candidate_execution_verified", "build_verified",
    "evidence_verified", "receipt_published", "blocker_5_complete",
    "activation_performed", "apply_performed", "live_state_accessed",
    "live_state_modified", "service_modified", "config_modified",
    "selector_modified", "floor_modified", "activation_journal_written",
)
RESULT_KEYS = (
    ("schema", "command", "status", "reason", "storage_contract_id")
    + RESULT_DIGEST_KEYS
    + RESULT_IDENTITY_KEYS
    + RESULT_FLAG_KEYS
    + ("nonclaims", "result_sha256")
)
RENDER_KEYS = (
    ("schema", "result_schema", "command", "status", "reason",
     "storage_contract_id")
    + RESULT_DIGEST_KEYS
    + RESULT_IDENTITY_KEYS
    + RESULT_FLAG_KEYS
    + ("result_sha256",)
)
STORAGE_FACT_KEYS = (
    "storage_read_supported", "storage_write_supported",
    "storage_read_performed", "storage_write_attempted", "storage_written",
)
SUCCESS_VERIFIED_TRUE_KEYS = (
    "stage_correlation_verified", "filesystem_verified", "access_verified",
    "environment_tree_verified", "environment_tree_published",
)
SUCCESS_ROWS = {
    (COMMAND_FINALIZE, SUCCESS_REASONS[0]): (True, True, True, True, True, False),
    (COMMAND_FINALIZE, SUCCESS_REASONS[1]): (True, True, True, False, False, False),
    (COMMAND_FINALIZE, SUCCESS_REASONS[2]): (True, True, True, True, True, True),
    (COMMAND_INSPECT, SUCCESS_REASONS[3]): (True, False, True, False, False, False),
}
EXIT_CODES = {"success": 0, "unsupported": 2, "blocked": 3, "outcome_unknown": 4}

RENDER_FALLBACK_LINE = (
    '{"reason":"blocked:result-not-renderable",'
    '"schema":"synapse-s2.release-environment-storage-render.v1",'
    '"status":"blocked"}'
)

NONCLAIMS = (
    "no-dependency-proof", "no-import-proof", "no-native-extension-proof",
    "no-model-proof", "no-candidate-execution",
    "no-builder-or-provenance-authority",
    "no-phase5a-observation-or-receipt", "no-blocker5-completion",
    "no-profile-3-ticket-or-result-verification", "no-live-state-access",
    "no-recovery-state-access", "no-service-modification",
    "no-config-modification", "no-selector-modification",
    "no-floor-modification", "no-activation-journal-write",
    "no-network-access", "no-credential-access", "no-activation", "no-apply",
    "no-post-return-immutability-guarantee", "no-acl-or-xattr-authority",
    "no-hardware-durability-guarantee", "no-orphan-cleanup-guarantee",
    "no-preimage-reclamation", "no-stage-authority",
    "no-release-tree-verification", "no-stage-invocation-root-binding",
    "no-result-authentication", "no-malicious-same-uid-authenticity",
    "no-hostile-interpreter-or-in-process-runtime-authenticity",
    "final-lock-and-fd-cleanup-best-effort-only",
)

REGEX_PINS = {
    "_SHA256_HEX_RE": r"^[0-9a-f]{64}$",
    "_ENTRY_NAME_RE": r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$",
    "_TREE_ENTRY_NAME_RE": r"^[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}$",
    "_PRODUCT_ID_RE": r"\Aproduct-[0-9a-f]{64}\Z",
    "_POLICY_ID_RE": r"\Ainventory-policy-[0-9a-f]{64}\Z",
    "_LAYOUT_ID_RE": r"\Alayout-[0-9a-f]{64}\Z",
}

LIMIT_PINS = {
    "MAX_DOC_BYTES": 1_000_000,
    "MAX_PATH_LENGTH": 3500,
    "MAX_NAME_LENGTH": 200,
    "MAX_TREE_ENTRIES": 20_000,
    "MAX_TREE_TOTAL_BYTES": 6 * 1024 * 1024 * 1024,
    "MAX_TREE_FILE_BYTES": 1024 * 1024 * 1024,
    "MAX_TREE_DEPTH": 24,
    "MAX_ROOT_DEPTH": 48,
    "MAX_JOURNAL_LINE_BYTES": 200_000,
    "MAX_DOCUMENT_DEPTH": 6,
    "MAX_DOCUMENT_ITEMS": 512,
    "MAX_DOCUMENT_STRING_CHARACTERS": 3500,
    "MAX_STAGE_JOURNAL_BYTES": 4 * 1024 * 1024,
    "MAX_STAGE_JOURNAL_ENTRIES": 4096,
    "MAX_CONTRACT_PROJECTION_BYTES": 65536,
    "MAX_RESULT_BYTES": 8192,
    "MAX_RENDER_BYTES": 4096,
    "MAX_SIBLING_SOURCE_BYTES": 2_000_000,
}

# ---------------------------------------------------------------------------
# Test-local canonical JSON and hash helpers (literal domains only).
# ---------------------------------------------------------------------------


def canon(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )


def dsha(domain, value):
    return hashlib.sha256(
        domain.encode("ascii") + canon(value).encode("ascii")
    ).hexdigest()


def dsha_bytes(domain_bytes, value):
    return hashlib.sha256(
        domain_bytes + canon(value).encode("ascii")
    ).hexdigest()


def raw_sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with open(path, "rb") as handle:
        return raw_sha(handle.read())


def storage_digest(request_sha256, manifest_sha256, prepare_sha256):
    return raw_sha(
        (
            STORAGE_DIGEST_DOMAIN + request_sha256 + manifest_sha256
            + prepare_sha256
        ).encode("ascii")
    )


def rehash(result):
    """Coordinated forgery helper: recompute result_sha256 like an attacker."""
    body = {k: result[k] for k in RESULT_KEYS if k != "result_sha256"}
    result["result_sha256"] = dsha(RESULT_DOMAIN, body)
    return result


# ---------------------------------------------------------------------------
# Hostile shapes.
# ---------------------------------------------------------------------------


class SystemExitBomb:
    def __eq__(self, other):
        raise SystemExit(9)

    def __hash__(self):
        return 0

    def __str__(self):
        raise SystemExit(9)


class BombDict(dict):
    def __getitem__(self, key):
        raise SystemExit(9)


class RaisingStr(str):
    def __eq__(self, other):
        raise SystemExit(9)

    def __hash__(self):
        return 0


class EvilList(list):
    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0


# ---------------------------------------------------------------------------
# Coordinated pure fixtures (no filesystem, no .synapse_s2 anywhere).
# ---------------------------------------------------------------------------

PRODUCT_ID = "product-" + "9c" * 32
POLICY_ID = "inventory-policy-" + "0d" * 32

INSTALL_ROOT = "/opt/synapse-s2/install"
ENVIRONMENT_ROOT = "/opt/synapse-s2/environment"
DATA_ROOT = "/opt/synapse-s2/data"
UPDATER_STATE_ROOT = "/opt/synapse-s2/updater-state"
LEGACY_CHECKOUT_ROOT = "/opt/synapse-s2/legacy-checkout"


def stage_result_fixture(row=0):
    status, reason, resumed = STAGE_RESULT_ACCEPTED[row]
    return {
        "schema": STAGE_RESULT_SCHEMA,
        "mode": STAGE_RESULT_MODE,
        "status": status,
        "reason": reason,
        "product_id": PRODUCT_ID,
        "inventory_policy_id": POLICY_ID,
        "source_staged": True,
        "identity_pin_verified": True,
        "journal_committed": True,
        "resumed": resumed,
        "reconciled": False,
        "environment_stage_supported": False,
        "environment_built": False,
        "activation_supported": False,
        "activation_performed": False,
        "live_state_modified": False,
        "nonclaims": list(STAGE_RESULT_NONCLAIMS),
    }


STAGE_RESULT = stage_result_fixture()
STAGE_RESULT_SHA256 = raw_sha(canon(STAGE_RESULT).encode("ascii"))

LAYOUT_PLAN = installed_layout.plan_inactive_versioned_layout(
    install_root=INSTALL_ROOT,
    environment_root=ENVIRONMENT_ROOT,
    data_root=DATA_ROOT,
    updater_state_root=UPDATER_STATE_ROOT,
    legacy_checkout_root=LEGACY_CHECKOUT_ROOT,
    product_id=PRODUCT_ID,
    inventory_policy_id=POLICY_ID,
    stage_result=STAGE_RESULT,
)


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
        "candidate_product_id": PRODUCT_ID,
        "inventory_policy_id": POLICY_ID,
        "candidate_dependency_component_id": "component-" + "1e" * 32,
        "surfaces_digest": "2f" * 32,
        "layout_schema": "synapse-s2.installed-layout-contract.v1",
        "layout_mode": "inactive-versioned-v1",
        "layout_contract_id": PINNED_LAYOUT_CONTRACT_ID,
        "layout_id": LAYOUT_PLAN["layout_id"],
        "stage_result_sha256": STAGE_RESULT_SHA256,
        "stage_journal_head_sha256": "6d" * 32,
        "staged_product_id": PRODUCT_ID,
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


_PLAN_RESULT = release_environment.plan_environment_request(**valid_bindings())
REQUEST = _PLAN_RESULT["request"]
REQUEST_SHA256 = _PLAN_RESULT["request_sha256"]


def success_result(command, reason):
    row = SUCCESS_ROWS[(command, reason)]
    req = "aa" * 32
    man = "bb" * 32
    prep = "cc" * 32
    flags = dict(zip(STORAGE_FACT_KEYS, row[:5]))
    flags["reconciled"] = row[5]
    for key in SUCCESS_VERIFIED_TRUE_KEYS:
        flags[key] = True
    return rs._build_result(
        command,
        "success",
        reason,
        flags=flags,
        digests={
            "request_sha256": req,
            "manifest_sha256": man,
            "prepare_sha256": prep,
            "storage_digest": storage_digest(req, man, prep),
        },
        identity={
            "operation_id": "operation-" + req,
            "layout_plan_id": "layout-" + "dd" * 32,
            "product_id": PRODUCT_ID,
            "policy_id": POLICY_ID,
        },
    )


def blocked_result(command):
    flags = {"storage_read_supported": True}
    if command == COMMAND_FINALIZE:
        flags["storage_write_supported"] = True
        reason = BLOCKED_FINALIZE_REASON
    else:
        reason = BLOCKED_INSPECT_REASON
    return rs._build_result(command, "blocked", reason, flags=flags)


def unknown_result():
    return rs._build_result(
        COMMAND_FINALIZE,
        "outcome_unknown",
        UNKNOWN_FINALIZE_REASON,
        flags={
            "storage_read_supported": True,
            "storage_write_supported": True,
            "storage_read_performed": True,
            "storage_write_attempted": True,
            "storage_written": None,
        },
    )


def unsupported_result(command, reason="unsupported:platform-not-darwin"):
    return rs._build_result(command, "unsupported", reason)


class _OsProxy:
    """Real-os passthrough with selected names missing and open recorded."""

    def __init__(self, missing=()):
        object.__setattr__(self, "_missing", frozenset(missing))
        object.__setattr__(self, "open_calls", [])

    def __getattr__(self, name):
        if name in self._missing:
            raise AttributeError(name)
        if name == "open":
            calls = self.open_calls

            def _recording_open(*args, **kwargs):
                calls.append(args)
                raise OSError(errno.EACCES, "test-refused")

            return _recording_open
        return getattr(_REAL_OS, name)


class StorageFixture:
    """A tiny owner-private inactive environment fixture under /private/tmp."""

    def __init__(self):
        self._temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.base = self._temporary.name
        os.chmod(self.base, 0o700)
        self.authority_root = self.base + "/authority"
        self.journal_root = self.base + "/updater"
        self.install_root = self.base + "/install"
        self.data_root = self.base + "/data"
        self.legacy_root = self.base + "/legacy"
        for path in (
            self.authority_root,
            self.journal_root,
            self.install_root,
            self.data_root,
            self.legacy_root,
        ):
            self._mkdir(path)
        self.environment_root = self.authority_root + "/environment"
        self._mkdir(self.environment_root)
        self.stage_result = stage_result_fixture()
        self.layout_plan = installed_layout.plan_inactive_versioned_layout(
            install_root=self.install_root,
            environment_root=self.environment_root,
            data_root=self.data_root,
            updater_state_root=self.journal_root,
            legacy_checkout_root=self.legacy_root,
            product_id=PRODUCT_ID,
            inventory_policy_id=POLICY_ID,
            stage_result=self.stage_result,
        )
        journal_body = {
            "schema": STAGE_JOURNAL_SCHEMA,
            "sequence": 1,
            "previous_hash": "0" * 64,
            "product_id": PRODUCT_ID,
            "inventory_policy_id": POLICY_ID,
            "release_state": "staged",
        }
        self.stage_head = dsha(STAGE_JOURNAL_DOMAIN, journal_body)
        self.stage_entry = dict(journal_body, entry_hash=self.stage_head)
        self.stage_journal_path = (
            self.journal_root + "/" + rs.STAGE_JOURNAL_FILE_NAME
        )
        self._write(
            self.stage_journal_path,
            (canon(self.stage_entry) + "\n").encode("ascii"),
            0o600,
        )
        bindings = valid_bindings()
        bindings.update(
            {
                "layout_id": self.layout_plan["layout_id"],
                "stage_result_sha256": raw_sha(
                    canon(self.stage_result).encode("ascii")
                ),
                "stage_journal_head_sha256": self.stage_head,
            }
        )
        plan = release_environment.plan_environment_request(**bindings)
        self.request = plan["request"]
        self.request_sha256 = plan["request_sha256"]
        self.state_root = (
            self.journal_root
            + "/"
            + rs.STATE_ROOT_PREFIX
            + self.request_sha256
        )
        self._mkdir(self.state_root)
        self.operations_root = (
            self.authority_root + "/" + rs.OPERATIONS_DIR_NAME
        )
        self._mkdir(self.operations_root)
        self.operation_name = rs.OPERATION_PREFIX + self.request_sha256
        self.operation_root = self.operations_root + "/" + self.operation_name
        self._mkdir(self.operation_root)
        self._mkdir(self.operation_root + "/bin")
        self._write(
            self.operation_root + "/bin/python",
            b"#!/bin/sh\nexit 0\n",
            0o700,
        )
        self._write(
            self.operation_root + "/pyvenv.cfg",
            b"home = /synthetic\n",
            0o600,
        )
        self._mkdir(self.operation_root + "/lib")
        self._write(
            self.operation_root + "/lib/__init__.py", b"", 0o600
        )
        self._mkdir(self.operation_root + "/lib/__pycache__")
        self._write(
            self.operation_root + "/lib/__pycache__/module.cpython-314.pyc",
            b"synthetic-bytecode",
            0o600,
        )
        self.sentinel_path = self.data_root + "/must-not-touch"
        self._write(self.sentinel_path, b"durable-user-state", 0o600)
        self.sentinel_before = self._snapshot(self.sentinel_path)

    @staticmethod
    def _mkdir(path):
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)

    @staticmethod
    def _write(path, payload, mode):
        with open(path, "wb") as handle:
            handle.write(payload)
        os.chmod(path, mode)

    @staticmethod
    def _snapshot(path):
        info = os.stat(path, follow_symlinks=False)
        with open(path, "rb") as handle:
            data = handle.read()
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            hashlib.sha256(data).hexdigest(),
        )

    def fake_swap(self, ops_fd, operation_name, parent_fd, environment_name,
                  _flags):
        temporary_name = "swap-intermediate"
        operation = operation_name.decode("ascii")
        environment = environment_name.decode("ascii")
        os.rename(
            operation,
            temporary_name,
            src_dir_fd=ops_fd,
            dst_dir_fd=parent_fd,
        )
        os.rename(
            environment,
            operation,
            src_dir_fd=parent_fd,
            dst_dir_fd=ops_fd,
        )
        os.rename(
            temporary_name,
            environment,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        return 0

    def finalize(self, swap=None):
        callable_ = self.fake_swap if swap is None else swap
        with mock.patch.object(rs, "_bind_renameatx_np", lambda: callable_):
            return rs.finalize_prebuilt_environment_stage(
                self.authority_root,
                self.state_root,
                self.journal_root,
                environment_request=self.request,
                layout_plan=self.layout_plan,
                stage_result=self.stage_result,
            )

    def inspect(self):
        return rs.inspect_prebuilt_environment_stage(
            self.authority_root,
            self.state_root,
            self.journal_root,
            environment_request=self.request,
            layout_plan=self.layout_plan,
            stage_result=self.stage_result,
        )

    def close(self):
        self._temporary.cleanup()


class TestPinnedLiterals(unittest.TestCase):
    def test_schemas(self):
        self.assertEqual(rs.STORAGE_CONTRACT_SCHEMA, CONTRACT_SCHEMA)
        self.assertEqual(rs.STORAGE_REQUEST_RECORD_SCHEMA, REQUEST_RECORD_SCHEMA)
        self.assertEqual(rs.TREE_MANIFEST_SCHEMA, TREE_MANIFEST_SCHEMA)
        self.assertEqual(rs.STORAGE_PREPARE_SCHEMA, PREPARE_SCHEMA)
        self.assertEqual(rs.STORAGE_RESULT_SCHEMA, RESULT_SCHEMA)
        self.assertEqual(rs.STORAGE_RENDER_SCHEMA, RENDER_SCHEMA)

    def test_domains(self):
        self.assertEqual(rs.CONTRACT_DOMAIN, CONTRACT_DOMAIN)
        self.assertEqual(rs.REQUEST_DOMAIN, REQUEST_DOMAIN)
        self.assertEqual(rs.TREE_MANIFEST_DOMAIN, TREE_MANIFEST_DOMAIN)
        self.assertEqual(rs.PREPARE_DOMAIN, PREPARE_DOMAIN)
        self.assertEqual(rs.RESULT_DOMAIN, RESULT_DOMAIN)
        self.assertEqual(rs.STORAGE_DIGEST_DOMAIN, STORAGE_DIGEST_DOMAIN)
        self.assertEqual(rs.STAGE_JOURNAL_DOMAIN, STAGE_JOURNAL_DOMAIN)
        self.assertEqual(rs.LAYOUT_ID_DOMAIN, LAYOUT_ID_DOMAIN)

    def test_frozen_external_identities(self):
        self.assertEqual(rs.PHASE5A_SOURCE_SHA256, PINNED_PHASE5A_SOURCE_SHA256)
        self.assertEqual(rs.PHASE5A_CONTRACT_ID, PINNED_PHASE5A_CONTRACT_ID)
        self.assertEqual(
            rs.INSTALLED_LAYOUT_SOURCE_SHA256,
            PINNED_INSTALLED_LAYOUT_SOURCE_SHA256,
        )
        self.assertEqual(
            rs.ACTIVATION_JOURNAL_SOURCE_SHA256,
            PINNED_ACTIVATION_JOURNAL_SOURCE_SHA256,
        )
        self.assertEqual(
            release_environment.ENVIRONMENT_CONTRACT_ID,
            PINNED_PHASE5A_CONTRACT_ID,
        )
        self.assertEqual(rs.LAYOUT_CONTRACT_ID, PINNED_LAYOUT_CONTRACT_ID)

    def test_on_disk_sibling_sources_match_frozen_hashes(self):
        table = (
            ("release_environment_storage.py", PINNED_STORAGE_SOURCE_SHA256),
            ("release_environment.py", PINNED_PHASE5A_SOURCE_SHA256),
            ("installed_layout.py", PINNED_INSTALLED_LAYOUT_SOURCE_SHA256),
            (
                "release_activation_journal.py",
                PINNED_ACTIVATION_JOURNAL_SOURCE_SHA256,
            ),
        )
        for basename, expected in table:
            with self.subTest(basename=basename):
                path = os.path.join(_REPO, "scripts", basename)
                self.assertEqual(file_sha(path), expected)

    def test_phase5a_keysets(self):
        self.assertEqual(len(PHASE5A_REQUEST_KEYS), 47)
        self.assertEqual(len(PHASE5A_BINDING_KEYS), 40)
        self.assertEqual(tuple(rs.PHASE5A_REQUEST_KEYS), PHASE5A_REQUEST_KEYS)
        self.assertEqual(tuple(rs.PHASE5A_BINDING_KEYS), PHASE5A_BINDING_KEYS)
        self.assertEqual(
            tuple(release_environment.REQUEST_KEYS), PHASE5A_REQUEST_KEYS
        )
        self.assertEqual(
            tuple(release_environment.BINDING_KEYS), PHASE5A_BINDING_KEYS
        )

    def test_layout_and_stage_keysets(self):
        self.assertEqual(tuple(rs.LAYOUT_PLAN_KEYS), LAYOUT_PLAN_KEYS)
        self.assertEqual(
            tuple(rs.LAYOUT_PLAN_FALSE_FLAGS), LAYOUT_PLAN_FALSE_FLAGS
        )
        self.assertEqual(
            tuple(rs.LAYOUT_PLAN_NONCLAIMS), LAYOUT_PLAN_NONCLAIMS
        )
        self.assertEqual(
            tuple(rs.LAYOUT_ID_BINDING_KEYS), LAYOUT_ID_BINDING_KEYS
        )
        self.assertEqual(tuple(rs.LAYOUT_ADAPTER_TABLE), LAYOUT_ADAPTER_TABLE)
        self.assertEqual(rs.STAGE_RESULT_SCHEMA_V1, STAGE_RESULT_SCHEMA)
        self.assertEqual(rs.STAGE_RESULT_MODE, STAGE_RESULT_MODE)
        self.assertEqual(tuple(rs.STAGE_RESULT_KEYS), STAGE_RESULT_KEYS)
        self.assertEqual(
            tuple(rs.STAGE_RESULT_TRUE_PROOFS), STAGE_RESULT_TRUE_PROOFS
        )
        self.assertEqual(
            tuple(rs.STAGE_RESULT_FALSE_FLAGS), STAGE_RESULT_FALSE_FLAGS
        )
        self.assertEqual(tuple(rs.STAGE_RESULT_ACCEPTED), STAGE_RESULT_ACCEPTED)
        self.assertEqual(
            tuple(rs.STAGE_RESULT_NONCLAIMS), STAGE_RESULT_NONCLAIMS
        )
        self.assertEqual(rs.STAGE_JOURNAL_SCHEMA, STAGE_JOURNAL_SCHEMA)
        self.assertEqual(tuple(rs.STAGE_JOURNAL_KEYS), STAGE_JOURNAL_KEYS)
        self.assertEqual(rs.STAGE_JOURNAL_GENESIS_HASH, "0" * 64)
        self.assertEqual(tuple(rs.STAGE_JOURNAL_STATES), ("staged", "reconciled"))

    def test_manifest_and_state_keysets(self):
        self.assertEqual(tuple(rs.TREE_MANIFEST_KEYS), TREE_MANIFEST_KEYS)
        self.assertEqual(tuple(rs.TREE_ENTRY_KEYS), TREE_ENTRY_KEYS)
        self.assertEqual(tuple(rs.FINGERPRINT_KEYS), FINGERPRINT_KEYS)
        self.assertEqual(
            tuple(rs.FULL_STAT_FINGERPRINT_KEYS), FULL_STAT_FINGERPRINT_KEYS
        )
        self.assertEqual(
            tuple(rs.STORAGE_REQUEST_RECORD_KEYS), STORAGE_REQUEST_RECORD_KEYS
        )
        self.assertEqual(
            tuple(rs.STORAGE_PREPARE_RECORD_KEYS), STORAGE_PREPARE_RECORD_KEYS
        )
        self.assertEqual(
            rs.OPERATIONS_DIR_NAME, ".release-environment-operations-v1"
        )
        self.assertEqual(
            rs.STATE_REQUEST_DOC_NAME, "storage-request-record-v1.json"
        )
        self.assertEqual(
            rs.STATE_MANIFEST_DOC_NAME, "storage-tree-manifest-v1.json"
        )
        self.assertEqual(
            rs.STATE_PREPARE_DOC_NAME, "storage-prepare-record-v1.json"
        )
        self.assertEqual(rs.STATE_LOCK_NAME, "storage-finalize-v1.lock")
        self.assertEqual(
            rs.STATE_ROOT_PREFIX, "release-environment-storage-v1-"
        )
        self.assertEqual(rs.OPERATION_PREFIX, "operation-")

    def test_platform_modes_and_lock_literals(self):
        self.assertEqual(rs.REQUIRED_OS_NAME, "posix")
        self.assertEqual(rs.SIBLING_SOURCE_MODE, 0o644)
        self.assertEqual(rs.PRIVATE_DIRECTORY_MODE, 0o700)
        self.assertEqual(rs.STATE_FILE_MODE, 0o600)
        self.assertEqual(rs.TREE_REGULAR_FILE_MODE, 0o600)
        self.assertEqual(rs.TREE_PYTHON_FILE_MODE, 0o700)
        self.assertEqual(rs.SPECIAL_MODE_BITS, 0o7000)
        self.assertEqual(rs.RESULT_REASON_MIN_CHARACTERS, 1)
        self.assertEqual(rs.RESULT_REASON_MAX_CHARACTERS, 300)
        self.assertEqual(
            tuple(rs._FCNTL_READ_LOCK_FLAGS), ("LOCK_SH", "LOCK_NB")
        )
        self.assertEqual(
            tuple(rs._FCNTL_WRITE_LOCK_FLAGS), ("LOCK_EX", "LOCK_NB")
        )

    def test_regex_sources_and_effective_flags(self):
        for name, pattern in REGEX_PINS.items():
            with self.subTest(name=name):
                compiled = getattr(rs, name)
                self.assertEqual(compiled.pattern, pattern)
                self.assertEqual(int(compiled.flags), 32)

    def test_limits(self):
        for name, expected in LIMIT_PINS.items():
            with self.subTest(name=name):
                self.assertEqual(getattr(rs, name), expected)

    def test_nonclaims(self):
        self.assertEqual(tuple(rs.NONCLAIMS), NONCLAIMS)

    def test_result_and_render_contract_literals(self):
        self.assertEqual(rs.COMMAND_FINALIZE, COMMAND_FINALIZE)
        self.assertEqual(rs.COMMAND_INSPECT, COMMAND_INSPECT)
        self.assertEqual(tuple(rs.SUCCESS_REASONS), SUCCESS_REASONS)
        self.assertEqual(tuple(rs.RESULT_DIGEST_KEYS), RESULT_DIGEST_KEYS)
        self.assertEqual(tuple(rs.RESULT_IDENTITY_KEYS), RESULT_IDENTITY_KEYS)
        self.assertEqual(tuple(rs._RESULT_FLAG_KEYS), RESULT_FLAG_KEYS)
        self.assertEqual(tuple(rs.RESULT_KEYS), RESULT_KEYS)
        self.assertEqual(tuple(rs.RENDER_KEYS), RENDER_KEYS)
        self.assertEqual(
            tuple(rs.RENDER_FALLBACK_KEYS), ("schema", "status", "reason")
        )
        self.assertEqual(
            rs.RENDER_FALLBACK_REASON, "blocked:result-not-renderable"
        )
        self.assertEqual(rs.RENDER_FALLBACK_LINE, RENDER_FALLBACK_LINE)
        self.assertEqual(tuple(rs._STORAGE_FACT_KEYS), STORAGE_FACT_KEYS)
        self.assertEqual(
            tuple(rs._SUCCESS_VERIFIED_TRUE_KEYS), SUCCESS_VERIFIED_TRUE_KEYS
        )
        self.assertEqual(dict(rs._SUCCESS_ROWS), SUCCESS_ROWS)
        self.assertEqual(
            frozenset(rs.UNSUPPORTED_REASONS[COMMAND_FINALIZE]),
            UNSUPPORTED_WRITE_REASONS,
        )
        self.assertEqual(
            frozenset(rs.UNSUPPORTED_REASONS[COMMAND_INSPECT]),
            UNSUPPORTED_READ_REASONS,
        )
        self.assertEqual(rs.BLOCKED_FINALIZE_REASON, BLOCKED_FINALIZE_REASON)
        self.assertEqual(rs.BLOCKED_INSPECT_REASON, BLOCKED_INSPECT_REASON)
        self.assertEqual(rs.UNKNOWN_FINALIZE_REASON, UNKNOWN_FINALIZE_REASON)
        self.assertEqual(dict(rs._EXIT_CODES), EXIT_CODES)
        self.assertEqual(
            frozenset(rs._SUCCESS_TRUE_ALLOWED),
            frozenset(STORAGE_FACT_KEYS)
            | frozenset(SUCCESS_VERIFIED_TRUE_KEYS)
            | {"reconciled"},
        )
        # The fallback line is itself canonical JSON of the fallback keys.
        self.assertEqual(
            RENDER_FALLBACK_LINE,
            canon(
                {
                    "schema": RENDER_SCHEMA,
                    "status": "blocked",
                    "reason": "blocked:result-not-renderable",
                }
            ),
        )


class TestContractProjection(unittest.TestCase):
    def test_contract_id_replay_and_pin(self):
        projection = rs.environment_storage_contract_projection()
        body = {k: v for k, v in projection.items() if k != "contract_id"}
        replayed = "environment-storage-contract-" + dsha(CONTRACT_DOMAIN, body)
        self.assertEqual(projection["contract_id"], replayed)
        self.assertEqual(projection["contract_id"], PINNED_STORAGE_CONTRACT_ID)
        self.assertEqual(projection["schema"], CONTRACT_SCHEMA)

    def test_projection_canonical_size_bound(self):
        projection = rs.environment_storage_contract_projection()
        self.assertLessEqual(
            len(canon(projection).encode("ascii")), 65536
        )

    def test_projection_claims_and_nonclaims(self):
        projection = rs.environment_storage_contract_projection()
        for name, value in projection["projection_claims"].items():
            with self.subTest(claim=name):
                self.assertIs(value, False)
        self.assertEqual(tuple(projection["nonclaims"]), NONCLAIMS)
        self.assertEqual(
            projection["frozen_external_identities"]["phase5a_contract_id"],
            PINNED_PHASE5A_CONTRACT_ID,
        )
        self.assertEqual(
            projection["phase5a_request"]["request_key_count"], 47
        )
        self.assertEqual(
            projection["phase5a_request"]["binding_key_count"], 40
        )
        self.assertEqual(
            projection["roots"]["required_containments"],
            [
                "authority-root-direct-parent-of-environment-root",
                "authority-root-direct-parent-of-operations-directory",
                "journal-root-direct-parent-of-derived-state-root",
            ],
        )
        self.assertEqual(
            projection["roots"]["allowed_overlap"],
            [
                "authority-root-parent-of-environment-root",
                "authority-root-parent-of-operations-directory",
                "journal-root-parent-of-derived-state-root",
            ],
        )

    def test_projection_deterministic(self):
        first = rs.environment_storage_contract_projection()
        second = rs.environment_storage_contract_projection()
        self.assertEqual(canon(first), canon(second))


class TestRequestValidation(unittest.TestCase):
    def test_native_plan_fixture_is_planned(self):
        self.assertEqual(_PLAN_RESULT["status"], "planned")
        self.assertEqual(tuple(sorted(REQUEST)), tuple(sorted(PHASE5A_REQUEST_KEYS)))

    def test_request_digest_recomputed_independently(self):
        expected = {
            "schema": "synapse-s2.release-environment-request.v1",
            "mode": "dormant-source-only-environment-contract",
            "profile": "exact-build-only",
            "profile_version": 1,
            "environment_contract_id": PINNED_PHASE5A_CONTRACT_ID,
            "activation_contract_id": (
                "activation-contract-"
                "db5a82b45bfc11d9a56a81fb7f0710e95d429fdfd313aac3743bd6d31abad276"
            ),
            "compatibility_profile_version": 3,
        }
        expected.update(valid_bindings())
        self.assertEqual(canon(expected), canon(REQUEST))
        self.assertEqual(
            REQUEST_SHA256,
            dsha_bytes(PHASE5A_REQUEST_DOMAIN_BYTES, expected),
        )

    def test_validate_request_accepts_native_request(self):
        validated, digest = validate_request(dict(REQUEST))
        self.assertEqual(canon(validated), canon(REQUEST))
        self.assertEqual(digest, REQUEST_SHA256)

    def test_validate_request_refuses_every_field_mutation(self):
        for key in PHASE5A_REQUEST_KEYS:
            with self.subTest(key=key, mode="mutate"):
                mutated = dict(REQUEST)
                mutated[key] = None
                with self.assertRaises(rs._StorageFailure):
                    validate_request(mutated)
            with self.subTest(key=key, mode="delete"):
                mutated = dict(REQUEST)
                del mutated[key]
                with self.assertRaises(rs._StorageFailure):
                    validate_request(mutated)

    def test_validate_request_refuses_extra_key_and_bad_shapes(self):
        mutated = dict(REQUEST)
        mutated["extra_key"] = "x"
        for hostile in (mutated, None, [], "", 7, BombDict()):
            with self.subTest(value=type(hostile).__name__):
                with self.assertRaises(rs._StorageFailure):
                    validate_request(hostile)

    def test_validate_request_refuses_valid_but_diverged_staged_identity(self):
        mutated = dict(REQUEST)
        mutated["staged_product_id"] = "product-" + "00" * 32
        with self.assertRaises(rs._StorageFailure):
            validate_request(mutated)
        mutated = dict(REQUEST)
        mutated["staged_source_build_id"] = "source-" + "00" * 12
        with self.assertRaises(rs._StorageFailure):
            validate_request(mutated)

    def test_validate_request_refuses_sibling_keyset_drift(self):
        drifted = PHASE5A_REQUEST_KEYS[1:] + PHASE5A_REQUEST_KEYS[:1]
        phase5a, _ = rs._verify_frozen_sibling_sources()
        phase5a["REQUEST_KEYS"] = drifted
        with self.assertRaises(rs._StorageFailure) as caught:
            validate_request(dict(REQUEST), phase5a)
        self.assertEqual(
            caught.exception.reason, "blocked:phase5a-request-keyset-drift"
        )
        drifted_bindings = PHASE5A_BINDING_KEYS[1:] + PHASE5A_BINDING_KEYS[:1]
        phase5a, _ = rs._verify_frozen_sibling_sources()
        phase5a["BINDING_KEYS"] = drifted_bindings
        with self.assertRaises(rs._StorageFailure) as caught:
            validate_request(dict(REQUEST), phase5a)
        self.assertEqual(
            caught.exception.reason, "blocked:phase5a-binding-keyset-drift"
        )
        # Restored: the native request validates again.
        self.assertEqual(validate_request(dict(REQUEST))[1], REQUEST_SHA256)

    def test_private_sibling_replay_ignores_imported_module_monkeypatches(self):
        def forged_planner(**_kwargs):
            return {"status": "forged"}

        with mock.patch.object(
            release_environment, "plan_environment_request", forged_planner
        ), mock.patch.object(
            installed_layout, "plan_inactive_versioned_layout", forged_planner
        ):
            phase5a, layout = rs._verify_frozen_sibling_sources()
            validated, digest = validate_request(dict(REQUEST), phase5a)
            self.assertEqual(canon(validated), canon(REQUEST))
            self.assertEqual(digest, REQUEST_SHA256)
            replayed = validate_layout_plan(
                json.loads(canon(LAYOUT_PLAN)),
                REQUEST,
                STAGE_RESULT,
                layout,
            )
            self.assertEqual(canon(replayed), canon(LAYOUT_PLAN))

    def test_both_sibling_files_are_verified_before_either_executes(self):
        events = []

        def fake_read(_expected_hash, basename, _token):
            events.append(("read", basename))
            return b"pass\n", "/verified/" + basename

        def stop_execute(_raw, path, _private_name, _token):
            events.append(("execute", os.path.basename(path)))
            raise rs._blocked("test-stop")

        with mock.patch.object(
            rs, "_read_frozen_sibling_source", fake_read
        ), mock.patch.object(
            rs, "_execute_frozen_sibling_source", stop_execute
        ):
            with self.assertRaises(rs._StorageFailure):
                rs._verify_frozen_sibling_sources()
        self.assertEqual(
            events,
            [
                ("read", "release_environment.py"),
                ("read", "installed_layout.py"),
                ("execute", "release_environment.py"),
            ],
        )

    def test_sibling_source_requires_exact_0644_mode(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as root:
            os.chmod(root, 0o700)
            storage_path = root + "/release_environment_storage.py"
            sibling_path = root + "/release_environment.py"
            StorageFixture._write(storage_path, b"# storage anchor\n", 0o644)
            payload = b"VALUE = 1\n"
            StorageFixture._write(sibling_path, payload, 0o664)
            with mock.patch.object(rs, "__file__", storage_path):
                with self.assertRaises(rs._StorageFailure) as caught:
                    rs._read_frozen_sibling_source(
                        raw_sha(payload), "release_environment.py", "test"
                    )
            self.assertEqual(caught.exception.reason, "blocked:test-source-shape")

    def test_sibling_compile_exec_baseexception_is_closed(self):
        with self.assertRaises(rs._StorageFailure) as caught:
            rs._execute_frozen_sibling_source(
                b"raise SystemExit(9)\n",
                "/verified/release_environment.py",
                "_verified_test_namespace",
                "test",
            )
        self.assertEqual(
            caught.exception.reason, "blocked:test-source-execution"
        )


class TestLayoutPlanAndStageResult(unittest.TestCase):
    def test_layout_plan_fixture_shape(self):
        self.assertEqual(LAYOUT_PLAN["status"], "planned")
        self.assertEqual(
            LAYOUT_PLAN["reason"], "planned:inactive-versioned-layout-bound"
        )
        self.assertEqual(LAYOUT_PLAN["mode"], "inactive-versioned-v1")
        self.assertEqual(
            LAYOUT_PLAN["layout_contract_id"], PINNED_LAYOUT_CONTRACT_ID
        )
        self.assertEqual(tuple(LAYOUT_PLAN), LAYOUT_PLAN_KEYS)
        for flag in LAYOUT_PLAN_FALSE_FLAGS:
            self.assertIs(LAYOUT_PLAN[flag], False)
        self.assertEqual(
            tuple(LAYOUT_PLAN["nonclaims"]), LAYOUT_PLAN_NONCLAIMS
        )
        # Independent layout_id replay over the literal binding payload.
        binding = {
            "schema": "synapse-s2.installed-layout-plan.v1",
            "mode": "inactive-versioned-v1",
            "layout_contract_id": PINNED_LAYOUT_CONTRACT_ID,
            "product_id": PRODUCT_ID,
            "inventory_policy_id": POLICY_ID,
            "install_root": INSTALL_ROOT,
            "code_root": LAYOUT_PLAN["release_root"],
            "environment_root": ENVIRONMENT_ROOT,
            "data_root": DATA_ROOT,
            "release_root": INSTALL_ROOT + "/releases/" + PRODUCT_ID,
            "updater_state_root": UPDATER_STATE_ROOT,
            "legacy_checkout_root": LEGACY_CHECKOUT_ROOT,
            "adapters": LAYOUT_PLAN["adapters"],
        }
        self.assertEqual(
            LAYOUT_PLAN["layout_id"], "layout-" + dsha(LAYOUT_ID_DOMAIN, binding)
        )

    def test_validate_layout_plan_exact_replay(self):
        validated = validate_layout_plan(
            json.loads(canon(LAYOUT_PLAN)), REQUEST, STAGE_RESULT
        )
        self.assertEqual(canon(validated), canon(LAYOUT_PLAN))

    def test_validate_layout_plan_refuses_every_field_mutation(self):
        def mutate(value):
            if type(value) is bool:
                return not value
            if type(value) is str:
                return value + "x"
            if type(value) is list:
                return value + ["x"]
            if type(value) is dict:
                return {**value, "extra": "/mutation/x"}
            return "mutated"

        for key in LAYOUT_PLAN_KEYS:
            with self.subTest(key=key, mode="mutate"):
                plan = json.loads(canon(LAYOUT_PLAN))
                plan[key] = mutate(plan[key])
                with self.assertRaises(rs._StorageFailure):
                    validate_layout_plan(plan, REQUEST, STAGE_RESULT)
            with self.subTest(key=key, mode="delete"):
                plan = json.loads(canon(LAYOUT_PLAN))
                del plan[key]
                with self.assertRaises(rs._StorageFailure):
                    validate_layout_plan(plan, REQUEST, STAGE_RESULT)

    def test_validate_layout_plan_refuses_request_binding_mismatch(self):
        for key, value in (
            ("layout_contract_id", "layout-contract-" + "00" * 32),
            ("layout_id", "layout-" + "00" * 32),
            ("candidate_product_id", "product-" + "00" * 32),
            ("inventory_policy_id", "inventory-policy-" + "00" * 32),
            ("stage_result_sha256", "00" * 32),
        ):
            with self.subTest(key=key):
                request = dict(REQUEST)
                request[key] = value
                with self.assertRaises(rs._StorageFailure):
                    validate_layout_plan(
                        json.loads(canon(LAYOUT_PLAN)), request, STAGE_RESULT
                    )

    def test_stage_result_fixture_hash_binds_request(self):
        self.assertEqual(REQUEST["stage_result_sha256"], STAGE_RESULT_SHA256)
        self.assertEqual(tuple(STAGE_RESULT), STAGE_RESULT_KEYS)
        validated = rs._validate_stage_result(
            json.loads(canon(STAGE_RESULT)), REQUEST
        )
        self.assertEqual(canon(validated), canon(STAGE_RESULT))

    def test_validate_stage_result_accepts_resumed_row(self):
        resumed = stage_result_fixture(row=1)
        request = dict(REQUEST)
        request["stage_result_sha256"] = raw_sha(canon(resumed).encode("ascii"))
        validated = rs._validate_stage_result(resumed, request)
        self.assertEqual(canon(validated), canon(resumed))

    def test_validate_stage_result_refuses_mutations(self):
        mutations = [("__delete__", key) for key in STAGE_RESULT_KEYS]
        for key in STAGE_RESULT_KEYS:
            mutations.append(("__none__", key))
        for mode, key in mutations:
            with self.subTest(mode=mode, key=key):
                doc = json.loads(canon(STAGE_RESULT))
                if mode == "__delete__":
                    del doc[key]
                else:
                    doc[key] = None
                with self.assertRaises(rs._StorageFailure):
                    rs._validate_stage_result(doc, REQUEST)
        # Coordinated-but-forbidden shapes: rehashing the request cannot save
        # an outcome/flag/nonclaim forgery.
        forgeries = (
            {"status": "already-staged"},
            {"reason": "identity-already-staged"},
            {"resumed": True},
            {"source_staged": False},
            {"environment_built": True},
            {"nonclaims": list(reversed(STAGE_RESULT_NONCLAIMS))},
            {"product_id": "product-" + "00" * 32},
        )
        for forgery in forgeries:
            with self.subTest(forgery=sorted(forgery)):
                doc = json.loads(canon(STAGE_RESULT))
                doc.update(forgery)
                request = dict(REQUEST)
                request["stage_result_sha256"] = raw_sha(
                    canon(doc).encode("ascii")
                )
                with self.assertRaises(rs._StorageFailure):
                    rs._validate_stage_result(doc, request)


class TestPlatformGate(unittest.TestCase):
    """Platform gating precedes all public-input inspection and all os.open
    access. Every patched global is restored by mock.patch context exit."""

    def _finalize_with(self, os_proxy=None, sys_stub=None, rename=mock.DEFAULT):
        bombs = (SystemExitBomb(), SystemExitBomb(), SystemExitBomb())
        patches = []
        if os_proxy is not None:
            patches.append(mock.patch.object(rs, "os", os_proxy))
        patches.append(
            mock.patch.object(
                rs,
                "sys",
                sys_stub
                if sys_stub is not None
                else types.SimpleNamespace(platform="darwin"),
            )
        )
        if rename is not mock.DEFAULT:
            patches.append(mock.patch.object(rs, "_bind_renameatx_np", rename))
        try:
            for patch in patches:
                patch.start()
            return rs.finalize_prebuilt_environment_stage(
                SystemExitBomb(),
                SystemExitBomb(),
                SystemExitBomb(),
                environment_request=bombs[0],
                layout_plan=bombs[1],
                stage_result=bombs[2],
            )
        finally:
            for patch in reversed(patches):
                patch.stop()

    def _assert_unsupported(self, result, reason):
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["reason"], reason)
        for key in STORAGE_FACT_KEYS:
            self.assertIs(result[key], False, key)
        for key in RESULT_DIGEST_KEYS + RESULT_IDENTITY_KEYS:
            self.assertIsNone(result[key], key)
        self.assertEqual(
            rs.environment_storage_result_exit_code(result), 2
        )

    def test_finalize_unsupported_platform(self):
        result = self._finalize_with(
            os_proxy=_OsProxy(),
            sys_stub=types.SimpleNamespace(platform="linux"),
        )
        self._assert_unsupported(result, "unsupported:platform-not-darwin")

    def test_finalize_missing_read_capabilities(self):
        table = (
            ({"O_NOFOLLOW"}, "unsupported:missing-nofollow-directory-open"),
            ({"O_DIRECTORY"}, "unsupported:missing-nofollow-directory-open"),
            ({"scandir"}, "unsupported:missing-os-callable"),
            ({"geteuid"}, "unsupported:missing-os-callable"),
        )
        for missing, reason in table:
            with self.subTest(missing=sorted(missing)):
                proxy = _OsProxy(missing=missing)
                result = self._finalize_with(os_proxy=proxy)
                self._assert_unsupported(result, reason)
                self.assertEqual(proxy.open_calls, [])

    def test_finalize_missing_flock_capabilities(self):
        proxy = _OsProxy()
        with mock.patch.object(fcntl, "flock", None):
            result = self._finalize_with(os_proxy=proxy)
        self._assert_unsupported(result, "unsupported:missing-flock")
        with mock.patch.object(fcntl, "LOCK_NB", None):
            result = self._finalize_with(os_proxy=proxy)
        self._assert_unsupported(result, "unsupported:missing-flock")
        self.assertEqual(proxy.open_calls, [])

    def test_command_specific_lock_capabilities_do_not_overrequire(self):
        with mock.patch.object(
            rs, "sys", types.SimpleNamespace(platform="darwin")
        ), mock.patch.object(fcntl, "LOCK_EX", None):
            self.assertIsNone(
                rs._platform_gate(COMMAND_INSPECT, require_write=False)
            )
        with mock.patch.object(
            rs, "sys", types.SimpleNamespace(platform="darwin")
        ), mock.patch.object(fcntl, "LOCK_SH", None), mock.patch.object(
            rs, "_bind_renameatx_np", lambda: (lambda *_args: 0)
        ):
            self.assertIsNone(
                rs._platform_gate(COMMAND_FINALIZE, require_write=True)
            )

    def test_finalize_missing_write_capabilities(self):
        table = (
            ({"O_EXCL"}, "unsupported:missing-write-open-flags"),
            ({"O_CREAT"}, "unsupported:missing-write-open-flags"),
            ({"fsync"}, "unsupported:missing-os-callable"),
            ({"fchmod"}, "unsupported:missing-os-callable"),
        )
        for missing, reason in table:
            with self.subTest(missing=sorted(missing)):
                proxy = _OsProxy(missing=missing)
                result = self._finalize_with(os_proxy=proxy)
                self._assert_unsupported(result, reason)
                self.assertEqual(proxy.open_calls, [])

    def test_finalize_missing_rename_swap_capability(self):
        proxy = _OsProxy()
        result = self._finalize_with(os_proxy=proxy, rename=lambda: None)
        self._assert_unsupported(
            result, "unsupported:missing-renameatx-np-swap-capability"
        )
        self.assertEqual(proxy.open_calls, [])

    def test_inspect_passes_gate_without_write_capabilities(self):
        proxy = _OsProxy(
            missing={"O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL",
                     "write", "fsync", "fchmod"}
        )

        def _never_bound():
            raise RuntimeError("renameatx_np must not be bound for inspect")

        with mock.patch.object(rs, "os", proxy), mock.patch.object(
            rs, "sys", types.SimpleNamespace(platform="darwin")
        ), mock.patch.object(rs, "_bind_renameatx_np", _never_bound):
            result = rs.inspect_prebuilt_environment_stage(
                "not-absolute",
                "also-not-absolute",
                "still-not-absolute",
                environment_request=dict(REQUEST),
                layout_plan=json.loads(canon(LAYOUT_PLAN)),
                stage_result=json.loads(canon(STAGE_RESULT)),
            )
        # The read-only gate passed (not unsupported); the lexically invalid
        # roots then refused deterministically before any descriptor I/O.
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], BLOCKED_INSPECT_REASON)
        self.assertIs(result["storage_read_supported"], True)
        self.assertIs(result["storage_write_supported"], False)
        self.assertIs(result["storage_write_attempted"], False)
        self.assertIs(result["storage_written"], False)
        self.assertEqual(proxy.open_calls, [])
        self.assertEqual(rs.environment_storage_result_exit_code(result), 3)

    def test_finalize_blocked_before_io_on_invalid_roots(self):
        proxy = _OsProxy()
        with mock.patch.object(rs, "os", proxy), mock.patch.object(
            rs, "sys", types.SimpleNamespace(platform="darwin")
        ), mock.patch.object(rs, "_bind_renameatx_np", lambda: (lambda *a: 0)):
            result = rs.finalize_prebuilt_environment_stage(
                "relative-root",
                "/x//bad",
                "/ok/root",
                environment_request=dict(REQUEST),
                layout_plan=json.loads(canon(LAYOUT_PLAN)),
                stage_result=json.loads(canon(STAGE_RESULT)),
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], BLOCKED_FINALIZE_REASON)
        self.assertIs(result["storage_write_attempted"], False)
        self.assertIs(result["storage_written"], False)
        self.assertEqual(proxy.open_calls, [])
        self.assertEqual(rs.environment_storage_result_exit_code(result), 3)

    def test_cached_contract_id_keeps_failure_results_total(self):
        def projection_bomb():
            raise SystemExit(9)

        with mock.patch.object(
            rs, "environment_storage_contract_projection", projection_bomb
        ), mock.patch.object(
            rs, "_platform_gate", lambda *_args, **_kwargs: None
        ):
            result = rs.finalize_prebuilt_environment_stage(
                "relative-root",
                "also-relative",
                "still-relative",
                environment_request=SystemExitBomb(),
                layout_plan=SystemExitBomb(),
                stage_result=SystemExitBomb(),
            )
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["storage_contract_id"], PINNED_STORAGE_CONTRACT_ID)
        self.assertNotEqual(
            rs.render_environment_storage_result(result), RENDER_FALLBACK_LINE
        )
        self.assertEqual(rs.environment_storage_result_exit_code(result), 3)


class TestSwapBoundary(unittest.TestCase):
    def test_swap_rebinds_all_visible_operands_at_syscall_boundary(self):
        events = []

        def reprove(parent_fd, name, held_fd, token):
            events.append(("reprove", parent_fd, name, held_fd, token))

        def swap(*args):
            events.append(("swap",) + args)
            return 0

        tracker = rs._MutationTracker(write_supported=True)
        with mock.patch.object(
            rs, "_reprove_named_child_dir", reprove
        ), mock.patch.object(
            rs, "_bind_renameatx_np", lambda: swap
        ), mock.patch.object(rs.os, "fsync", lambda _fd: None):
            rs._perform_swap(11, "operation-" + "ab" * 32, 12, 21, "env", 22,
                             tracker)
        self.assertEqual(
            [event[-1] for event in events[:3]],
            [
                "swap-operations-dir",
                "swap-operation-tree",
                "swap-environment-preimage",
            ],
        )
        self.assertEqual(events[3][0], "swap")
        self.assertIs(tracker.write_attempted, True)
        self.assertIs(tracker.known_written, True)

    def test_operand_reproof_failure_precedes_write_attempt(self):
        tracker = rs._MutationTracker(write_supported=True)
        swap = mock.Mock(return_value=0)

        def refuse(_parent_fd, _name, _held_fd, token):
            if token == "swap-environment-preimage":
                raise rs._blocked("test-visible-substitution")

        with mock.patch.object(
            rs, "_reprove_named_child_dir", refuse
        ), mock.patch.object(rs, "_bind_renameatx_np", lambda: swap):
            with self.assertRaises(rs._StorageFailure):
                rs._perform_swap(
                    11, "operation-" + "ab" * 32, 12, 21, "env", 22, tracker
                )
        self.assertIs(tracker.write_attempted, False)
        self.assertIs(tracker.known_written, False)
        swap.assert_not_called()


class TestResultContract(unittest.TestCase):
    def _assert_replayable(self, result):
        body = {k: result[k] for k in RESULT_KEYS if k != "result_sha256"}
        self.assertEqual(result["result_sha256"], dsha(RESULT_DOMAIN, body))
        self.assertEqual(len(result), len(RESULT_KEYS))
        self.assertEqual(set(result), set(RESULT_KEYS))
        self.assertEqual(
            result["storage_contract_id"], PINNED_STORAGE_CONTRACT_ID
        )
        self.assertEqual(tuple(result["nonclaims"]), NONCLAIMS)
        self.assertLessEqual(len(canon(result).encode("ascii")), 8192)

    def test_native_unsupported_result(self):
        result = unsupported_result(COMMAND_FINALIZE)
        self._assert_replayable(result)
        self.assertEqual(rs.environment_storage_result_exit_code(result), 2)
        result = unsupported_result(
            COMMAND_INSPECT, "unsupported:platform-gate-error"
        )
        self._assert_replayable(result)
        self.assertEqual(rs.environment_storage_result_exit_code(result), 2)

    def test_native_blocked_results(self):
        for command in (COMMAND_FINALIZE, COMMAND_INSPECT):
            with self.subTest(command=command):
                result = blocked_result(command)
                self._assert_replayable(result)
                self.assertEqual(
                    rs.environment_storage_result_exit_code(result), 3
                )

    def test_native_unknown_result(self):
        result = unknown_result()
        self._assert_replayable(result)
        self.assertIsNone(result["storage_written"])
        self.assertEqual(rs.environment_storage_result_exit_code(result), 4)

    def test_each_success_row(self):
        for (command, reason), row in SUCCESS_ROWS.items():
            with self.subTest(command=command, reason=reason):
                result = success_result(command, reason)
                self._assert_replayable(result)
                observed = tuple(
                    result[key] for key in STORAGE_FACT_KEYS + ("reconciled",)
                )
                self.assertEqual(observed, row)
                self.assertEqual(
                    result["storage_digest"],
                    storage_digest(
                        result["request_sha256"],
                        result["manifest_sha256"],
                        result["prepare_sha256"],
                    ),
                )
                self.assertEqual(
                    result["operation_id"],
                    "operation-" + result["request_sha256"],
                )
                self.assertEqual(
                    rs.environment_storage_result_exit_code(result), 0
                )

    def test_exact_render_mapping_and_byte_cap(self):
        samples = [
            success_result(command, reason) for command, reason in SUCCESS_ROWS
        ] + [
            unsupported_result(COMMAND_FINALIZE),
            blocked_result(COMMAND_INSPECT),
            unknown_result(),
        ]
        for result in samples:
            with self.subTest(status=result["status"], reason=result["reason"]):
                expected = {
                    "schema": RENDER_SCHEMA,
                    "result_schema": RESULT_SCHEMA,
                }
                for key in RENDER_KEYS:
                    if key in ("schema", "result_schema"):
                        continue
                    expected[key] = result[key]
                line = rs.render_environment_storage_result(result)
                self.assertEqual(line, canon(expected))
                self.assertNotIn("\n", line)
                self.assertLessEqual(len(line.encode("ascii")), 4096)

    def test_render_never_leaks_request_values_roots_or_nonclaims(self):
        samples = [
            success_result(COMMAND_FINALIZE, SUCCESS_REASONS[0]),
            blocked_result(COMMAND_FINALIZE),
            unsupported_result(COMMAND_INSPECT),
            unknown_result(),
        ]
        forbidden = [item for item in NONCLAIMS]
        forbidden += [
            str(REQUEST[key])
            for key in (
                "channel", "version", "embedding_provider", "model_id",
                "embedding_space_identity", "environment_policy_id",
                "root_key_id", "host_id_sha256",
            )
        ]
        forbidden += [INSTALL_ROOT, ENVIRONMENT_ROOT, DATA_ROOT,
                      UPDATER_STATE_ROOT, LEGACY_CHECKOUT_ROOT,
                      "/opt/synapse-s2", "Traceback", "Exception"]
        for result in samples:
            line = rs.render_environment_storage_result(result)
            for token in forbidden:
                with self.subTest(status=result["status"], token=token):
                    self.assertNotIn(token, line)

    def _assert_rejected(self, forged):
        self.assertEqual(
            rs.render_environment_storage_result(forged), RENDER_FALLBACK_LINE
        )
        self.assertEqual(rs.environment_storage_result_exit_code(forged), 3)

    def test_exhaustive_coordinated_success_mutations(self):
        base = success_result(COMMAND_FINALIZE, SUCCESS_REASONS[0])
        mutations = {
            "schema": "synapse-s2.other-result.v1",
            "command": COMMAND_INSPECT,
            "status": "blocked",
            "reason": SUCCESS_REASONS[1],
            "storage_contract_id": "environment-storage-contract-" + "0" * 64,
            "request_sha256": "ee" * 32,
            "manifest_sha256": "ee" * 32,
            "prepare_sha256": "ee" * 32,
            "storage_digest": "ee" * 32,
            "operation_id": "operation-" + "ee" * 32,
            "layout_plan_id": "not-a-layout-id",
            "product_id": "product-" + "zz" * 32,
            "policy_id": "inventory-policy-short",
            "nonclaims": list(NONCLAIMS[:-1]) + ["forged-claim"],
        }
        for key in RESULT_FLAG_KEYS:
            mutations.setdefault(key, not base[key])
        for key, value in mutations.items():
            with self.subTest(key=key):
                forged = rehash({**base, key: value})
                self._assert_rejected(forged)
        with self.subTest(key="result_sha256"):
            self._assert_rejected({**base, "result_sha256": "0" * 64})
        with self.subTest(key="nonclaims-dropped"):
            self._assert_rejected(
                rehash({**base, "nonclaims": list(NONCLAIMS[:-1])})
            )
        with self.subTest(key="extra-key"):
            forged = dict(base)
            forged["extra"] = True
            self._assert_rejected(forged)
        with self.subTest(key="missing-key"):
            forged = dict(base)
            del forged["reconciled"]
            self._assert_rejected(forged)

    def test_forged_minimal_success_with_all_flags_false(self):
        forged = dict(success_result(COMMAND_FINALIZE, SUCCESS_REASONS[0]))
        for key in RESULT_FLAG_KEYS:
            forged[key] = False
        self._assert_rejected(rehash(forged))

    def test_status_reason_command_cross_forgeries(self):
        base_unknown = unknown_result()
        with self.subTest(case="unknown-with-bool-written"):
            self._assert_rejected(
                rehash({**base_unknown, "storage_written": False})
            )
        with self.subTest(case="unknown-on-inspect"):
            self._assert_rejected(
                rehash({**base_unknown, "command": COMMAND_INSPECT})
            )
        blocked = blocked_result(COMMAND_FINALIZE)
        with self.subTest(case="blocked-with-swapped-reason"):
            self._assert_rejected(
                rehash({**blocked, "reason": BLOCKED_INSPECT_REASON})
            )
        unsupported = unsupported_result(COMMAND_FINALIZE)
        with self.subTest(case="unsupported-free-text-reason"):
            self._assert_rejected(
                rehash({**unsupported, "reason": "unsupported:invented"})
            )
        with self.subTest(case="unsupported-write-reason-on-inspect"):
            self._assert_rejected(
                rehash(
                    {
                        **unsupported_result(COMMAND_INSPECT),
                        "reason": "unsupported:missing-write-open-flags",
                    }
                )
            )

    def test_render_and_exit_totality_on_hostile_objects(self):
        base = success_result(COMMAND_FINALIZE, SUCCESS_REASONS[0])
        hostile_reason = dict(base)
        hostile_reason["reason"] = RaisingStr(base["reason"])
        hostile_nonclaims = dict(base)
        hostile_nonclaims["nonclaims"] = EvilList(NONCLAIMS)
        hostile_flag = dict(base)
        hostile_flag["filesystem_verified"] = SystemExitBomb()
        samples = (
            None, 0, "", b"", [], {}, object(), SystemExitBomb(),
            BombDict(base), hostile_reason, hostile_nonclaims, hostile_flag,
            {RaisingStr("schema"): RESULT_SCHEMA},
        )
        for hostile in samples:
            with self.subTest(kind=type(hostile).__name__):
                line = rs.render_environment_storage_result(hostile)
                self.assertEqual(line, RENDER_FALLBACK_LINE)
                self.assertEqual(
                    rs.environment_storage_result_exit_code(hostile), 3
                )


class TestStorageLifecycle(unittest.TestCase):
    def setUp(self):
        self.fixture = StorageFixture()

    def tearDown(self):
        self.fixture.close()

    def test_finalize_inspect_and_exact_retry(self):
        environment_inode = os.stat(
            self.fixture.environment_root, follow_symlinks=False
        ).st_ino
        operation_inode = os.stat(
            self.fixture.operation_root, follow_symlinks=False
        ).st_ino
        result = self.fixture.finalize()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["reason"], SUCCESS_REASONS[0])
        self.assertIs(result["storage_written"], True)
        self.assertEqual(rs.environment_storage_result_exit_code(result), 0)
        self.assertEqual(
            os.stat(self.fixture.environment_root).st_ino, operation_inode
        )
        self.assertEqual(
            os.stat(self.fixture.operation_root).st_ino, environment_inode
        )
        self.assertEqual(os.listdir(self.fixture.operation_root), [])
        self.assertEqual(
            sorted(os.listdir(self.fixture.environment_root)),
            ["bin", "lib", "pyvenv.cfg"],
        )
        self.assertEqual(
            sorted(os.listdir(self.fixture.state_root)),
            sorted(
                [
                    rs.STATE_LOCK_NAME,
                    rs.STATE_REQUEST_DOC_NAME,
                    rs.STATE_MANIFEST_DOC_NAME,
                    rs.STATE_PREPARE_DOC_NAME,
                ]
            ),
        )
        for name in os.listdir(self.fixture.state_root):
            info = os.stat(
                self.fixture.state_root + "/" + name,
                follow_symlinks=False,
            )
            self.assertEqual(info.st_mode & 0o7777, 0o600)
            self.assertEqual(info.st_nlink, 1)
        inspected = self.fixture.inspect()
        self.assertEqual(inspected["status"], "success")
        self.assertEqual(inspected["reason"], SUCCESS_REASONS[3])
        self.assertIs(inspected["storage_write_supported"], False)
        self.assertIs(inspected["storage_written"], False)
        retried = self.fixture.finalize()
        self.assertEqual(retried["status"], "success")
        self.assertEqual(retried["reason"], SUCCESS_REASONS[1])
        self.assertIs(retried["storage_write_attempted"], False)
        self.assertIs(retried["storage_written"], False)
        self.assertEqual(
            self.fixture._snapshot(self.fixture.sentinel_path),
            self.fixture.sentinel_before,
        )

    def test_symlink_and_hardlink_trees_refuse_before_swap(self):
        outside = self.fixture.base + "/outside"
        self.fixture._write(outside, b"outside", 0o600)
        os.symlink(outside, self.fixture.operation_root + "/escape")
        swap = mock.Mock(return_value=0)
        result = self.fixture.finalize(swap)
        self.assertEqual(result["status"], "blocked")
        self.assertIs(result["storage_write_attempted"], True)
        self.assertIs(result["storage_written"], True)
        swap.assert_not_called()
        self.assertEqual(os.listdir(self.fixture.environment_root), [])
        self.assertEqual(
            self.fixture._snapshot(self.fixture.sentinel_path),
            self.fixture.sentinel_before,
        )

        self.fixture.close()
        self.fixture = StorageFixture()
        outside = self.fixture.base + "/outside"
        self.fixture._write(outside, b"outside", 0o600)
        os.link(outside, self.fixture.operation_root + "/shared")
        swap = mock.Mock(return_value=0)
        result = self.fixture.finalize(swap)
        self.assertEqual(result["status"], "blocked")
        self.assertIs(result["storage_written"], True)
        swap.assert_not_called()
        self.assertEqual(os.listdir(self.fixture.environment_root), [])

    def test_post_swap_tree_drift_is_outcome_unknown(self):
        def swap_then_mutate(*args):
            result = self.fixture.fake_swap(*args)
            self.fixture._write(
                self.fixture.environment_root + "/bin/python",
                b"#!/bin/sh\nexit 99\n",
                0o700,
            )
            return result

        result = self.fixture.finalize(swap_then_mutate)
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertEqual(result["reason"], UNKNOWN_FINALIZE_REASON)
        self.assertIs(result["storage_write_attempted"], True)
        self.assertIsNone(result["storage_written"])
        self.assertEqual(rs.environment_storage_result_exit_code(result), 4)

    def test_post_swap_stage_journal_drift_is_outcome_unknown(self):
        def swap_then_corrupt_journal(*args):
            result = self.fixture.fake_swap(*args)
            self.fixture._write(
                self.fixture.stage_journal_path,
                b"not-canonical\n",
                0o600,
            )
            return result

        result = self.fixture.finalize(swap_then_corrupt_journal)
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertIsNone(result["storage_written"])
        self.assertNotEqual(os.listdir(self.fixture.environment_root), [])

    def test_post_swap_state_document_drift_is_outcome_unknown(self):
        def swap_then_corrupt_state(*args):
            result = self.fixture.fake_swap(*args)
            self.fixture._write(
                self.fixture.state_root + "/" + rs.STATE_MANIFEST_DOC_NAME,
                b"{}",
                0o600,
            )
            return result

        result = self.fixture.finalize(swap_then_corrupt_state)
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertIs(result["storage_write_attempted"], True)
        self.assertIsNone(result["storage_written"])

    def test_fifo_tree_entry_is_rejected_before_swap(self):
        os.mkfifo(self.fixture.operation_root + "/pipe", 0o600)
        swap = mock.Mock(return_value=0)
        result = self.fixture.finalize(swap)
        self.assertEqual(result["status"], "blocked")
        self.assertIs(result["storage_write_attempted"], True)
        self.assertIs(result["storage_written"], True)
        swap.assert_not_called()
        self.assertEqual(os.listdir(self.fixture.environment_root), [])

    def test_existing_document_durable_reread_mismatch_is_unknown(self):
        path = self.fixture.state_root + "/" + rs.STATE_REQUEST_DOC_NAME
        payload = b'{"fixed":true}'
        self.fixture._write(path, payload, 0o600)
        state_fd = os.open(
            self.fixture.state_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        tracker = rs._MutationTracker(write_supported=True)
        original = rs._read_doc_bytes

        def mismatched_durable(*args, **kwargs):
            if kwargs.get("durable") is True:
                return b"different"
            return original(*args, **kwargs)

        try:
            with mock.patch.object(
                rs, "_read_doc_bytes", mismatched_durable
            ):
                with self.assertRaises(rs._StorageFailure) as caught:
                    rs._persist_immutable_doc(
                        state_fd,
                        rs.STATE_REQUEST_DOC_NAME,
                        payload,
                        "request-record",
                        tracker,
                    )
            self.assertEqual(caught.exception.status, "outcome_unknown")
            self.assertIs(tracker.write_attempted, True)
            self.assertIs(tracker.ambiguous, True)
        finally:
            os.close(state_fd)

    def test_partial_writes_complete_and_zero_progress_is_unknown(self):
        state_fd = os.open(
            self.fixture.state_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        payload = b'{"partial-write":"must-complete"}'
        real_write = os.write
        calls = []

        def partial_write(fd, view):
            chunk = bytes(view[:3])
            calls.append(len(chunk))
            return real_write(fd, chunk)

        try:
            tracker = rs._MutationTracker(write_supported=True)
            with mock.patch.object(rs.os, "write", partial_write):
                outcome = rs._persist_immutable_doc(
                    state_fd, "partial.json", payload, "partial", tracker
                )
            self.assertEqual(outcome, "written")
            self.assertGreater(len(calls), 1)
            with open(self.fixture.state_root + "/partial.json", "rb") as handle:
                self.assertEqual(handle.read(), payload)

            tracker = rs._MutationTracker(write_supported=True)
            with mock.patch.object(rs.os, "write", lambda _fd, _view: 0):
                with self.assertRaises(rs._StorageFailure) as caught:
                    rs._persist_immutable_doc(
                        state_fd, "zero.json", b"payload", "zero", tracker
                    )
            self.assertEqual(caught.exception.status, "outcome_unknown")
            self.assertIs(tracker.write_attempted, True)
            self.assertIs(tracker.ambiguous, True)
        finally:
            os.close(state_fd)

    def test_fsync_and_ambiguous_close_are_unknown_without_close_retry(self):
        state_fd = os.open(
            self.fixture.state_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        try:
            tracker = rs._MutationTracker(write_supported=True)
            with mock.patch.object(
                rs.os, "fsync", side_effect=OSError(errno.EIO, "fsync")
            ):
                with self.assertRaises(rs._StorageFailure) as caught:
                    rs._persist_immutable_doc(
                        state_fd, "fsync.json", b"payload", "fsync", tracker
                    )
            self.assertEqual(caught.exception.status, "outcome_unknown")
            self.assertIs(tracker.ambiguous, True)

            real_close = os.close
            closed = []

            def close_then_raise(fd):
                closed.append(fd)
                real_close(fd)
                raise OSError(errno.EIO, "ambiguous close")

            tracker = rs._MutationTracker(write_supported=True)
            with mock.patch.object(rs.os, "close", close_then_raise):
                with self.assertRaises(rs._StorageFailure) as caught:
                    rs._persist_immutable_doc(
                        state_fd, "close.json", b"payload", "close", tracker
                    )
            self.assertEqual(caught.exception.status, "outcome_unknown")
            self.assertEqual(len(closed), 1)
            self.assertIs(tracker.ambiguous, True)
        finally:
            os.close(state_fd)

    def test_o_excl_attempt_boundary_precedes_create_failures(self):
        state_fd = os.open(
            self.fixture.state_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        try:
            tracker = rs._MutationTracker(write_supported=True)
            with mock.patch.object(
                rs.os, "open", side_effect=OSError(errno.EACCES, "refused")
            ):
                with self.assertRaises(rs._StorageFailure):
                    rs._persist_immutable_doc(
                        state_fd, "refused.json", b"payload", "refused", tracker
                    )
            self.assertIs(tracker.write_attempted, True)
            self.assertIs(tracker.known_written, False)

            existing = self.fixture.state_root + "/conflict.json"
            self.fixture._write(existing, b"other", 0o600)
            tracker = rs._MutationTracker(write_supported=True)
            with self.assertRaises(rs._StorageFailure):
                rs._persist_immutable_doc(
                    state_fd, "conflict.json", b"payload", "conflict", tracker
                )
            self.assertIs(tracker.write_attempted, True)
            self.assertIs(tracker.known_written, False)

            tracker = rs._MutationTracker(write_supported=True)
            with mock.patch.object(
                rs.os,
                "open",
                side_effect=[FileNotFoundError(), FileExistsError()],
            ):
                with self.assertRaises(rs._StorageFailure):
                    rs._acquire_lock(
                        state_fd, [], exclusive=True, tracker=tracker
                    )
            self.assertIs(tracker.write_attempted, True)
            self.assertIs(tracker.known_written, False)
        finally:
            os.close(state_fd)

    def test_create_boundary_baseexception_routes_public_result_to_unknown(self):
        def boundary_failure(_state_fd, _name, _payload, _token, tracker):
            tracker.mark_attempted()
            raise SystemExit(9)

        with mock.patch.object(
            rs, "_persist_immutable_doc", boundary_failure
        ):
            result = self.fixture.finalize()
        self.assertEqual(result["status"], "outcome_unknown")
        self.assertIs(result["storage_write_attempted"], True)
        self.assertIsNone(result["storage_written"])

    def test_cross_process_lock_contention_refuses_without_swap(self):
        lock_path = self.fixture.state_root + "/" + rs.STATE_LOCK_NAME
        self.fixture._write(lock_path, b"", 0o600)
        child_code = (
            "import fcntl,os,sys\n"
            "fd=os.open(sys.argv[1],os.O_RDWR)\n"
            "fcntl.flock(fd,fcntl.LOCK_EX)\n"
            "print('ready',flush=True)\n"
            "sys.stdin.buffer.read(1)\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", child_code, lock_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertEqual(process.stdout.readline(), b"ready\n")
            swap = mock.Mock(return_value=0)
            result = self.fixture.finalize(swap)
            self.assertEqual(result["status"], "blocked")
            self.assertIs(result["storage_write_attempted"], False)
            self.assertIs(result["storage_written"], False)
            swap.assert_not_called()
        finally:
            if process.stdin is not None:
                process.stdin.write(b"x")
                process.stdin.flush()
                process.stdin.close()
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def test_empty_preimage_requires_two_stable_name_snapshots(self):
        parent_fd = os.open(
            self.fixture.authority_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        environment_fd = os.open(
            self.fixture.environment_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
        try:
            with mock.patch.object(
                rs, "_snapshot_directory_names", side_effect=[(), ("late",)]
            ):
                with self.assertRaises(rs._StorageFailure):
                    rs._empty_preimage_fingerprint(
                        environment_fd,
                        parent_fd=parent_fd,
                        visible_name="environment",
                    )
        finally:
            os.close(environment_fd)
            os.close(parent_fd)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin renameatx_np only")
    def test_real_darwin_rename_swap(self):
        environment_inode = os.stat(self.fixture.environment_root).st_ino
        operation_inode = os.stat(self.fixture.operation_root).st_ino
        result = rs.finalize_prebuilt_environment_stage(
            self.fixture.authority_root,
            self.fixture.state_root,
            self.fixture.journal_root,
            environment_request=self.fixture.request,
            layout_plan=self.fixture.layout_plan,
            stage_result=self.fixture.stage_result,
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["reason"], SUCCESS_REASONS[0])
        self.assertEqual(rs.environment_storage_result_exit_code(result), 0)
        self.assertEqual(
            os.stat(self.fixture.environment_root).st_ino, operation_inode
        )
        self.assertEqual(
            os.stat(self.fixture.operation_root).st_ino, environment_inode
        )
        self.assertEqual(os.listdir(self.fixture.operation_root), [])
        self.assertEqual(
            self.fixture._snapshot(self.fixture.sentinel_path),
            self.fixture.sentinel_before,
        )


class TestModuleAudit(unittest.TestCase):
    _SOURCE_PATH = os.path.join(
        _REPO, "scripts", "release_environment_storage.py"
    )

    def _tree(self):
        with open(self._SOURCE_PATH, "r", encoding="ascii") as handle:
            return ast.parse(handle.read())

    def test_import_allowlist(self):
        allowed = {
            "__future__", "errno", "hashlib", "json", "os", "re", "stat",
            "sys", "typing", "ctypes", "fcntl",
        }
        for node in ast.walk(self._tree()):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    with self.subTest(module=alias.name):
                        self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]
                if module == "scripts":
                    names = {alias.name for alias in node.names}
                    self.assertTrue(
                        names <= {"installed_layout", "release_environment"},
                        names,
                    )
                else:
                    with self.subTest(module=module):
                        self.assertIn(module, allowed)

    def test_no_forbidden_modules_or_cli_wiring(self):
        forbidden = {
            "subprocess", "socket", "sqlite3", "importlib", "argparse",
            "shlex", "http", "urllib", "shutil", "tempfile", "threading",
            "multiprocessing",
        }
        tree = self._tree()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name.split(".")[0], forbidden)
            elif isinstance(node, ast.ImportFrom):
                self.assertNotIn(
                    (node.module or "").split(".")[0], forbidden
                )
        for node in tree.body:
            if isinstance(node, ast.If):
                rendered = ast.dump(node.test)
                self.assertNotIn("__main__", rendered)
        with open(self._SOURCE_PATH, "r", encoding="ascii") as handle:
            source = handle.read()
        self.assertNotIn("__main__", source)
        self.assertNotIn("argparse", source)

    def test_public_api_names_exact(self):
        tree = self._tree()
        public_functions = {
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and not node.name.startswith("_")
        }
        self.assertEqual(
            public_functions,
            {
                "environment_storage_contract_projection",
                "render_environment_storage_result",
                "environment_storage_result_exit_code",
                "finalize_prebuilt_environment_stage",
                "inspect_prebuilt_environment_stage",
            },
        )
        public_classes = {
            node.name
            for node in tree.body
            if isinstance(node, ast.ClassDef) and not node.name.startswith("_")
        }
        self.assertEqual(public_classes, set())
        for name in (
            "environment_storage_contract_projection",
            "render_environment_storage_result",
            "environment_storage_result_exit_code",
            "finalize_prebuilt_environment_stage",
            "inspect_prebuilt_environment_stage",
        ):
            self.assertTrue(callable(getattr(rs, name)), name)

if __name__ == "__main__":
    unittest.main()

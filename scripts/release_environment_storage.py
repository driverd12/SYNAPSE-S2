"""Dormant owner-only storage/finalization contract for a PREBUILT inactive
release environment tree (Phase 5B1 slice).

This module NEVER builds, imports or executes candidate code, probes the
candidate, authenticates evidence, activates, issues a Phase5A receipt, or
completes Blocker 5. It does execute only the exact hash-pinned, audited pure
Phase5A and installed-layout contract source bytes in fresh private namespaces
to bind their planner semantics. It has no CLI or runtime wiring. It only
validates and publishes an already prepared inactive environment tree under an
owner-private authority root.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Frozen external identities (must never drift).
# ---------------------------------------------------------------------------

PHASE5A_SOURCE_SHA256 = (
    "42da38a8710ebdeaaabf11741859f4822a943df3d6b9d8deff2236fa64672308"
)
PHASE5A_CONTRACT_ID = (
    "environment-contract-"
    "fec40398c01456d33b1bf5980b737987d1825fea8194d102af7d0afd939cfe3e"
)
ACTIVATION_JOURNAL_SOURCE_SHA256 = (
    "36f8b4befcf2783608be4e3c95911ead8176bfab35b8bcf9593301f8e0bcc3df"
)
INSTALLED_LAYOUT_SOURCE_SHA256 = (
    "7c4e3069f225488a76f261b1e2fff37bb5ad163aef731364ac86f433d138ba12"
)
MAX_SIBLING_SOURCE_BYTES = 2_000_000
SIBLING_SOURCE_MODE = 0o644

# ---------------------------------------------------------------------------
# Schemas and hash domains.
# ---------------------------------------------------------------------------

STORAGE_CONTRACT_SCHEMA = "synapse-s2.release-environment-storage-contract.v1"
STORAGE_REQUEST_RECORD_SCHEMA = "synapse-s2.release-environment-storage-request.v1"
TREE_MANIFEST_SCHEMA = "synapse-s2.release-environment-tree-manifest.v1"
STORAGE_PREPARE_SCHEMA = "synapse-s2.release-environment-storage-prepare.v1"
STORAGE_RESULT_SCHEMA = "synapse-s2.release-environment-storage-result.v1"
STORAGE_RENDER_SCHEMA = "synapse-s2.release-environment-storage-render.v1"

CONTRACT_DOMAIN = "SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-CONTRACT\0v1\0"
REQUEST_DOMAIN = "SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-REQUEST\0v1\0"
TREE_MANIFEST_DOMAIN = "SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-TREE-MANIFEST\0v1\0"
PREPARE_DOMAIN = "SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-PREPARE\0v1\0"
RESULT_DOMAIN = "SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-RESULT\0v1\0"

OPERATIONS_DIR_NAME = ".release-environment-operations-v1"
STATE_REQUEST_DOC_NAME = "storage-request-record-v1.json"
STATE_MANIFEST_DOC_NAME = "storage-tree-manifest-v1.json"
STATE_PREPARE_DOC_NAME = "storage-prepare-record-v1.json"
STATE_LOCK_NAME = "storage-finalize-v1.lock"
STATE_ROOT_PREFIX = "release-environment-storage-v1-"

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# Bounds.
MAX_DOC_BYTES = 1_000_000
MAX_PATH_LENGTH = 3500
MAX_NAME_LENGTH = 200
MAX_TREE_ENTRIES = 20_000
MAX_TREE_TOTAL_BYTES = 6 * 1024 * 1024 * 1024
MAX_TREE_FILE_BYTES = 1024 * 1024 * 1024
MAX_TREE_DEPTH = 24
MAX_ROOT_DEPTH = 48
MAX_JOURNAL_LINE_BYTES = 200_000
MAX_DOCUMENT_DEPTH = 6
MAX_DOCUMENT_ITEMS = 512
MAX_DOCUMENT_STRING_CHARACTERS = MAX_PATH_LENGTH

_ENTRY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
# A prebuilt Python environment legitimately contains leading-underscore
# entries such as __init__.py and __pycache__. Keep external authority/state
# basenames on the stricter grammar above while admitting that exact extra
# prefix class only inside the fully descriptor-confined tree scanner.
_TREE_ENTRY_NAME_RE = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}$"
)
_PRODUCT_ID_RE = re.compile(r"\Aproduct-[0-9a-f]{64}\Z")
_POLICY_ID_RE = re.compile(r"\Ainventory-policy-[0-9a-f]{64}\Z")
_LAYOUT_ID_RE = re.compile(r"\Alayout-[0-9a-f]{64}\Z")

REQUIRED_PLATFORM = "darwin"
REQUIRED_OS_NAME = "posix"

# ---------------------------------------------------------------------------
# Frozen sibling identities (installed layout / stage result / stage journal).
# ---------------------------------------------------------------------------

LAYOUT_PLAN_SCHEMA = "synapse-s2.installed-layout-plan.v1"
LAYOUT_PLAN_MODE = "inactive-versioned-v1"
LAYOUT_PLAN_STATUS = "planned"
LAYOUT_PLAN_REASON = "planned:inactive-versioned-layout-bound"
LAYOUT_CONTRACT_ID = (
    "layout-contract-"
    "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
)
LAYOUT_ID_DOMAIN = "SYNAPSE-S2\0INSTALLED-LAYOUT-PLAN\0v1\0"
LAYOUT_ACTIVATION_ELIGIBILITY = "requires-future-governed-activation"
LAYOUT_REQUIREMENTS = ("clean-incumbent-source-snapshot",)
LAYOUT_STAGE_ASSOCIATION = "shape-only-untrusted"
LAYOUT_RELEASES_DIRECTORY = "releases"

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

# Adapter table: (adapter name, root kind, path relative to that root).
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

LAYOUT_ID_BINDING_KEYS = (
    "schema", "mode", "layout_contract_id", "product_id",
    "inventory_policy_id", "install_root", "code_root", "environment_root",
    "data_root", "release_root", "updater_state_root", "legacy_checkout_root",
    "adapters",
)

STAGE_RESULT_SCHEMA_V1 = "synapse-s2.release-stage-result.v1"
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

# (status, reason, resumed) tuples permitted for an accepted stage result.
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
STAGE_JOURNAL_DOMAIN = "SYNAPSE-S2\0RELEASE-STAGE-JOURNAL\0v1\0"
STAGE_JOURNAL_FILE_NAME = "release-stage.jsonl"
STAGE_JOURNAL_GENESIS_HASH = "0" * 64
STAGE_JOURNAL_STATES = ("staged", "reconciled")
STAGE_JOURNAL_KEYS = (
    "schema", "sequence", "previous_hash", "product_id",
    "inventory_policy_id", "release_state", "entry_hash",
)
MAX_STAGE_JOURNAL_BYTES = 4 * 1024 * 1024
MAX_STAGE_JOURNAL_ENTRIES = 4096

# Exact frozen Phase-5A request/binding keysets (copied literally from the
# pinned release_environment.py; drift is refused at validation time).
PHASE5A_BINDING_KEYS = (
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

PHASE5A_REQUEST_KEYS = (
    "schema",
    "mode",
    "profile",
    "profile_version",
    "environment_contract_id",
    "activation_contract_id",
    "compatibility_profile_version",
) + PHASE5A_BINDING_KEYS

# Exact keysets for every persisted/derived document shape.
TREE_MANIFEST_KEYS = (
    "schema", "storage_contract_id", "request_sha256", "operation_id",
    "product_id", "inventory_policy_id", "entry_count", "total_bytes",
    "entries",
)
TREE_ENTRY_KEYS = ("path", "kind", "mode", "size", "sha256")
FINGERPRINT_KEYS = ("device", "inode", "mode", "nlink")
FULL_STAT_FINGERPRINT_KEYS = (
    "device", "inode", "uid", "mode", "nlink", "size", "mtime_ns",
    "ctime_ns",
)

MAX_CONTRACT_PROJECTION_BYTES = 65536

# Darwin atomic-swap publication seam.
LIBSYSTEM_PATH = "/usr/lib/libSystem.B.dylib"
RENAMEATX_NP_SYMBOL = "renameatx_np"
RENAME_SWAP_FLAG = 0x00000002
OPERATION_PREFIX = "operation-"
PRIVATE_DIRECTORY_MODE = 0o700
STATE_FILE_MODE = 0o600
TREE_REGULAR_FILE_MODE = 0o600
TREE_PYTHON_FILE_MODE = 0o700
SPECIAL_MODE_BITS = 0o7000
PREIMAGE_DIR_MODE = PRIVATE_DIRECTORY_MODE
PREIMAGE_NLINK = 2
RESULT_REASON_MIN_CHARACTERS = 1
RESULT_REASON_MAX_CHARACTERS = 300

COMMAND_FINALIZE = "finalize-prebuilt-environment-stage"
COMMAND_INSPECT = "inspect-prebuilt-environment-stage"

STATUS_SUCCESS = "success"
STATUS_UNSUPPORTED = "unsupported"
STATUS_BLOCKED = "blocked"
STATUS_OUTCOME_UNKNOWN = "outcome_unknown"

_EXIT_CODES = {
    STATUS_SUCCESS: 0,
    STATUS_UNSUPPORTED: 2,
    STATUS_BLOCKED: 3,
    STATUS_OUTCOME_UNKNOWN: 4,
}

SUCCESS_REASONS = (
    "tree_published:prebuilt-environment-published",
    "tree_published:prebuilt-environment-already-present",
    "tree_published:prebuilt-environment-publication-reconciled",
    "inspected:prebuilt-environment-tree-consistent",
)

_RESULT_FLAG_KEYS = (
    "storage_read_supported",
    "storage_write_supported",
    "storage_read_performed",
    "storage_write_attempted",
    "storage_written",
    "stage_authority_verified",
    "stage_correlation_verified",
    "filesystem_verified",
    "access_verified",
    "environment_tree_verified",
    "environment_tree_published",
    "reconciled",
    "dependency_proof_verified",
    "model_proof_verified",
    "candidate_execution_verified",
    "build_verified",
    "evidence_verified",
    "receipt_published",
    "blocker_5_complete",
    "activation_performed",
    "apply_performed",
    "live_state_accessed",
    "live_state_modified",
    "service_modified",
    "config_modified",
    "selector_modified",
    "floor_modified",
    "activation_journal_written",
)

# Flags that may ever be true on success; everything else must stay false.
_SUCCESS_TRUE_ALLOWED = frozenset(
    {
        "storage_read_supported",
        "storage_write_supported",
        "storage_read_performed",
        "storage_write_attempted",
        "storage_written",
        "stage_correlation_verified",
        "filesystem_verified",
        "access_verified",
        "environment_tree_verified",
        "environment_tree_published",
        "reconciled",
    }
)

NONCLAIMS = (
    "no-dependency-proof",
    "no-import-proof",
    "no-native-extension-proof",
    "no-model-proof",
    "no-candidate-execution",
    "no-builder-or-provenance-authority",
    "no-phase5a-observation-or-receipt",
    "no-blocker5-completion",
    "no-profile-3-ticket-or-result-verification",
    "no-live-state-access",
    "no-recovery-state-access",
    "no-service-modification",
    "no-config-modification",
    "no-selector-modification",
    "no-floor-modification",
    "no-activation-journal-write",
    "no-network-access",
    "no-credential-access",
    "no-activation",
    "no-apply",
    "no-post-return-immutability-guarantee",
    "no-acl-or-xattr-authority",
    "no-hardware-durability-guarantee",
    "no-orphan-cleanup-guarantee",
    "no-preimage-reclamation",
    "no-stage-authority",
    "no-release-tree-verification",
    "no-stage-invocation-root-binding",
    "no-result-authentication",
    "no-malicious-same-uid-authenticity",
    "no-hostile-interpreter-or-in-process-runtime-authenticity",
    "final-lock-and-fd-cleanup-best-effort-only",
)

# ---------------------------------------------------------------------------
# Exact self-hashed result contract.
# ---------------------------------------------------------------------------

STORAGE_DIGEST_DOMAIN = "SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-DIGEST\0v1\0"
MAX_RESULT_BYTES = 8192

RESULT_DIGEST_KEYS = (
    "request_sha256",
    "manifest_sha256",
    "prepare_sha256",
    "storage_digest",
)

RESULT_IDENTITY_KEYS = (
    "operation_id",
    "layout_plan_id",
    "product_id",
    "policy_id",
)

RESULT_KEYS = (
    ("schema", "command", "status", "reason", "storage_contract_id")
    + RESULT_DIGEST_KEYS
    + RESULT_IDENTITY_KEYS
    + _RESULT_FLAG_KEYS
    + ("nonclaims", "result_sha256")
)

# Bounded render contract: one canonical JSON line, no nonclaims, no raw
# (unvalidated) values, hard byte cap, fixed fallback line.
MAX_RENDER_BYTES = 4096

RENDER_KEYS = (
    ("schema", "result_schema", "command", "status", "reason",
     "storage_contract_id")
    + RESULT_DIGEST_KEYS
    + RESULT_IDENTITY_KEYS
    + _RESULT_FLAG_KEYS
    + ("result_sha256",)
)

RENDER_FALLBACK_KEYS = ("schema", "status", "reason")
RENDER_FALLBACK_REASON = "blocked:result-not-renderable"
RENDER_FALLBACK_LINE = (
    '{"reason":"blocked:result-not-renderable",'
    '"schema":"synapse-s2.release-environment-storage-render.v1",'
    '"status":"blocked"}'
)

_STORAGE_FACT_KEYS = (
    "storage_read_supported",
    "storage_write_supported",
    "storage_read_performed",
    "storage_write_attempted",
    "storage_written",
)

_SUCCESS_VERIFIED_TRUE_KEYS = (
    "stage_correlation_verified",
    "filesystem_verified",
    "access_verified",
    "environment_tree_verified",
    "environment_tree_published",
)

# Exact success storage-fact rows keyed by (command, reason):
# (read_supported, write_supported, read_performed,
#  write_attempted, storage_written, reconciled)
_SUCCESS_ROWS = {
    (COMMAND_FINALIZE, SUCCESS_REASONS[0]): (True, True, True, True, True, False),
    (COMMAND_FINALIZE, SUCCESS_REASONS[1]): (True, True, True, False, False, False),
    (COMMAND_FINALIZE, SUCCESS_REASONS[2]): (True, True, True, True, True, True),
    (COMMAND_INSPECT, SUCCESS_REASONS[3]): (True, False, True, False, False, False),
}

_UNSUPPORTED_READ_REASONS = frozenset(
    {
        "unsupported:platform-not-darwin",
        "unsupported:missing-nofollow-directory-open",
        "unsupported:missing-os-callable",
        "unsupported:missing-flock",
        "unsupported:platform-gate-error",
    }
)
_UNSUPPORTED_WRITE_REASONS = _UNSUPPORTED_READ_REASONS | frozenset(
    {
        "unsupported:missing-write-open-flags",
        "unsupported:missing-renameatx-np-swap-capability",
    }
)
UNSUPPORTED_REASONS = {
    COMMAND_FINALIZE: _UNSUPPORTED_WRITE_REASONS,
    COMMAND_INSPECT: _UNSUPPORTED_READ_REASONS,
}

BLOCKED_FINALIZE_REASON = "blocked:environment-storage-finalization-refused"
BLOCKED_INSPECT_REASON = "blocked:environment-storage-inspection-refused"
BLOCKED_REASONS = {
    COMMAND_FINALIZE: BLOCKED_FINALIZE_REASON,
    COMMAND_INSPECT: BLOCKED_INSPECT_REASON,
}
UNKNOWN_FINALIZE_REASON = (
    "outcome_unknown:environment-storage-finalization-ambiguous"
)

_FORBIDDEN_PATH_SEGMENTS = frozenset(
    {
        ".synapse_s2",
        "current",
        "latest",
        "recovery",
        "live",
    }
)
_FORBIDDEN_PATH_PREFIXES = (
    "/System/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/etc/",
    "/var/",
    "/private/etc/",
    "/private/var/",
    "/Library/",
    "/dev/",
)


class _StorageFailure(Exception):
    """Internal control-flow failure carrying a closed status/reason."""

    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


class _MutationTracker:
    """Exact per-invocation mutation-truth record (attempted/written/ambiguity).

    Marks are sticky: a later deterministic blocked/conflict never erases an
    earlier known attempt or known write."""

    def __init__(self, *, write_supported: bool) -> None:
        self.write_supported = write_supported
        self.read_performed = False
        self.write_attempted = False
        self.known_written = False
        self.ambiguous = False

    def mark_read(self) -> None:
        self.read_performed = True

    def mark_attempted(self) -> None:
        self.write_attempted = True

    def mark_written(self) -> None:
        self.write_attempted = True
        self.known_written = True

    def mark_ambiguous(self) -> None:
        self.write_attempted = True
        self.ambiguous = True

    def failure_flags(self, status: str) -> dict[str, Any]:
        if status == STATUS_OUTCOME_UNKNOWN:
            # Ambiguity always implies a supported, attempted write whose
            # outcome is unknowable; the exact contract row is T/T/T/T/None.
            return {
                "storage_read_supported": True,
                "storage_write_supported": True,
                "storage_read_performed": True,
                "storage_write_attempted": True,
                "storage_written": None,
            }
        return {
            "storage_read_supported": True,
            "storage_write_supported": self.write_supported,
            "storage_read_performed": self.read_performed,
            "storage_write_attempted": self.write_attempted,
            "storage_written": self.known_written,
        }


# ---------------------------------------------------------------------------
# Canonical JSON.
# ---------------------------------------------------------------------------


def _canonical_json_bytes(document: Any) -> bytes:
    text = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return text.encode("ascii")


def _domain_sha256(domain: str, document: Any) -> str:
    payload = domain.encode("ascii") + _canonical_json_bytes(document)
    return hashlib.sha256(payload).hexdigest()


def _raw_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Contract projection.
# ---------------------------------------------------------------------------


def environment_storage_contract_projection() -> dict[str, Any]:
    body = {
        "schema": STORAGE_CONTRACT_SCHEMA,
        "schemas": {
            "contract": STORAGE_CONTRACT_SCHEMA,
            "request": STORAGE_REQUEST_RECORD_SCHEMA,
            "tree_manifest": TREE_MANIFEST_SCHEMA,
            "prepare": STORAGE_PREPARE_SCHEMA,
            "result": STORAGE_RESULT_SCHEMA,
            "render": STORAGE_RENDER_SCHEMA,
            "phase5a_request": "synapse-s2.release-environment-request.v1",
            "layout_plan": LAYOUT_PLAN_SCHEMA,
            "stage_result": STAGE_RESULT_SCHEMA_V1,
            "stage_journal_entry": STAGE_JOURNAL_SCHEMA,
        },
        "domains": {
            "contract": CONTRACT_DOMAIN,
            "request": REQUEST_DOMAIN,
            "tree_manifest": TREE_MANIFEST_DOMAIN,
            "prepare": PREPARE_DOMAIN,
            "result": RESULT_DOMAIN,
            "storage_digest": STORAGE_DIGEST_DOMAIN,
            "stage_journal": STAGE_JOURNAL_DOMAIN,
            "layout_id": LAYOUT_ID_DOMAIN,
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
        },
        "hash_bindings": {
            "contract_id": {
                "domain": "contract",
                "prefix": "environment-storage-contract-",
                "preimage": "canonical-contract-body",
                "excluded_fields": ["contract_id"],
            },
            "phase5a_request_sha256": {
                "producer": "release_environment.plan_environment_request",
                "replay": (
                    "rebuild-from-bindings-and-require-canonical-byte-"
                    "equality-with-caller-request"
                ),
                "digest_source": "phase5a-plan-result-request_sha256",
            },
            "request_record_sha256": {
                "domain": "request",
                "preimage": "canonical-request-record",
                "excluded_fields": ["request_record_sha256"],
            },
            "manifest_sha256": {
                "domain": "tree_manifest",
                "preimage": "canonical-complete-tree-manifest",
            },
            "prepare_sha256": {
                "domain": "prepare",
                "preimage": "canonical-prepare-record",
                "excluded_fields": ["prepare_sha256"],
            },
            "result_sha256": {
                "domain": "result",
                "preimage": "canonical-result",
                "excluded_fields": ["result_sha256"],
            },
            "storage_digest": {
                "preimage": (
                    "raw-ascii-concatenation:storage-digest-domain+"
                    "request_sha256+manifest_sha256+prepare_sha256"
                ),
                "output": "sha256-hex",
            },
            "layout_plan_sha256": "raw-sha256-of-canonical-layout-plan-bytes",
            "stage_result_sha256": (
                "raw-sha256-of-canonical-stage-result-bytes"
            ),
            "stage_journal_entry_hash": {
                "domain": "stage_journal",
                "preimage": "canonical-entry",
                "excluded_fields": ["entry_hash"],
            },
        },
        "frozen_external_identities": {
            "phase5a_source_sha256": PHASE5A_SOURCE_SHA256,
            "phase5a_source_basename": "release_environment.py",
            "phase5a_contract_id": PHASE5A_CONTRACT_ID,
            "installed_layout_source_sha256": (
                INSTALLED_LAYOUT_SOURCE_SHA256
            ),
            "installed_layout_source_basename": "installed_layout.py",
            "activation_journal_source_sha256": (
                ACTIVATION_JOURNAL_SOURCE_SHA256
            ),
            "activation_journal_source_read_here": False,
            "max_sibling_source_bytes": MAX_SIBLING_SOURCE_BYTES,
            "sibling_source_mode": format(SIBLING_SOURCE_MODE, "04o"),
            "verification_scope": (
                "finalize-and-inspect-after-platform-preflight-before-"
                "caller-document-replay"
            ),
            "execution": (
                "both-files-fully-verified-before-either-is-compiled;"
                "compile-and-exec-the-same-hashed-bytes-in-fresh-"
                "unregistered-non-main-private-namespaces"
            ),
            "candidate_tree_execution": False,
        },
        "platform_requirements": {
            "platform": REQUIRED_PLATFORM,
            "os_name": REQUIRED_OS_NAME,
            "requires_o_nofollow": True,
            "requires_flock": True,
        },
        "capabilities": {
            "read_os_flags": list(_READ_OS_FLAGS),
            "read_os_callables": list(_READ_OS_CALLABLES),
            "inspect_fcntl_lock_flags": list(_FCNTL_READ_LOCK_FLAGS),
            "finalize_fcntl_lock_flags": list(_FCNTL_WRITE_LOCK_FLAGS),
            "write_os_flags": list(_WRITE_OS_FLAGS),
            "write_os_callables": list(_WRITE_OS_CALLABLES),
            "write_ctypes_symbol": RENAMEATX_NP_SYMBOL,
            "commands": {
                COMMAND_FINALIZE: "read-and-write-capabilities-required",
                COMMAND_INSPECT: "read-capabilities-only",
            },
        },
        "state": {
            "operations_dir_name": OPERATIONS_DIR_NAME,
            "operation_prefix": OPERATION_PREFIX,
            "request_record_doc": STATE_REQUEST_DOC_NAME,
            "tree_manifest_doc": STATE_MANIFEST_DOC_NAME,
            "prepare_record_doc": STATE_PREPARE_DOC_NAME,
            "lock_name": STATE_LOCK_NAME,
            "state_root_prefix": STATE_ROOT_PREFIX,
            "root_dir_mode": format(PRIVATE_DIRECTORY_MODE, "04o"),
            "doc_mode": format(STATE_FILE_MODE, "04o"),
            "request_record_keys": list(STORAGE_REQUEST_RECORD_KEYS),
            "prepare_record_keys": list(STORAGE_PREPARE_RECORD_KEYS),
            "tree_manifest_keys": list(TREE_MANIFEST_KEYS),
            "tree_entry_keys": list(TREE_ENTRY_KEYS),
            "fingerprint_keys": list(FINGERPRINT_KEYS),
            "full_stat_fingerprint_keys": list(FULL_STAT_FINGERPRINT_KEYS),
            "allowed_directory_names": [
                STATE_LOCK_NAME,
                STATE_REQUEST_DOC_NAME,
                STATE_MANIFEST_DOC_NAME,
                STATE_PREPARE_DOC_NAME,
            ],
            "document_policy": {
                "type": "regular-file",
                "owner": "euid",
                "mode": format(STATE_FILE_MODE, "04o"),
                "nlink": 1,
                "creation": "o-excl-or-exact-byte-equal-reconcile",
                "write_attempt_boundary": "before-o-creat-o-excl-open",
                "durability": (
                    "file-fsync-plus-directory-fsync-plus-same-inode-"
                    "exact-byte-reread"
                ),
                "ambiguous_write": STATUS_OUTCOME_UNKNOWN,
            },
            "lock_policy": {
                "type": "regular-file",
                "owner": "euid",
                "mode": format(STATE_FILE_MODE, "04o"),
                "nlink": 1,
                "finalize": "exclusive-nonblocking",
                "inspect": "shared-nonblocking",
                "visible-held-reproof": True,
                "write_attempt_boundary": "before-o-creat-o-excl-open",
            },
            "observed_fingerprint_binding": (
                "environment-preimage-and-operation-fingerprints-are-"
                "observed-during-this-call-and-are-not-phase5a-request-fields"
            ),
        },
        "bounds": {
            "max_doc_bytes": MAX_DOC_BYTES,
            "max_path_length": MAX_PATH_LENGTH,
            "max_name_length": MAX_NAME_LENGTH,
            "max_tree_entries": MAX_TREE_ENTRIES,
            "max_tree_total_bytes": MAX_TREE_TOTAL_BYTES,
            "max_tree_file_bytes": MAX_TREE_FILE_BYTES,
            "max_tree_depth": MAX_TREE_DEPTH,
            "max_root_depth": MAX_ROOT_DEPTH,
            "max_journal_line_bytes": MAX_JOURNAL_LINE_BYTES,
            "max_stage_journal_bytes": MAX_STAGE_JOURNAL_BYTES,
            "max_stage_journal_entries": MAX_STAGE_JOURNAL_ENTRIES,
            "max_document_depth": MAX_DOCUMENT_DEPTH,
            "max_document_items": MAX_DOCUMENT_ITEMS,
            "max_document_string_characters": (
                MAX_DOCUMENT_STRING_CHARACTERS
            ),
            "max_result_bytes": MAX_RESULT_BYTES,
            "max_render_bytes": MAX_RENDER_BYTES,
            "max_contract_projection_bytes": MAX_CONTRACT_PROJECTION_BYTES,
        },
        "phase5a_request": {
            "request_keys": list(PHASE5A_REQUEST_KEYS),
            "request_key_count": len(PHASE5A_REQUEST_KEYS),
            "binding_keys": list(PHASE5A_BINDING_KEYS),
            "binding_key_count": len(PHASE5A_BINDING_KEYS),
            "sibling_keyset_equality_required": True,
        },
        "roots": {
            "authority_root": "must-equal-environment-root-parent",
            "journal_root": "must-equal-layout-plan-updater-state-root",
            "state_root_derivation": (
                "journal-root/" + STATE_ROOT_PREFIX + "<request_sha256>"
            ),
            "state_child_open": (
                "single-basename-relative-to-held-journal-root-only"
            ),
            "required_containments": [
                "authority-root-direct-parent-of-environment-root",
                "authority-root-direct-parent-of-operations-directory",
                "journal-root-direct-parent-of-derived-state-root",
            ],
            "casefold_disjointness": (
                "every-independent-root-pair-disjoint-after-exempting-"
                "the-three-required-parent-child-relations"
            ),
            "forbidden_path_segments": sorted(_FORBIDDEN_PATH_SEGMENTS),
            "forbidden_path_prefixes": list(_FORBIDDEN_PATH_PREFIXES),
            "same_device_scope": [
                "environment-parent", "operations-directory",
                "environment-root", "operation-tree",
            ],
            "descriptor_rules": (
                "segment-by-segment-nofollow-directory-opens-descriptor-"
                "confined-io-only"
            ),
            "reproof_rules": (
                "held-descriptor-full-fingerprint-plus-parent-visible-"
                "nofollow-identity-reproved-before-every-success"
            ),
            "path_grammar": {
                "ascii_only": True,
                "min_characters": 2,
                "max_characters": MAX_PATH_LENGTH,
                "absolute": True,
                "no_trailing_slash": True,
                "no_double_slash": True,
                "no_dot_segments": True,
                "max_components": MAX_ROOT_DEPTH,
                "max_component_characters": MAX_NAME_LENGTH,
            },
            "allowed_overlap": [
                "authority-root-parent-of-environment-root",
                "authority-root-parent-of-operations-directory",
                "journal-root-parent-of-derived-state-root",
            ],
        },
        "scanner": {
            "allowed_kinds": ["directory", "file"],
            "directory_mode": format(PRIVATE_DIRECTORY_MODE, "04o"),
            "file_mode": format(TREE_REGULAR_FILE_MODE, "04o"),
            "file_mode_exceptions": {
                "bin/python": format(TREE_PYTHON_FILE_MODE, "04o")
            },
            "file_nlink": 1,
            "no_symlink": True,
            "no_hardlink": True,
            "no_special_files": True,
            "no_special_mode_bits": True,
            "casefold_duplicate_rejected": True,
            "full_stat_fields": list(FULL_STAT_FINGERPRINT_KEYS),
            "directory_entry_semantics": {"size": 0, "sha256": ""},
            "file_digest": "raw-sha256",
            "name_snapshot_order": "sorted",
            "adapter_presence_required": ["bin", "bin/python"],
        },
        "layout_plan": {
            "schema": LAYOUT_PLAN_SCHEMA, "mode": LAYOUT_PLAN_MODE,
            "status": LAYOUT_PLAN_STATUS, "reason": LAYOUT_PLAN_REASON,
            "layout_contract_id": LAYOUT_CONTRACT_ID,
            "layout_id_domain": LAYOUT_ID_DOMAIN,
            "layout_id_binding_keys": list(LAYOUT_ID_BINDING_KEYS),
            "keys": list(LAYOUT_PLAN_KEYS),
            "false_flags": list(LAYOUT_PLAN_FALSE_FLAGS),
            "activation_eligibility": LAYOUT_ACTIVATION_ELIGIBILITY,
            "requirements": list(LAYOUT_REQUIREMENTS),
            "stage_association": LAYOUT_STAGE_ASSOCIATION,
            "releases_directory": LAYOUT_RELEASES_DIRECTORY,
            "adapter_table": [list(row) for row in LAYOUT_ADAPTER_TABLE],
            "nonclaims": list(LAYOUT_PLAN_NONCLAIMS),
        },
        "stage_result": {
            "schema": STAGE_RESULT_SCHEMA_V1, "mode": STAGE_RESULT_MODE,
            "keys": list(STAGE_RESULT_KEYS),
            "true_proofs": list(STAGE_RESULT_TRUE_PROOFS),
            "false_flags": list(STAGE_RESULT_FALSE_FLAGS),
            "accepted": [list(row) for row in STAGE_RESULT_ACCEPTED],
            "hash_binding": "raw-sha256-of-canonical-result-bytes",
            "nonclaims": list(STAGE_RESULT_NONCLAIMS),
        },
        "stage_journal": {
            "schema": STAGE_JOURNAL_SCHEMA, "domain": STAGE_JOURNAL_DOMAIN,
            "file_name": STAGE_JOURNAL_FILE_NAME,
            "keys": list(STAGE_JOURNAL_KEYS),
            "states": list(STAGE_JOURNAL_STATES),
            "genesis_previous_hash": STAGE_JOURNAL_GENESIS_HASH,
            "max_bytes": MAX_STAGE_JOURNAL_BYTES,
            "max_entries": MAX_STAGE_JOURNAL_ENTRIES,
            "full_chain_verified": True,
            "head_binding": (
                "request-stage-journal-head-sha256-must-match-some-chain-"
                "entry-hash-possibly-a-historical-matching-prefix"
            ),
            "authority": "integrity-and-correlation-only-never-authority",
        },
        "publication": {
            "mechanism": "renameatx_np-rename-swap-exchange",
            "libc_path": LIBSYSTEM_PATH, "libc_symbol": RENAMEATX_NP_SYMBOL,
            "rename_swap_flag": RENAME_SWAP_FLAG,
            "descriptor_relative_only": True, "no_two_rename_fallback": True,
            "no_shell_or_subprocess": True,
            "operation_prefix": OPERATION_PREFIX,
            "operations_dir_name": OPERATIONS_DIR_NAME,
            "preimage": {
                "must_preexist": True, "must_be_empty": True,
                "owner": "euid", "mode": "0700", "nlink": PREIMAGE_NLINK,
                "retained_after_swap": True, "never_reclaimed": True,
            },
            "same_device_required": True,
            "branches": {
                "fresh": (
                    "empty-environment-preimage:scan-operation-tree,"
                    "persist-immutable-state-docs,rescan-byte-equal,swap,"
                    "post-swap-reproof,reason=" + SUCCESS_REASONS[0]
                ),
                "reconciled": (
                    "fresh-branch-with-all-docs-preexisting-and-lock-"
                    "preexisting,reason=" + SUCCESS_REASONS[2]
                ),
                "already_published": (
                    "successful-non-empty-environment-root-outcome-is-"
                    "strictly-read-only;lock-must-preexist,all-docs-must-"
                    "match,reason="
                    + SUCCESS_REASONS[1]
                ),
                "inspect": (
                    "shared-lock-read-only-consistency-proof,reason="
                    + SUCCESS_REASONS[3]
                ),
                "ambiguity": (
                    "any-ambiguous-write-outcome-is-finalize-only-"
                    "outcome_unknown-with-fixed-reason"
                ),
                "retained_preimage": (
                    "post-swap-held-preimage-descriptor-must-sit-at-the-"
                    "operation-path-empty-0700-nlink2-never-reclaimed"
                ),
                "pre_swap_boundary": (
                    "reprove-all-visible-swap-operands,empty-preimage,"
                    "complete-operation-manifest,state-docs,journal,and-lock-"
                    "immediately-before-one-swap-call"
                ),
                "final_success_boundary": (
                    "content-proofs-bracketed-by-held-and-visible-identity-"
                    "reproofs-followed-by-second-root-lock-state-doc-and-"
                    "journal-reproof"
                ),
            },
        },
        "regex": {
            "sha256_hex": {
                "pattern": _SHA256_HEX_RE.pattern,
                "flags": int(_SHA256_HEX_RE.flags),
            },
            "entry_name": {
                "pattern": _ENTRY_NAME_RE.pattern,
                "flags": int(_ENTRY_NAME_RE.flags),
            },
            "tree_entry_name": {
                "pattern": _TREE_ENTRY_NAME_RE.pattern,
                "flags": int(_TREE_ENTRY_NAME_RE.flags),
            },
            "product_id": {
                "pattern": _PRODUCT_ID_RE.pattern,
                "flags": int(_PRODUCT_ID_RE.flags),
            },
            "inventory_policy_id": {
                "pattern": _POLICY_ID_RE.pattern,
                "flags": int(_POLICY_ID_RE.flags),
            },
            "layout_id": {
                "pattern": _LAYOUT_ID_RE.pattern,
                "flags": int(_LAYOUT_ID_RE.flags),
            },
        },
        "result_contract": {
            "keys": list(RESULT_KEYS),
            "digest_keys": list(RESULT_DIGEST_KEYS),
            "identity_keys": list(RESULT_IDENTITY_KEYS),
            "flags": list(_RESULT_FLAG_KEYS),
            "always_false_flags": sorted(
                set(_RESULT_FLAG_KEYS) - _SUCCESS_TRUE_ALLOWED
            ),
            "success_true_allowed": sorted(_SUCCESS_TRUE_ALLOWED),
            "success_verified_true": list(_SUCCESS_VERIFIED_TRUE_KEYS),
            "storage_fact_keys": list(_STORAGE_FACT_KEYS),
            "success_reasons": list(SUCCESS_REASONS),
            "success_rows": [
                list(key) + list(_SUCCESS_ROWS[key])
                for key in sorted(_SUCCESS_ROWS)
            ],
            "success_row_columns": [
                "command", "reason", "storage_read_supported",
                "storage_write_supported", "storage_read_performed",
                "storage_write_attempted", "storage_written", "reconciled",
            ],
            "unsupported_reasons": {
                command: sorted(UNSUPPORTED_REASONS[command])
                for command in sorted(UNSUPPORTED_REASONS)
            },
            "blocked_reasons": {
                command: BLOCKED_REASONS[command]
                for command in sorted(BLOCKED_REASONS)
            },
            "unknown_reason": UNKNOWN_FINALIZE_REASON,
            "unknown_row": {
                "command": COMMAND_FINALIZE,
                "status": STATUS_OUTCOME_UNKNOWN,
                "reason": UNKNOWN_FINALIZE_REASON,
                "storage_read_supported": True,
                "storage_write_supported": True,
                "storage_read_performed": True,
                "storage_write_attempted": True,
                "storage_written": None,
                "all_non_storage_flags": False,
            },
            "failure_invariants": (
                "non-success-results-carry-null-digests-and-identities-and-"
                "every-non-storage-fact-flag-false"
            ),
            "digest_pattern": "sha256-hex",
            "operation_id_binding": "operation-prefix-plus-request-sha256",
            "result_binding_chain": {
                "request_sha256": (
                    "phase5a-request-digest-and-request-record-manifest-"
                    "prepare-record-binding"
                ),
                "manifest_sha256": (
                    "tree-manifest-domain-hash-of-complete-manifest"
                ),
                "prepare_sha256": (
                    "prepare-domain-hash-transitively-binding-"
                    "request_record_sha256"
                ),
                "operation_id": "phase5a-request-digest-derived-name",
                "layout_plan_id": "phase5a-request-layout_id-on-native-output",
                "product_id": (
                    "phase5a-request-candidate_product_id-on-native-output"
                ),
                "policy_id": (
                    "phase5a-request-inventory_policy_id-on-native-output"
                ),
                "replay_limitation": (
                    "without-persisted-documents-layout-product-policy-"
                    "identities-are-grammar-and-self-hash-only"
                ),
            },
            "self_hash": (
                "result_sha256-replayed-over-canonical-result-without-"
                "result_sha256-under-result-domain"
            ),
            "statuses": sorted(_EXIT_CODES),
            "exit_codes": {k: _EXIT_CODES[k] for k in sorted(_EXIT_CODES)},
            "render_keys": list(RENDER_KEYS),
            "render_fallback_keys": list(RENDER_FALLBACK_KEYS),
            "render_fallback_reason": RENDER_FALLBACK_REASON,
            "render_fallback_line": RENDER_FALLBACK_LINE,
            "reason_character_bounds": [
                RESULT_REASON_MIN_CHARACTERS,
                RESULT_REASON_MAX_CHARACTERS,
            ],
            "unsupported_row": [False, False, False, False, False],
            "failure_row_columns": list(_STORAGE_FACT_KEYS),
            "inspect_blocked_rows": [
                [True, False, False, False, False],
                [True, False, True, False, False],
            ],
            "finalize_blocked_rows": [
                [True, True, False, False, False],
                [True, True, True, False, False],
                [True, True, True, True, False],
                [True, True, True, True, True],
            ],
            "render_semantics": {
                "canonical_ascii": True,
                "trailing_newline": False,
                "nonclaims_omitted": True,
                "invalid_or_oversize": "fixed-fallback-and-exit-3",
            },
        },
        "result_truth": {
            "write_ambiguity_status": STATUS_OUTCOME_UNKNOWN,
            "write_ambiguity_storage_written": None,
            "platform_unsupported_precedes_caller_storage_io": True,
            "native_entrypoints_never_emit_success_without_claimed_checks": (
                True
            ),
            "replayed_result_does_not_prove_checks_occurred": True,
            "exit_zero_meaning": (
                "self-consistent-success-document-not-producer-or-"
                "filesystem-authenticity"
            ),
        },
        "projection_claims": {
            "stage_authority": False,
            "evidence_verification": False,
            "dependency_verification": False,
            "model_verification": False,
            "build_verification": False,
            "receipt_publication": False,
            "blocker_5_complete": False,
            "activation": False,
            "live_state_access": False,
        },
        "replay_scope": {
            "document_self_consistency": True,
            "filesystem_replayed": False,
            "producer_authenticated": False,
            "activation_authority": False,
        },
        "nonclaims": list(NONCLAIMS),
    }
    if len(_canonical_json_bytes(body)) > MAX_CONTRACT_PROJECTION_BYTES:
        raise _blocked("contract-projection-oversize")
    contract_id = "environment-storage-contract-" + _domain_sha256(
        CONTRACT_DOMAIN, body
    )
    projection = dict(body)
    projection["contract_id"] = contract_id
    if len(_canonical_json_bytes(projection)) > MAX_CONTRACT_PROJECTION_BYTES:
        raise _blocked("contract-projection-oversize")
    return projection


# ---------------------------------------------------------------------------
# Result construction / rendering (fail-closed).
# ---------------------------------------------------------------------------


def _default_flags() -> dict[str, Any]:
    # Every flag defaults to False, including storage_written; only an
    # outcome_unknown result may carry storage_written None.
    return {key: False for key in _RESULT_FLAG_KEYS}


def _storage_digest(
    request_sha256: str, manifest_sha256: str, prepare_sha256: str
) -> str:
    payload = (
        STORAGE_DIGEST_DOMAIN + request_sha256 + manifest_sha256 + prepare_sha256
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _build_result(
    command: str,
    status: str,
    reason: str,
    *,
    flags: dict[str, Any] | None = None,
    digests: dict[str, Any] | None = None,
    identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    merged_flags = _default_flags()
    if flags is not None:
        if type(flags) is not dict:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-build-input")
        for key, value in flags.items():
            if type(key) is not str or key not in merged_flags:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-build-input"
                )
            merged_flags[key] = value
    if digests is not None:
        if type(digests) is not dict:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-build-input")
        for key in digests:
            if type(key) is not str or key not in RESULT_DIGEST_KEYS:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-build-input"
                )
    if identity is not None:
        if type(identity) is not dict:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-build-input")
        for key in identity:
            if type(key) is not str or key not in RESULT_IDENTITY_KEYS:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-build-input"
                )
    result: dict[str, Any] = {
        "schema": STORAGE_RESULT_SCHEMA,
        "command": command,
        "status": status,
        "reason": reason,
        "storage_contract_id": STORAGE_CONTRACT_ID,
        "request_sha256": None,
        "manifest_sha256": None,
        "prepare_sha256": None,
        "storage_digest": None,
        "operation_id": None,
        "layout_plan_id": None,
        "product_id": None,
        "policy_id": None,
        "nonclaims": list(NONCLAIMS),
    }
    if digests:
        for key in (
            "request_sha256",
            "manifest_sha256",
            "prepare_sha256",
            "storage_digest",
        ):
            if key in digests:
                result[key] = digests[key]
    if identity:
        for key in RESULT_IDENTITY_KEYS:
            if key in identity:
                result[key] = identity[key]
    result.update(merged_flags)
    if set(result) != set(RESULT_KEYS) - {"result_sha256"}:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-build-keyset")
    result["result_sha256"] = _domain_sha256(
        RESULT_DOMAIN,
        {key: result[key] for key in RESULT_KEYS if key != "result_sha256"},
    )
    return _validate_result_replay(result)


def _validate_result_replay(result: dict[str, Any]) -> dict[str, Any]:
    """Replay-validate a result object against the exact self-hashed
    contract; totally reject hostile shapes."""
    if type(result) is not dict:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-not-object")
    if len(result) != len(RESULT_KEYS):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-keyset")
    for key in result:
        if type(key) is not str:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-keyset")
    if set(result) != set(RESULT_KEYS):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-keyset")
    schema = result["schema"]
    if type(schema) is not str or schema != STORAGE_RESULT_SCHEMA:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-schema")
    command = result["command"]
    if type(command) is not str or command not in (
        COMMAND_FINALIZE,
        COMMAND_INSPECT,
    ):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-command")
    status = result["status"]
    if type(status) is not str or status not in _EXIT_CODES:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-status")
    reason = result["reason"]
    if type(reason) is not str or not (
        RESULT_REASON_MIN_CHARACTERS
        <= len(reason)
        <= RESULT_REASON_MAX_CHARACTERS
    ):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-reason")
    storage_contract_id = result["storage_contract_id"]
    if type(storage_contract_id) is not str or (
        storage_contract_id != STORAGE_CONTRACT_ID
    ):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-contract-binding")
    nonclaims = result["nonclaims"]
    if type(nonclaims) is not list or len(nonclaims) != len(NONCLAIMS):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-nonclaims")
    for item in nonclaims:
        if type(item) is not str:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-nonclaims")
    if nonclaims != list(NONCLAIMS):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-nonclaims")
    # Exact boolean typing for every flag; storage_written may be None only
    # on outcome_unknown and must otherwise be an exact bool.
    for key in _RESULT_FLAG_KEYS:
        value = result[key]
        if key == "storage_written":
            if value is None:
                if status != STATUS_OUTCOME_UNKNOWN:
                    raise _StorageFailure(
                        STATUS_BLOCKED, "blocked:result-flag-domain"
                    )
            elif type(value) is not bool:
                raise _StorageFailure(STATUS_BLOCKED, "blocked:result-flag-domain")
        elif type(value) is not bool:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-flag-domain")
    # Canonical encodability and exact result byte bound.
    try:
        canonical = _canonical_json_bytes(result)
    except BaseException:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-not-canonical")
    if len(canonical) > MAX_RESULT_BYTES:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-too-large")
    # Self-hash: the whole body excluding result_sha256, under RESULT_DOMAIN.
    result_sha256 = result["result_sha256"]
    if type(result_sha256) is not str or (
        _SHA256_HEX_RE.fullmatch(result_sha256) is None
    ):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-self-hash")
    try:
        body = {
            key: result[key] for key in RESULT_KEYS if key != "result_sha256"
        }
        replayed_sha256 = _domain_sha256(RESULT_DOMAIN, body)
    except BaseException:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-self-hash")
    if replayed_sha256 != result_sha256:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-self-hash")
    # Digest and identity fields: populated only on success, otherwise None.
    if status == STATUS_SUCCESS:
        for key in RESULT_DIGEST_KEYS + RESULT_IDENTITY_KEYS:
            value = result[key]
            if type(value) is not str:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-success-binding"
                )
        for key in RESULT_DIGEST_KEYS:
            if _SHA256_HEX_RE.fullmatch(result[key]) is None:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-digest-grammar"
                )
        if result["operation_id"] != OPERATION_PREFIX + result["request_sha256"]:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-operation-binding"
            )
        if _LAYOUT_ID_RE.fullmatch(result["layout_plan_id"]) is None:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-layout-grammar"
            )
        if _PRODUCT_ID_RE.fullmatch(result["product_id"]) is None:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-product-grammar"
            )
        if _POLICY_ID_RE.fullmatch(result["policy_id"]) is None:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-policy-grammar"
            )
        try:
            replayed_storage_digest = _storage_digest(
                result["request_sha256"],
                result["manifest_sha256"],
                result["prepare_sha256"],
            )
        except BaseException:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-storage-digest"
            )
        if result["storage_digest"] != replayed_storage_digest:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-storage-digest"
            )
        row = _SUCCESS_ROWS.get((command, reason))
        if row is None:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-success-reason")
        observed = tuple(
            result[key] for key in _STORAGE_FACT_KEYS + ("reconciled",)
        )
        if observed != row:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-success-row")
        for key in _SUCCESS_VERIFIED_TRUE_KEYS:
            if result[key] is not True:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-success-row"
                )
        for key in _RESULT_FLAG_KEYS:
            if key in _STORAGE_FACT_KEYS:
                continue
            if key in _SUCCESS_VERIFIED_TRUE_KEYS or key == "reconciled":
                continue
            if result[key] is not False:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-forbidden-success-flag"
                )
        return result
    for key in RESULT_DIGEST_KEYS + RESULT_IDENTITY_KEYS:
        if result[key] is not None:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-failure-binding"
            )
    for key in _RESULT_FLAG_KEYS:
        if key in _STORAGE_FACT_KEYS:
            continue
        if result[key] is not False:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-failure-flag")
    if status == STATUS_UNSUPPORTED:
        if reason not in UNSUPPORTED_REASONS[command]:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-unsupported-reason"
            )
        for key in _STORAGE_FACT_KEYS:
            if result[key] is not False:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-unsupported-flag"
                )
        return result
    if status == STATUS_BLOCKED:
        if reason != BLOCKED_REASONS[command]:
            raise _StorageFailure(
                STATUS_BLOCKED, "blocked:result-blocked-reason"
            )
        if result["storage_read_supported"] is not True:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-blocked-facts")
        if type(result["storage_written"]) is not bool:
            raise _StorageFailure(STATUS_BLOCKED, "blocked:result-blocked-facts")
        if command == COMMAND_INSPECT:
            if (
                result["storage_write_supported"] is not False
                or result["storage_write_attempted"] is not False
                or result["storage_written"] is not False
            ):
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-blocked-facts"
                )
        else:
            if result["storage_write_supported"] is not True:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-blocked-facts"
                )
            if result["storage_written"] and not result["storage_write_attempted"]:
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-blocked-facts"
                )
            if (
                result["storage_write_attempted"]
                and not result["storage_read_performed"]
            ):
                raise _StorageFailure(
                    STATUS_BLOCKED, "blocked:result-blocked-facts"
                )
        return result
    # STATUS_OUTCOME_UNKNOWN: finalize only, fixed reason, exact
    # T/T/T/T/None storage facts.
    if command != COMMAND_FINALIZE or reason != UNKNOWN_FINALIZE_REASON:
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-unknown-reason")
    if (
        result["storage_read_supported"] is not True
        or result["storage_write_supported"] is not True
        or result["storage_read_performed"] is not True
        or result["storage_write_attempted"] is not True
        or result["storage_written"] is not None
    ):
        raise _StorageFailure(STATUS_BLOCKED, "blocked:result-unknown-facts")
    return result


def _build_validated_render(result: Any) -> str:
    """Replay-validate a result via an exact builtin-dict copy and build the
    single-line canonical render; raises on any invalid or oversize shape."""
    if type(result) is not dict:
        raise _StorageFailure(STATUS_BLOCKED, RENDER_FALLBACK_REASON)
    replayed = {}
    for key in result:
        replayed[key] = result[key]
    validated = _validate_result_replay(replayed)
    render: dict[str, Any] = {
        "schema": STORAGE_RENDER_SCHEMA,
        "result_schema": validated["schema"],
    }
    for key in RENDER_KEYS:
        if key == "schema" or key == "result_schema":
            continue
        render[key] = validated[key]
    if len(render) != len(RENDER_KEYS) or set(render) != set(RENDER_KEYS):
        raise _StorageFailure(STATUS_BLOCKED, RENDER_FALLBACK_REASON)
    encoded = _canonical_json_bytes(render)
    if len(encoded) > MAX_RENDER_BYTES:
        raise _StorageFailure(STATUS_BLOCKED, RENDER_FALLBACK_REASON)
    return encoded.decode("ascii")


def render_environment_storage_result(result: Any) -> str:
    """Render a result document as one bounded canonical JSON line.

    Never raises: any invalid, hostile, or nonrenderable input yields exactly
    the fixed canonical ASCII fallback line."""
    try:
        return _build_validated_render(result)
    except BaseException:
        return RENDER_FALLBACK_LINE


def environment_storage_result_exit_code(result: Any) -> int:
    """Exit 0 only after exact replay and a bounded render both succeed;
    every invalid or nonrenderable object maps to the blocked exit code."""
    try:
        if type(result) is not dict:
            return _EXIT_CODES[STATUS_BLOCKED]
        replayed = {}
        for key in result:
            replayed[key] = result[key]
        validated = _validate_result_replay(replayed)
        _build_validated_render(validated)
        return _EXIT_CODES[validated["status"]]
    except BaseException:
        return _EXIT_CODES[STATUS_BLOCKED]


# ---------------------------------------------------------------------------
# Public entry points (fail-closed skeleton; expanded below).
# ---------------------------------------------------------------------------


# Read-only inspect capabilities (no rename-swap requirement).
_READ_OS_FLAGS = ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
_READ_OS_CALLABLES = (
    "open", "close", "fstat", "stat", "geteuid", "scandir", "read",
)
# Finalize-only write and rename-swap capabilities.
_WRITE_OS_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL")
_WRITE_OS_CALLABLES = ("write", "fsync", "fchmod")
_FCNTL_READ_LOCK_FLAGS = ("LOCK_SH", "LOCK_NB")
_FCNTL_WRITE_LOCK_FLAGS = ("LOCK_EX", "LOCK_NB")


def _unsupported_result(command: str, reason: str) -> dict[str, Any]:
    # Unsupported precedes all I/O: every support/performed/write flag is
    # false, including storage_written (never the ambiguous None).
    return _build_result(command, STATUS_UNSUPPORTED, reason)


def _platform_gate(
    command: str, *, require_write: bool
) -> dict[str, Any] | None:
    try:
        if sys.platform != REQUIRED_PLATFORM or os.name != REQUIRED_OS_NAME:
            return _unsupported_result(
                command, "unsupported:platform-not-darwin"
            )
        for flag_name in _READ_OS_FLAGS:
            if type(getattr(os, flag_name, None)) is not int:
                return _unsupported_result(
                    command, "unsupported:missing-nofollow-directory-open"
                )
        for callable_name in _READ_OS_CALLABLES:
            if not callable(getattr(os, callable_name, None)):
                return _unsupported_result(
                    command, "unsupported:missing-os-callable"
                )
        try:
            import fcntl
        except BaseException:
            return _unsupported_result(command, "unsupported:missing-flock")
        if not callable(getattr(fcntl, "flock", None)):
            return _unsupported_result(command, "unsupported:missing-flock")
        lock_flags = (
            _FCNTL_WRITE_LOCK_FLAGS if require_write
            else _FCNTL_READ_LOCK_FLAGS
        )
        for flag_name in lock_flags:
            if type(getattr(fcntl, flag_name, None)) is not int:
                return _unsupported_result(
                    command, "unsupported:missing-flock"
                )
        if require_write:
            for flag_name in _WRITE_OS_FLAGS:
                if type(getattr(os, flag_name, None)) is not int:
                    return _unsupported_result(
                        command, "unsupported:missing-write-open-flags"
                    )
            for callable_name in _WRITE_OS_CALLABLES:
                if not callable(getattr(os, callable_name, None)):
                    return _unsupported_result(
                        command, "unsupported:missing-os-callable"
                    )
            rename_swap = _bind_renameatx_np()
            if rename_swap is None or not callable(rename_swap):
                return _unsupported_result(
                    command,
                    "unsupported:missing-renameatx-np-swap-capability",
                )
        return None
    except BaseException:
        return _unsupported_result(
            command, "unsupported:platform-gate-error"
        )


_RENAMEATX_NP = None


def _bind_renameatx_np() -> Any:
    """Bind and cache the Darwin renameatx_np libc callable, or None."""
    global _RENAMEATX_NP
    if _RENAMEATX_NP is not None:
        return _RENAMEATX_NP
    try:
        import ctypes
    except ImportError:
        return None
    try:
        libc = ctypes.CDLL(LIBSYSTEM_PATH, use_errno=True)
        callable_ = getattr(libc, RENAMEATX_NP_SYMBOL)
        callable_.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        callable_.restype = ctypes.c_int
    except (OSError, AttributeError, TypeError):
        return None
    _RENAMEATX_NP = callable_
    return callable_


def finalize_prebuilt_environment_stage(
    environment_authority_root: Any,
    environment_state_root: Any,
    stage_journal_root: Any,
    *,
    environment_request: Any,
    layout_plan: Any,
    stage_result: Any,
) -> dict[str, Any]:
    tracker = _MutationTracker(write_supported=True)
    try:
        gate = _platform_gate(COMMAND_FINALIZE, require_write=True)
        if gate is not None:
            return gate
        return _finalize_impl(
            environment_authority_root,
            environment_state_root,
            stage_journal_root,
            environment_request=environment_request,
            layout_plan=layout_plan,
            stage_result=stage_result,
            tracker=tracker,
        )
    except _StorageFailure as failure:
        # Internal diagnostics stay private: every deterministic failure is
        # mapped to the fixed redacted blocked reason, and every ambiguity
        # to the fixed redacted unknown reason.
        if failure.status == STATUS_OUTCOME_UNKNOWN:
            return _build_result(
                COMMAND_FINALIZE,
                STATUS_OUTCOME_UNKNOWN,
                UNKNOWN_FINALIZE_REASON,
                flags=tracker.failure_flags(STATUS_OUTCOME_UNKNOWN),
            )
        return _build_result(
            COMMAND_FINALIZE,
            STATUS_BLOCKED,
            BLOCKED_FINALIZE_REASON,
            flags=tracker.failure_flags(STATUS_BLOCKED),
        )
    except BaseException:
        # An unexpected exception after any write attempt is unknown.
        if tracker.write_attempted:
            return _build_result(
                COMMAND_FINALIZE,
                STATUS_OUTCOME_UNKNOWN,
                UNKNOWN_FINALIZE_REASON,
                flags=tracker.failure_flags(STATUS_OUTCOME_UNKNOWN),
            )
        return _build_result(
            COMMAND_FINALIZE,
            STATUS_BLOCKED,
            BLOCKED_FINALIZE_REASON,
            flags=tracker.failure_flags(STATUS_BLOCKED),
        )


def inspect_prebuilt_environment_stage(
    environment_authority_root: Any,
    environment_state_root: Any,
    stage_journal_root: Any,
    *,
    environment_request: Any,
    layout_plan: Any,
    stage_result: Any,
) -> dict[str, Any]:
    tracker = _MutationTracker(write_supported=False)
    try:
        gate = _platform_gate(COMMAND_INSPECT, require_write=False)
        if gate is not None:
            return gate
        return _inspect_impl(
            environment_authority_root,
            environment_state_root,
            stage_journal_root,
            environment_request=environment_request,
            layout_plan=layout_plan,
            stage_result=stage_result,
            tracker=tracker,
        )
    except _StorageFailure:
        # Inspect is strictly read-only; every internal failure (including
        # any claimed ambiguity) maps to the fixed redacted blocked reason.
        return _build_result(
            COMMAND_INSPECT,
            STATUS_BLOCKED,
            BLOCKED_INSPECT_REASON,
            flags=tracker.failure_flags(STATUS_BLOCKED),
        )
    except BaseException:
        return _build_result(
            COMMAND_INSPECT,
            STATUS_BLOCKED,
            BLOCKED_INSPECT_REASON,
            flags=tracker.failure_flags(STATUS_BLOCKED),
        )


# ---------------------------------------------------------------------------
# Hostile-type-first primitive validators.
# ---------------------------------------------------------------------------


def _blocked(reason: str) -> _StorageFailure:
    return _StorageFailure(STATUS_BLOCKED, "blocked:" + reason)


def _unknown(reason: str) -> _StorageFailure:
    return _StorageFailure(STATUS_OUTCOME_UNKNOWN, "outcome_unknown:" + reason)


def _exact_str(value: Any, token: str) -> str:
    if type(value) is not str:
        raise _blocked(token)
    return value


def _exact_bool(value: Any, token: str) -> bool:
    if type(value) is not bool:
        raise _blocked(token)
    return value


def _exact_int(value: Any, token: str, low: int, high: int) -> int:
    if type(value) is not int or not (low <= value <= high):
        raise _blocked(token)
    return value


def _hex64(value: Any, token: str) -> str:
    text = _exact_str(value, token)
    if _SHA256_HEX_RE.fullmatch(text) is None:
        raise _blocked(token)
    return text


def _identity(value: Any, pattern: re.Pattern, token: str) -> str:
    text = _exact_str(value, token)
    if pattern.fullmatch(text) is None:
        raise _blocked(token)
    return text


def _require_exact_keys(doc: Any, keys: tuple, token: str) -> dict:
    if type(doc) is not dict:
        raise _blocked(token + "-not-object")
    if len(doc) != len(keys):
        raise _blocked(token + "-keyset")
    for key in doc:
        if type(key) is not str:
            raise _blocked(token + "-keyset")
    if set(doc) != set(keys):
        raise _blocked(token + "-keyset")
    return doc


def _require_bounded_native_document(value: Any, token: str) -> None:
    """Bound hostile containers before sibling replay or canonicalization."""
    remaining = [MAX_DOCUMENT_ITEMS]

    def visit(item: Any, depth: int) -> None:
        if depth > MAX_DOCUMENT_DEPTH:
            raise _blocked(token + "-too-deep")
        remaining[0] -= 1
        if remaining[0] < 0:
            raise _blocked(token + "-too-many-items")
        if type(item) is str:
            if len(item) > MAX_DOCUMENT_STRING_CHARACTERS:
                raise _blocked(token + "-string-too-large")
            return
        if type(item) in (bool, int) or item is None:
            return
        if type(item) is list:
            if len(item) > MAX_DOCUMENT_ITEMS:
                raise _blocked(token + "-too-many-items")
            for child in item:
                visit(child, depth + 1)
            return
        if type(item) is dict:
            if len(item) > MAX_DOCUMENT_ITEMS:
                raise _blocked(token + "-too-many-items")
            for key in item:
                if type(key) is not str or len(key) > MAX_NAME_LENGTH:
                    raise _blocked(token + "-key")
            for key in item:
                visit(item[key], depth + 1)
            return
        raise _blocked(token + "-value-type")

    visit(value, 0)


def _validate_abs_path(
    value: Any, token: str, *, forbid_segments: bool = True
) -> str:
    """Validate one lexical absolute path; no filesystem access."""
    text = _exact_str(value, token)
    if not (2 <= len(text) <= MAX_PATH_LENGTH):
        raise _blocked(token)
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        raise _blocked(token)
    if not text.startswith("/") or text.endswith("/") or "//" in text:
        raise _blocked(token)
    segments = text[1:].split("/")
    if len(segments) > MAX_ROOT_DEPTH:
        raise _blocked(token)
    for segment in segments:
        if segment in (".", "..") or not segment:
            raise _blocked(token)
        if len(segment) > MAX_NAME_LENGTH:
            raise _blocked(token)
        if forbid_segments and segment.casefold() in _FORBIDDEN_PATH_SEGMENTS:
            raise _blocked(token + "-forbidden-segment")
    if forbid_segments:
        folded_text = text.casefold()
        for prefix in _FORBIDDEN_PATH_PREFIXES:
            folded_prefix = prefix.casefold()
            if folded_text.startswith(folded_prefix) or (
                folded_text == folded_prefix.rstrip("/")
            ):
                raise _blocked(token + "-forbidden-prefix")
    return text


def _overlaps(first: str, second: str) -> bool:
    return (
        first == second
        or first.startswith(second + "/")
        or second.startswith(first + "/")
    )


# ---------------------------------------------------------------------------
# Document validators (request / layout plan / stage result).
# ---------------------------------------------------------------------------


def _validate_request(
    environment_request: Any, phase5a: dict[str, Any]
) -> tuple[dict, str]:
    if type(environment_request) is not dict:
        raise _blocked("request-not-object")
    # The frozen sibling keysets must equal the local literal projection
    # exactly; any drift refuses before any request field is inspected.
    if phase5a.get("REQUEST_KEYS") != PHASE5A_REQUEST_KEYS:
        raise _blocked("phase5a-request-keyset-drift")
    if phase5a.get("BINDING_KEYS") != PHASE5A_BINDING_KEYS:
        raise _blocked("phase5a-binding-keyset-drift")
    if len(environment_request) != len(PHASE5A_REQUEST_KEYS):
        raise _blocked("request-keyset")
    for key in environment_request:
        if type(key) is not str:
            raise _blocked("request-keyset")
    if set(environment_request) != set(PHASE5A_REQUEST_KEYS):
        raise _blocked("request-keyset")
    _require_bounded_native_document(environment_request, "request")
    bindings = {
        key: environment_request[key] for key in PHASE5A_BINDING_KEYS
    }
    planner = _require_private_planner(
        phase5a, "plan_environment_request", "phase5a"
    )
    plan = planner(**bindings)
    if type(plan) is not dict or plan.get("status") != "planned":
        raise _blocked("request-plan-not-planned")
    returned_request = plan.get("request")
    if type(returned_request) is not dict:
        raise _blocked("request-plan-request")
    try:
        replay_equal = _canonical_json_bytes(
            returned_request
        ) == _canonical_json_bytes(environment_request)
    except (TypeError, ValueError):
        raise _blocked("request-not-canonical")
    if not replay_equal:
        raise _blocked("request-replay-mismatch")
    request_sha256 = _hex64(
        plan.get("request_sha256"), "request-plan-sha256"
    )
    return returned_request, request_sha256


def _validate_layout_plan(
    layout_plan: Any,
    request: dict,
    stage_result: Any,
    installed_layout_namespace: dict[str, Any],
) -> dict:
    plan = _require_exact_keys(layout_plan, LAYOUT_PLAN_KEYS, "layout-plan")
    _require_bounded_native_document(plan, "layout-plan")
    planner = _require_private_planner(
        installed_layout_namespace,
        "plan_inactive_versioned_layout",
        "installed-layout",
    )
    replayed = planner(
        install_root=plan["install_root"],
        environment_root=plan["environment_root"],
        data_root=plan["data_root"],
        updater_state_root=plan["updater_state_root"],
        legacy_checkout_root=plan["legacy_checkout_root"],
        product_id=plan["product_id"],
        inventory_policy_id=plan["inventory_policy_id"],
        stage_result=stage_result,
    )
    if type(replayed) is not dict:
        raise _blocked("layout-plan-replay-not-object")
    if replayed.get("status") != LAYOUT_PLAN_STATUS:
        raise _blocked("layout-plan-replay-not-planned")
    try:
        replay_equal = _canonical_json_bytes(replayed) == _canonical_json_bytes(
            plan
        )
    except (TypeError, ValueError):
        raise _blocked("layout-plan-not-canonical")
    if not replay_equal:
        raise _blocked("layout-plan-replay-mismatch")
    if plan["layout_contract_id"] != request["layout_contract_id"]:
        raise _blocked("layout-plan-contract-binding")
    if plan["layout_id"] != request["layout_id"]:
        raise _blocked("layout-plan-layout-id-binding")
    if plan["product_id"] != request["candidate_product_id"]:
        raise _blocked("layout-plan-product-binding")
    if plan["inventory_policy_id"] != request["inventory_policy_id"]:
        raise _blocked("layout-plan-policy-binding")
    try:
        stage_canonical = _canonical_json_bytes(stage_result)
    except (TypeError, ValueError):
        raise _blocked("stage-result-not-canonical")
    if _raw_sha256(stage_canonical) != request["stage_result_sha256"]:
        raise _blocked("stage-result-hash-binding")
    return plan


def _validate_stage_result(stage_result: Any, request: dict) -> dict:
    result = _require_exact_keys(stage_result, STAGE_RESULT_KEYS, "stage-result")
    _require_bounded_native_document(result, "stage-result")
    if (
        _exact_str(result["schema"], "stage-result-schema")
        != STAGE_RESULT_SCHEMA_V1
    ):
        raise _blocked("stage-result-schema")
    if _exact_str(result["mode"], "stage-result-mode") != STAGE_RESULT_MODE:
        raise _blocked("stage-result-mode")
    product = _identity(
        result["product_id"], _PRODUCT_ID_RE, "stage-result-product-id"
    )
    policy = _identity(
        result["inventory_policy_id"], _POLICY_ID_RE, "stage-result-policy-id"
    )
    if (
        product != request["candidate_product_id"]
        or policy != request["inventory_policy_id"]
    ):
        raise _blocked("stage-result-identity-mismatch")
    status = _exact_str(result["status"], "stage-result-status")
    reason = _exact_str(result["reason"], "stage-result-reason")
    resumed = _exact_bool(result["resumed"], "stage-result-resumed")
    if (status, reason, resumed) not in STAGE_RESULT_ACCEPTED:
        raise _blocked("stage-result-outcome")
    for key in STAGE_RESULT_TRUE_PROOFS:
        if result[key] is not True:
            raise _blocked("stage-result-proof-flag")
    _exact_bool(result["reconciled"], "stage-result-reconciled")
    for key in STAGE_RESULT_FALSE_FLAGS:
        if result[key] is not False:
            raise _blocked("stage-result-effect-flag")
    nonclaims = result["nonclaims"]
    if type(nonclaims) is not list or nonclaims != list(STAGE_RESULT_NONCLAIMS):
        raise _blocked("stage-result-nonclaims")
    for item in nonclaims:
        if type(item) is not str:
            raise _blocked("stage-result-nonclaims")
    try:
        canonical = _canonical_json_bytes(result)
    except (TypeError, ValueError):
        raise _blocked("stage-result-not-canonical")
    if _raw_sha256(canonical) != request["stage_result_sha256"]:
        raise _blocked("stage-result-hash-binding")
    return result


# ---------------------------------------------------------------------------
# Descriptor-confined filesystem helpers.
# ---------------------------------------------------------------------------

# Guarded lookups: the platform gate validates real presence before any I/O;
# zero defaults only keep module import total on platforms lacking a flag.
_DIR_OPEN_FLAGS = (
    getattr(os, "O_RDONLY", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_OPEN_FLAGS = (
    getattr(os, "O_RDONLY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def _close_quietly(fds: list) -> None:
    while fds:
        fd = fds.pop()
        try:
            os.close(fd)
        except OSError:
            pass


def _open_root_dir(path: str, fds: list, token: str) -> int:
    """Open an absolute directory path segment-by-segment, never following
    symlinks at any component."""
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise _blocked(token + "-open-failed")
    fds.append(fd)
    for segment in path[1:].split("/"):
        try:
            next_fd = os.open(segment, _DIR_OPEN_FLAGS, dir_fd=fd)
        except FileNotFoundError:
            raise _blocked(token + "-absent")
        except OSError:
            raise _blocked(token + "-open-failed")
        fds.append(next_fd)
        fd = next_fd
    return fd


def _require_private_dir(fd: int, token: str, *, exact_0700: bool) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError:
        raise _blocked(token + "-stat-failed")
    if not stat.S_ISDIR(info.st_mode):
        raise _blocked(token + "-not-directory")
    if info.st_uid != os.geteuid():
        raise _blocked(token + "-not-owned")
    perm = stat.S_IMODE(info.st_mode)
    if exact_0700:
        if perm != PREIMAGE_DIR_MODE:
            raise _blocked(token + "-mode")
    elif perm & 0o022:
        raise _blocked(token + "-writable")
    return info


def _empty_preimage_fingerprint(
    fd: int,
    expected: dict | None = None,
    *,
    parent_fd: int | None = None,
    visible_name: str | None = None,
) -> dict:
    """Fingerprint the held empty preimage directory descriptor.

    Same-sample pre/post fstat brackets a bounded scandir emptiness proof;
    the directory must be euid-owned, exactly 0700, nlink 2, and empty.
    Returns an exact built-in dict of device/inode/mode/nlink; if expected
    is supplied it must match exactly."""
    try:
        pre = os.fstat(fd)
    except OSError:
        raise _blocked("preimage-inspection-failed")
    if not stat.S_ISDIR(pre.st_mode):
        raise _blocked("preimage-not-directory")
    if pre.st_uid != os.geteuid():
        raise _blocked("preimage-not-owned")
    if stat.S_IMODE(pre.st_mode) != PREIMAGE_DIR_MODE:
        raise _blocked("preimage-mode")
    if pre.st_nlink != PREIMAGE_NLINK:
        raise _blocked("preimage-nlink")
    pre_full = _full_stat_fingerprint(pre)
    first_names = _snapshot_directory_names(fd)
    if first_names:
        raise _blocked("preimage-not-empty")
    second_names = _snapshot_directory_names(fd)
    if second_names or second_names != first_names:
        raise _blocked("preimage-not-empty")
    try:
        post = os.fstat(fd)
    except OSError:
        raise _blocked("preimage-inspection-failed")
    if _full_stat_fingerprint(post) != pre_full:
        raise _blocked("preimage-mutated")
    if (parent_fd is None) != (visible_name is None):
        raise _blocked("preimage-visible-binding")
    if parent_fd is not None:
        if type(visible_name) is not str or (
            _ENTRY_NAME_RE.fullmatch(visible_name) is None
        ):
            raise _blocked("preimage-visible-binding")
        try:
            visible = os.stat(
                visible_name, dir_fd=parent_fd, follow_symlinks=False
            )
        except OSError:
            raise _blocked("preimage-visible-stat-failed")
        if _full_stat_fingerprint(visible) != pre_full:
            raise _blocked("preimage-visible-substitution")
    fingerprint = {
        "device": int(pre.st_dev),
        "inode": int(pre.st_ino),
        "mode": int(stat.S_IMODE(pre.st_mode)),
        "nlink": int(pre.st_nlink),
    }
    if tuple(fingerprint) != FINGERPRINT_KEYS:
        raise _blocked("preimage-fingerprint-keyset")
    if expected is not None:
        if type(expected) is not dict or expected != fingerprint:
            raise _blocked("preimage-fingerprint-mismatch")
    return fingerprint


def _read_fd_fully(fd: int, limit: int, token: str) -> bytes:
    chunks = []
    total = 0
    while True:
        try:
            chunk = os.read(fd, 1 << 20)
        except OSError:
            raise _blocked(token + "-read-failed")
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise _blocked(token + "-too-large")
        chunks.append(chunk)


# ---------------------------------------------------------------------------
# Frozen sibling source pinning and private replay loading.
# ---------------------------------------------------------------------------


def _read_frozen_sibling_source(
    expected_hash: str, expected_basename: str, token: str
) -> tuple[bytes, str]:
    """Read one fixed sibling source beside this module under held
    descriptors, prove its exact safe identity, and return the exact bytes
    that were hashed.  The caller compiles these same bytes without reread."""
    storage_path = _validate_abs_path(
        globals().get("__file__"), "storage-source-path", forbid_segments=False
    )
    if not storage_path.endswith("/release_environment_storage.py"):
        raise _blocked("storage-source-basename")
    parent_path = storage_path.rsplit("/", 1)[0]
    path = parent_path + "/" + expected_basename
    fds: list = []
    try:
        parent_fd = _open_root_dir(parent_path, fds, token + "-source-parent")
        _require_private_dir(
            parent_fd, token + "-source-parent", exact_0700=False
        )
        parent_fingerprint = _held_full_fingerprint(parent_fd)
        try:
            fd = os.open(expected_basename, _FILE_OPEN_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            raise _blocked(token + "-source-absent")
        except OSError:
            raise _blocked(token + "-source-open-failed")
        fds.append(fd)
        try:
            pre = os.fstat(fd)
        except OSError:
            raise _blocked(token + "-source-stat-failed")
        if (
            not stat.S_ISREG(pre.st_mode)
            or pre.st_uid != os.geteuid()
            or stat.S_IMODE(pre.st_mode) != SIBLING_SOURCE_MODE
            or pre.st_nlink != 1
            or pre.st_size > MAX_SIBLING_SOURCE_BYTES
        ):
            raise _blocked(token + "-source-shape")
        held_full = _full_stat_fingerprint(pre)
        try:
            visible = os.stat(
                expected_basename, dir_fd=parent_fd, follow_symlinks=False
            )
        except OSError:
            raise _blocked(token + "-source-stat-failed")
        if _full_stat_fingerprint(visible) != held_full:
            raise _blocked(token + "-source-substitution")
        raw = _read_fd_fully(fd, MAX_SIBLING_SOURCE_BYTES, token + "-source")
        if len(raw) != pre.st_size:
            raise _blocked(token + "-source-size-mismatch")
        try:
            post = os.fstat(fd)
        except OSError:
            raise _blocked(token + "-source-stat-failed")
        if _full_stat_fingerprint(post) != held_full:
            raise _blocked(token + "-source-mutated")
        try:
            visible_post = os.stat(
                expected_basename, dir_fd=parent_fd, follow_symlinks=False
            )
        except OSError:
            raise _blocked(token + "-source-stat-failed")
        if _full_stat_fingerprint(visible_post) != held_full:
            raise _blocked(token + "-source-substitution")
        if _raw_sha256(raw) != expected_hash:
            raise _blocked(token + "-source-hash-mismatch")
        _strict_close_last(fds, token + "-source-close-failed")
        _reprove_absolute_root(
            parent_path,
            parent_fingerprint,
            token + "-source-parent",
            exact_private=False,
        )
        return raw, path
    finally:
        _close_quietly(fds)


def _execute_frozen_sibling_source(
    raw: bytes, path: str, private_name: str, token: str
) -> dict[str, Any]:
    """Compile and execute only already-hash-verified trusted contract
    source bytes in a fresh, unregistered, non-main namespace."""
    namespace: dict[str, Any] = {
        "__name__": private_name,
        "__file__": path,
        "__package__": None,
        "__builtins__": __builtins__,
    }
    try:
        code = compile(raw, path, "exec", dont_inherit=True, optimize=0)
        exec(code, namespace, namespace)
    except BaseException:
        raise _blocked(token + "-source-execution")
    return namespace


def _require_private_planner(
    namespace: dict[str, Any], name: str, token: str
) -> Any:
    function = namespace.get(name)
    if type(function) is not type(_require_private_planner):
        raise _blocked(token + "-planner-type")
    try:
        function_globals = object.__getattribute__(function, "__globals__")
    except BaseException:
        raise _blocked(token + "-planner-globals")
    if function_globals is not namespace:
        raise _blocked(token + "-planner-globals")
    return function


def _verify_frozen_sibling_sources() -> tuple[dict[str, Any], dict[str, Any]]:
    # Verify both complete files before executing either one.
    phase5a_raw, phase5a_path = _read_frozen_sibling_source(
        PHASE5A_SOURCE_SHA256,
        "release_environment.py",
        "phase5a",
    )
    layout_raw, layout_path = _read_frozen_sibling_source(
        INSTALLED_LAYOUT_SOURCE_SHA256,
        "installed_layout.py",
        "installed-layout",
    )
    phase5a = _execute_frozen_sibling_source(
        phase5a_raw,
        phase5a_path,
        "_synapse_s2_verified_release_environment",
        "phase5a",
    )
    layout = _execute_frozen_sibling_source(
        layout_raw,
        layout_path,
        "_synapse_s2_verified_installed_layout",
        "installed-layout",
    )
    _require_private_planner(
        phase5a, "plan_environment_request", "phase5a"
    )
    _require_private_planner(
        layout, "plan_inactive_versioned_layout", "installed-layout"
    )
    if phase5a.get("REQUEST_KEYS") != PHASE5A_REQUEST_KEYS:
        raise _blocked("phase5a-request-keyset-drift")
    if phase5a.get("BINDING_KEYS") != PHASE5A_BINDING_KEYS:
        raise _blocked("phase5a-binding-keyset-drift")
    if layout.get("ADAPTERS") != LAYOUT_ADAPTER_TABLE:
        raise _blocked("installed-layout-adapter-drift")
    return phase5a, layout


# ---------------------------------------------------------------------------
# Bounded canonical stage-journal verification (integrity only).
# ---------------------------------------------------------------------------


def _verify_stage_journal(journal_root_fd: int, request: dict) -> None:
    fd: int | None = None
    try:
        try:
            fd = os.open(
                STAGE_JOURNAL_FILE_NAME, _FILE_OPEN_FLAGS, dir_fd=journal_root_fd
            )
        except FileNotFoundError:
            raise _blocked("stage-journal-absent")
        except OSError:
            raise _blocked("stage-journal-open-failed")
        try:
            pre = os.fstat(fd)
        except OSError:
            raise _blocked("stage-journal-stat-failed")
        if (
            not stat.S_ISREG(pre.st_mode)
            or pre.st_uid != os.geteuid()
            or stat.S_IMODE(pre.st_mode) != STATE_FILE_MODE
            or pre.st_nlink != 1
            or pre.st_size > MAX_STAGE_JOURNAL_BYTES
        ):
            raise _blocked("stage-journal-file-shape")
        try:
            visible = os.stat(
                STAGE_JOURNAL_FILE_NAME,
                dir_fd=journal_root_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _blocked("stage-journal-stat-failed")
        if visible.st_dev != pre.st_dev or visible.st_ino != pre.st_ino:
            raise _blocked("stage-journal-substitution")
        held_full = _full_stat_fingerprint(pre)
        raw = _read_fd_fully(fd, MAX_STAGE_JOURNAL_BYTES, "stage-journal")
        try:
            post = os.fstat(fd)
        except OSError:
            raise _blocked("stage-journal-stat-failed")
        if (
            post.st_dev != pre.st_dev
            or post.st_ino != pre.st_ino
            or post.st_mode != pre.st_mode
            or post.st_nlink != pre.st_nlink
            or post.st_size != pre.st_size
        ):
            raise _blocked("stage-journal-mutated")
        if _full_stat_fingerprint(post) != held_full:
            raise _blocked("stage-journal-mutated")
        # Second parent-visible nofollow sample after the read: the name must
        # still resolve to the exact held inode with the full fingerprint.
        try:
            revisible = os.stat(
                STAGE_JOURNAL_FILE_NAME,
                dir_fd=journal_root_fd,
                follow_symlinks=False,
            )
        except OSError:
            raise _blocked("stage-journal-stat-failed")
        if _full_stat_fingerprint(revisible) != held_full:
            raise _blocked("stage-journal-substitution")
        # Strict pre-cleared close before any parsing; never quietly accepted.
        pending_fd, fd = fd, None
        try:
            os.close(pending_fd)
        except OSError:
            raise _blocked("stage-journal-close-failed")
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise _blocked("stage-journal-not-ascii")
    if not text or not text.endswith("\n"):
        raise _blocked("stage-journal-not-newline-terminated")
    lines = text.split("\n")[:-1]
    if not (1 <= len(lines) <= MAX_STAGE_JOURNAL_ENTRIES):
        raise _blocked("stage-journal-entry-count")
    previous = STAGE_JOURNAL_GENESIS_HASH
    head_entry_found = False
    for index, line in enumerate(lines):
        if not line or len(line) > MAX_JOURNAL_LINE_BYTES:
            raise _blocked("stage-journal-line-bounds")
        try:
            entry = json.loads(line)
        except ValueError:
            raise _blocked("stage-journal-line-not-json")
        entry = _require_exact_keys(
            entry, STAGE_JOURNAL_KEYS, "stage-journal-entry"
        )
        try:
            if _canonical_json_bytes(entry).decode("ascii") != line:
                raise _blocked("stage-journal-line-not-canonical")
        except (TypeError, ValueError):
            raise _blocked("stage-journal-line-not-canonical")
        if entry["schema"] != STAGE_JOURNAL_SCHEMA:
            raise _blocked("stage-journal-entry-schema")
        _exact_int(
            entry["sequence"],
            "stage-journal-sequence",
            index + 1,
            index + 1,
        )
        if _hex64(entry["previous_hash"], "stage-journal-previous") != previous:
            raise _blocked("stage-journal-chain-broken")
        product = _identity(
            entry["product_id"], _PRODUCT_ID_RE, "stage-journal-product-id"
        )
        policy = _identity(
            entry["inventory_policy_id"],
            _POLICY_ID_RE,
            "stage-journal-policy-id",
        )
        state = _exact_str(entry["release_state"], "stage-journal-state")
        if state not in STAGE_JOURNAL_STATES:
            raise _blocked("stage-journal-state")
        entry_hash = _hex64(entry["entry_hash"], "stage-journal-entry-hash")
        body = {
            key: entry[key] for key in STAGE_JOURNAL_KEYS if key != "entry_hash"
        }
        if _domain_sha256(STAGE_JOURNAL_DOMAIN, body) != entry_hash:
            raise _blocked("stage-journal-entry-hash")
        previous = entry_hash
        if entry_hash == request["stage_journal_head_sha256"]:
            if (
                product != request["candidate_product_id"]
                or policy != request["inventory_policy_id"]
            ):
                raise _blocked("stage-journal-head-identity-mismatch")
            head_entry_found = True
    if not head_entry_found:
        raise _blocked("stage-journal-head-binding")


# ---------------------------------------------------------------------------
# Descriptor-confined bounded tree scanner and manifest binding.
# ---------------------------------------------------------------------------


def _full_stat_fingerprint(info: os.stat_result) -> dict:
    """Exact full fingerprint of one stat sample."""
    fingerprint = {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "mode": int(info.st_mode),
        "nlink": int(info.st_nlink),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "ctime_ns": int(info.st_ctime_ns),
    }
    if tuple(fingerprint) != FULL_STAT_FINGERPRINT_KEYS:
        raise _blocked("full-stat-fingerprint-keyset")
    return fingerprint


def _held_full_fingerprint(fd: int, expected: dict | None = None) -> dict:
    try:
        info = os.fstat(fd)
    except OSError:
        raise _blocked("tree-fingerprint-failed")
    fingerprint = _full_stat_fingerprint(info)
    if expected is not None and expected != fingerprint:
        raise _blocked("tree-fingerprint-mismatch")
    return fingerprint


def _strict_close_last(fds: list, token: str) -> None:
    """Strict success-path close: the descriptor is popped from the local
    cleanup list before close so an ambiguous close is never retried."""
    fd = fds.pop()
    try:
        os.close(fd)
    except OSError:
        raise _blocked(token)


def _scan_tree(
    root_fd: int, request: dict, request_sha256: str, operation_name: str
) -> dict:
    """Scan one prebuilt tree under a held directory descriptor and return
    its canonical manifest document. Never follows symlinks, never leaves
    the root device, never executes or imports anything."""
    root_info = _require_private_dir(root_fd, "tree-root", exact_0700=True)
    if stat.S_IMODE(root_info.st_mode) & SPECIAL_MODE_BITS:
        raise _blocked("tree-root-special-bits")
    root_pre_fingerprint = _held_full_fingerprint(root_fd)
    root_pre_names = _snapshot_directory_names(root_fd)
    counters = {"entries": 0, "bytes": 0}
    entries: list = []
    _scan_directory(root_fd, "", 0, root_info.st_dev, counters, entries)
    root_post_names = _snapshot_directory_names(root_fd)
    if root_post_names != root_pre_names:
        raise _blocked("tree-root-mutated")
    _held_full_fingerprint(root_fd, expected=root_pre_fingerprint)
    manifest = {
        "schema": TREE_MANIFEST_SCHEMA,
        "storage_contract_id": STORAGE_CONTRACT_ID,
        "request_sha256": request_sha256,
        "operation_id": operation_name,
        "product_id": request["candidate_product_id"],
        "inventory_policy_id": request["inventory_policy_id"],
        "entry_count": counters["entries"],
        "total_bytes": counters["bytes"],
        "entries": entries,
    }
    if tuple(manifest) != TREE_MANIFEST_KEYS:
        raise _blocked("tree-manifest-keyset")
    return manifest


def _snapshot_directory_names(dir_fd: int) -> tuple:
    """Bounded fd-scandir name snapshot; stops at MAX_TREE_ENTRIES+1 before
    sorting and strictly closes the iterator."""
    names: list = []
    iterator = None
    try:
        try:
            iterator = os.scandir(dir_fd)
        except OSError:
            raise _blocked("tree-list-failed")
        while True:
            try:
                entry = next(iterator)
            except StopIteration:
                break
            except OSError:
                raise _blocked("tree-list-failed")
            names.append(entry.name)
            if len(names) > MAX_TREE_ENTRIES:
                raise _blocked("tree-too-many-entries")
        # Strict pre-cleared close on the success path; never silently
        # accepted. Post-swap callers convert this blocked to unknown.
        pending_iterator, iterator = iterator, None
        try:
            pending_iterator.close()
        except BaseException:
            raise _blocked("tree-list-close-failed")
        return tuple(sorted(names))
    finally:
        if iterator is not None:
            try:
                iterator.close()
            except BaseException:
                pass


def _scan_directory(
    dir_fd: int,
    prefix: str,
    depth: int,
    device: int,
    counters: dict,
    entries: list,
) -> None:
    if depth > MAX_TREE_DEPTH:
        raise _blocked("tree-too-deep")
    held_pre_fingerprint = _held_full_fingerprint(dir_fd)
    names = _snapshot_directory_names(dir_fd)
    seen_casefold: set = set()
    for name in names:
        if type(name) is not str or _TREE_ENTRY_NAME_RE.fullmatch(name) is None:
            raise _blocked("tree-entry-name")
        if name.casefold() in _FORBIDDEN_PATH_SEGMENTS:
            raise _blocked("tree-entry-name-forbidden")
        folded = name.casefold()
        if folded in seen_casefold:
            raise _blocked("tree-entry-casefold-duplicate")
        seen_casefold.add(folded)
        relative = name if not prefix else prefix + "/" + name
        if len(relative) > MAX_PATH_LENGTH:
            raise _blocked("tree-path-too-long")
        counters["entries"] += 1
        if counters["entries"] > MAX_TREE_ENTRIES:
            raise _blocked("tree-too-many-entries")
        try:
            info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            raise _blocked("tree-entry-stat-failed")
        if stat.S_ISLNK(info.st_mode):
            raise _blocked("tree-symlink-rejected")
        if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
            raise _blocked("tree-entry-type")
        if info.st_dev != device:
            raise _blocked("tree-device-crossing")
        if info.st_uid != os.geteuid():
            raise _blocked("tree-entry-not-owned")
        perm = stat.S_IMODE(info.st_mode)
        if perm & SPECIAL_MODE_BITS:
            raise _blocked("tree-entry-special-bits")
        if stat.S_ISDIR(info.st_mode):
            if perm != PREIMAGE_DIR_MODE:
                raise _blocked("tree-directory-mode")
            child_fds: list = []
            try:
                try:
                    child_fd = os.open(name, _DIR_OPEN_FLAGS, dir_fd=dir_fd)
                except OSError:
                    raise _blocked("tree-directory-open-failed")
                child_fds.append(child_fd)
                try:
                    child_info = os.fstat(child_fd)
                except OSError:
                    raise _blocked("tree-directory-stat-failed")
                child_fingerprint = _full_stat_fingerprint(child_info)
                if child_fingerprint != _full_stat_fingerprint(info):
                    raise _blocked("tree-directory-substitution")
                if child_info.st_dev != device:
                    raise _blocked("tree-device-crossing")
                directory_entry = {
                    "path": relative,
                    "kind": "directory",
                    "mode": format(perm, "04o"),
                    "size": 0,
                    "sha256": "",
                }
                if tuple(directory_entry) != TREE_ENTRY_KEYS:
                    raise _blocked("tree-entry-keyset")
                entries.append(directory_entry)
                _scan_directory(
                    child_fd, relative, depth + 1, device, counters, entries
                )
                _held_full_fingerprint(child_fd, expected=child_fingerprint)
                try:
                    parent_view = os.stat(
                        name, dir_fd=dir_fd, follow_symlinks=False
                    )
                except OSError:
                    raise _blocked("tree-directory-stat-failed")
                if _full_stat_fingerprint(parent_view) != child_fingerprint:
                    raise _blocked("tree-directory-mutated")
                _strict_close_last(child_fds, "tree-scanner-close-failed")
            finally:
                _close_quietly(child_fds)
            continue
        if info.st_nlink != 1:
            raise _blocked("tree-file-nlink")
        expected_file_mode = (
            TREE_PYTHON_FILE_MODE
            if relative == "bin/python"
            else TREE_REGULAR_FILE_MODE
        )
        if perm != expected_file_mode:
            raise _blocked("tree-file-mode")
        file_fds: list = []
        try:
            try:
                file_fd = os.open(name, _FILE_OPEN_FLAGS, dir_fd=dir_fd)
            except OSError:
                raise _blocked("tree-file-open-failed")
            file_fds.append(file_fd)
            try:
                file_info = os.fstat(file_fd)
            except OSError:
                raise _blocked("tree-file-stat-failed")
            file_fingerprint = _full_stat_fingerprint(file_info)
            if file_fingerprint != _full_stat_fingerprint(info):
                raise _blocked("tree-file-substitution")
            if file_info.st_dev != device:
                raise _blocked("tree-device-crossing")
            if file_info.st_size > MAX_TREE_FILE_BYTES:
                raise _blocked("tree-file-too-large")
            counters["bytes"] += file_info.st_size
            if counters["bytes"] > MAX_TREE_TOTAL_BYTES:
                raise _blocked("tree-too-many-bytes")
            digest = hashlib.sha256()
            observed = 0
            while True:
                try:
                    chunk = os.read(file_fd, 1 << 20)
                except OSError:
                    raise _blocked("tree-file-read-failed")
                if not chunk:
                    break
                observed += len(chunk)
                if observed > file_info.st_size:
                    raise _blocked("tree-file-grew")
                digest.update(chunk)
            if observed != file_info.st_size:
                raise _blocked("tree-file-shrank")
            try:
                post_info = os.fstat(file_fd)
            except OSError:
                raise _blocked("tree-file-stat-failed")
            if _full_stat_fingerprint(post_info) != file_fingerprint:
                raise _blocked("tree-file-mutated")
            try:
                parent_view = os.stat(
                    name, dir_fd=dir_fd, follow_symlinks=False
                )
            except OSError:
                raise _blocked("tree-file-stat-failed")
            if _full_stat_fingerprint(parent_view) != file_fingerprint:
                raise _blocked("tree-file-mutated")
            file_entry = {
                "path": relative,
                "kind": "file",
                "mode": format(perm, "04o"),
                "size": file_info.st_size,
                "sha256": digest.hexdigest(),
            }
            if tuple(file_entry) != TREE_ENTRY_KEYS:
                raise _blocked("tree-entry-keyset")
            entries.append(file_entry)
            _strict_close_last(file_fds, "tree-scanner-close-failed")
        finally:
            _close_quietly(file_fds)
    post_names = _snapshot_directory_names(dir_fd)
    if post_names != names:
        raise _blocked("tree-directory-mutated")
    _held_full_fingerprint(dir_fd, expected=held_pre_fingerprint)


def _directory_fingerprint(fd: int, expected: dict | None = None) -> dict:
    """Same-sample pre/post fstat fingerprint of a held directory descriptor.

    Returns an exact built-in dict of device/inode/mode/nlink; if expected
    is supplied it must match exactly."""
    try:
        pre = os.fstat(fd)
    except OSError:
        raise _blocked("directory-fingerprint-failed")
    if not stat.S_ISDIR(pre.st_mode):
        raise _blocked("directory-fingerprint-not-directory")
    if pre.st_uid != os.geteuid():
        raise _blocked("directory-fingerprint-not-owned")
    try:
        post = os.fstat(fd)
    except OSError:
        raise _blocked("directory-fingerprint-failed")
    if (
        post.st_dev != pre.st_dev
        or post.st_ino != pre.st_ino
        or post.st_mode != pre.st_mode
        or post.st_nlink != pre.st_nlink
    ):
        raise _blocked("directory-fingerprint-mutated")
    fingerprint = {
        "device": int(pre.st_dev),
        "inode": int(pre.st_ino),
        "mode": int(stat.S_IMODE(pre.st_mode)),
        "nlink": int(pre.st_nlink),
    }
    if tuple(fingerprint) != FINGERPRINT_KEYS:
        raise _blocked("directory-fingerprint-keyset")
    if expected is not None:
        if type(expected) is not dict or expected != fingerprint:
            raise _blocked("directory-fingerprint-mismatch")
    return fingerprint


def _require_adapter_presence(manifest: dict) -> None:
    by_path = {entry["path"]: entry for entry in manifest["entries"]}
    bin_entry = by_path.get("bin")
    if bin_entry is None or bin_entry["kind"] != "directory":
        raise _blocked("environment-adapter-bin-missing")
    python_entry = by_path.get("bin/python")
    if python_entry is None or python_entry["kind"] != "file":
        raise _blocked("environment-adapter-python-missing")
    if int(python_entry["mode"], 8) & 0o111 == 0:
        raise _blocked("environment-adapter-python-not-executable")


# ---------------------------------------------------------------------------
# Immutable state records (O_EXCL, full write, fsync, reread).
# ---------------------------------------------------------------------------


def _read_doc_bytes(
    state_fd: int,
    name: str,
    token: str,
    expected_fingerprint: dict | None = None,
    durable: bool = False,
    return_fingerprint: bool = False,
) -> Any:
    fd: int | None = None
    try:
        try:
            fd = os.open(name, _FILE_OPEN_FLAGS, dir_fd=state_fd)
        except FileNotFoundError:
            raise _blocked(token + "-absent")
        except OSError:
            raise _blocked(token + "-open-failed")
        try:
            pre = os.fstat(fd)
        except OSError:
            raise _blocked(token + "-stat-failed")
        if (
            not stat.S_ISREG(pre.st_mode)
            or pre.st_uid != os.geteuid()
            or stat.S_IMODE(pre.st_mode) != STATE_FILE_MODE
            or pre.st_nlink != 1
            or pre.st_size > MAX_DOC_BYTES
        ):
            raise _blocked(token + "-shape")
        try:
            visible = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        except OSError:
            raise _blocked(token + "-stat-failed")
        if visible.st_dev != pre.st_dev or visible.st_ino != pre.st_ino:
            raise _blocked(token + "-substitution")
        held_full = _full_stat_fingerprint(pre)
        if (
            expected_fingerprint is not None
            and expected_fingerprint != held_full
        ):
            raise _blocked(token + "-fingerprint-mismatch")
        data = _read_fd_fully(fd, MAX_DOC_BYTES, token)
        if len(data) != pre.st_size:
            raise _blocked(token + "-shape")
        try:
            post = os.fstat(fd)
        except OSError:
            raise _blocked(token + "-stat-failed")
        if (
            post.st_dev != pre.st_dev
            or post.st_ino != pre.st_ino
            or post.st_mode != pre.st_mode
            or post.st_nlink != pre.st_nlink
            or post.st_size != pre.st_size
        ):
            raise _blocked(token + "-mutated")
        if _full_stat_fingerprint(post) != held_full:
            raise _blocked(token + "-mutated")
        if durable:
            try:
                os.fsync(fd)
            except OSError:
                raise _blocked(token + "-durability-failed")
        # Second parent-visible nofollow sample after the read: the name must
        # still resolve to the exact held inode with the full fingerprint.
        try:
            revisible = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        except OSError:
            raise _blocked(token + "-stat-failed")
        if _full_stat_fingerprint(revisible) != held_full:
            raise _blocked(token + "-substitution")
        # Strict pre-cleared close: never retried, never quietly accepted.
        pending_fd, fd = fd, None
        try:
            os.close(pending_fd)
        except OSError:
            raise _blocked(token + "-close-failed")
        if return_fingerprint:
            return data, held_full
        return data
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _persist_immutable_doc(
    state_fd: int, name: str, payload: bytes, token: str,
    tracker: _MutationTracker,
) -> str:
    """Create-or-verify one immutable state record. Returns 'written' or
    'existing'. Any ambiguity after bytes may have reached disk is
    outcome_unknown; no retry is attempted after an ambiguous close."""
    if len(payload) > MAX_DOC_BYTES:
        raise _blocked(token + "-too-large")
    # Issuing O_CREAT|O_EXCL is itself the write-attempt boundary. Mark it
    # before the syscall so deterministic refusal is reported as attempted
    # but unwritten, while an asynchronous BaseException is conservatively
    # surfaced by the public caller as outcome_unknown.
    tracker.mark_attempted()
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            STATE_FILE_MODE,
            dir_fd=state_fd,
        )
    except FileExistsError:
        existing, existing_fingerprint = _read_doc_bytes(
            state_fd, name, token, return_fingerprint=True
        )
        if existing != payload:
            raise _blocked(token + "-conflict")
        # Durability reconciliation for the equal existing document: fsync
        # the held file and the state directory before reporting existing.
        # The fsync pair is a write-side operation, so the attempt is
        # recorded before it runs.
        try:
            durable_bytes = _read_doc_bytes(
                state_fd,
                name,
                token,
                expected_fingerprint=existing_fingerprint,
                durable=True,
            )
            if durable_bytes != payload:
                raise _blocked(token + "-durability-content-mismatch")
            os.fsync(state_fd)
        except BaseException:
            tracker.mark_ambiguous()
            raise _unknown("state-doc-existing-durability-ambiguous")
        return "existing"
    except OSError:
        raise _blocked(token + "-create-failed")
    # Strict pre-cleared close: the descriptor is cleared before close so an
    # ambiguous close is never retried.
    pending_fd: int | None = fd
    try:
        os.fchmod(fd, STATE_FILE_MODE)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written == 0:
                raise OSError(errno.EIO, "zero-progress-write")
            view = view[written:]
        os.fsync(fd)
        created_fingerprint = _full_stat_fingerprint(os.fstat(fd))
        created_visible = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
        if (
            created_visible.st_dev != created_fingerprint["device"]
            or created_visible.st_ino != created_fingerprint["inode"]
        ):
            raise OSError(errno.EIO, "created-identity-mismatch")
        pending_fd = None
        os.close(fd)
    except BaseException:
        if pending_fd is not None:
            try:
                os.close(pending_fd)
            except OSError:
                pass
        tracker.mark_ambiguous()
        raise _unknown("state-doc-write-ambiguous")
    try:
        os.fsync(state_fd)
    except BaseException:
        tracker.mark_ambiguous()
        raise _unknown("state-doc-directory-sync-ambiguous")
    try:
        reread = _read_doc_bytes(
            state_fd, name, token, expected_fingerprint=created_fingerprint
        )
    except _StorageFailure:
        tracker.mark_ambiguous()
        raise _unknown("state-doc-reread-ambiguous")
    if reread != payload:
        tracker.mark_ambiguous()
        raise _unknown("state-doc-reread-mismatch")
    tracker.mark_written()
    return "written"


# ---------------------------------------------------------------------------
# Finalize / inspect / reconcile.
# ---------------------------------------------------------------------------


def _validate_roots(
    environment_authority_root: Any,
    environment_state_root: Any,
    stage_journal_root: Any,
    layout_plan: dict,
    request_sha256: str,
) -> tuple[str, str, str, str, str]:
    request_sha256 = _hex64(request_sha256, "request-sha256")
    authority = _validate_abs_path(
        environment_authority_root, "authority-root"
    )
    state_root = _validate_abs_path(environment_state_root, "state-root")
    journal_root = _validate_abs_path(stage_journal_root, "journal-root")
    environment_root = layout_plan["environment_root"]
    environment_parent = environment_root.rsplit("/", 1)[0]
    operations_dir = environment_parent + "/" + OPERATIONS_DIR_NAME
    if authority != environment_parent:
        raise _blocked("authority-root-not-environment-parent")
    if journal_root != layout_plan["updater_state_root"]:
        raise _blocked("journal-root-not-updater-state-root")
    state_name = STATE_ROOT_PREFIX + request_sha256
    if _ENTRY_NAME_RE.fullmatch(state_name) is None:
        raise _blocked("state-root-basename")
    if state_root != journal_root + "/" + state_name:
        raise _blocked("state-root-not-updater-state-derived")
    # The updater-root parent (journal) / state-child relation is the only
    # permitted overlap; every other pair must be disjoint even casefolded.
    for first, second, token in (
        (journal_root, authority, "journal-root-overlap"),
        (journal_root, environment_root, "journal-root-overlap"),
        (journal_root, operations_dir, "journal-root-overlap"),
        (state_root, authority, "state-root-overlap"),
        (state_root, environment_root, "state-root-overlap"),
        (state_root, operations_dir, "state-root-overlap"),
        (environment_root, operations_dir, "environment-operations-overlap"),
    ):
        if _overlaps(first.casefold(), second.casefold()):
            raise _blocked(token)
    environment_name = environment_root.rsplit("/", 1)[1]
    if _ENTRY_NAME_RE.fullmatch(environment_name) is None:
        raise _blocked("environment-root-basename")
    return (
        authority,
        state_root,
        journal_root,
        environment_parent,
        environment_name,
    )


def _reprove_absolute_root(
    path: str,
    held_fingerprint: dict,
    token: str,
    *,
    exact_private: bool = True,
) -> None:
    """Reopen an already-held absolute root nofollow segment-by-segment and
    require the reopened directory to match the held full fingerprint and the
    exact owner-private 0700 policy."""
    reopen_fds: list = []
    try:
        fd = _open_root_dir(path, reopen_fds, token)
        _require_private_dir(fd, token, exact_0700=exact_private)
        _held_full_fingerprint(fd, expected=held_fingerprint)
    finally:
        _close_quietly(reopen_fds)


def _reprove_named_child_dir(
    parent_fd: int, name: str, held_fd: int, token: str
) -> None:
    """Compare the held child-directory descriptor against the parent-visible
    nofollow view of the same name, requiring identity and exact policy."""
    try:
        held = os.fstat(held_fd)
    except OSError:
        raise _blocked(token + "-stat-failed")
    if (
        not stat.S_ISDIR(held.st_mode)
        or held.st_uid != os.geteuid()
        or stat.S_IMODE(held.st_mode) != PREIMAGE_DIR_MODE
    ):
        raise _blocked(token + "-policy")
    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise _blocked(token + "-stat-failed")
    if (
        visible.st_dev != held.st_dev
        or visible.st_ino != held.st_ino
        or visible.st_mode != held.st_mode
        or visible.st_nlink != held.st_nlink
    ):
        raise _blocked(token + "-substitution")


def _acquire_lock(
    state_fd: int,
    fds: list,
    *,
    exclusive: bool,
    tracker: _MutationTracker | None = None,
) -> tuple[int, dict, bool]:
    import fcntl

    open_flags = os.O_NOFOLLOW | os.O_CLOEXEC
    open_flags |= os.O_RDWR if exclusive else os.O_RDONLY
    lock_fd: int | None
    try:
        lock_fd = os.open(STATE_LOCK_NAME, open_flags, dir_fd=state_fd)
    except FileNotFoundError:
        lock_fd = None
    except OSError:
        raise _blocked("lock-open-failed")
    created = False
    if lock_fd is None:
        if not exclusive or tracker is None:
            raise _blocked("storage-state-absent")
        # As with immutable documents, the O_CREAT|O_EXCL call itself is the
        # mutation-attempt boundary, not the later successful return.
        tracker.mark_attempted()
        try:
            create_fd = os.open(
                STATE_LOCK_NAME,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                STATE_FILE_MODE,
                dir_fd=state_fd,
            )
        except FileExistsError:
            raise _blocked("lock-create-conflict")
        except OSError:
            raise _blocked("lock-create-failed")
        # Strict pre-cleared close: an ambiguous close is never retried.
        pending_fd: int | None = create_fd
        try:
            os.fchmod(create_fd, STATE_FILE_MODE)
            os.fsync(create_fd)
            pending_fd = None
            os.close(create_fd)
        except BaseException:
            if pending_fd is not None:
                try:
                    os.close(pending_fd)
                except OSError:
                    pass
            tracker.mark_ambiguous()
            raise _unknown("lock-create-ambiguous")
        try:
            os.fsync(state_fd)
        except BaseException:
            tracker.mark_ambiguous()
            raise _unknown("lock-create-directory-sync-ambiguous")
        try:
            lock_fd = os.open(STATE_LOCK_NAME, open_flags, dir_fd=state_fd)
        except BaseException:
            tracker.mark_ambiguous()
            raise _unknown("lock-create-reopen-ambiguous")
        tracker.mark_written()
        created = True
    fds.append(lock_fd)
    try:
        held = os.fstat(lock_fd)
    except OSError:
        raise _blocked("lock-stat-failed")
    if (
        not stat.S_ISREG(held.st_mode)
        or held.st_uid != os.geteuid()
        or stat.S_IMODE(held.st_mode) != STATE_FILE_MODE
        or held.st_nlink != 1
    ):
        raise _blocked("lock-shape")
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(lock_fd, operation | fcntl.LOCK_NB)
    except OSError:
        raise _blocked("finalize-lock-held")
    try:
        held_after = os.fstat(lock_fd)
        visible = os.stat(
            STATE_LOCK_NAME, dir_fd=state_fd, follow_symlinks=False
        )
    except OSError:
        raise _blocked("lock-stat-failed")
    if (
        held_after.st_dev != held.st_dev
        or held_after.st_ino != held.st_ino
        or held_after.st_mode != held.st_mode
        or held_after.st_nlink != held.st_nlink
        or visible.st_dev != held.st_dev
        or visible.st_ino != held.st_ino
    ):
        raise _blocked("lock-substitution")
    return lock_fd, _full_stat_fingerprint(held_after), created


def _reprove_lock(
    state_fd: int, lock_fd: int, held_fingerprint: dict
) -> None:
    """Reprove the held lock descriptor and its parent-visible identity."""
    try:
        held = os.fstat(lock_fd)
    except OSError:
        raise _blocked("lock-reproof-stat-failed")
    if (
        not stat.S_ISREG(held.st_mode)
        or held.st_uid != os.geteuid()
        or stat.S_IMODE(held.st_mode) != STATE_FILE_MODE
        or held.st_nlink != 1
        or _full_stat_fingerprint(held) != held_fingerprint
    ):
        raise _blocked("lock-reproof-held")
    try:
        visible = os.stat(
            STATE_LOCK_NAME, dir_fd=state_fd, follow_symlinks=False
        )
    except OSError:
        raise _blocked("lock-reproof-stat-failed")
    if (
        not stat.S_ISREG(visible.st_mode)
        or visible.st_uid != os.geteuid()
        or stat.S_IMODE(visible.st_mode) != STATE_FILE_MODE
        or visible.st_nlink != 1
        or visible.st_dev != held.st_dev
        or visible.st_ino != held.st_ino
    ):
        raise _blocked("lock-reproof-substitution")


_STATE_DOC_NAMES = (
    STATE_REQUEST_DOC_NAME,
    STATE_MANIFEST_DOC_NAME,
    STATE_PREPARE_DOC_NAME,
)


def _require_state_dir_names(state_fd: int, *, require_all: bool) -> None:
    """Exact state-directory name validation under the held descriptor.

    After lock acquisition only the lock plus any subset of the three fixed
    docs may exist; before success exactly the lock plus all three docs must
    exist. Unknown names are always rejected."""
    names = set(_snapshot_directory_names(state_fd))
    allowed = {STATE_LOCK_NAME, *_STATE_DOC_NAMES}
    if STATE_LOCK_NAME not in names:
        raise _blocked("state-dir-lock-missing")
    if names - allowed:
        raise _blocked("state-dir-unknown-entry")
    if require_all and names != allowed:
        raise _blocked("state-dir-docs-incomplete")


def _match_state_docs(
    state_fd: int,
    request_payload: bytes,
    manifest_payload: bytes,
    prepare_payload: bytes,
) -> None:
    """Read all three expected state docs and require exact byte equality.

    Strictly read-only: never creates or repairs a document."""
    for name, payload, token in (
        (STATE_REQUEST_DOC_NAME, request_payload, "request-record"),
        (STATE_MANIFEST_DOC_NAME, manifest_payload, "manifest-record"),
        (STATE_PREPARE_DOC_NAME, prepare_payload, "prepare-record"),
    ):
        if _read_doc_bytes(state_fd, name, token) != payload:
            raise _blocked(token + "-mismatch")


def _final_state_reproof(
    *,
    journal_root: str,
    journal_fingerprint: dict,
    journal_fd: int,
    state_name: str,
    state_fd: int,
    lock_fd: int,
    lock_fingerprint: dict,
    request_payload: bytes,
    manifest_payload: bytes,
    prepare_payload: bytes,
    request: dict,
    request_sha256: str,
    operation_name: str,
    environment_parent: str,
    environment_name: str,
    operation_fingerprint: dict,
    preimage_fingerprint: dict,
) -> None:
    """Common final reproof run immediately before every success return.

    Reproves the absolute journal root, the relative state child, the held
    and parent-visible lock, exact state names and doc bytes, the full stage
    journal, then the currently visible environment parent and operations
    dir, freshly opens the visible environment and retained operation paths
    (same device, exact 0700), rescans the published tree byte-equal to the
    manifest and reproves the retained exact empty preimage. Proof
    descriptors are strictly closed."""
    _reprove_absolute_root(
        journal_root, journal_fingerprint, "final-journal-root"
    )
    _reprove_named_child_dir(
        journal_fd, state_name, state_fd, "final-state-root"
    )
    _reprove_lock(state_fd, lock_fd, lock_fingerprint)
    _require_state_dir_names(state_fd, require_all=True)
    _match_state_docs(
        state_fd, request_payload, manifest_payload, prepare_payload
    )
    _verify_stage_journal(journal_fd, request)
    proof_fds: list = []
    try:
        parent_fd = _open_root_dir(
            environment_parent, proof_fds, "final-environment-parent"
        )
        parent_info = _require_private_dir(
            parent_fd, "final-environment-parent", exact_0700=True
        )
        parent_fingerprint = _full_stat_fingerprint(parent_info)
        try:
            ops_fd = os.open(
                OPERATIONS_DIR_NAME, _DIR_OPEN_FLAGS, dir_fd=parent_fd
            )
        except OSError:
            raise _blocked("final-operations-dir-open-failed")
        proof_fds.append(ops_fd)
        ops_info = _require_private_dir(
            ops_fd, "final-operations-dir", exact_0700=True
        )
        if ops_info.st_dev != parent_info.st_dev:
            raise _blocked("final-operations-dir-device-crossing")
        _reprove_named_child_dir(
            parent_fd, OPERATIONS_DIR_NAME, ops_fd, "final-operations-dir"
        )
        try:
            published_fd = os.open(
                environment_name, _DIR_OPEN_FLAGS, dir_fd=parent_fd
            )
        except OSError:
            raise _blocked("final-environment-open-failed")
        proof_fds.append(published_fd)
        published_info = _require_private_dir(
            published_fd, "final-environment-root", exact_0700=True
        )
        if published_info.st_dev != parent_info.st_dev:
            raise _blocked("final-environment-device-crossing")
        _reprove_named_child_dir(
            parent_fd, environment_name, published_fd, "final-environment-root"
        )
        try:
            retained_fd = os.open(
                operation_name, _DIR_OPEN_FLAGS, dir_fd=ops_fd
            )
        except OSError:
            raise _blocked("final-operation-open-failed")
        proof_fds.append(retained_fd)
        retained_info = _require_private_dir(
            retained_fd, "final-operation-tree", exact_0700=True
        )
        if retained_info.st_dev != parent_info.st_dev:
            raise _blocked("final-operation-device-crossing")
        _reprove_named_child_dir(
            ops_fd, operation_name, retained_fd, "final-operation-tree"
        )
        _directory_fingerprint(published_fd, operation_fingerprint)
        published_manifest = _scan_tree(
            published_fd, request, request_sha256, operation_name
        )
        if _canonical_json_bytes(published_manifest) != manifest_payload:
            raise _blocked("final-published-tree-mismatch")
        _empty_preimage_fingerprint(
            retained_fd,
            preimage_fingerprint,
            parent_fd=ops_fd,
            visible_name=operation_name,
        )
        # Bracket the complete content proofs with a second visible-name and
        # held-descriptor identity pass before accepting the point-in-time
        # result.
        _reprove_named_child_dir(
            parent_fd,
            OPERATIONS_DIR_NAME,
            ops_fd,
            "final-operations-dir-post",
        )
        _reprove_named_child_dir(
            parent_fd,
            environment_name,
            published_fd,
            "final-environment-root-post",
        )
        _reprove_named_child_dir(
            ops_fd,
            operation_name,
            retained_fd,
            "final-operation-tree-post",
        )
        _directory_fingerprint(published_fd, operation_fingerprint)
        while proof_fds:
            _strict_close_last(proof_fds, "final-reproof-close-failed")
    finally:
        _close_quietly(proof_fds)
    _reprove_absolute_root(
        environment_parent,
        parent_fingerprint,
        "final-environment-parent-post",
    )
    _reprove_absolute_root(
        journal_root, journal_fingerprint, "final-journal-root-post"
    )
    _reprove_named_child_dir(
        journal_fd, state_name, state_fd, "final-state-root-post"
    )
    _reprove_lock(state_fd, lock_fd, lock_fingerprint)
    _require_state_dir_names(state_fd, require_all=True)
    _match_state_docs(
        state_fd, request_payload, manifest_payload, prepare_payload
    )
    _verify_stage_journal(journal_fd, request)


def _open_publication_fds(
    environment_parent: str,
    environment_name: str,
    request_sha256: str,
    fds: list,
) -> tuple[int, int, int, int | None, str]:
    parent_fd = _open_root_dir(environment_parent, fds, "environment-parent")
    parent_info = _require_private_dir(
        parent_fd, "environment-parent", exact_0700=True
    )
    try:
        ops_fd = os.open(OPERATIONS_DIR_NAME, _DIR_OPEN_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise _blocked("operations-dir-absent")
    except OSError:
        raise _blocked("operations-dir-open-failed")
    fds.append(ops_fd)
    ops_info = _require_private_dir(ops_fd, "operations-dir", exact_0700=True)
    if ops_info.st_dev != parent_info.st_dev:
        raise _blocked("operations-dir-device-crossing")
    _reprove_named_child_dir(
        parent_fd, OPERATIONS_DIR_NAME, ops_fd, "operations-dir"
    )
    operation_name = OPERATION_PREFIX + request_sha256
    if _ENTRY_NAME_RE.fullmatch(operation_name) is None:
        raise _blocked("operation-id-basename")
    try:
        environment_fd = os.open(
            environment_name, _DIR_OPEN_FLAGS, dir_fd=parent_fd
        )
    except FileNotFoundError:
        raise _blocked("environment-root-absent")
    except OSError:
        raise _blocked("environment-root-open-failed")
    fds.append(environment_fd)
    environment_info = _require_private_dir(
        environment_fd, "environment-root", exact_0700=True
    )
    if environment_info.st_dev != parent_info.st_dev:
        raise _blocked("environment-root-device-crossing")
    _reprove_named_child_dir(
        parent_fd, environment_name, environment_fd, "environment-root"
    )
    operation_fd: int | None
    try:
        operation_fd = os.open(operation_name, _DIR_OPEN_FLAGS, dir_fd=ops_fd)
    except FileNotFoundError:
        operation_fd = None
    except OSError:
        raise _blocked("operation-tree-open-failed")
    if operation_fd is not None:
        fds.append(operation_fd)
        operation_info = _require_private_dir(
            operation_fd, "operation-tree", exact_0700=True
        )
        if operation_info.st_dev != parent_info.st_dev:
            raise _blocked("operation-tree-device-crossing")
        _reprove_named_child_dir(
            ops_fd, operation_name, operation_fd, "operation-tree"
        )
    return parent_fd, ops_fd, environment_fd, operation_fd, operation_name


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

# Compute once after every projected document keyset is defined. Runtime
# result construction and persisted documents use this frozen identifier, so
# a later projection-function mutation cannot break public failure totality.
STORAGE_CONTRACT_ID = environment_storage_contract_projection()["contract_id"]


def _state_doc_payloads(
    request: dict,
    layout_plan: dict,
    request_sha256: str,
    manifest: dict,
    operation_name: str,
    preimage_fingerprint: dict,
    operation_fingerprint: dict,
) -> tuple[bytes, bytes, bytes, str, str, str]:
    storage_contract_id = STORAGE_CONTRACT_ID
    layout_plan_sha256 = _raw_sha256(_canonical_json_bytes(layout_plan))
    request_record_body = {
        "schema": STORAGE_REQUEST_RECORD_SCHEMA,
        "storage_contract_id": storage_contract_id,
        "phase5a_contract_id": PHASE5A_CONTRACT_ID,
        "request": request,
        "request_sha256": request_sha256,
        "layout_id": layout_plan["layout_id"],
        "layout_plan_sha256": layout_plan_sha256,
        "stage_result_sha256": request["stage_result_sha256"],
        "stage_journal_entry_sha256": request["stage_journal_head_sha256"],
        "operation_id": operation_name,
        "environment_preimage_fingerprint": preimage_fingerprint,
        "operation_fingerprint": operation_fingerprint,
    }
    request_record_sha256 = _domain_sha256(REQUEST_DOMAIN, request_record_body)
    request_record = dict(request_record_body)
    request_record["request_record_sha256"] = request_record_sha256
    if tuple(sorted(request_record)) != tuple(
        sorted(STORAGE_REQUEST_RECORD_KEYS)
    ):
        raise _blocked("request-record-keyset")
    manifest_sha256 = _domain_sha256(TREE_MANIFEST_DOMAIN, manifest)
    prepare_body = {
        "schema": STORAGE_PREPARE_SCHEMA,
        "storage_contract_id": storage_contract_id,
        "request_record_sha256": request_record_sha256,
        "request_sha256": request_sha256,
        "operation_id": operation_name,
        "layout_id": layout_plan["layout_id"],
        "manifest_sha256": manifest_sha256,
        "manifest_entry_count": manifest["entry_count"],
        "manifest_total_bytes": manifest["total_bytes"],
        "environment_preimage_fingerprint": preimage_fingerprint,
        "operation_fingerprint": operation_fingerprint,
        "stage_result_sha256": request["stage_result_sha256"],
        "stage_journal_entry_sha256": request["stage_journal_head_sha256"],
    }
    prepare_sha256 = _domain_sha256(PREPARE_DOMAIN, prepare_body)
    prepare_record = dict(prepare_body)
    prepare_record["prepare_sha256"] = prepare_sha256
    if tuple(sorted(prepare_record)) != tuple(
        sorted(STORAGE_PREPARE_RECORD_KEYS)
    ):
        raise _blocked("prepare-record-keyset")
    return (
        _canonical_json_bytes(request_record),
        _canonical_json_bytes(manifest),
        _canonical_json_bytes(prepare_record),
        request_record_sha256,
        manifest_sha256,
        prepare_sha256,
    )


def _perform_swap(
    ops_fd: int,
    operation_name: str,
    operation_fd: int,
    parent_fd: int,
    environment_name: str,
    environment_fd: int,
    tracker: _MutationTracker,
) -> None:
    import ctypes

    swap = _bind_renameatx_np()
    if swap is None:
        raise _StorageFailure(
            STATUS_UNSUPPORTED, "unsupported:missing-renameatx-np-swap-capability"
        )
    # The complete content and policy scans happen immediately before this
    # helper. Rebind both rename operands to their held descriptors again at
    # the syscall boundary so a later name substitution cannot inherit those
    # earlier proofs. This is still subject to the explicit no-hostile-same-
    # uid/in-process-authenticity boundary, but closes the avoidable scan-to-
    # swap gap for ordinary races and injected failures.
    _reprove_named_child_dir(
        parent_fd, OPERATIONS_DIR_NAME, ops_fd, "swap-operations-dir"
    )
    _reprove_named_child_dir(
        ops_fd, operation_name, operation_fd, "swap-operation-tree"
    )
    _reprove_named_child_dir(
        parent_fd,
        environment_name,
        environment_fd,
        "swap-environment-preimage",
    )
    tracker.mark_attempted()
    try:
        ctypes.set_errno(0)
        code = swap(
            ops_fd,
            operation_name.encode("ascii"),
            parent_fd,
            environment_name.encode("ascii"),
            RENAME_SWAP_FLAG,
        )
        error = ctypes.get_errno()
    except BaseException:
        tracker.mark_ambiguous()
        raise _unknown("rename-swap-call-ambiguous")
    if code != 0:
        # Deterministic syscall error: no swap occurred; earlier record
        # truth in the tracker is preserved as-is. A volume without swap
        # support is discovered only after state writes, so it is an
        # internal blocked condition, never a pre-I/O unsupported claim.
        if error in (errno.ENOTSUP, errno.EINVAL):
            raise _blocked("rename-swap-not-supported-on-volume")
        raise _blocked("rename-swap-failed")
    tracker.mark_written()
    try:
        os.fsync(parent_fd)
        os.fsync(ops_fd)
    except BaseException:
        tracker.mark_ambiguous()
        raise _unknown("post-swap-directory-sync-ambiguous")


def _success_flags(
    *, write_supported: bool, wrote: bool, reconciled: bool
) -> dict[str, Any]:
    return {
        "storage_read_supported": True,
        "storage_write_supported": write_supported,
        "storage_read_performed": True,
        "storage_write_attempted": wrote,
        "storage_written": wrote,
        "stage_correlation_verified": True,
        "filesystem_verified": True,
        "access_verified": True,
        "environment_tree_verified": True,
        "environment_tree_published": True,
        "reconciled": reconciled,
    }


def _success_result(
    command: str,
    reason: str,
    request: dict,
    request_sha256: str,
    manifest_sha256: str,
    prepare_sha256: str,
    operation_name: str,
    *,
    write_supported: bool,
    wrote: bool,
    reconciled: bool,
) -> dict[str, Any]:
    storage_digest = _storage_digest(
        request_sha256, manifest_sha256, prepare_sha256
    )
    return _build_result(
        command,
        STATUS_SUCCESS,
        reason,
        flags=_success_flags(
            write_supported=write_supported, wrote=wrote, reconciled=reconciled
        ),
        digests={
            "request_sha256": request_sha256,
            "manifest_sha256": manifest_sha256,
            "prepare_sha256": prepare_sha256,
            "storage_digest": storage_digest,
        },
        identity={
            "operation_id": operation_name,
            "layout_plan_id": request["layout_id"],
            "product_id": request["candidate_product_id"],
            "policy_id": request["inventory_policy_id"],
        },
    )


def _finalize_impl(
    environment_authority_root: Any,
    environment_state_root: Any,
    stage_journal_root: Any,
    *,
    environment_request: Any,
    layout_plan: Any,
    stage_result: Any,
    tracker: _MutationTracker,
) -> dict[str, Any]:
    # Bound the three public path strings before replaying any caller document.
    _validate_abs_path(environment_authority_root, "authority-root")
    _validate_abs_path(environment_state_root, "state-root")
    _validate_abs_path(stage_journal_root, "journal-root")
    tracker.mark_read()
    phase5a, installed_layout_namespace = _verify_frozen_sibling_sources()
    request, request_sha256 = _validate_request(environment_request, phase5a)
    _validate_stage_result(stage_result, request)
    validated_plan = _validate_layout_plan(
        layout_plan, request, stage_result, installed_layout_namespace
    )
    _, state_root, journal_root, environment_parent, environment_name = (
        _validate_roots(
            environment_authority_root,
            environment_state_root,
            stage_journal_root,
            validated_plan,
            request_sha256,
        )
    )
    fds: list = []
    try:
        journal_fd = _open_root_dir(journal_root, fds, "journal-root")
        _require_private_dir(journal_fd, "journal-root", exact_0700=True)
        journal_fingerprint = _held_full_fingerprint(journal_fd)
        _verify_stage_journal(journal_fd, request)

        # The derived state directory is opened only by its single basename
        # relative to the already-held journal root, never by a second
        # absolute chain.
        state_name = state_root[len(journal_root) + 1:]
        try:
            state_fd = os.open(state_name, _DIR_OPEN_FLAGS, dir_fd=journal_fd)
        except FileNotFoundError:
            raise _blocked("state-root-absent")
        except OSError:
            raise _blocked("state-root-open-failed")
        fds.append(state_fd)
        _require_private_dir(state_fd, "state-root", exact_0700=True)
        _reprove_named_child_dir(journal_fd, state_name, state_fd, "state-root")
        lock_fd, lock_fingerprint, lock_created = _acquire_lock(
            state_fd, fds, exclusive=True, tracker=tracker
        )
        _require_state_dir_names(state_fd, require_all=False)

        parent_fd, ops_fd, environment_fd, operation_fd, operation_name = (
            _open_publication_fds(
                environment_parent, environment_name, request_sha256, fds
            )
        )
        parent_fingerprint = _held_full_fingerprint(parent_fd)
        if operation_fd is None:
            raise _blocked("operation-tree-absent")

        environment_is_preimage = not _snapshot_directory_names(environment_fd)
        if environment_is_preimage:
            preimage_fingerprint = _empty_preimage_fingerprint(
                environment_fd,
                parent_fd=parent_fd,
                visible_name=environment_name,
            )
            operation_fingerprint = _directory_fingerprint(operation_fd)
            manifest = _scan_tree(
                operation_fd, request, request_sha256, operation_name
            )
        else:
            manifest = _scan_tree(
                environment_fd, request, request_sha256, operation_name
            )
            preimage_fingerprint = _empty_preimage_fingerprint(
                operation_fd,
                parent_fd=ops_fd,
                visible_name=operation_name,
            )
            operation_fingerprint = _directory_fingerprint(environment_fd)
        _require_adapter_presence(manifest)

        (
            request_payload,
            manifest_payload,
            prepare_payload,
            request_record_sha256,
            manifest_sha256,
            prepare_sha256,
        ) = _state_doc_payloads(
            request,
            validated_plan,
            request_sha256,
            manifest,
            operation_name,
            preimage_fingerprint,
            operation_fingerprint,
        )
        _reprove_lock(state_fd, lock_fd, lock_fingerprint)
        _reprove_absolute_root(journal_root, journal_fingerprint, "journal-root")
        _reprove_named_child_dir(journal_fd, state_name, state_fd, "state-root")

        if not environment_is_preimage:
            # Already published: strictly read-only. The lock must have
            # preexisted and all three docs must already exist and match;
            # this branch never persists any state document.
            if lock_created:
                raise _blocked("already-present-lock-not-preexisting")
            _final_state_reproof(
                journal_root=journal_root,
                journal_fingerprint=journal_fingerprint,
                journal_fd=journal_fd,
                state_name=state_name,
                state_fd=state_fd,
                lock_fd=lock_fd,
                lock_fingerprint=lock_fingerprint,
                request_payload=request_payload,
                manifest_payload=manifest_payload,
                prepare_payload=prepare_payload,
                request=request,
                request_sha256=request_sha256,
                operation_name=operation_name,
                environment_parent=environment_parent,
                environment_name=environment_name,
                operation_fingerprint=operation_fingerprint,
                preimage_fingerprint=preimage_fingerprint,
            )
            if tracker.write_attempted or tracker.known_written:
                raise _blocked("already-present-unexpected-write")
            return _success_result(
                COMMAND_FINALIZE,
                SUCCESS_REASONS[1],
                request,
                request_sha256,
                manifest_sha256,
                prepare_sha256,
                operation_name,
                write_supported=True,
                wrote=False,
                reconciled=False,
            )

        outcomes = (
            _persist_immutable_doc(
                state_fd, STATE_REQUEST_DOC_NAME, request_payload,
                "request-record", tracker,
            ),
            _persist_immutable_doc(
                state_fd, STATE_MANIFEST_DOC_NAME, manifest_payload,
                "manifest-record", tracker,
            ),
            _persist_immutable_doc(
                state_fd, STATE_PREPARE_DOC_NAME, prepare_payload,
                "prepare-record", tracker,
            ),
        )
        docs_preexisted = all(outcome == "existing" for outcome in outcomes)

        rescan = _scan_tree(
            operation_fd, request, request_sha256, operation_name
        )
        if _canonical_json_bytes(rescan) != manifest_payload:
            raise _blocked("operation-tree-rescan-mismatch")
        _verify_stage_journal(journal_fd, request)

        _reprove_lock(state_fd, lock_fd, lock_fingerprint)
        _reprove_absolute_root(journal_root, journal_fingerprint, "journal-root")
        _reprove_named_child_dir(journal_fd, state_name, state_fd, "state-root")
        _reprove_absolute_root(
            environment_parent, parent_fingerprint, "environment-parent"
        )
        # Bind every visible swap operand to its held descriptor at the last
        # pre-mutation boundary, then repeat the complete tree and empty
        # preimage proofs.  renameatx_np receives only these exact names.
        _reprove_named_child_dir(
            parent_fd, OPERATIONS_DIR_NAME, ops_fd, "pre-swap-operations-dir"
        )
        _reprove_named_child_dir(
            ops_fd, operation_name, operation_fd, "pre-swap-operation-tree"
        )
        _reprove_named_child_dir(
            parent_fd,
            environment_name,
            environment_fd,
            "pre-swap-environment-preimage",
        )
        _empty_preimage_fingerprint(
            environment_fd,
            preimage_fingerprint,
            parent_fd=parent_fd,
            visible_name=environment_name,
        )
        _directory_fingerprint(operation_fd, operation_fingerprint)
        boundary_rescan = _scan_tree(
            operation_fd, request, request_sha256, operation_name
        )
        if _canonical_json_bytes(boundary_rescan) != manifest_payload:
            raise _blocked("pre-swap-operation-tree-mismatch")
        _require_state_dir_names(state_fd, require_all=True)
        _match_state_docs(
            state_fd, request_payload, manifest_payload, prepare_payload
        )
        _verify_stage_journal(journal_fd, request)
        _reprove_lock(state_fd, lock_fd, lock_fingerprint)

        _perform_swap(
            ops_fd,
            operation_name,
            operation_fd,
            parent_fd,
            environment_name,
            environment_fd,
            tracker,
        )

        # Reprove both sides after the exchange. The originally held
        # descriptors follow their inodes across the swap: the held preimage
        # descriptor must now sit at the operation path (never reclaimed),
        # and freshly reopened paths must show the exchanged content.
        try:
            _empty_preimage_fingerprint(
                environment_fd,
                preimage_fingerprint,
                parent_fd=ops_fd,
                visible_name=operation_name,
            )
            _final_state_reproof(
                journal_root=journal_root,
                journal_fingerprint=journal_fingerprint,
                journal_fd=journal_fd,
                state_name=state_name,
                state_fd=state_fd,
                lock_fd=lock_fd,
                lock_fingerprint=lock_fingerprint,
                request_payload=request_payload,
                manifest_payload=manifest_payload,
                prepare_payload=prepare_payload,
                request=request,
                request_sha256=request_sha256,
                operation_name=operation_name,
                environment_parent=environment_parent,
                environment_name=environment_name,
                operation_fingerprint=operation_fingerprint,
                preimage_fingerprint=preimage_fingerprint,
            )
        except _StorageFailure as failure:
            if failure.status == STATUS_BLOCKED:
                raise _unknown("post-swap-reproof-failed")
            raise
        except OSError:
            raise _unknown("post-swap-reproof-failed")

        # Success truth derives from the mutation tracker and the actual
        # branch taken: the swap always marks a known write here, and a
        # newly created lock can never yield a reconciled no-write claim.
        if not tracker.known_written:
            raise _blocked("swap-branch-write-truth-missing")
        reconciled = docs_preexisted and not lock_created
        reason = SUCCESS_REASONS[2] if reconciled else SUCCESS_REASONS[0]
        return _success_result(
            COMMAND_FINALIZE,
            reason,
            request,
            request_sha256,
            manifest_sha256,
            prepare_sha256,
            operation_name,
            write_supported=True,
            wrote=True,
            reconciled=reconciled,
        )
    finally:
        _close_quietly(fds)


def _inspect_impl(
    environment_authority_root: Any,
    environment_state_root: Any,
    stage_journal_root: Any,
    *,
    environment_request: Any,
    layout_plan: Any,
    stage_result: Any,
    tracker: _MutationTracker,
) -> dict[str, Any]:
    # Bound the three public path strings before replaying any caller document.
    _validate_abs_path(environment_authority_root, "authority-root")
    _validate_abs_path(environment_state_root, "state-root")
    _validate_abs_path(stage_journal_root, "journal-root")
    tracker.mark_read()
    phase5a, installed_layout_namespace = _verify_frozen_sibling_sources()
    request, request_sha256 = _validate_request(environment_request, phase5a)
    _validate_stage_result(stage_result, request)
    validated_plan = _validate_layout_plan(
        layout_plan, request, stage_result, installed_layout_namespace
    )
    _, state_root, journal_root, environment_parent, environment_name = (
        _validate_roots(
            environment_authority_root,
            environment_state_root,
            stage_journal_root,
            validated_plan,
            request_sha256,
        )
    )
    fds: list = []
    try:
        journal_fd = _open_root_dir(journal_root, fds, "journal-root")
        _require_private_dir(journal_fd, "journal-root", exact_0700=True)
        journal_fingerprint = _held_full_fingerprint(journal_fd)
        _verify_stage_journal(journal_fd, request)

        # The derived state directory is opened only by its single basename
        # relative to the already-held journal root, never by a second
        # absolute chain.
        state_name = state_root[len(journal_root) + 1:]
        try:
            state_fd = os.open(state_name, _DIR_OPEN_FLAGS, dir_fd=journal_fd)
        except FileNotFoundError:
            raise _blocked("state-root-absent")
        except OSError:
            raise _blocked("state-root-open-failed")
        fds.append(state_fd)
        _require_private_dir(state_fd, "state-root", exact_0700=True)
        _reprove_named_child_dir(journal_fd, state_name, state_fd, "state-root")
        lock_fd, lock_fingerprint, _lock_created = _acquire_lock(
            state_fd, fds, exclusive=False
        )
        _require_state_dir_names(state_fd, require_all=False)

        parent_fd, ops_fd, environment_fd, operation_fd, operation_name = (
            _open_publication_fds(
                environment_parent, environment_name, request_sha256, fds
            )
        )
        if operation_fd is None:
            raise _blocked("operation-preimage-absent")

        manifest = _scan_tree(
            environment_fd, request, request_sha256, operation_name
        )
        _require_adapter_presence(manifest)
        preimage_fingerprint = _empty_preimage_fingerprint(
            operation_fd,
            parent_fd=ops_fd,
            visible_name=operation_name,
        )
        operation_fingerprint = _directory_fingerprint(environment_fd)

        (
            request_payload,
            manifest_payload,
            prepare_payload,
            request_record_sha256,
            manifest_sha256,
            prepare_sha256,
        ) = _state_doc_payloads(
            request,
            validated_plan,
            request_sha256,
            manifest,
            operation_name,
            preimage_fingerprint,
            operation_fingerprint,
        )
        _final_state_reproof(
            journal_root=journal_root,
            journal_fingerprint=journal_fingerprint,
            journal_fd=journal_fd,
            state_name=state_name,
            state_fd=state_fd,
            lock_fd=lock_fd,
            lock_fingerprint=lock_fingerprint,
            request_payload=request_payload,
            manifest_payload=manifest_payload,
            prepare_payload=prepare_payload,
            request=request,
            request_sha256=request_sha256,
            operation_name=operation_name,
            environment_parent=environment_parent,
            environment_name=environment_name,
            operation_fingerprint=operation_fingerprint,
            preimage_fingerprint=preimage_fingerprint,
        )

        # Inspect success truthfully claims no write support at all.
        return _success_result(
            COMMAND_INSPECT,
            SUCCESS_REASONS[3],
            request,
            request_sha256,
            manifest_sha256,
            prepare_sha256,
            operation_name,
            write_supported=False,
            wrote=False,
            reconciled=False,
        )
    finally:
        _close_quietly(fds)

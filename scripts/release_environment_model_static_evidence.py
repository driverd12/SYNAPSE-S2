"""Dormant Phase-5B3b held-root environment-static evidence fragment.

This module is a read-only bridge between the frozen Phase-5B1 storage
inspector and the frozen Phase-5B2 documentary evidence contract.  It emits
the environment, installed-distribution, and model static document roles;
native-file evidence remains deliberately pending.  It never completes an
evidence set, runs a model or candidate, performs a dynamic probe, issues a
receipt, or changes configuration, services, selectors, journals, or
activation state.

The two upstream modules are read through held descriptors, hash checked, and
executed in private namespaces.  Materialization copies, installed
distributions, and the model snapshot are independently read from the
descriptor supplied by B1's private held-snapshot seam; no caller may supply a
plan, path, descriptor, or observer.
"""

import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
from typing import Any


CONTRACT_SCHEMA = "synapse-s2.release-environment-static-contract.v1"
FRAGMENT_SCHEMA = "synapse-s2.release-environment-static-fragment.v1"
RESULT_SCHEMA = "synapse-s2.release-environment-static-result.v1"
RENDER_SCHEMA = "synapse-s2.release-environment-static-render.v1"
SOURCE_IDENTITY_SCHEMA = (
    "synapse-s2.release-environment-installed-source-identity.v1"
)

MODE = "held-root-environment-static-fragment"
COMMAND = "inspect-prebuilt-environment-static-evidence"

CONTRACT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STATIC-CONTRACT\0v1\0"
)
FRAGMENT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STATIC-FRAGMENT\0v1\0"
)
RESULT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STATIC-RESULT\0v1\0"
)
SOURCE_IDENTITY_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-INSTALLED-SOURCE-IDENTITY\0v1\0"
)
WHEEL_TAGS_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-WHEEL-TAGS\0v1\0"
)

PHASE5B1_SOURCE_SHA256 = (
    "3aa1fbc1042ddc05b3482ad657d8e41d8f62e02debcc2c897e4ca3ba20574bb0"
)
PHASE5B1_CONTRACT_ID = (
    "environment-storage-contract-"
    "9d10496d94003ad2d46905f19155de31c48a3834914c60469a739a73298c20aa"
)
PHASE5B2_SOURCE_SHA256 = (
    "af214b2938fa0c2909730d590f515900709d370e264c32df8192844a6ccea5bf"
)
PHASE5B2_CONTRACT_ID = (
    "environment-evidence-contract-"
    "924123716d28c35acfe78fc833cfc9c2ac1703e9c01fd7eba265332a6312b3e2"
)
ENVIRONMENT_POLICY_ID = (
    "environment-policy-"
    "d739e429e1be375f2cf762312acf5a0b8d84b7854baad2436c0c6f1be279b5db"
)
UPSTREAM_COMPATIBILITY_PROFILE_VERSION = 3

STATUS_SUCCESS = "success"
STATUS_UNSUPPORTED = "unsupported"
STATUS_BLOCKED = "blocked"
SUCCESS_REASON = "produced:environment-static-fragment-held-snapshot"
UNSUPPORTED_REASON = "unsupported:environment-static-fragment-platform"
BLOCKED_REASON = "blocked:environment-static-fragment-refused"
STATUS_REASON_EXIT_BINDINGS = (
    (STATUS_SUCCESS, SUCCESS_REASON, 0),
    (STATUS_UNSUPPORTED, UNSUPPORTED_REASON, 2),
    (STATUS_BLOCKED, BLOCKED_REASON, 3),
)
_EXIT_CODES = {status: code for status, _reason, code in STATUS_REASON_EXIT_BINDINGS}

HELD_SNAPSHOT_CONTEXT_KEYS = (
    "environment_root_fd",
    "environment_request_json",
    "environment_request_sha256",
    "storage_request_record_json",
    "storage_request_record_sha256",
    "storage_manifest_json",
    "storage_manifest_sha256",
    "storage_prepare_record_json",
    "storage_prepare_sha256",
    "storage_digest",
    "operation_id",
)
ENVIRONMENT_FRAGMENT_KEYS = (
    "environment_request",
    "environment_request_sha256",
    "layout_plan",
    "stage_result",
    "storage_request_record",
    "storage_request_record_sha256",
    "storage_prepare_record",
    "storage_prepare_sha256",
    "storage_manifest",
    "storage_manifest_sha256",
    "storage_digest",
)
MODEL_FRAGMENT_KEYS = ("model_manifest", "model_manifest_sha256")
INSTALLED_FRAGMENT_KEYS = (
    "installed_distribution_manifest",
    "installed_distribution_manifest_sha256",
    "wheel_metadata_semantics",
)
WHEEL_METADATA_SEMANTICS_KEYS = (
    "normalized_name",
    "wheel_sha256",
    "wheel_version",
    "root_is_purelib",
    "generator_sha256",
    "tag_count",
    "tags_sha256",
)
SOURCE_IDENTITY_PREIMAGE_KEYS = (
    "schema",
    "source_kind",
    "normalized_name",
    "version",
    "dependency_component_id",
    "dependency_lock_sha256",
    "project_metadata_sha256",
    "wheel_version",
    "wheel_root_is_purelib",
    "wheel_generator_sha256",
    "wheel_tag_count",
    "wheel_tags_sha256",
    "metadata_sha256",
    "wheel_sha256",
    "record_sha256",
    "direct_url_sha256",
)
STATIC_ROLES_PRESENT = (
    "environment_manifest_sha256",
    "installed_distribution_manifest_sha256",
    "model_manifest_sha256",
)
STATIC_ROLES_PENDING = (
    "native_file_manifest_sha256",
)
FRAGMENT_KEYS = (
    "schema",
    "mode",
    "environment_static_contract_id",
    "phase5b1_source_sha256",
    "phase5b1_contract_id",
    "phase5b2_source_sha256",
    "phase5b2_contract_id",
    "environment_policy_id",
    "environment",
    "installed",
    "model",
    "static_roles_present",
    "static_roles_pending",
    "static_evidence_complete",
    "fragment_sha256",
)
FIXED_FALSE_RESULT_FIELDS = (
    "static_evidence_complete",
    "evidence_verified",
    "receipt_issuable",
    "receipt_published",
    "dynamic_probe_performed",
    "candidate_executed",
    "activation_performed",
)
_SUCCESS_TRUE_RESULT_FIELDS = (
    "document_valid",
    "held_snapshot_reproved",
    "environment_static_fragment_produced",
)
RESULT_KEYS = (
    "schema",
    "command",
    "status",
    "reason",
    "environment_static_contract_id",
    "environment_policy_id",
    "storage_inspect_result",
    "environment_static_fragment",
    "environment_static_fragment_sha256",
    "document_valid",
    "held_snapshot_reproved",
    "environment_static_fragment_produced",
    "static_evidence_complete",
    "evidence_verified",
    "receipt_issuable",
    "receipt_published",
    "dynamic_probe_performed",
    "candidate_executed",
    "activation_performed",
    "nonclaims",
    "result_sha256",
)
RENDER_KEYS = (
    "schema",
    "result_schema",
    "command",
    "status",
    "reason",
    "environment_static_contract_id",
    "environment_policy_id",
    "environment_static_fragment_sha256",
    "document_valid",
    "held_snapshot_reproved",
    "environment_static_fragment_produced",
    "static_evidence_complete",
    "evidence_verified",
    "receipt_issuable",
    "receipt_published",
    "dynamic_probe_performed",
    "candidate_executed",
    "activation_performed",
    "result_sha256",
)
CONTRACT_BODY_KEYS = (
    "schema",
    "mode",
    "command",
    "phase5b1_source_sha256",
    "phase5b1_contract_id",
    "phase5b2_source_sha256",
    "phase5b2_contract_id",
    "environment_policy_id",
    "upstream_compatibility_profile_version",
    "fragment_schema",
    "result_schema",
    "render_schema",
    "held_snapshot_context_keys",
    "environment_fragment_keys",
    "installed_fragment_keys",
    "model_fragment_keys",
    "fragment_keys",
    "result_keys",
    "render_keys",
    "static_roles_present",
    "static_roles_pending",
    "fixed_false_result_fields",
    "status_reason_exit_bindings",
    "model_cache_binding",
    "installed_distribution_binding",
    "python_site_packages_policy",
    "metadata_header_policy",
    "wheel_header_policy",
    "record_policy",
    "capture_policy",
    "wheel_metadata_semantics_keys",
    "source_identity_preimage_keys",
    "environment_document_bindings",
    "domains",
    "canonicalization",
    "limits",
    "nonclaims",
)
CONTRACT_KEYS = CONTRACT_BODY_KEYS + ("contract_id",)

NONCLAIMS = (
    "partial-static-document-only",
    "no-complete-static-evidence-set",
    "no-environment-evidence-set",
    "no-native-file-manifest",
    "no-original-wheel-archive-hash-or-provenance",
    "wheel-sha256-means-raw-wheel-metadata-only",
    "no-original-archive-index-source-build-or-resolver-provenance",
    "no-wheel-tag-runtime-or-native-compatibility-proof",
    "no-archive-path-url-or-payload-input",
    "metadata-wheel-parsing-is-held-snapshot-producer-observation",
    "post-return-replay-correlates-digests-and-source-identity-not-raw-bytes",
    "no-full-core-metadata-semantic-validation",
    "no-raw-wheel-generator-or-tag-values-in-result",
    "no-uv-resolution-or-lock-provenance",
    "no-installed-importability-claim",
    "producer-emits-wheel-source-kind-only",
    "source-kind-wheel-is-installed-wheel-metadata-classification-only",
    "no-wheel-archive-origin-or-materialization-provenance",
    "non-null-git-direct-url-uninhabited-under-frozen-phase5b2-validator",
    "no-inventory-policy-admission-or-currentness",
    "no-compatibility-profile-admission-or-currentness",
    "no-outside-site-packages-or-install-scheme-evidence",
    "no-dependency-probe",
    "no-interpreter-observation",
    "no-toolchain-observation",
    "no-model-probe",
    "no-model-load-or-inference",
    "no-candidate-import-or-execution",
    "no-evidence-authentication-or-provenance",
    "no-receipt-or-environment-identity",
    "no-compatibility-ticket-or-result-verification",
    "no-network-access",
    "no-clock-access",
    "no-process-inspection",
    "no-activation",
    "no-configuration-or-service-write",
    "no-selector-floor-or-journal-write",
    "no-post-return-immutability-guarantee",
    "coordinated-unauthenticated-raw-semantics-rehash-forgery-not-prevented",
    "no-result-authentication",
    "no-hostile-interpreter-or-in-process-runtime-authenticity",
    "no-b3-source-self-authentication",
    "no-untrusted-observer-containment",
)

MAX_CONTRACT_BYTES = 98_304
MAX_FRAGMENT_BYTES = 16_000_000
MAX_RESULT_BYTES = 16_000_000
MAX_RENDER_BYTES = 4096
MAX_SOURCE_BYTES = 2_000_000
MAX_DOCUMENT_DEPTH = 12
MAX_DOCUMENT_ITEMS = 500_000
MAX_STRING_CHARACTERS = 4096
MAX_PATH_LENGTH = 3500
MAX_TREE_DEPTH = 24
MAX_TREE_ENTRIES = 20_000
MAX_TREE_FILE_BYTES = 1024 * 1024 * 1024
MAX_TREE_TOTAL_BYTES = 6 * 1024 * 1024 * 1024
MAX_CONTROL_FILE_BYTES = 2 * 1024 * 1024
MAX_CAPTURED_CONTROL_BYTES = 64 * 1024 * 1024
MAX_MATERIALIZATION_CAPTURED_BYTES = 4 * 1024 * 1024
MAX_RECORD_ROWS = 20_000
MAX_DISTRIBUTIONS = 2048
MAX_METADATA_HEADERS = 4096
MAX_WHEEL_HEADERS = 256
MAX_HEADER_LINE_BYTES = 4096
MAX_GENERATOR_CHARACTERS = 256
MAX_WHEEL_TAGS = 128
MAX_NATIVE_INT = 2**64 - 1
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
MATERIALIZATION_ROOT_RELATIVE = "share/synapse-s2/materialization-v1"
MATERIALIZATION_FILES = (
    ("uv.lock", "dependency_lock_sha256"),
    ("pyproject.toml", "project_metadata_sha256"),
)
SITE_PACKAGES_IMPLEMENTATION = "cpython"
SITE_PACKAGES_PYTHON_MAJOR = 3
SITE_PACKAGES_MINOR_MINIMUM = 8
SITE_PACKAGES_MINOR_MAXIMUM = 99
SITE_PACKAGES_MINOR_DECIMAL_POLICY = "canonical-no-leading-zero"
SITE_PACKAGES_ABI_PATTERN = r"\Acp(3)([0-9]{1,2})\Z"
SITE_PACKAGES_PATH_TEMPLATE = "lib/python{major}.{minor}/site-packages"
PYTHON_SITE_PACKAGES_POLICY = (
    ("implementation_request_field", "target_python_implementation"),
    ("abi_request_field", "target_python_abi"),
    ("implementation", SITE_PACKAGES_IMPLEMENTATION),
    ("abi_pattern", SITE_PACKAGES_ABI_PATTERN),
    ("python_major", SITE_PACKAGES_PYTHON_MAJOR),
    ("minor_minimum", SITE_PACKAGES_MINOR_MINIMUM),
    ("minor_maximum", SITE_PACKAGES_MINOR_MAXIMUM),
    ("minor_decimal", SITE_PACKAGES_MINOR_DECIMAL_POLICY),
    ("site_packages_template", SITE_PACKAGES_PATH_TEMPLATE),
)
PYTHON_SITE_PACKAGES_POLICY_KEYS = tuple(
    key for key, _value in PYTHON_SITE_PACKAGES_POLICY
)
RECORD_ENCODING = "utf-8"
RECORD_COLUMN_COUNT = 3
RECORD_PATH_MAX_CHARACTERS = 1024
RECORD_HASH_ALGORITHM = "sha256"
RECORD_HASH_B64_LENGTH = 43
RECORD_DIGEST_BYTES = 32
RECORD_DELIMITER = ","
RECORD_LINE_ENDING = "\n"
INSTALLED_PATH_COMPONENT_PATTERN = r"\A[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}\Z"
RECORD_EXECUTABLE_SELECTOR_KEYS = (
    "encoding",
    "nul_codepoint",
    "max_bytes",
    "row_count_minimum",
    "row_count_maximum",
    "column_count",
    "csv_reader_newline",
    "csv_strict",
    "path_max_characters",
    "path_separator",
    "backslash_character",
    "absolute_path_prefix",
    "path_components",
    "path_components_forbidden",
    "hash_algorithm",
    "hash_urlsafe_base64_character_class",
    "hash_urlsafe_base64_characters",
    "hash_decoded_bytes",
    "hash_assignment_separator",
    "hash_decode_padding",
    "decimal_zero_character",
    "empty_field",
    "canonical_path_encoding",
    "delimiter",
    "line_ending",
)
RECORD_POLICY = (
    (
        "row_roles",
        "all-rows-normative-documentary-semantics-with-listed-runtime-selectors",
    ),
    (
        "executable_selector_keys",
        ",".join(RECORD_EXECUTABLE_SELECTOR_KEYS),
    ),
    ("encoding", RECORD_ENCODING),
    ("nul", "forbidden"),
    ("nul_codepoint", 0),
    ("max_bytes", MAX_CONTROL_FILE_BYTES),
    ("row_count_minimum", 1),
    ("row_count_maximum", MAX_RECORD_ROWS),
    ("row_iteration", "streaming-refuse-before-over-limit-row-processing"),
    ("column_count", RECORD_COLUMN_COUNT),
    ("csv_reader_newline", ""),
    ("csv_strict", 1),
    ("path_root", "exact-derived-site-packages-relative-root"),
    ("path_max_characters", RECORD_PATH_MAX_CHARACTERS),
    ("path_separator", "/"),
    ("backslash", "forbidden"),
    ("backslash_character", "\\"),
    ("absolute_path_prefix", "/"),
    ("path_components", INSTALLED_PATH_COMPONENT_PATTERN),
    ("path_components_forbidden", ",.,.."),
    ("path_uniqueness", "raw-and-unicode-casefold"),
    ("target", "observed-regular-file-under-exact-site-packages-root"),
    ("hash_algorithm", RECORD_HASH_ALGORITHM),
    ("hash_urlsafe_base64_character_class", "A-Za-z0-9_-"),
    ("hash_urlsafe_base64_characters", RECORD_HASH_B64_LENGTH),
    ("hash_decoded_bytes", RECORD_DIGEST_BYTES),
    ("hash_assignment_separator", "="),
    ("hash_decode_padding", "="),
    (
        "hash",
        "exact-sha256-equals-43-urlsafe-base64-no-padding-decodes-32-bytes",
    ),
    ("hash_binding", "decoded-digest-equals-observed-raw-file-sha256"),
    ("size", "canonical-decimal-no-leading-zero-equals-observed-size"),
    ("decimal_zero_character", "0"),
    ("self_record", "sole-self-row-must-have-empty-hash-and-size"),
    ("empty_field", ""),
    ("canonical_path_encoding", "ascii"),
    ("delimiter", RECORD_DELIMITER),
    ("line_ending", RECORD_LINE_ENDING),
    ("quoting", "forbidden"),
    (
        "canonical_csv",
        "ascii-path-sorted-unquoted-comma-three-columns-LF",
    ),
    ("dist_info_ownership", "each-dist-info-file-owned-by-own-record"),
    ("cross_distribution", "no-overlap-and-full-observed-file-ownership"),
    (
        "replay_limitation",
        "raw-record-bytes-not-carried-reconstruct-documentary-canonical-form",
    ),
)
RECORD_POLICY_KEYS = tuple(key for key, _value in RECORD_POLICY)
INSTALLED_DISTRIBUTION_BINDING = (
    ("python_implementation", "request:target_python_implementation=cpython"),
    ("python_abi", "exact-projected-python-site-packages-policy"),
    ("site_packages", "derived-by-projected-python-site-packages-policy"),
    ("materialization_root", MATERIALIZATION_ROOT_RELATIVE),
    ("dependency_lock", "uv.lock:raw-sha256=request:dependency_lock_sha256"),
    (
        "project_metadata",
        "pyproject.toml:raw-sha256=request:project_metadata_sha256",
    ),
    (
        "metadata",
        "raw-METADATA-sha256-and-bounded-supported-Metadata-Version-Name-Version",
    ),
    (
        "metadata_version",
        "singleton-supported-core-metadata-version-1.1-1.2-or-2.1-through-2.6",
    ),
    ("wheel", "strictly-parsed-raw-dist-info-WHEEL-metadata"),
    ("wheel_sha256", "raw-dist-info-WHEEL-bytes-not-wheel-archive"),
    ("record", "exact-projected-record-policy"),
    ("distribution_cardinality", "one-through-2048"),
    (
        "source_kind",
        "wheel-means-strict-dist-info-controls-record-complete-and-direct-url-absent",
    ),
    (
        "direct_url",
        "absent-emitted-wheel-or-strict-sanitized-git-input-fail-closed",
    ),
    (
        "dist_info_tree_shape",
        "exact-case-top-level-dist-info-name-requires-directory-kind-in-producer-and-replay",
    ),
    (
        "source_identity",
        "domain-separated-canonical-source-identity-preimage-keys",
    ),
)
SUPPORTED_METADATA_VERSIONS = (
    "1.1",
    "1.2",
    "2.1",
    "2.2",
    "2.3",
    "2.4",
    "2.5",
    "2.6",
)
SUPPORTED_WHEEL_VERSION = "1.0"
WHEEL_BOOLEAN_LEXICAL_VALUES = ("false", "true")
METADATA_HEADER_POLICY = (
    ("encoding", "ascii-header-block"),
    ("body_encoding", "utf-8"),
    ("delimiter", "exact-first-LF-LF"),
    ("required_singletons", "Metadata-Version,Name,Version"),
    ("required_singleton_aliases", "case-insensitive-aliases-rejected"),
    ("supported_metadata_versions", ",".join(SUPPORTED_METADATA_VERSIONS)),
    ("folding", "forbidden"),
    ("header_names", "ascii-alnum-hyphen-starting-alpha"),
    ("header_values", "nonempty-trimmed-no-controls"),
    ("other_safe_headers", "allowed-with-bounded-cardinality"),
)
WHEEL_HEADER_POLICY = (
    ("encoding", "ascii"),
    ("line_ending", "LF-with-exactly-one-final-LF"),
    ("blank_lines", "forbidden"),
    ("folding", "forbidden"),
    ("allowed_headers", "Wheel-Version,Generator,Root-Is-Purelib,Tag"),
    ("wheel_version", SUPPORTED_WHEEL_VERSION),
    ("root_is_purelib", "false-or-true-lowercase"),
    ("generator", "required-singleton-1-through-256-printable-ascii"),
    ("generator_projection", "raw-ascii-value-sha256-only"),
    ("tag", "one-through-128-unique-sorted-python-abi-platform"),
    (
        "tag_projection",
        "count-and-domain-separated-canonical-ascii-list-sha256-only",
    ),
    ("unknown_headers", "rejected-including-Build"),
)
CAPTURE_POLICY = (
    (
        "row_roles",
        "numeric-limit-rows-share-runtime-constants-other-rows-documentary",
    ),
    ("per_file_max_bytes", MAX_CONTROL_FILE_BYTES),
    ("per_file", "read-exact-pre-fstat-size-at-most-control-limit"),
    ("growth_probe", "one-byte-EOF-probe-must-be-empty"),
    (
        "aggregate_accounting",
        "preflight-declared-size-then-commit-stable-actual-size",
    ),
    ("installed_aggregate_bytes", MAX_CAPTURED_CONTROL_BYTES),
    (
        "materialization_aggregate_bytes",
        MAX_MATERIALIZATION_CAPTURED_BYTES,
    ),
    (
        "read_open_flags",
        "O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK",
    ),
    (
        "read_open_shape_order",
        "visible-nofollow-stat-then-nonblocking-held-open-then-regular-fstat",
    ),
    ("directory_iteration", "held-duplicate-fd-os-scandir-incremental"),
    ("directory_entry_maximum", MAX_TREE_ENTRIES),
    (
        "directory_retention",
        "refuse-on-maximum-plus-one-before-retain-or-sort",
    ),
)
MODEL_CACHE_ROOT_RELATIVE = "share/synapse-s2/model-cache-v1"
MODEL_SNAPSHOTS_RELATIVE = MODEL_CACHE_ROOT_RELATIVE + "/snapshots"
MODEL_CACHE_BINDING = (
    ("layout_plan_field", "environment_root"),
    ("core_config_field", "embedding_neural_cache_dir"),
    ("runtime_config_field", "cache_dir"),
    ("separator", "/"),
    ("relative_path", MODEL_CACHE_ROOT_RELATIVE),
    ("comparison", "exact-string-equality"),
)
ENVIRONMENT_DOCUMENT_BINDINGS = (
    ("environment_request", "phase5b1-validated-phase5a-request"),
    ("layout_plan", "phase5b1-validated-installed-layout-plan"),
    (
        "layout_plan_sha256",
        "storage_request_record.layout_plan_sha256",
    ),
    ("stage_result", "phase5b1-validated-stage-result"),
    (
        "stage_result_sha256",
        "request-and-storage-request-and-storage-prepare",
    ),
)
MODEL_ALLOWED_FILE_SUFFIXES = (".json", ".safetensors", ".txt")
MODEL_FORBIDDEN_FILE_SUFFIXES = (".py", ".pyc", ".pyo", ".pkl", ".pickle")

_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_TREE_NAME_RE = re.compile(INSTALLED_PATH_COMPONENT_PATTERN)
_DISTRIBUTION_VERSION_RE = re.compile(
    r"\A[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z"
)
_CANONICAL_DISTRIBUTION_RE = re.compile(
    r"\A[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z"
)
_GIT_COMMIT_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_HEADER_NAME_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9-]{0,63}\Z")
_WHEEL_TAG_COMPONENT = r"[a-z0-9_]+(?:\.[a-z0-9_]+)*"
_WHEEL_TAG_RE = re.compile(
    rf"\A{_WHEEL_TAG_COMPONENT}-{_WHEEL_TAG_COMPONENT}-{_WHEEL_TAG_COMPONENT}\Z"
)
_REQUESTED_REVISION_RE = re.compile(
    r"\A[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z"
)
_SANITIZED_HTTPS_URL_RE = re.compile(
    r"\Ahttps://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?"
    r"(?::[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@/-]{1,1024}\Z"
)
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_SOURCE_MODE = 0o644
_PRIVATE_FUNCTION_TYPE = type(lambda: None)
_B1_STORAGE_RESULT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-RESULT\0v1\0"
)
_B1_INSPECT_COMMAND = "inspect-prebuilt-environment-stage"
_B1_INSPECT_REASON = "inspected:prebuilt-environment-tree-consistent"
_B1_RESULT_SCHEMA = "synapse-s2.release-environment-storage-result.v1"
_B2_MODEL_MANIFEST_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-MODEL-MANIFEST\0v1\0"
)
_B2_INSTALLED_MANIFEST_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-"
    b"INSTALLED-DISTRIBUTION-MANIFEST\0v1\0"
)
_REQUIRED_OS_FLAGS = (
    "O_RDONLY",
    "O_DIRECTORY",
    "O_NOFOLLOW",
    "O_CLOEXEC",
    "O_NONBLOCK",
)
_REQUIRED_OS_CALLABLES = (
    "open",
    "close",
    "fstat",
    "stat",
    "read",
    "scandir",
    "geteuid",
)


class _Refused(Exception):
    """Private, redacted deterministic refusal."""


def _refuse(_token: str) -> _Refused:
    return _Refused()


def _require_native(value: Any, *, max_bytes: int | None = None) -> None:
    remaining = [MAX_DOCUMENT_ITEMS]

    def visit(item: Any, depth: int) -> None:
        if depth > MAX_DOCUMENT_DEPTH:
            raise _refuse("native-depth")
        remaining[0] -= 1
        if remaining[0] < 0:
            raise _refuse("native-items")
        if item is None or type(item) is bool:
            return
        if type(item) is int:
            if not (-MAX_NATIVE_INT <= item <= MAX_NATIVE_INT):
                raise _refuse("native-integer")
            return
        if type(item) is float:
            if item != item or item in (float("inf"), float("-inf")):
                raise _refuse("native-float")
            return
        if type(item) is str:
            if len(item) > MAX_STRING_CHARACTERS:
                raise _refuse("native-string")
            return
        if type(item) is list:
            for child in item:
                visit(child, depth + 1)
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str or len(key) > 128:
                    raise _refuse("native-key")
                visit(child, depth + 1)
            return
        raise _refuse("native-type")

    visit(value, 0)
    if max_bytes is not None:
        _canonical_bytes(value, max_bytes)


def _canonical_bytes(value: Any, maximum: int | None = None) -> bytes:
    """Encode canonically while enforcing a pre-allocation byte ceiling."""
    try:
        encoder = json.JSONEncoder(
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        output = bytearray()
        total = 0
        for text_chunk in encoder.iterencode(value):
            raw_chunk = text_chunk.encode("ascii")
            total += len(raw_chunk)
            if maximum is not None and total > maximum:
                raise _refuse("canonical-size")
            output.extend(raw_chunk)
        return bytes(output)
    except _Refused:
        raise
    except BaseException:
        raise _refuse("canonical")


def _freeze_document(value: Any, token: str, maximum: int) -> tuple[Any, bytes]:
    _require_native(value)
    raw = _canonical_bytes(value, maximum)
    try:
        frozen = json.loads(raw.decode("ascii"))
    except BaseException:
        raise _refuse(token + "-parse")
    _require_native(frozen)
    if _canonical_bytes(frozen, maximum) != raw:
        raise _refuse(token + "-roundtrip")
    return frozen, raw


def _parse_canonical_bytes(value: Any, token: str, maximum: int) -> tuple[Any, bytes]:
    if type(value) is not bytes or len(value) > maximum:
        raise _refuse(token + "-bytes")
    try:
        document = json.loads(value.decode("ascii"))
    except BaseException:
        raise _refuse(token + "-parse")
    _require_native(document)
    if _canonical_bytes(document, maximum) != value:
        raise _refuse(token + "-canonical")
    return document, value


def _domain_hash(domain: bytes, value: Any, maximum: int | None = None) -> str:
    raw = _canonical_bytes(value, maximum)
    return hashlib.sha256(domain + raw).hexdigest()


def _raw_hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hex64(value: Any) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        raise _refuse("digest")
    return value


def _exact_dict(value: Any, keys: tuple[str, ...], token: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(keys):
        raise _refuse(token + "-keyset")
    for key in value:
        if type(key) is not str:
            raise _refuse(token + "-keyset")
    if set(value) != set(keys):
        raise _refuse(token + "-keyset")
    return value


def _descriptor_policy(
    value: Any, keys: tuple[str, ...], token: str
) -> dict[str, Any]:
    if type(value) is not tuple or len(value) != len(keys):
        raise _refuse(token + "-shape")
    for binding in value:
        if (
            type(binding) is not tuple
            or len(binding) != 2
            or type(binding[0]) is not str
            or type(binding[1]) not in (str, int)
        ):
            raise _refuse(token + "-shape")
    if tuple(binding[0] for binding in value) != keys:
        raise _refuse(token + "-keys")
    return dict(value)


def _contract_body() -> dict[str, Any]:
    body = {
        "schema": CONTRACT_SCHEMA,
        "mode": MODE,
        "command": COMMAND,
        "phase5b1_source_sha256": PHASE5B1_SOURCE_SHA256,
        "phase5b1_contract_id": PHASE5B1_CONTRACT_ID,
        "phase5b2_source_sha256": PHASE5B2_SOURCE_SHA256,
        "phase5b2_contract_id": PHASE5B2_CONTRACT_ID,
        "environment_policy_id": ENVIRONMENT_POLICY_ID,
        "upstream_compatibility_profile_version": (
            UPSTREAM_COMPATIBILITY_PROFILE_VERSION
        ),
        "fragment_schema": FRAGMENT_SCHEMA,
        "result_schema": RESULT_SCHEMA,
        "render_schema": RENDER_SCHEMA,
        "held_snapshot_context_keys": list(HELD_SNAPSHOT_CONTEXT_KEYS),
        "environment_fragment_keys": list(ENVIRONMENT_FRAGMENT_KEYS),
        "installed_fragment_keys": list(INSTALLED_FRAGMENT_KEYS),
        "model_fragment_keys": list(MODEL_FRAGMENT_KEYS),
        "fragment_keys": list(FRAGMENT_KEYS),
        "result_keys": list(RESULT_KEYS),
        "render_keys": list(RENDER_KEYS),
        "static_roles_present": list(STATIC_ROLES_PRESENT),
        "static_roles_pending": list(STATIC_ROLES_PENDING),
        "fixed_false_result_fields": list(FIXED_FALSE_RESULT_FIELDS),
        "status_reason_exit_bindings": [
            list(binding) for binding in STATUS_REASON_EXIT_BINDINGS
        ],
        "model_cache_binding": [list(binding) for binding in MODEL_CACHE_BINDING],
        "installed_distribution_binding": [
            list(binding) for binding in INSTALLED_DISTRIBUTION_BINDING
        ],
        "python_site_packages_policy": [
            list(binding) for binding in PYTHON_SITE_PACKAGES_POLICY
        ],
        "metadata_header_policy": [
            list(binding) for binding in METADATA_HEADER_POLICY
        ],
        "wheel_header_policy": [
            list(binding) for binding in WHEEL_HEADER_POLICY
        ],
        "record_policy": [list(binding) for binding in RECORD_POLICY],
        "capture_policy": [list(binding) for binding in CAPTURE_POLICY],
        "wheel_metadata_semantics_keys": list(
            WHEEL_METADATA_SEMANTICS_KEYS
        ),
        "source_identity_preimage_keys": list(SOURCE_IDENTITY_PREIMAGE_KEYS),
        "environment_document_bindings": [
            list(binding) for binding in ENVIRONMENT_DOCUMENT_BINDINGS
        ],
        "domains": {
            "contract": CONTRACT_DOMAIN.decode("ascii"),
            "fragment": FRAGMENT_DOMAIN.decode("ascii"),
            "result": RESULT_DOMAIN.decode("ascii"),
            "source_identity": SOURCE_IDENTITY_DOMAIN.decode("ascii"),
            "wheel_tags": WHEEL_TAGS_DOMAIN.decode("ascii"),
        },
        "canonicalization": {
            "encoding": "ascii",
            "sort_keys": True,
            "separators": [",", ":"],
            "ensure_ascii": True,
            "allow_nan": False,
            "trailing_newline": False,
        },
        "limits": {
            "max_contract_bytes": MAX_CONTRACT_BYTES,
            "max_fragment_bytes": MAX_FRAGMENT_BYTES,
            "max_result_bytes": MAX_RESULT_BYTES,
            "max_render_bytes": MAX_RENDER_BYTES,
            "max_control_file_bytes": MAX_CONTROL_FILE_BYTES,
            "max_captured_control_bytes": MAX_CAPTURED_CONTROL_BYTES,
            "max_materialization_captured_bytes": (
                MAX_MATERIALIZATION_CAPTURED_BYTES
            ),
            "max_tree_entries": MAX_TREE_ENTRIES,
            "max_record_rows": MAX_RECORD_ROWS,
            "max_distributions": MAX_DISTRIBUTIONS,
            "max_metadata_headers": MAX_METADATA_HEADERS,
            "max_wheel_headers": MAX_WHEEL_HEADERS,
            "max_header_line_bytes": MAX_HEADER_LINE_BYTES,
            "max_generator_characters": MAX_GENERATOR_CHARACTERS,
            "max_wheel_tags": MAX_WHEEL_TAGS,
        },
        "nonclaims": list(NONCLAIMS),
    }
    _exact_dict(body, CONTRACT_BODY_KEYS, "contract-body")
    return body


def environment_static_contract_projection() -> dict[str, Any]:
    """Return the deterministic dormant B3b documentary contract."""
    body = _contract_body()
    projection = dict(body)
    projection["contract_id"] = (
        "environment-static-contract-"
        + _domain_hash(CONTRACT_DOMAIN, body, MAX_CONTRACT_BYTES)
    )
    _exact_dict(projection, CONTRACT_KEYS, "contract")
    _canonical_bytes(projection, MAX_CONTRACT_BYTES)
    return projection


ENVIRONMENT_STATIC_CONTRACT_ID = environment_static_contract_projection()[
    "contract_id"
]


def _full_fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _close_owned(fd: int, token: str) -> None:
    try:
        os.close(fd)
    except OSError:
        # An ambiguous close is never retried: the integer may already have
        # been reused for an unrelated descriptor.
        raise _refuse(token + "-close")


def _open_absolute_directory(path: str, token: str) -> int:
    if type(path) is not str or not path.startswith("/") or len(path) > MAX_PATH_LENGTH:
        raise _refuse(token + "-path")
    parts = path.split("/")[1:]
    if not parts or any(not part or part in (".", "..") for part in parts):
        raise _refuse(token + "-path")
    try:
        current: int | None = os.open("/", _DIR_FLAGS)
    except OSError:
        raise _refuse(token + "-open")
    try:
        for part in parts:
            try:
                child = os.open(part, _DIR_FLAGS, dir_fd=current)
            except OSError:
                raise _refuse(token + "-open")
            previous = current
            current = None
            try:
                _close_owned(previous, token)
            except BaseException:
                # The newly opened child has independent ownership.  Revoke
                # it once before propagating the ambiguous parent close.
                owned_child = child
                child = None
                _close_owned(owned_child, token + "-child")
                raise
            current = child
        if current is None:
            raise _refuse(token + "-ownership")
        return current
    except BaseException:
        if current is not None:
            owned = current
            current = None
            _close_owned(owned, token)
        raise


def _read_frozen_source(
    parent_path: str, basename: str, expected_hash: str, token: str
) -> tuple[bytes, str]:
    parent_fd = _open_absolute_directory(parent_path, token + "-parent")
    file_fd: int | None = None
    try:
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) & 0o022
        ):
            raise _refuse(token + "-parent-shape")
        parent_fingerprint = _full_fingerprint(parent_info)
        try:
            file_fd = os.open(basename, _FILE_FLAGS, dir_fd=parent_fd)
        except OSError:
            raise _refuse(token + "-open")
        pre = os.fstat(file_fd)
        if (
            not stat.S_ISREG(pre.st_mode)
            or pre.st_uid != os.geteuid()
            or stat.S_IMODE(pre.st_mode) != _SOURCE_MODE
            or pre.st_nlink != 1
            or pre.st_dev != parent_info.st_dev
            or pre.st_size > MAX_SOURCE_BYTES
        ):
            raise _refuse(token + "-shape")
        visible = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
        if _full_fingerprint(visible) != _full_fingerprint(pre):
            raise _refuse(token + "-substitution")
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(file_fd, min(131_072, MAX_SOURCE_BYTES + 1 - total))
            except OSError:
                raise _refuse(token + "-read")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_SOURCE_BYTES:
                raise _refuse(token + "-size")
        raw = b"".join(chunks)
        post = os.fstat(file_fd)
        visible_post = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(raw) != pre.st_size
            or _full_fingerprint(post) != _full_fingerprint(pre)
            or _full_fingerprint(visible_post) != _full_fingerprint(pre)
            or _raw_hash(raw) != expected_hash
        ):
            raise _refuse(token + "-drift")
        owned_file = file_fd
        file_fd = None
        _close_owned(owned_file, token)
        reproved_fd = _open_absolute_directory(parent_path, token + "-parent-reproof")
        try:
            if _full_fingerprint(os.fstat(reproved_fd)) != parent_fingerprint:
                raise _refuse(token + "-parent-drift")
        finally:
            owned_reproof = reproved_fd
            reproved_fd = None
            _close_owned(owned_reproof, token + "-parent-reproof")
        return raw, parent_path + "/" + basename
    finally:
        close_failed = False
        if file_fd is not None:
            owned_file = file_fd
            file_fd = None
            try:
                _close_owned(owned_file, token)
            except BaseException:
                close_failed = True
        owned_parent = parent_fd
        parent_fd = None
        try:
            _close_owned(owned_parent, token + "-parent")
        except BaseException:
            close_failed = True
        if close_failed:
            raise _refuse(token + "-cleanup")


def _execute_frozen_source(raw: bytes, path: str, name: str) -> dict[str, Any]:
    namespace: dict[str, Any] = {
        "__name__": name,
        "__file__": path,
        "__package__": None,
        "__builtins__": __builtins__,
    }
    try:
        code = compile(raw, path, "exec", dont_inherit=True, optimize=0)
        exec(code, namespace, namespace)
    except BaseException:
        raise _refuse("source-execution")
    return namespace


def _private_function(namespace: dict[str, Any], name: str) -> Any:
    function = namespace.get(name)
    if type(function) is not _PRIVATE_FUNCTION_TYPE:
        raise _refuse("private-function")
    try:
        function_globals = object.__getattribute__(function, "__globals__")
    except BaseException:
        raise _refuse("private-function")
    if function_globals is not namespace:
        raise _refuse("private-function")
    return function


def _read_platform_capable() -> bool:
    """Gate every descriptor capability before any source or tree I/O."""
    try:
        if sys.platform != "darwin" or os.name != "posix":
            return False
        for name in _REQUIRED_OS_FLAGS:
            value = getattr(os, name, None)
            if type(value) is not int or (name != "O_RDONLY" and value == 0):
                return False
        for name in _REQUIRED_OS_CALLABLES:
            if not callable(getattr(os, name, None)):
                return False
        import fcntl

        return (
            callable(getattr(fcntl, "flock", None))
            and type(getattr(fcntl, "LOCK_SH", None)) is int
            and type(getattr(fcntl, "LOCK_NB", None)) is int
            and fcntl.LOCK_SH != 0
            and fcntl.LOCK_NB != 0
        )
    except BaseException:
        return False


def _load_frozen_upstreams() -> tuple[dict[str, Any], dict[str, Any]]:
    if not _read_platform_capable():
        raise _refuse("platform-capability")
    source_path = globals().get("__file__")
    if type(source_path) is not str or not source_path.startswith("/"):
        raise _refuse("self-path")
    if not source_path.endswith("/release_environment_model_static_evidence.py"):
        raise _refuse("self-basename")
    parent_path = source_path.rsplit("/", 1)[0]
    b1_raw, b1_path = _read_frozen_source(
        parent_path,
        "release_environment_storage.py",
        PHASE5B1_SOURCE_SHA256,
        "phase5b1",
    )
    b2_raw, b2_path = _read_frozen_source(
        parent_path,
        "release_environment_evidence.py",
        PHASE5B2_SOURCE_SHA256,
        "phase5b2",
    )
    # Both complete byte streams are verified before either is executed.
    b1 = _execute_frozen_source(
        b1_raw, b1_path, "_synapse_s2_verified_release_environment_storage"
    )
    b2 = _execute_frozen_source(
        b2_raw, b2_path, "_synapse_s2_verified_release_environment_evidence"
    )
    for name in (
        "_platform_gate",
        "_inspect_with_held_snapshot",
        "_validate_result_replay",
        "_verify_frozen_sibling_sources",
        "_validate_request",
        "_validate_stage_result",
        "_validate_layout_plan",
    ):
        _private_function(b1, name)
    for name in (
        "_phase5a_request",
        "_storage_request",
        "_tree_manifest",
        "_crosscheck_storage_fingerprints",
        "_storage_prepare",
        "_storage_digest",
        "_core_config",
        "_embedding_runtime_config",
        "_model_snapshot_plan",
        "_installed_manifest",
        "_model_manifest",
    ):
        _private_function(b2, name)
    if (
        b1.get("STORAGE_CONTRACT_ID") != PHASE5B1_CONTRACT_ID
        or b1.get("_HELD_SNAPSHOT_CONTEXT_KEYS") != HELD_SNAPSHOT_CONTEXT_KEYS
        or b2.get("PHASE5B1_SOURCE_SHA256") != PHASE5B1_SOURCE_SHA256
        or b2.get("PHASE5B1_CONTRACT_ID") != PHASE5B1_CONTRACT_ID
        or b2.get("EVIDENCE_CONTRACT_ID") != PHASE5B2_CONTRACT_ID
        or b2.get("ENVIRONMENT_POLICY_ID") != ENVIRONMENT_POLICY_ID
        or b2.get("COMPATIBILITY_PROFILE_VERSION")
        != UPSTREAM_COMPATIBILITY_PROFILE_VERSION
        or b2.get("MODEL_CACHE_ROOT_RELATIVE") != MODEL_CACHE_ROOT_RELATIVE
        or b2.get("DISTRIBUTION_SOURCE_KINDS") != ("wheel", "git")
        or b2.get("INSTALLED_FILE_MODES") != ("0600", "0700")
    ):
        raise _refuse("upstream-binding")
    runtime_intact = _private_function(b2, "_runtime_projection_intact")
    try:
        if runtime_intact() is not True:
            raise _refuse("upstream-runtime")
    except _Refused:
        raise
    except BaseException:
        raise _refuse("upstream-runtime")
    return b1, b2


def _require_path_string(value: Any, token: str) -> str:
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > MAX_PATH_LENGTH
        or "\x00" in value
    ):
        raise _refuse(token)
    return value


def _require_model_cache_binding(
    layout_plan: Any,
    core_config: Any,
    runtime_config: Any,
) -> str:
    """Bind planned runtime model reads to the exact held layout root."""
    if (
        type(layout_plan) is not dict
        or type(core_config) is not dict
        or type(runtime_config) is not dict
    ):
        raise _refuse("model-cache-binding-type")
    binding = dict(MODEL_CACHE_BINDING)
    try:
        environment_root = _require_path_string(
            layout_plan[binding["layout_plan_field"]],
            "model-cache-environment-root",
        )
        core_cache = core_config[binding["core_config_field"]]
        runtime_cache = runtime_config[binding["runtime_config_field"]]
        expected = (
            environment_root
            + binding["separator"]
            + binding["relative_path"]
        )
    except (KeyError, TypeError):
        raise _refuse("model-cache-binding-field")
    if (
        type(core_cache) is not str
        or type(runtime_cache) is not str
        or core_cache != expected
        or runtime_cache != expected
    ):
        raise _refuse("model-cache-binding")
    return expected


def _require_directory(fd: int, device: int | None, token: str) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError:
        raise _refuse(token + "-stat")
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != DIRECTORY_MODE
        or (device is not None and info.st_dev != device)
    ):
        raise _refuse(token + "-shape")
    return info


def _safe_names(fd: int, token: str) -> list[str]:
    scan_fd: int | None = None
    iterator = None
    names: list[str] = []
    folded: set[str] = set()
    try:
        try:
            scan_fd = os.open(".", _DIR_FLAGS, dir_fd=fd)
            iterator = os.scandir(scan_fd)
        except OSError:
            raise _refuse(token + "-list")

        count = 0
        while True:
            try:
                entry = next(iterator)
            except StopIteration:
                break
            except OSError:
                raise _refuse(token + "-list")
            count += 1
            if count > MAX_TREE_ENTRIES:
                raise _refuse(token + "-names")
            name = entry.name
            if type(name) is not str or _TREE_NAME_RE.fullmatch(name) is None:
                raise _refuse(token + "-name")
            folded_name = name.casefold()
            if folded_name in folded:
                raise _refuse(token + "-casefold")
            folded.add(folded_name)
            names.append(name)

        owned_iterator, iterator = iterator, None
        try:
            owned_iterator.close()
        except BaseException:
            raise _refuse(token + "-list-close")

        owned_scan, scan_fd = scan_fd, None
        _close_owned(owned_scan, token + "-list")
        return sorted(names)
    finally:
        if iterator is not None:
            owned_iterator, iterator = iterator, None
            try:
                owned_iterator.close()
            except BaseException:
                pass
        if scan_fd is not None:
            owned_scan, scan_fd = scan_fd, None
            try:
                _close_owned(owned_scan, token + "-list")
            except BaseException:
                pass


def _open_child_directory(
    parent_fd: int, name: str, device: int, token: str
) -> tuple[int, tuple[int, ...]]:
    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        child_fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError:
        raise _refuse(token + "-open")
    try:
        held = _require_directory(child_fd, device, token)
        if _full_fingerprint(visible) != _full_fingerprint(held):
            raise _refuse(token + "-substitution")
        return child_fd, _full_fingerprint(held)
    except BaseException:
        _close_owned(child_fd, token)
        raise


def _reprove_child_directory(
    parent_fd: int,
    name: str,
    child_fd: int,
    fingerprint: tuple[int, ...],
    token: str,
) -> None:
    try:
        held = os.fstat(child_fd)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise _refuse(token + "-reproof")
    if (
        _full_fingerprint(held) != fingerprint
        or _full_fingerprint(visible) != fingerprint
    ):
        raise _refuse(token + "-drift")


def _manifest_directory_entry(path: str) -> dict[str, Any]:
    return {
        "path": path,
        "kind": "directory",
        "mode": "0700",
        "size": 0,
        "sha256": "",
    }


def _read_model_file(
    parent_fd: int,
    name: str,
    device: int,
    relative_path: str,
    token: str,
) -> dict[str, Any]:
    lowered = relative_path.lower()
    if lowered.endswith(MODEL_FORBIDDEN_FILE_SUFFIXES) or not lowered.endswith(
        MODEL_ALLOWED_FILE_SUFFIXES
    ):
        raise _refuse(token + "-suffix")
    file_fd: int | None = None
    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        file_fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
        pre = os.fstat(file_fd)
        if (
            not stat.S_ISREG(pre.st_mode)
            or pre.st_uid != os.geteuid()
            or stat.S_IMODE(pre.st_mode) != FILE_MODE
            or pre.st_nlink != 1
            or pre.st_dev != device
            or pre.st_size > MAX_TREE_FILE_BYTES
            or _full_fingerprint(visible) != _full_fingerprint(pre)
        ):
            raise _refuse(token + "-shape")
        digest = hashlib.sha256()
        total = 0
        while True:
            try:
                chunk = os.read(
                    file_fd, min(1024 * 1024, MAX_TREE_FILE_BYTES + 1 - total)
                )
            except OSError:
                raise _refuse(token + "-read")
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TREE_FILE_BYTES:
                raise _refuse(token + "-size")
            digest.update(chunk)
        post = os.fstat(file_fd)
        visible_post = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            total != pre.st_size
            or _full_fingerprint(post) != _full_fingerprint(pre)
            or _full_fingerprint(visible_post) != _full_fingerprint(pre)
        ):
            raise _refuse(token + "-drift")
        return {
            "path": relative_path,
            "kind": "file",
            "mode": "0600",
            "size": total,
            "sha256": digest.hexdigest(),
        }
    except OSError:
        raise _refuse(token + "-io")
    finally:
        if file_fd is not None:
            owned_file = file_fd
            file_fd = None
            _close_owned(owned_file, token)


def _scan_revision_directory(
    directory_fd: int,
    device: int,
    parent_relative: str,
    entries: list[dict[str, Any]],
    counters: dict[str, int],
    depth: int,
) -> None:
    if depth > MAX_TREE_DEPTH:
        raise _refuse("model-depth")
    directory_fingerprint = _full_fingerprint(
        _require_directory(directory_fd, device, "model-directory")
    )
    names = _safe_names(directory_fd, "model-directory")
    for name in names:
        path = name if not parent_relative else parent_relative + "/" + name
        if len(path) > MAX_PATH_LENGTH:
            raise _refuse("model-path")
        counters["entries"] += 1
        if counters["entries"] > MAX_TREE_ENTRIES:
            raise _refuse("model-entry-count")
        try:
            visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            raise _refuse("model-entry-stat")
        if stat.S_ISDIR(visible.st_mode):
            child_fd, child_fingerprint = _open_child_directory(
                directory_fd, name, device, "model-directory"
            )
            entries.append(
                {
                    "path": path,
                    "kind": "directory",
                    "mode": "0700",
                    "size": 0,
                    "sha256": "",
                }
            )
            try:
                _scan_revision_directory(
                    child_fd, device, path, entries, counters, depth + 1
                )
                _reprove_child_directory(
                    directory_fd,
                    name,
                    child_fd,
                    child_fingerprint,
                    "model-directory",
                )
            finally:
                _close_owned(child_fd, "model-directory")
        elif stat.S_ISREG(visible.st_mode):
            entry = _read_model_file(
                directory_fd, name, device, path, "model-file"
            )
            counters["bytes"] += entry["size"]
            if counters["bytes"] > MAX_TREE_TOTAL_BYTES:
                raise _refuse("model-total-bytes")
            entries.append(entry)
        else:
            raise _refuse("model-special-file")
    if _safe_names(directory_fd, "model-directory-reproof") != names:
        raise _refuse("model-directory-names-drift")
    if _full_fingerprint(os.fstat(directory_fd)) != directory_fingerprint:
        raise _refuse("model-directory-drift")


def _require_manifest_entry(
    manifest_by_path: dict[str, dict[str, Any]], expected: dict[str, Any]
) -> None:
    if manifest_by_path.get(expected["path"]) != expected:
        raise _refuse("manifest-correlation")


def _derive_model_snapshot_plan(
    environment_root_fd: int,
    request: dict[str, Any],
    manifest: dict[str, Any],
    b2: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if type(environment_root_fd) is not int or environment_root_fd < 0:
        raise _refuse("held-root-fd")
    revision = request.get("model_revision")
    model_id = request.get("model_id")
    if type(revision) is not str or type(model_id) is not str:
        raise _refuse("model-request")
    snapshot_root = MODEL_SNAPSHOTS_RELATIVE + "/" + revision
    manifest_entries = manifest.get("entries")
    if type(manifest_entries) is not list:
        raise _refuse("manifest-entries")
    manifest_by_path = {
        entry["path"]: entry
        for entry in manifest_entries
        if type(entry) is dict and type(entry.get("path")) is str
    }
    if len(manifest_by_path) != len(manifest_entries):
        raise _refuse("manifest-paths")
    root_fd: int | None = None
    chain: list[tuple[int, str, int, tuple[int, ...], str]] = []
    try:
        root_fd = os.open(".", _DIR_FLAGS, dir_fd=environment_root_fd)
        root_info = _require_directory(root_fd, None, "held-root")
        device = root_info.st_dev
        current_fd = root_fd
        relative = ""
        for index, segment in enumerate(MODEL_CACHE_ROOT_RELATIVE.split("/")):
            relative = segment if not relative else relative + "/" + segment
            _require_manifest_entry(
                manifest_by_path, _manifest_directory_entry(relative)
            )
            child_fd, fingerprint = _open_child_directory(
                current_fd, segment, device, "model-root-segment"
            )
            chain.append(
                (current_fd, segment, child_fd, fingerprint, "segment-" + str(index))
            )
            current_fd = child_fd
        cache_fd = current_fd
        if _safe_names(cache_fd, "model-cache-root") != ["snapshots"]:
            raise _refuse("model-cache-names")
        _require_manifest_entry(
            manifest_by_path, _manifest_directory_entry(MODEL_SNAPSHOTS_RELATIVE)
        )
        snapshots_fd, snapshots_fingerprint = _open_child_directory(
            cache_fd, "snapshots", device, "model-snapshots"
        )
        chain.append(
            (
                cache_fd,
                "snapshots",
                snapshots_fd,
                snapshots_fingerprint,
                "snapshots",
            )
        )
        if _safe_names(snapshots_fd, "model-snapshots") != [revision]:
            raise _refuse("model-snapshot-selection")
        _require_manifest_entry(
            manifest_by_path, _manifest_directory_entry(snapshot_root)
        )
        revision_fd, revision_fingerprint = _open_child_directory(
            snapshots_fd, revision, device, "model-revision"
        )
        chain.append(
            (
                snapshots_fd,
                revision,
                revision_fd,
                revision_fingerprint,
                "revision",
            )
        )
        entries: list[dict[str, Any]] = []
        counters = {"entries": 0, "bytes": 0}
        _scan_revision_directory(
            revision_fd, device, "", entries, counters, 1
        )
        entries.sort(key=lambda entry: entry["path"])
        paths = [entry["path"] for entry in entries]
        if len(paths) != len(set(paths)) or len(paths) != len(
            {path.casefold() for path in paths}
        ):
            raise _refuse("model-path-alias")
        for entry in entries:
            expected = dict(entry)
            expected["path"] = snapshot_root + "/" + entry["path"]
            _require_manifest_entry(manifest_by_path, expected)
        actual_cache_paths = {
            MODEL_CACHE_ROOT_RELATIVE,
            MODEL_SNAPSHOTS_RELATIVE,
            snapshot_root,
            *(snapshot_root + "/" + entry["path"] for entry in entries),
        }
        manifested_cache_paths = {
            path
            for path in manifest_by_path
            if path == MODEL_CACHE_ROOT_RELATIVE
            or path.startswith(MODEL_CACHE_ROOT_RELATIVE + "/")
        }
        if actual_cache_paths != manifested_cache_paths:
            raise _refuse("model-cache-manifest-closure")
        if _safe_names(cache_fd, "model-cache-root-reproof") != ["snapshots"]:
            raise _refuse("model-cache-drift")
        if _safe_names(snapshots_fd, "model-snapshots-reproof") != [revision]:
            raise _refuse("model-snapshots-drift")
        for parent_fd, name, child_fd, fingerprint, token in reversed(chain):
            _reprove_child_directory(parent_fd, name, child_fd, fingerprint, token)
        plan = {
            "schema": b2["MODEL_SNAPSHOT_PLAN_SCHEMA"],
            "environment_policy_id": ENVIRONMENT_POLICY_ID,
            "model_id": model_id,
            "model_revision": revision,
            "cache_root_relative": MODEL_CACHE_ROOT_RELATIVE,
            "snapshot_root_relative": snapshot_root,
            "entry_count": len(entries),
            "total_bytes": counters["bytes"],
            "entries": entries,
        }
        try:
            plan_sha256 = b2["_model_snapshot_plan"](plan)
        except BaseException:
            raise _refuse("model-plan")
        if plan_sha256 != request.get("expected_model_snapshot_sha256"):
            raise _refuse("model-plan-request-binding")
        return plan, plan_sha256
    except OSError:
        raise _refuse("model-scan-io")
    finally:
        # Every child descriptor appears once as the third tuple element.
        close_failed = False
        while chain:
            _parent, _name, child, _fingerprint, token = chain.pop()
            try:
                _close_owned(child, token)
            except BaseException:
                close_failed = True
        if root_fd is not None:
            owned_root = root_fd
            root_fd = None
            try:
                _close_owned(owned_root, "held-root")
            except BaseException:
                close_failed = True
        if close_failed:
            raise _refuse("model-scan-close")


def _site_packages_relative(request: dict[str, Any]) -> str:
    policy = _descriptor_policy(
        PYTHON_SITE_PACKAGES_POLICY,
        PYTHON_SITE_PACKAGES_POLICY_KEYS,
        "python-site-packages-policy",
    )
    if (
        request.get(policy["implementation_request_field"])
        != policy["implementation"]
    ):
        raise _refuse("installed-python-implementation")
    abi = request.get(policy["abi_request_field"])
    if type(abi) is not str:
        raise _refuse("installed-python-abi")
    match = re.fullmatch(policy["abi_pattern"], abi)
    if match is None:
        raise _refuse("installed-python-abi")
    major, minor = match.groups()
    minor_number = int(minor)
    if (
        policy["minor_decimal"] != SITE_PACKAGES_MINOR_DECIMAL_POLICY
        or major != str(policy["python_major"])
        or str(minor_number) != minor
        or not (
            policy["minor_minimum"]
            <= minor_number
            <= policy["minor_maximum"]
        )
    ):
        raise _refuse("installed-python-abi")
    return policy["site_packages_template"].format(
        major=major, minor=minor
    )


def _normalize_distribution_name(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) > 128
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is None
    ):
        raise _refuse("installed-distribution-name")
    normalized = re.sub(r"[-_.]+", "-", value).lower()
    if _CANONICAL_DISTRIBUTION_RE.fullmatch(normalized) is None:
        raise _refuse("installed-distribution-name")
    return normalized


def _manifest_index(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = manifest.get("entries")
    if type(entries) is not list:
        raise _refuse("manifest-entries")
    by_path = {
        entry["path"]: entry
        for entry in entries
        if type(entry) is dict and type(entry.get("path")) is str
    }
    if len(by_path) != len(entries):
        raise _refuse("manifest-paths")
    return by_path


def _open_manifest_chain(
    environment_root_fd: int,
    relative_path: str,
    manifest_by_path: dict[str, dict[str, Any]],
    token: str,
) -> tuple[int, int, list[tuple[int, str, int, tuple[int, ...], str]]]:
    root_fd: int | None = None
    chain: list[tuple[int, str, int, tuple[int, ...], str]] = []
    try:
        root_fd = os.open(".", _DIR_FLAGS, dir_fd=environment_root_fd)
        root_info = _require_directory(root_fd, None, token + "-root")
        current_fd = root_fd
        current_path = ""
        for index, segment in enumerate(relative_path.split("/")):
            current_path = (
                segment if not current_path else current_path + "/" + segment
            )
            _require_manifest_entry(
                manifest_by_path, _manifest_directory_entry(current_path)
            )
            child_fd, fingerprint = _open_child_directory(
                current_fd, segment, root_info.st_dev, token + "-segment"
            )
            chain.append(
                (
                    current_fd,
                    segment,
                    child_fd,
                    fingerprint,
                    token + "-segment-" + str(index),
                )
            )
            current_fd = child_fd
        return root_fd, root_info.st_dev, chain
    except BaseException:
        close_failed = False
        while chain:
            _parent, _name, child, _fingerprint, child_token = chain.pop()
            try:
                _close_owned(child, child_token)
            except BaseException:
                close_failed = True
        if root_fd is not None:
            owned_root = root_fd
            root_fd = None
            try:
                _close_owned(owned_root, token + "-root")
            except BaseException:
                close_failed = True
        if close_failed:
            raise _refuse(token + "-open-cleanup")
        raise


def _reprove_manifest_chain(
    chain: list[tuple[int, str, int, tuple[int, ...], str]],
) -> None:
    for parent_fd, name, child_fd, fingerprint, token in reversed(chain):
        _reprove_child_directory(parent_fd, name, child_fd, fingerprint, token)


def _close_manifest_chain(
    root_fd: int,
    chain: list[tuple[int, str, int, tuple[int, ...], str]],
    token: str,
) -> None:
    close_failed = False
    while chain:
        _parent, _name, child, _fingerprint, child_token = chain.pop()
        try:
            _close_owned(child, child_token)
        except BaseException:
            close_failed = True
    try:
        _close_owned(root_fd, token + "-root")
    except BaseException:
        close_failed = True
    if close_failed:
        raise _refuse(token + "-close")


def _read_static_file(
    parent_fd: int,
    name: str,
    device: int,
    relative_path: str,
    token: str,
    *,
    capture: bool,
    capture_counters: dict[str, int] | None = None,
    capture_maximum: int | None = None,
) -> tuple[dict[str, Any], bytes | None]:
    file_fd: int | None = None
    try:
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        file_fd = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
        pre = os.fstat(file_fd)
        if (
            not stat.S_ISREG(pre.st_mode)
            or pre.st_uid != os.geteuid()
            or stat.S_IMODE(pre.st_mode) != FILE_MODE
            or pre.st_nlink != 1
            or pre.st_dev != device
            or pre.st_size > MAX_TREE_FILE_BYTES
            or (capture and pre.st_size > MAX_CONTROL_FILE_BYTES)
            or _full_fingerprint(visible) != _full_fingerprint(pre)
        ):
            raise _refuse(token + "-shape")
        if capture:
            if capture_counters is None or capture_maximum is None:
                raise _refuse(token + "-capture-budget")
            _capture_budget(
                capture_counters,
                pre.st_size,
                capture_maximum,
                token,
                commit=False,
            )
        elif capture_counters is not None or capture_maximum is not None:
            raise _refuse(token + "-capture-counter")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        if capture:
            while total < pre.st_size:
                read_size = min(1024 * 1024, pre.st_size - total)
                try:
                    chunk = os.read(file_fd, read_size)
                except OSError:
                    raise _refuse(token + "-read")
                if type(chunk) is not bytes:
                    raise _refuse(token + "-read")
                if not chunk:
                    break
                if (
                    len(chunk) > read_size
                    or total + len(chunk) > pre.st_size
                    or total + len(chunk) > MAX_CONTROL_FILE_BYTES
                ):
                    raise _refuse(token + "-capture-size")
                total += len(chunk)
                digest.update(chunk)
                chunks.append(chunk)
            if total == pre.st_size:
                try:
                    probe = os.read(file_fd, 1)
                except OSError:
                    raise _refuse(token + "-read")
                if type(probe) is not bytes or probe:
                    raise _refuse(token + "-capture-growth")
        else:
            while True:
                try:
                    chunk = os.read(
                        file_fd,
                        min(1024 * 1024, MAX_TREE_FILE_BYTES + 1 - total),
                    )
                except OSError:
                    raise _refuse(token + "-read")
                if type(chunk) is not bytes:
                    raise _refuse(token + "-read")
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TREE_FILE_BYTES:
                    raise _refuse(token + "-size")
                digest.update(chunk)
        post = os.fstat(file_fd)
        visible_post = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            total != pre.st_size
            or _full_fingerprint(post) != _full_fingerprint(pre)
            or _full_fingerprint(visible_post) != _full_fingerprint(pre)
        ):
            raise _refuse(token + "-drift")
        return (
            {
                "path": relative_path,
                "kind": "file",
                "mode": "0600",
                "size": total,
                "sha256": digest.hexdigest(),
            },
            b"".join(chunks) if capture else None,
        )
    except OSError:
        raise _refuse(token + "-io")
    finally:
        if file_fd is not None:
            owned_file = file_fd
            file_fd = None
            _close_owned(owned_file, token)


def _validate_materialization_copies(
    environment_root_fd: int,
    request: dict[str, Any],
    manifest_by_path: dict[str, dict[str, Any]],
) -> None:
    root_fd, device, chain = _open_manifest_chain(
        environment_root_fd,
        MATERIALIZATION_ROOT_RELATIVE,
        manifest_by_path,
        "materialization",
    )
    materialization_fd = chain[-1][2]
    try:
        capture_counters = {"captured_bytes": 0}
        names = _safe_names(materialization_fd, "materialization")
        expected_names = sorted(name for name, _field in MATERIALIZATION_FILES)
        if names != expected_names:
            raise _refuse("materialization-closure")
        expected_paths = {MATERIALIZATION_ROOT_RELATIVE}
        for name, request_field in MATERIALIZATION_FILES:
            path = MATERIALIZATION_ROOT_RELATIVE + "/" + name
            entry, raw = _read_static_file(
                materialization_fd,
                name,
                device,
                path,
                "materialization-file",
                capture=True,
                capture_counters=capture_counters,
                capture_maximum=MAX_MATERIALIZATION_CAPTURED_BYTES,
            )
            _capture_budget(
                capture_counters,
                entry["size"],
                MAX_MATERIALIZATION_CAPTURED_BYTES,
                "materialization-file",
                commit=True,
            )
            if raw is None or _raw_hash(raw) != _hex64(request[request_field]):
                raise _refuse("materialization-request-binding")
            _require_manifest_entry(manifest_by_path, entry)
            expected_paths.add(path)
        manifested = {
            path
            for path in manifest_by_path
            if path == MATERIALIZATION_ROOT_RELATIVE
            or path.startswith(MATERIALIZATION_ROOT_RELATIVE + "/")
        }
        if manifested != expected_paths:
            raise _refuse("materialization-manifest-closure")
        if _safe_names(materialization_fd, "materialization-reproof") != names:
            raise _refuse("materialization-names-drift")
        _reprove_manifest_chain(chain)
    finally:
        _close_manifest_chain(root_fd, chain, "materialization")


def _control_file_path(relative_path: str) -> bool:
    parent, separator, basename = relative_path.rpartition("/")
    return bool(
        separator
        and parent.endswith(".dist-info")
        and basename in ("METADATA", "WHEEL", "RECORD", "direct_url.json")
    )


def _capture_budget(
    counters: dict[str, int],
    size: int,
    maximum: int,
    token: str,
    *,
    commit: bool,
) -> None:
    if (
        type(size) is not int
        or size < 0
        or type(maximum) is not int
        or maximum < 0
    ):
        raise _refuse(token + "-capture-total")
    current = counters.get("captured_bytes")
    if type(current) is not int or current < 0:
        raise _refuse(token + "-capture-total")
    total = current + size
    if total > maximum:
        raise _refuse(token + "-capture-total")
    if commit:
        counters["captured_bytes"] = total


def _scan_installed_directory(
    directory_fd: int,
    device: int,
    site_packages_relative: str,
    parent_relative: str,
    entries: list[dict[str, Any]],
    control_raw: dict[str, bytes],
    counters: dict[str, int],
    depth: int,
) -> None:
    if depth > MAX_TREE_DEPTH:
        raise _refuse("installed-depth")
    directory_fingerprint = _full_fingerprint(
        _require_directory(directory_fd, device, "installed-directory")
    )
    names = _safe_names(directory_fd, "installed-directory")
    for name in names:
        lowered = name.casefold()
        if (
            lowered.endswith(".egg-info")
            or lowered.endswith(".egg-link")
            or lowered.startswith("__editable__")
            or (lowered.endswith(".dist-info") and not name.endswith(".dist-info"))
            or (
                parent_relative.endswith(".dist-info")
                and lowered in {"metadata", "wheel", "record", "direct_url.json"}
                and name not in {"METADATA", "WHEEL", "RECORD", "direct_url.json"}
            )
        ):
            raise _refuse("installed-unsupported-form")
        relative = name if not parent_relative else parent_relative + "/" + name
        full_path = site_packages_relative + "/" + relative
        if len(full_path) > MAX_PATH_LENGTH:
            raise _refuse("installed-path")
        counters["entries"] += 1
        if counters["entries"] > MAX_TREE_ENTRIES:
            raise _refuse("installed-entry-count")
        try:
            visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            raise _refuse("installed-entry-stat")
        if stat.S_ISDIR(visible.st_mode):
            if relative.endswith(".dist-info") and "/" in relative:
                raise _refuse("installed-nested-dist-info")
            child_fd, child_fingerprint = _open_child_directory(
                directory_fd, name, device, "installed-directory"
            )
            entries.append(_manifest_directory_entry(full_path))
            try:
                _scan_installed_directory(
                    child_fd,
                    device,
                    site_packages_relative,
                    relative,
                    entries,
                    control_raw,
                    counters,
                    depth + 1,
                )
                _reprove_child_directory(
                    directory_fd,
                    name,
                    child_fd,
                    child_fingerprint,
                    "installed-directory",
                )
            finally:
                _close_owned(child_fd, "installed-directory")
        elif stat.S_ISREG(visible.st_mode):
            capture = _control_file_path(relative)
            entry, raw = _read_static_file(
                directory_fd,
                name,
                device,
                full_path,
                "installed-file",
                capture=capture,
                capture_counters=counters if capture else None,
                capture_maximum=(
                    MAX_CAPTURED_CONTROL_BYTES if capture else None
                ),
            )
            if capture:
                _capture_budget(
                    counters,
                    entry["size"],
                    MAX_CAPTURED_CONTROL_BYTES,
                    "installed-file",
                    commit=True,
                )
                if raw is None or relative in control_raw:
                    raise _refuse("installed-control-file")
                control_raw[relative] = raw
            counters["bytes"] += entry["size"]
            if counters["bytes"] > MAX_TREE_TOTAL_BYTES:
                raise _refuse("installed-total-bytes")
            entries.append(entry)
        else:
            raise _refuse("installed-special-file")
    if _safe_names(directory_fd, "installed-directory-reproof") != names:
        raise _refuse("installed-directory-names-drift")
    if _full_fingerprint(os.fstat(directory_fd)) != directory_fingerprint:
        raise _refuse("installed-directory-drift")


def _strict_header_lines(
    raw: bytes,
    token: str,
    *,
    metadata_block: bool,
    maximum_headers: int,
) -> list[tuple[str, str]]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_CONTROL_FILE_BYTES:
        raise _refuse(token + "-size")
    if b"\x00" in raw or b"\r" in raw:
        raise _refuse(token + "-control")
    if metadata_block:
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            raise _refuse(token + "-encoding")
        delimiter = raw.find(b"\n\n")
        if delimiter <= 0:
            raise _refuse(token + "-delimiter")
        header_raw = raw[:delimiter]
    else:
        if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
            raise _refuse(token + "-line-ending")
        header_raw = raw[:-1]
        if not header_raw or b"\n\n" in header_raw:
            raise _refuse(token + "-blank")
    raw_lines = header_raw.split(b"\n")
    if not raw_lines or len(raw_lines) > maximum_headers:
        raise _refuse(token + "-count")
    headers: list[tuple[str, str]] = []
    for raw_line in raw_lines:
        if (
            not raw_line
            or len(raw_line) > MAX_HEADER_LINE_BYTES
            or raw_line[:1] in (b" ", b"\t")
        ):
            raise _refuse(token + "-line")
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError:
            raise _refuse(token + "-encoding")
        if any(ord(character) < 32 or ord(character) > 126 for character in line):
            raise _refuse(token + "-control")
        key, separator, value = line.partition(": ")
        if (
            separator != ": "
            or _HEADER_NAME_RE.fullmatch(key) is None
            or not value
            or value != value.strip()
        ):
            raise _refuse(token + "-grammar")
        headers.append((key, value))
    return headers


def _metadata_identity(raw: bytes) -> tuple[str, str]:
    headers = _strict_header_lines(
        raw,
        "installed-metadata",
        metadata_block=True,
        maximum_headers=MAX_METADATA_HEADERS,
    )
    required = ("Metadata-Version", "Name", "Version")
    required_by_casefold = {key.casefold(): key for key in required}
    values: dict[str, str] = {}
    for key, value in headers:
        canonical_key = required_by_casefold.get(key.casefold())
        if canonical_key is not None:
            if key != canonical_key:
                raise _refuse("installed-metadata-required-alias")
            if canonical_key in values:
                raise _refuse("installed-metadata-singleton")
            values[canonical_key] = value
    if set(values) != set(required):
        raise _refuse("installed-metadata-required")
    if values["Metadata-Version"] not in SUPPORTED_METADATA_VERSIONS:
        raise _refuse("installed-metadata-version")
    normalized = _normalize_distribution_name(values["Name"])
    version = values["Version"]
    if _DISTRIBUTION_VERSION_RE.fullmatch(version) is None:
        raise _refuse("installed-version")
    return normalized, version


def _wheel_metadata_semantics(raw: bytes) -> dict[str, Any]:
    headers = _strict_header_lines(
        raw,
        "installed-wheel",
        metadata_block=False,
        maximum_headers=MAX_WHEEL_HEADERS,
    )
    allowed = {"Wheel-Version", "Generator", "Root-Is-Purelib", "Tag"}
    if any(key not in allowed for key, _value in headers):
        raise _refuse("installed-wheel-unknown-header")
    singletons: dict[str, str] = {}
    tags: list[str] = []
    for key, value in headers:
        if key == "Tag":
            tags.append(value)
            continue
        if key in singletons:
            raise _refuse("installed-wheel-singleton")
        singletons[key] = value
    if set(singletons) != {
        "Wheel-Version",
        "Generator",
        "Root-Is-Purelib",
    }:
        raise _refuse("installed-wheel-required")
    if singletons["Wheel-Version"] != SUPPORTED_WHEEL_VERSION:
        raise _refuse("installed-wheel-version")
    purelib = singletons["Root-Is-Purelib"]
    if purelib not in WHEEL_BOOLEAN_LEXICAL_VALUES:
        raise _refuse("installed-wheel-purelib")
    generator = singletons["Generator"]
    if len(generator) > MAX_GENERATOR_CHARACTERS:
        raise _refuse("installed-wheel-generator")
    if (
        not tags
        or len(tags) > MAX_WHEEL_TAGS
        or tags != sorted(tags)
        or len(tags) != len(set(tags))
        or any(_WHEEL_TAG_RE.fullmatch(tag) is None for tag in tags)
    ):
        raise _refuse("installed-wheel-tags")
    return {
        "wheel_version": singletons["Wheel-Version"],
        "root_is_purelib": purelib == "true",
        "generator_sha256": _raw_hash(generator.encode("ascii")),
        "tag_count": len(tags),
        "tags_sha256": _domain_hash(
            WHEEL_TAGS_DOMAIN, tags, MAX_CONTROL_FILE_BYTES
        ),
    }


def _validate_wheel_metadata_semantics(value: Any) -> dict[str, Any]:
    document = _exact_dict(
        value, WHEEL_METADATA_SEMANTICS_KEYS, "wheel-metadata-semantics"
    )
    normalized_name = _normalize_distribution_name(document["normalized_name"])
    if normalized_name != document["normalized_name"]:
        raise _refuse("wheel-metadata-name")
    _hex64(document["wheel_sha256"])
    if document["wheel_version"] != SUPPORTED_WHEEL_VERSION:
        raise _refuse("wheel-metadata-version")
    if type(document["root_is_purelib"]) is not bool:
        raise _refuse("wheel-metadata-purelib")
    _hex64(document["generator_sha256"])
    if (
        type(document["tag_count"]) is not int
        or not (1 <= document["tag_count"] <= MAX_WHEEL_TAGS)
    ):
        raise _refuse("wheel-metadata-tag-count")
    _hex64(document["tags_sha256"])
    return document


def _validate_wheel_semantics_projection(
    value: Any,
) -> list[dict[str, Any]]:
    if type(value) is not list or not value or len(value) > MAX_DISTRIBUTIONS:
        raise _refuse("wheel-semantics-projection")
    validated = [_validate_wheel_metadata_semantics(item) for item in value]
    names = [item["normalized_name"] for item in validated]
    if names != sorted(names) or len(names) != len(set(names)):
        raise _refuse("wheel-semantics-order")
    return validated


def _strict_json_object(raw: bytes, token: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_CONTROL_FILE_BYTES:
        raise _refuse(token + "-size")

    def pairs(items: list[tuple[Any, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if type(key) is not str or key in result:
                raise _refuse(token + "-duplicate-key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except _Refused:
        raise
    except BaseException:
        raise _refuse(token + "-json")
    _require_native(value)
    if type(value) is not dict:
        raise _refuse(token + "-object")
    return value


def _validate_pep610_git(raw: bytes) -> None:
    document = _strict_json_object(raw, "installed-direct-url")
    if set(document) != {"url", "vcs_info"}:
        raise _refuse("installed-direct-url-keyset")
    url = document["url"]
    vcs_info = document["vcs_info"]
    if (
        type(url) is not str
        or not url.isascii()
        or _SANITIZED_HTTPS_URL_RE.fullmatch(url) is None
        or "?" in url
        or "#" in url
        or "%" in url
        or "@" in url[len("https://") :].split("/", 1)[0]
        or "/../" in url
        or "/./" in url
    ):
        raise _refuse("installed-direct-url-sanitization")
    authority, url_path = url[len("https://") :].split("/", 1)
    if any(part in ("", ".", "..") for part in url_path.split("/")):
        raise _refuse("installed-direct-url-sanitization")
    if ":" in authority:
        _host, port = authority.rsplit(":", 1)
        if not port.isdecimal() or not (1 <= int(port) <= 65535):
            raise _refuse("installed-direct-url-port")
    if type(vcs_info) is not dict or set(vcs_info) not in (
        {"vcs", "commit_id"},
        {"vcs", "commit_id", "requested_revision"},
    ):
        raise _refuse("installed-vcs-keyset")
    if vcs_info.get("vcs") != "git" or _GIT_COMMIT_RE.fullmatch(
        vcs_info.get("commit_id", "")
    ) is None:
        raise _refuse("installed-vcs")
    if "requested_revision" in vcs_info:
        revision = vcs_info["requested_revision"]
        if (
            type(revision) is not str
            or _REQUESTED_REVISION_RE.fullmatch(revision) is None
            or any(
                part in ("", ".", "..") for part in revision.split("/")
            )
        ):
            raise _refuse("installed-vcs-revision")


def _strict_record_rows(
    raw: bytes,
    record_path: str,
    actual_files: dict[str, dict[str, Any]],
) -> list[str]:
    policy = _descriptor_policy(
        RECORD_POLICY, RECORD_POLICY_KEYS, "record-policy"
    )
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > policy["max_bytes"]
    ):
        raise _refuse("installed-record-size")
    try:
        text = raw.decode(policy["encoding"])
    except UnicodeDecodeError:
        raise _refuse("installed-record-encoding")
    if chr(policy["nul_codepoint"]) in text:
        raise _refuse("installed-record-control")
    paths: list[str] = []
    raw_paths: set[str] = set()
    folded_paths: set[str] = set()
    row_count = 0
    try:
        reader = csv.reader(
            io.StringIO(text, newline=policy["csv_reader_newline"]),
            delimiter=policy["delimiter"],
            strict=bool(policy["csv_strict"]),
        )
        for row in reader:
            row_count += 1
            if row_count > policy["row_count_maximum"]:
                raise _refuse("installed-record-rows")
            if len(row) != policy["column_count"]:
                raise _refuse("installed-record-row")
            path, hash_field, size_field = row
            _strict_installed_relative_path(path)
            folded = path.casefold()
            if path in raw_paths or folded in folded_paths:
                raise _refuse("installed-record-alias")
            raw_paths.add(path)
            folded_paths.add(folded)
            entry = actual_files.get(path)
            if entry is None:
                raise _refuse("installed-record-missing-file")
            if path == record_path:
                if (
                    hash_field != policy["empty_field"]
                    or size_field != policy["empty_field"]
                ):
                    raise _refuse("installed-record-self")
                paths.append(path)
                continue
            if (
                hash_field == policy["empty_field"]
                or size_field == policy["empty_field"]
            ):
                raise _refuse("installed-record-missing-digest")
            match = re.fullmatch(
                rf"{re.escape(policy['hash_algorithm'])}"
                rf"{re.escape(policy['hash_assignment_separator'])}"
                rf"([{policy['hash_urlsafe_base64_character_class']}]"
                rf"{{{policy['hash_urlsafe_base64_characters']}}})",
                hash_field,
            )
            if match is None:
                raise _refuse("installed-record-hash")
            encoded_digest = match.group(1)
            try:
                decoded = base64.urlsafe_b64decode(
                    encoded_digest + policy["hash_decode_padding"]
                )
            except (ValueError, TypeError):
                raise _refuse("installed-record-hash")
            canonical_digest = base64.urlsafe_b64encode(decoded).rstrip(
                policy["hash_decode_padding"].encode("ascii")
            )
            if (
                len(decoded) != policy["hash_decoded_bytes"]
                or canonical_digest.decode("ascii") != encoded_digest
                or decoded.hex() != entry["sha256"]
            ):
                raise _refuse("installed-record-digest")
            if (
                not size_field.isascii()
                or not size_field.isdecimal()
                or (
                    len(size_field) > 1
                    and size_field.startswith(policy["decimal_zero_character"])
                )
                or int(size_field) != entry["size"]
            ):
                raise _refuse("installed-record-file-size")
            paths.append(path)
    except (csv.Error, UnicodeError):
        raise _refuse("installed-record-csv")
    if row_count < policy["row_count_minimum"]:
        raise _refuse("installed-record-rows")
    if record_path not in paths:
        raise _refuse("installed-record-self")
    if raw != _canonical_record_bytes(paths, actual_files, record_path):
        raise _refuse("installed-record-canonical")
    return paths


def _strict_installed_relative_path(path: Any) -> str:
    policy = _descriptor_policy(
        RECORD_POLICY, RECORD_POLICY_KEYS, "record-policy"
    )
    if (
        type(path) is not str
        or not path
        or len(path) > policy["path_max_characters"]
        or path.startswith(policy["absolute_path_prefix"])
        or policy["backslash_character"] in path
        or chr(policy["nul_codepoint"]) in path
    ):
        raise _refuse("installed-record-path")
    parts = path.split(policy["path_separator"])
    forbidden_parts = tuple(policy["path_components_forbidden"].split(","))
    if any(
        part in forbidden_parts
        or re.fullmatch(policy["path_components"], part) is None
        for part in parts
    ):
        raise _refuse("installed-record-path")
    return path


def _canonical_record_bytes(
    paths: list[str] | set[str] | tuple[str, ...],
    actual_files: dict[str, dict[str, Any]],
    record_path: str,
) -> bytes:
    policy = _descriptor_policy(
        RECORD_POLICY, RECORD_POLICY_KEYS, "record-policy"
    )
    if type(record_path) is not str or record_path not in actual_files:
        raise _refuse("installed-record-canonical")
    path_list = list(paths)
    if (
        any(type(path) is not str for path in path_list)
        or not (
            policy["row_count_minimum"]
            <= len(path_list)
            <= policy["row_count_maximum"]
        )
        or path_list.count(record_path) != 1
        or len(path_list) != len(set(path_list))
        or len(path_list) != len({path.casefold() for path in path_list})
    ):
        raise _refuse("installed-record-canonical")
    output = bytearray()
    for path in sorted(path_list):
        _strict_installed_relative_path(path)
        entry = actual_files.get(path)
        if entry is None:
            raise _refuse("installed-record-canonical")
        output.extend(path.encode(policy["canonical_path_encoding"]))
        if path == record_path:
            output.extend(
                (policy["delimiter"] * 2 + policy["line_ending"]).encode(
                    "ascii"
                )
            )
            continue
        try:
            digest = base64.urlsafe_b64encode(
                bytes.fromhex(_hex64(entry["sha256"]))
            ).rstrip(b"=")
        except (ValueError, TypeError, KeyError):
            raise _refuse("installed-record-canonical")
        output.extend(policy["delimiter"].encode("ascii"))
        output.extend(policy["hash_algorithm"].encode("ascii"))
        output.extend(policy["hash_assignment_separator"].encode("ascii"))
        output.extend(digest)
        output.extend(policy["delimiter"].encode("ascii"))
        output.extend(str(entry["size"]).encode("ascii"))
        output.extend(policy["line_ending"].encode("ascii"))
    if len(output) > policy["max_bytes"]:
        raise _refuse("installed-record-canonical-size")
    return bytes(output)


def _source_identity_sha256(
    entry: dict[str, Any],
    *,
    dependency_component_id: str,
    dependency_lock_sha256: str,
    project_metadata_sha256: str,
    wheel_metadata_semantics: dict[str, Any],
) -> str:
    semantics = _validate_wheel_metadata_semantics(wheel_metadata_semantics)
    if (
        semantics["normalized_name"] != entry["normalized_name"]
        or semantics["wheel_sha256"] != entry["wheel_sha256"]
    ):
        raise _refuse("source-identity-wheel-semantics")
    body = {
        "schema": SOURCE_IDENTITY_SCHEMA,
        "source_kind": entry["source_kind"],
        "normalized_name": entry["normalized_name"],
        "version": entry["version"],
        "dependency_component_id": dependency_component_id,
        "dependency_lock_sha256": _hex64(dependency_lock_sha256),
        "project_metadata_sha256": _hex64(project_metadata_sha256),
        "wheel_version": semantics["wheel_version"],
        "wheel_root_is_purelib": semantics["root_is_purelib"],
        "wheel_generator_sha256": semantics["generator_sha256"],
        "wheel_tag_count": semantics["tag_count"],
        "wheel_tags_sha256": semantics["tags_sha256"],
        "metadata_sha256": entry["metadata_sha256"],
        "wheel_sha256": entry["wheel_sha256"],
        "record_sha256": entry["record_sha256"],
        "direct_url_sha256": entry["direct_url_sha256"],
    }
    _exact_dict(body, SOURCE_IDENTITY_PREIMAGE_KEYS, "source-identity-preimage")
    return _domain_hash(SOURCE_IDENTITY_DOMAIN, body, MAX_CONTROL_FILE_BYTES)


def _derive_installed_distribution_manifest(
    environment_root_fd: int,
    request: dict[str, Any],
    request_sha256: str,
    storage_digest: str,
    manifest: dict[str, Any],
    b2: dict[str, Any],
) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    site_packages_relative = _site_packages_relative(request)
    manifest_by_path = _manifest_index(manifest)
    _validate_materialization_copies(
        environment_root_fd, request, manifest_by_path
    )
    root_fd, device, chain = _open_manifest_chain(
        environment_root_fd,
        site_packages_relative,
        manifest_by_path,
        "installed",
    )
    site_packages_fd = chain[-1][2]
    try:
        top_names = _safe_names(site_packages_fd, "installed-root")
        entries: list[dict[str, Any]] = []
        control_raw: dict[str, bytes] = {}
        counters = {"entries": 0, "bytes": 0, "captured_bytes": 0}
        _scan_installed_directory(
            site_packages_fd,
            device,
            site_packages_relative,
            "",
            entries,
            control_raw,
            counters,
            1,
        )
        entries.sort(key=lambda entry: entry["path"])
        paths = [entry["path"] for entry in entries]
        if len(paths) != len(set(paths)) or len(paths) != len(
            {path.casefold() for path in paths}
        ):
            raise _refuse("installed-path-alias")
        for entry in entries:
            _require_manifest_entry(manifest_by_path, entry)
        expected_manifest_paths = {site_packages_relative, *paths}
        observed_manifest_paths = {
            path
            for path in manifest_by_path
            if path == site_packages_relative
            or path.startswith(site_packages_relative + "/")
        }
        if observed_manifest_paths != expected_manifest_paths:
            raise _refuse("installed-manifest-closure")
        actual_files = {
            entry["path"][len(site_packages_relative) + 1 :]: entry
            for entry in entries
            if entry["kind"] == "file"
        }
        dist_info_names = [
            name for name in top_names if name.endswith(".dist-info")
        ]
        if (
            not dist_info_names
            or len(dist_info_names) > MAX_DISTRIBUTIONS
            or any(
                entry["kind"] == "directory"
                and entry["path"].endswith(".dist-info")
                and entry["path"].count("/")
                != site_packages_relative.count("/") + 1
                for entry in entries
            )
        ):
            raise _refuse("installed-distributions")
        distributions: list[dict[str, Any]] = []
        wheel_semantics_by_distribution: list[dict[str, Any]] = []
        owner_by_path: dict[str, str] = {}
        record_digest_by_owner: dict[str, str] = {}
        for dist_info in sorted(dist_info_names):
            metadata_path = dist_info + "/METADATA"
            wheel_path = dist_info + "/WHEEL"
            record_path = dist_info + "/RECORD"
            direct_url_path = dist_info + "/direct_url.json"
            required = (metadata_path, wheel_path, record_path)
            if any(path not in control_raw for path in required):
                raise _refuse("installed-control-required")
            normalized_name, version = _metadata_identity(
                control_raw[metadata_path]
            )
            suffix = "-" + version + ".dist-info"
            if not dist_info.endswith(suffix):
                raise _refuse("installed-dist-info-version")
            stem = dist_info[: -len(suffix)]
            if _normalize_distribution_name(stem) != normalized_name:
                raise _refuse("installed-dist-info-name")
            if normalized_name in record_digest_by_owner:
                raise _refuse("installed-distribution-alias")
            metadata_sha256 = _raw_hash(control_raw[metadata_path])
            wheel_sha256 = _raw_hash(control_raw[wheel_path])
            record_sha256 = _raw_hash(control_raw[record_path])
            parsed_wheel = _wheel_metadata_semantics(control_raw[wheel_path])
            wheel_semantics = {
                "normalized_name": normalized_name,
                "wheel_sha256": wheel_sha256,
                "wheel_version": parsed_wheel["wheel_version"],
                "root_is_purelib": parsed_wheel["root_is_purelib"],
                "generator_sha256": parsed_wheel["generator_sha256"],
                "tag_count": parsed_wheel["tag_count"],
                "tags_sha256": parsed_wheel["tags_sha256"],
            }
            _validate_wheel_metadata_semantics(wheel_semantics)
            if direct_url_path in control_raw:
                _validate_pep610_git(control_raw[direct_url_path])
                # Frozen B2's non-null optional-value comparison is
                # uninhabited on Python (str.__ne__(None) is NotImplemented).
                # Keep this slice explicitly wheel-only even if B2 changes.
                raise _refuse("installed-git-uninhabited")
            source_kind = "wheel"
            direct_url_sha256: str | None = None
            distribution = {
                "normalized_name": normalized_name,
                "version": version,
                "source_kind": source_kind,
                "source_identity_sha256": "",
                "metadata_sha256": metadata_sha256,
                "wheel_sha256": wheel_sha256,
                "record_sha256": record_sha256,
                "direct_url_sha256": direct_url_sha256,
            }
            distribution["source_identity_sha256"] = _source_identity_sha256(
                distribution,
                dependency_component_id=request[
                    "candidate_dependency_component_id"
                ],
                dependency_lock_sha256=request["dependency_lock_sha256"],
                project_metadata_sha256=request["project_metadata_sha256"],
                wheel_metadata_semantics=wheel_semantics,
            )
            owned_paths = _strict_record_rows(
                control_raw[record_path], record_path, actual_files
            )
            for path in owned_paths:
                if path in owner_by_path:
                    raise _refuse("installed-record-overlap")
                owner_by_path[path] = normalized_name
            for path in actual_files:
                if path.startswith(dist_info + "/") and (
                    owner_by_path.get(path) != normalized_name
                ):
                    raise _refuse("installed-dist-info-ownership")
            record_digest_by_owner[normalized_name] = record_sha256
            distributions.append(distribution)
            wheel_semantics_by_distribution.append(wheel_semantics)
        distributions.sort(key=lambda entry: entry["normalized_name"])
        wheel_semantics_by_distribution.sort(
            key=lambda entry: entry["normalized_name"]
        )
        names = [entry["normalized_name"] for entry in distributions]
        if len(names) != len(set(names)) or names != sorted(names):
            raise _refuse("installed-distribution-order")
        if set(owner_by_path) != set(actual_files):
            raise _refuse("installed-unowned-file")
        files = []
        for path, tree_entry in sorted(actual_files.items()):
            owner = owner_by_path[path]
            files.append(
                {
                    "path": tree_entry["path"],
                    "distribution": owner,
                    "mode": tree_entry["mode"],
                    "size": tree_entry["size"],
                    "sha256": tree_entry["sha256"],
                    "record_sha256": record_digest_by_owner[owner],
                }
            )
        installed_manifest = {
            "schema": b2["INSTALLED_DISTRIBUTION_MANIFEST_SCHEMA"],
            "evidence_contract_id": PHASE5B2_CONTRACT_ID,
            "environment_policy_id": ENVIRONMENT_POLICY_ID,
            "request_sha256": request_sha256,
            "storage_digest": storage_digest,
            "candidate_product_id": request["candidate_product_id"],
            "dependency_component_id": request[
                "candidate_dependency_component_id"
            ],
            "dependency_lock_sha256": request["dependency_lock_sha256"],
            "project_metadata_sha256": request["project_metadata_sha256"],
            "distribution_count": len(distributions),
            "file_count": len(files),
            "total_bytes": sum(entry["size"] for entry in files),
            "distributions": distributions,
            "files": files,
        }
        try:
            installed_manifest_sha256 = b2["_installed_manifest"](
                installed_manifest, request, request_sha256, storage_digest
            )
        except BaseException:
            raise _refuse("installed-manifest")
        if _safe_names(site_packages_fd, "installed-root-reproof") != top_names:
            raise _refuse("installed-root-drift")
        _reprove_manifest_chain(chain)
        return (
            installed_manifest,
            installed_manifest_sha256,
            wheel_semantics_by_distribution,
        )
    except OSError:
        raise _refuse("installed-scan-io")
    finally:
        _close_manifest_chain(root_fd, chain, "installed")


def _validate_context_and_build_candidate(
    context: Any,
    frozen_request: dict[str, Any],
    frozen_request_raw: bytes,
    layout_plan: dict[str, Any],
    stage_result: dict[str, Any],
    core_config: dict[str, Any],
    core_config_raw: bytes,
    runtime_config: dict[str, Any],
    runtime_config_raw: bytes,
    b2: dict[str, Any],
) -> dict[str, Any]:
    if type(context) is not dict or tuple(context) != HELD_SNAPSHOT_CONTEXT_KEYS:
        raise _refuse("held-context-keyset")
    request, request_raw = _parse_canonical_bytes(
        context["environment_request_json"], "held-request", 1_000_000
    )
    if request_raw != frozen_request_raw or request != frozen_request:
        raise _refuse("held-request-binding")
    try:
        request_sha256 = b2["_phase5a_request"](request)
    except BaseException:
        raise _refuse("held-request")
    if request_sha256 != _hex64(context["environment_request_sha256"]):
        raise _refuse("held-request-digest")
    request_record, _request_record_raw = _parse_canonical_bytes(
        context["storage_request_record_json"], "held-storage-request", 1_000_000
    )
    manifest, _manifest_raw = _parse_canonical_bytes(
        context["storage_manifest_json"], "held-storage-manifest", 1_000_000
    )
    prepare, _prepare_raw = _parse_canonical_bytes(
        context["storage_prepare_record_json"], "held-storage-prepare", 1_000_000
    )
    try:
        request_record_sha256 = b2["_storage_request"](
            request_record, request, request_sha256
        )
    except BaseException:
        raise _refuse("held-storage-request")
    try:
        manifest_sha256 = b2["_tree_manifest"](
            manifest, request, request_sha256
        )
    except BaseException:
        raise _refuse("held-storage-manifest")
    try:
        b2["_crosscheck_storage_fingerprints"](request_record, manifest)
    except BaseException:
        raise _refuse("held-storage-fingerprints")
    try:
        prepare_sha256 = b2["_storage_prepare"](
            prepare,
            request,
            request_sha256,
            request_record,
            manifest,
            manifest_sha256,
        )
    except BaseException:
        raise _refuse("held-storage-prepare")
    try:
        storage_digest = b2["_storage_digest"](
            {
                "request_sha256": request_sha256,
                "manifest_sha256": manifest_sha256,
                "prepare_sha256": prepare_sha256,
            }
        )
    except BaseException:
        raise _refuse("held-storage-digest")
    if (
        request_record_sha256 != _hex64(context["storage_request_record_sha256"])
        or manifest_sha256 != _hex64(context["storage_manifest_sha256"])
        or prepare_sha256 != _hex64(context["storage_prepare_sha256"])
        or storage_digest != _hex64(context["storage_digest"])
        or context["operation_id"] != "operation-" + request_sha256
    ):
        raise _refuse("held-storage-digests")
    try:
        _exact_dict(core_config, tuple(b2["CORE_CONFIG_KEYS"]), "core-config")
        _exact_dict(
            runtime_config,
            tuple(b2["EMBEDDING_RUNTIME_CONFIG_KEYS"]),
            "runtime-config",
        )
        _validated_core, embedding_space_identity = b2["_core_config"](
            core_config, request
        )
        b2["_embedding_runtime_config"](runtime_config, request, core_config)
    except BaseException:
        raise _refuse("planned-config")
    _require_model_cache_binding(layout_plan, core_config, runtime_config)
    (
        installed_manifest,
        installed_manifest_sha256,
        wheel_metadata_semantics,
    ) = (
        _derive_installed_distribution_manifest(
            context["environment_root_fd"],
            request,
            request_sha256,
            storage_digest,
            manifest,
            b2,
        )
    )
    plan, plan_sha256 = _derive_model_snapshot_plan(
        context["environment_root_fd"], request, manifest, b2
    )
    core_json = core_config_raw.decode("ascii")
    runtime_json = runtime_config_raw.decode("ascii")
    model_manifest = {
        "schema": b2["MODEL_MANIFEST_SCHEMA"],
        "evidence_contract_id": PHASE5B2_CONTRACT_ID,
        "environment_policy_id": ENVIRONMENT_POLICY_ID,
        "request_sha256": request_sha256,
        "storage_digest": storage_digest,
        "candidate_product_id": request["candidate_product_id"],
        "core_config_canonical_json": core_json,
        "core_config_fingerprint": _raw_hash(core_config_raw),
        "embedding_space_identity": embedding_space_identity,
        "embedding_runtime_config_canonical_json": runtime_json,
        "embedding_runtime_config_sha256": _raw_hash(runtime_config_raw),
        "embedding_provider": request["embedding_provider"],
        "model_id": request["model_id"],
        "model_revision": request["model_revision"],
        "cache_root_relative": MODEL_CACHE_ROOT_RELATIVE,
        "snapshot_plan": plan,
        "snapshot_plan_sha256": plan_sha256,
        "post_publication_snapshot_sha256": plan_sha256,
    }
    try:
        model_manifest_sha256 = b2["_model_manifest"](
            model_manifest, request, request_sha256, storage_digest
        )
    except BaseException:
        raise _refuse("model-manifest")
    environment = {
        "environment_request": request,
        "environment_request_sha256": request_sha256,
        "layout_plan": layout_plan,
        "stage_result": stage_result,
        "storage_request_record": request_record,
        "storage_request_record_sha256": request_record_sha256,
        "storage_prepare_record": prepare,
        "storage_prepare_sha256": prepare_sha256,
        "storage_manifest": manifest,
        "storage_manifest_sha256": manifest_sha256,
        "storage_digest": storage_digest,
    }
    model = {
        "model_manifest": model_manifest,
        "model_manifest_sha256": model_manifest_sha256,
    }
    installed = {
        "installed_distribution_manifest": installed_manifest,
        "installed_distribution_manifest_sha256": installed_manifest_sha256,
        "wheel_metadata_semantics": wheel_metadata_semantics,
    }
    _exact_dict(environment, ENVIRONMENT_FRAGMENT_KEYS, "environment-fragment")
    _exact_dict(installed, INSTALLED_FRAGMENT_KEYS, "installed-fragment")
    _exact_dict(model, MODEL_FRAGMENT_KEYS, "model-fragment")
    return {
        "environment": environment,
        "installed": installed,
        "model": model,
    }


def _build_fragment(candidate: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": FRAGMENT_SCHEMA,
        "mode": MODE,
        "environment_static_contract_id": ENVIRONMENT_STATIC_CONTRACT_ID,
        "phase5b1_source_sha256": PHASE5B1_SOURCE_SHA256,
        "phase5b1_contract_id": PHASE5B1_CONTRACT_ID,
        "phase5b2_source_sha256": PHASE5B2_SOURCE_SHA256,
        "phase5b2_contract_id": PHASE5B2_CONTRACT_ID,
        "environment_policy_id": ENVIRONMENT_POLICY_ID,
        "environment": candidate["environment"],
        "installed": candidate["installed"],
        "model": candidate["model"],
        "static_roles_present": list(STATIC_ROLES_PRESENT),
        "static_roles_pending": list(STATIC_ROLES_PENDING),
        "static_evidence_complete": False,
    }
    fragment = dict(body)
    fragment["fragment_sha256"] = _domain_hash(
        FRAGMENT_DOMAIN, body, MAX_FRAGMENT_BYTES
    )
    _validate_fragment(fragment)
    return fragment


def _build_result(
    status: str,
    *,
    storage_result: dict[str, Any] | None = None,
    fragment: dict[str, Any] | None = None,
    b1: dict[str, Any] | None = None,
    b2: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reasons = {
        item_status: reason
        for item_status, reason, _code in STATUS_REASON_EXIT_BINDINGS
    }
    if status not in reasons:
        status = STATUS_BLOCKED
    success = status == STATUS_SUCCESS
    if not success:
        storage_result = None
        fragment = None
    fragment_sha256 = fragment["fragment_sha256"] if fragment is not None else None
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "command": COMMAND,
        "status": status,
        "reason": reasons[status],
        "environment_static_contract_id": ENVIRONMENT_STATIC_CONTRACT_ID,
        "environment_policy_id": ENVIRONMENT_POLICY_ID,
        "storage_inspect_result": storage_result,
        "environment_static_fragment": fragment,
        "environment_static_fragment_sha256": fragment_sha256,
        "document_valid": success,
        "held_snapshot_reproved": success,
        "environment_static_fragment_produced": success,
        "static_evidence_complete": False,
        "evidence_verified": False,
        "receipt_issuable": False,
        "receipt_published": False,
        "dynamic_probe_performed": False,
        "candidate_executed": False,
        "activation_performed": False,
        "nonclaims": list(NONCLAIMS),
    }
    _exact_dict(result, RESULT_KEYS[:-1], "result-body")
    result["result_sha256"] = _domain_hash(RESULT_DOMAIN, result, MAX_RESULT_BYTES)
    return _validate_result(result, b1=b1, b2=b2)


def _validate_fragment(fragment: Any) -> dict[str, Any]:
    _require_native(fragment, max_bytes=MAX_FRAGMENT_BYTES)
    _exact_dict(fragment, FRAGMENT_KEYS, "fragment")
    fixed = {
        "schema": FRAGMENT_SCHEMA,
        "mode": MODE,
        "environment_static_contract_id": ENVIRONMENT_STATIC_CONTRACT_ID,
        "phase5b1_source_sha256": PHASE5B1_SOURCE_SHA256,
        "phase5b1_contract_id": PHASE5B1_CONTRACT_ID,
        "phase5b2_source_sha256": PHASE5B2_SOURCE_SHA256,
        "phase5b2_contract_id": PHASE5B2_CONTRACT_ID,
        "environment_policy_id": ENVIRONMENT_POLICY_ID,
        "static_roles_present": list(STATIC_ROLES_PRESENT),
        "static_roles_pending": list(STATIC_ROLES_PENDING),
        "static_evidence_complete": False,
    }
    for key, expected in fixed.items():
        if type(fragment[key]) is not type(expected) or fragment[key] != expected:
            raise _refuse("fragment-binding")
    environment = _exact_dict(
        fragment["environment"], ENVIRONMENT_FRAGMENT_KEYS, "environment-fragment"
    )
    installed = _exact_dict(
        fragment["installed"], INSTALLED_FRAGMENT_KEYS, "installed-fragment"
    )
    _validate_wheel_semantics_projection(installed["wheel_metadata_semantics"])
    model = _exact_dict(fragment["model"], MODEL_FRAGMENT_KEYS, "model-fragment")
    for key in (
        "environment_request_sha256",
        "storage_request_record_sha256",
        "storage_prepare_sha256",
        "storage_manifest_sha256",
        "storage_digest",
    ):
        _hex64(environment[key])
    _hex64(installed["installed_distribution_manifest_sha256"])
    if installed["installed_distribution_manifest_sha256"] != _domain_hash(
        _B2_INSTALLED_MANIFEST_DOMAIN,
        installed["installed_distribution_manifest"],
        MAX_FRAGMENT_BYTES,
    ):
        raise _refuse("fragment-installed-digest")
    _hex64(model["model_manifest_sha256"])
    if model["model_manifest_sha256"] != _domain_hash(
        _B2_MODEL_MANIFEST_DOMAIN, model["model_manifest"], MAX_FRAGMENT_BYTES
    ):
        raise _refuse("fragment-model-digest")
    body = {key: fragment[key] for key in FRAGMENT_KEYS if key != "fragment_sha256"}
    if _hex64(fragment["fragment_sha256"]) != _domain_hash(
        FRAGMENT_DOMAIN, body, MAX_FRAGMENT_BYTES
    ):
        raise _refuse("fragment-self-hash")
    return fragment


def _validate_storage_success(result: Any, fragment: dict[str, Any]) -> None:
    if type(result) is not dict:
        raise _refuse("storage-result")
    required = {
        "schema": _B1_RESULT_SCHEMA,
        "command": _B1_INSPECT_COMMAND,
        "status": STATUS_SUCCESS,
        "reason": _B1_INSPECT_REASON,
        "storage_contract_id": PHASE5B1_CONTRACT_ID,
        "storage_read_supported": True,
        "storage_write_supported": False,
        "storage_read_performed": True,
        "storage_write_attempted": False,
        "storage_written": False,
        "stage_correlation_verified": True,
        "filesystem_verified": True,
        "access_verified": True,
        "environment_tree_verified": True,
        "environment_tree_published": True,
        "reconciled": False,
    }
    for key, expected in required.items():
        if (
            key not in result
            or type(result[key]) is not type(expected)
            or result[key] != expected
        ):
            raise _refuse("storage-result-binding")
    environment = fragment["environment"]
    request = environment["environment_request"]
    bindings = {
        "request_sha256": environment["environment_request_sha256"],
        "manifest_sha256": environment["storage_manifest_sha256"],
        "prepare_sha256": environment["storage_prepare_sha256"],
        "storage_digest": environment["storage_digest"],
        "layout_plan_id": request["layout_id"],
        "product_id": request["candidate_product_id"],
        "policy_id": request["inventory_policy_id"],
    }
    for key, expected in bindings.items():
        if result.get(key) != expected:
            raise _refuse("storage-result-digest")
    claimed = result.get("result_sha256")
    if _hex64(claimed) != _domain_hash(
        _B1_STORAGE_RESULT_DOMAIN,
        {key: result[key] for key in result if key != "result_sha256"},
        8192,
    ):
        raise _refuse("storage-result-self-hash")


def _validate_fragment_semantics(
    fragment: dict[str, Any], b1: dict[str, Any], b2: dict[str, Any]
) -> None:
    environment = fragment["environment"]
    installed = fragment["installed"]
    model = fragment["model"]
    request = environment["environment_request"]
    layout_plan = environment["layout_plan"]
    stage_result = environment["stage_result"]
    request_record = environment["storage_request_record"]
    manifest = environment["storage_manifest"]
    prepare = environment["storage_prepare_record"]
    try:
        phase5a, installed_layout = b1["_verify_frozen_sibling_sources"]()
        validated_request, b1_request_sha256 = b1["_validate_request"](
            request, phase5a
        )
        validated_stage = b1["_validate_stage_result"](
            stage_result, validated_request
        )
        validated_layout = b1["_validate_layout_plan"](
            layout_plan,
            validated_request,
            validated_stage,
            installed_layout,
        )
        request_sha256 = b2["_phase5a_request"](request)
        if b1_request_sha256 != request_sha256:
            raise _refuse("fragment-request-replay")
        request_record_sha256 = b2["_storage_request"](
            request_record, request, request_sha256
        )
        manifest_sha256 = b2["_tree_manifest"](
            manifest, request, request_sha256
        )
        b2["_crosscheck_storage_fingerprints"](request_record, manifest)
        prepare_sha256 = b2["_storage_prepare"](
            prepare,
            request,
            request_sha256,
            request_record,
            manifest,
            manifest_sha256,
        )
        storage_digest = b2["_storage_digest"](
            {
                "request_sha256": request_sha256,
                "manifest_sha256": manifest_sha256,
                "prepare_sha256": prepare_sha256,
            }
        )
        installed_manifest_sha256 = b2["_installed_manifest"](
            installed["installed_distribution_manifest"],
            request,
            request_sha256,
            storage_digest,
        )
        model_manifest_sha256 = b2["_model_manifest"](
            model["model_manifest"], request, request_sha256, storage_digest
        )
        core_config, _core_raw = _parse_canonical_bytes(
            model["model_manifest"]["core_config_canonical_json"].encode(
                "ascii"
            ),
            "fragment-core-config",
            1_000_000,
        )
        runtime_config, _runtime_raw = _parse_canonical_bytes(
            model["model_manifest"][
                "embedding_runtime_config_canonical_json"
            ].encode("ascii"),
            "fragment-runtime-config",
            1_000_000,
        )
        _require_model_cache_binding(
            validated_layout, core_config, runtime_config
        )
        layout_plan_sha256 = _raw_hash(
            _canonical_bytes(validated_layout, 1_000_000)
        )
        stage_result_sha256 = _raw_hash(
            _canonical_bytes(validated_stage, 1_000_000)
        )
        if (
            request_record["layout_plan_sha256"] != layout_plan_sha256
            or request["stage_result_sha256"] != stage_result_sha256
            or request_record["stage_result_sha256"] != stage_result_sha256
            or prepare["stage_result_sha256"] != stage_result_sha256
        ):
            raise _refuse("fragment-environment-document-binding")
    except BaseException:
        raise _refuse("fragment-semantic-replay")
    expected = {
        "environment_request_sha256": request_sha256,
        "storage_request_record_sha256": request_record_sha256,
        "storage_manifest_sha256": manifest_sha256,
        "storage_prepare_sha256": prepare_sha256,
        "storage_digest": storage_digest,
    }
    for key, value in expected.items():
        if environment[key] != value:
            raise _refuse("fragment-semantic-digest")
    if (
        installed["installed_distribution_manifest_sha256"]
        != installed_manifest_sha256
    ):
        raise _refuse("fragment-semantic-installed")
    if model["model_manifest_sha256"] != model_manifest_sha256:
        raise _refuse("fragment-semantic-model")
    _crosscheck_installed_manifest_tree(
        manifest,
        request,
        installed["installed_distribution_manifest"],
        installed["wheel_metadata_semantics"],
    )
    _crosscheck_model_plan_tree(
        manifest, model["model_manifest"]["snapshot_plan"]
    )


def _crosscheck_installed_manifest_tree(
    manifest: dict[str, Any],
    request: dict[str, Any],
    installed_manifest: dict[str, Any],
    wheel_metadata_semantics: list[dict[str, Any]],
) -> None:
    """Replay B3b's producer-owned static correlations without filesystem I/O."""
    site_packages_relative = _site_packages_relative(request)
    tree_entries = manifest["entries"]
    tree_by_path = {entry["path"]: entry for entry in tree_entries}
    if len(tree_by_path) != len(tree_entries):
        raise _refuse("fragment-installed-tree-paths")
    for relative, request_field in MATERIALIZATION_FILES:
        path = MATERIALIZATION_ROOT_RELATIVE + "/" + relative
        entry = tree_by_path.get(path)
        if (
            type(entry) is not dict
            or entry.get("kind") != "file"
            or entry.get("mode") != "0600"
            or entry.get("sha256") != request[request_field]
        ):
            raise _refuse("fragment-materialization-copy")
    materialization_paths = {
        path
        for path in tree_by_path
        if path == MATERIALIZATION_ROOT_RELATIVE
        or path.startswith(MATERIALIZATION_ROOT_RELATIVE + "/")
    }
    expected_materialization_paths = {
        MATERIALIZATION_ROOT_RELATIVE,
        *(
            MATERIALIZATION_ROOT_RELATIVE + "/" + name
            for name, _field in MATERIALIZATION_FILES
        ),
    }
    if (
        materialization_paths != expected_materialization_paths
        or tree_by_path.get(MATERIALIZATION_ROOT_RELATIVE)
        != _manifest_directory_entry(MATERIALIZATION_ROOT_RELATIVE)
    ):
        raise _refuse("fragment-materialization-closure")
    if tree_by_path.get(site_packages_relative) != _manifest_directory_entry(
        site_packages_relative
    ):
        raise _refuse("fragment-site-packages-root")
    relative_tree_files: dict[str, dict[str, Any]] = {}
    dist_info_directories = set()
    for path, entry in tree_by_path.items():
        if not path.startswith(site_packages_relative + "/"):
            continue
        relative = path[len(site_packages_relative) + 1 :]
        parts = relative.split("/")
        lowered_parts = [part.casefold() for part in parts]
        if any(
            part.endswith(".egg-info")
            or part.endswith(".egg-link")
            or part.startswith("__editable__")
            for part in lowered_parts
        ):
            raise _refuse("fragment-installed-unsupported-form")
        if any(
            lowered.endswith(".dist-info") and not original.endswith(".dist-info")
            for original, lowered in zip(parts, lowered_parts)
        ):
            raise _refuse("fragment-installed-dist-info-alias")
        if len(parts) >= 2 and parts[-2].endswith(".dist-info"):
            control_names = {"METADATA", "WHEEL", "RECORD", "direct_url.json"}
            if parts[-1].casefold() in {
                name.casefold() for name in control_names
            } and parts[-1] not in control_names:
                raise _refuse("fragment-installed-control-alias")
        if entry["kind"] == "file":
            if len(parts) == 1 and relative.endswith(".dist-info"):
                raise _refuse("fragment-installed-dist-info-kind")
            relative_tree_files[relative] = entry
        elif relative.endswith(".dist-info"):
            if "/" in relative:
                raise _refuse("fragment-installed-nested-dist-info")
            dist_info_directories.add(relative)
    installed_files = installed_manifest["files"]
    installed_by_path = {entry["path"]: entry for entry in installed_files}
    if len(installed_by_path) != len(installed_files):
        raise _refuse("fragment-installed-file-paths")
    expected_full_paths = {
        site_packages_relative + "/" + path for path in relative_tree_files
    }
    if set(installed_by_path) != expected_full_paths:
        raise _refuse("fragment-installed-file-closure")
    installed_files_by_owner: dict[str, dict[str, dict[str, Any]]] = {}
    dist_info_owners: dict[str, set[str]] = {}
    for relative, tree_entry in relative_tree_files.items():
        full_path = site_packages_relative + "/" + relative
        installed_entry = installed_by_path[full_path]
        for field in ("mode", "size", "sha256"):
            if installed_entry[field] != tree_entry[field]:
                raise _refuse("fragment-installed-file-binding")
        owner = installed_entry["distribution"]
        owner_files = installed_files_by_owner.setdefault(owner, {})
        if relative in owner_files:
            raise _refuse("fragment-installed-file-owner-alias")
        owner_files[relative] = installed_entry
        top_level, separator, _remainder = relative.partition("/")
        if separator and top_level.endswith(".dist-info"):
            dist_info_owners.setdefault(top_level, set()).add(owner)
    semantics = _validate_wheel_semantics_projection(wheel_metadata_semantics)
    semantics_by_name = {item["normalized_name"]: item for item in semantics}
    distributions = installed_manifest["distributions"]
    if set(semantics_by_name) != {
        item["normalized_name"] for item in distributions
    }:
        raise _refuse("fragment-wheel-semantics-closure")
    matched_dist_info = set()
    for distribution in distributions:
        distribution_semantics = semantics_by_name[
            distribution["normalized_name"]
        ]
        if distribution["source_identity_sha256"] != _source_identity_sha256(
            distribution,
            dependency_component_id=installed_manifest[
                "dependency_component_id"
            ],
            dependency_lock_sha256=installed_manifest[
                "dependency_lock_sha256"
            ],
            project_metadata_sha256=installed_manifest[
                "project_metadata_sha256"
            ],
            wheel_metadata_semantics=distribution_semantics,
        ):
            raise _refuse("fragment-installed-source-identity")
        suffix = "-" + distribution["version"] + ".dist-info"
        candidates = [
            name
            for name in dist_info_directories
            if name.endswith(suffix)
            and _normalize_distribution_name(name[: -len(suffix)])
            == distribution["normalized_name"]
        ]
        if len(candidates) != 1:
            raise _refuse("fragment-installed-dist-info")
        dist_info = candidates[0]
        if dist_info in matched_dist_info:
            raise _refuse("fragment-installed-dist-info-alias")
        matched_dist_info.add(dist_info)
        if distribution_semantics["wheel_sha256"] != distribution["wheel_sha256"]:
            raise _refuse("fragment-wheel-semantics-digest")
        if dist_info_owners.get(dist_info) != {
            distribution["normalized_name"]
        }:
            raise _refuse("fragment-installed-dist-info-owner")
        control_bindings = (
            ("METADATA", "metadata_sha256"),
            ("WHEEL", "wheel_sha256"),
            ("RECORD", "record_sha256"),
        )
        for basename, digest_field in control_bindings:
            entry = relative_tree_files.get(dist_info + "/" + basename)
            if entry is None or entry["sha256"] != distribution[digest_field]:
                raise _refuse("fragment-installed-control-binding")
        record_relative = dist_info + "/RECORD"
        owner_files = installed_files_by_owner.get(
            distribution["normalized_name"], {}
        )
        canonical_record = _canonical_record_bytes(
            set(owner_files), owner_files, record_relative
        )
        record_entry = relative_tree_files[record_relative]
        if (
            _raw_hash(canonical_record) != distribution["record_sha256"]
            or len(canonical_record) != record_entry["size"]
        ):
            raise _refuse("fragment-installed-record-canonical")
        direct_entry = relative_tree_files.get(dist_info + "/direct_url.json")
        if distribution["source_kind"] == "wheel":
            if (
                direct_entry is not None
                or distribution["direct_url_sha256"] is not None
            ):
                raise _refuse("fragment-installed-wheel-direct-url")
        else:
            raise _refuse("fragment-installed-source-kind")
    if matched_dist_info != dist_info_directories:
        raise _refuse("fragment-installed-distribution-closure")


def _crosscheck_model_plan_tree(
    manifest: dict[str, Any], plan: dict[str, Any]
) -> None:
    """Replay B3a's partial static correlation without filesystem access."""
    revision = plan["model_revision"]
    snapshot_root = MODEL_SNAPSHOTS_RELATIVE + "/" + revision
    tree_entries = manifest["entries"]
    plan_entries = plan["entries"]
    tree_by_path = {entry["path"]: entry for entry in tree_entries}
    if len(tree_by_path) != len(tree_entries):
        raise _refuse("fragment-tree-paths")
    for required in (
        MODEL_CACHE_ROOT_RELATIVE,
        MODEL_SNAPSHOTS_RELATIVE,
        snapshot_root,
    ):
        if tree_by_path.get(required) != _manifest_directory_entry(required):
            raise _refuse("fragment-model-root")
    expected_cache_paths = {
        MODEL_CACHE_ROOT_RELATIVE,
        MODEL_SNAPSHOTS_RELATIVE,
        snapshot_root,
    }
    for plan_entry in plan_entries:
        full_path = snapshot_root + "/" + plan_entry["path"]
        expected_cache_paths.add(full_path)
        expected = dict(plan_entry)
        expected["path"] = full_path
        if tree_by_path.get(full_path) != expected:
            raise _refuse("fragment-model-entry")
    observed_cache_paths = {
        path
        for path in tree_by_path
        if path == MODEL_CACHE_ROOT_RELATIVE
        or path.startswith(MODEL_CACHE_ROOT_RELATIVE + "/")
    }
    if observed_cache_paths != expected_cache_paths:
        raise _refuse("fragment-model-closure")


def _validate_result(
    result: Any,
    *,
    b1: dict[str, Any] | None = None,
    b2: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _require_native(result, max_bytes=MAX_RESULT_BYTES)
    _exact_dict(result, RESULT_KEYS, "result")
    if (
        result["schema"] != RESULT_SCHEMA
        or result["command"] != COMMAND
        or result["environment_static_contract_id"]
        != ENVIRONMENT_STATIC_CONTRACT_ID
        or result["environment_policy_id"] != ENVIRONMENT_POLICY_ID
        or result["nonclaims"] != list(NONCLAIMS)
    ):
        raise _refuse("result-binding")
    expected_reason = {
        status: reason for status, reason, _code in STATUS_REASON_EXIT_BINDINGS
    }.get(result["status"])
    if expected_reason is None or result["reason"] != expected_reason:
        raise _refuse("result-status")
    for key in _SUCCESS_TRUE_RESULT_FIELDS + FIXED_FALSE_RESULT_FIELDS:
        if type(result[key]) is not bool:
            raise _refuse("result-flag")
    success = result["status"] == STATUS_SUCCESS
    for key in _SUCCESS_TRUE_RESULT_FIELDS:
        if result[key] is not success:
            raise _refuse("result-success-flag")
    for key in FIXED_FALSE_RESULT_FIELDS:
        if result[key] is not False:
            raise _refuse("result-false-flag")
    if success:
        fragment = _validate_fragment(result["environment_static_fragment"])
        if (
            result["environment_static_fragment_sha256"]
            != fragment["fragment_sha256"]
        ):
            raise _refuse("result-fragment-digest")
        if b1 is None or b2 is None:
            b1, b2 = _load_frozen_upstreams()
        try:
            b1["_validate_result_replay"](result["storage_inspect_result"])
        except BaseException:
            raise _refuse("storage-result-replay")
        _validate_storage_success(result["storage_inspect_result"], fragment)
        _validate_fragment_semantics(fragment, b1, b2)
    elif (
        result["storage_inspect_result"] is not None
        or result["environment_static_fragment"] is not None
        or result["environment_static_fragment_sha256"] is not None
    ):
        raise _refuse("result-failure-payload")
    body = {key: result[key] for key in RESULT_KEYS if key != "result_sha256"}
    if _hex64(result["result_sha256"]) != _domain_hash(
        RESULT_DOMAIN, body, MAX_RESULT_BYTES
    ):
        raise _refuse("result-self-hash")
    return result


def validate_environment_static_result(result: Any) -> dict[str, Any]:
    """Replay a result; invalid input becomes the fixed blocked result."""
    try:
        frozen, _raw = _freeze_document(result, "result", MAX_RESULT_BYTES)
        return _validate_result(frozen)
    except BaseException:
        return _build_result(STATUS_BLOCKED)


def inspect_prebuilt_environment_static_evidence(
    environment_authority_root: Any,
    environment_state_root: Any,
    stage_journal_root: Any,
    *,
    environment_request: Any,
    layout_plan: Any,
    stage_result: Any,
    planned_core_config: Any,
    planned_embedding_runtime_config: Any,
) -> dict[str, Any]:
    """Produce the partial static fragment inside B1's held-root proof."""
    try:
        # Freeze every caller-owned value before upstream source or governed
        # environment I/O.  Later caller mutation cannot alter the proof.
        authority_root = _require_path_string(
            environment_authority_root, "authority-root"
        )
        state_root = _require_path_string(environment_state_root, "state-root")
        journal_root = _require_path_string(stage_journal_root, "journal-root")
        frozen_request, request_raw = _freeze_document(
            environment_request, "request", 1_000_000
        )
        frozen_layout, _layout_raw = _freeze_document(
            layout_plan, "layout", 1_000_000
        )
        frozen_stage, _stage_raw = _freeze_document(
            stage_result, "stage", 1_000_000
        )
        frozen_core, core_raw = _freeze_document(
            planned_core_config, "core-config", 1_000_000
        )
        frozen_runtime, runtime_raw = _freeze_document(
            planned_embedding_runtime_config, "runtime-config", 1_000_000
        )
        if type(frozen_core) is not dict or type(frozen_runtime) is not dict:
            raise _refuse("planned-config-type")
        _require_model_cache_binding(
            frozen_layout, frozen_core, frozen_runtime
        )
        if not _read_platform_capable():
            return _build_result(STATUS_UNSUPPORTED)
        b1, b2 = _load_frozen_upstreams()
        try:
            request_sha256 = b2["_phase5a_request"](frozen_request)
            validated_core, _embedding_identity = b2["_core_config"](
                frozen_core, frozen_request
            )
            b2["_embedding_runtime_config"](
                frozen_runtime, frozen_request, validated_core
            )
        except BaseException:
            raise _refuse("planned-input")
        # The held observer context will bind this Phase-5A domain digest to
        # the exact frozen request bytes; it is not a raw JSON digest.
        _hex64(request_sha256)
        gate = b1["_platform_gate"](b1["COMMAND_INSPECT"], require_write=False)
        if gate is not None:
            b1["_validate_result_replay"](gate)
            return _build_result(STATUS_UNSUPPORTED)
        candidate_box: list[dict[str, Any]] = []

        def observe(context: Any) -> None:
            if candidate_box:
                raise _refuse("observer-cardinality")
            candidate_box.append(
                _validate_context_and_build_candidate(
                    context,
                    frozen_request,
                    request_raw,
                    frozen_layout,
                    frozen_stage,
                    frozen_core,
                    core_raw,
                    frozen_runtime,
                    runtime_raw,
                    b2,
                )
            )
            return None

        tracker_type = b1.get("_MutationTracker")
        if type(tracker_type) is not type or tracker_type.__module__ != b1["__name__"]:
            raise _refuse("tracker-type")
        storage_result, observer_return = b1["_inspect_with_held_snapshot"](
            authority_root,
            state_root,
            journal_root,
            environment_request=frozen_request,
            layout_plan=frozen_layout,
            stage_result=frozen_stage,
            tracker=tracker_type(write_supported=False),
            snapshot_observer=observe,
        )
        if observer_return is not None or len(candidate_box) != 1:
            raise _refuse("observer-result")
        b1["_validate_result_replay"](storage_result)
        if (
            storage_result.get("status") != STATUS_SUCCESS
            or storage_result.get("command") != _B1_INSPECT_COMMAND
            or storage_result.get("reason") != _B1_INSPECT_REASON
        ):
            raise _refuse("storage-inspect")
        fragment = _build_fragment(candidate_box[0])
        _validate_storage_success(storage_result, fragment)
        return _build_result(
            STATUS_SUCCESS,
            storage_result=storage_result,
            fragment=fragment,
            b1=b1,
            b2=b2,
        )
    except BaseException:
        return _build_result(STATUS_BLOCKED)


_RENDER_FALLBACK = (
    '{"reason":"blocked:environment-static-fragment-refused",'
    '"schema":"synapse-s2.release-environment-static-render.v1",'
    '"status":"blocked"}'
)


def render_environment_static_result(result: Any) -> str:
    """Render one bounded canonical line, never raw unvalidated input."""
    try:
        replayed, _raw = _freeze_document(result, "render-result", MAX_RESULT_BYTES)
        validated = _validate_result(replayed)
        render = {
            "schema": RENDER_SCHEMA,
            "result_schema": RESULT_SCHEMA,
            "command": COMMAND,
            "status": validated["status"],
            "reason": validated["reason"],
            "environment_static_contract_id": ENVIRONMENT_STATIC_CONTRACT_ID,
            "environment_policy_id": ENVIRONMENT_POLICY_ID,
            "environment_static_fragment_sha256": validated[
                "environment_static_fragment_sha256"
            ],
            "document_valid": validated["document_valid"],
            "held_snapshot_reproved": validated["held_snapshot_reproved"],
            "environment_static_fragment_produced": validated[
                "environment_static_fragment_produced"
            ],
            "static_evidence_complete": False,
            "evidence_verified": False,
            "receipt_issuable": False,
            "receipt_published": False,
            "dynamic_probe_performed": False,
            "candidate_executed": False,
            "activation_performed": False,
            "result_sha256": validated["result_sha256"],
        }
        _exact_dict(render, RENDER_KEYS, "render")
        raw = _canonical_bytes(render, MAX_RENDER_BYTES)
        return raw.decode("ascii")
    except BaseException:
        return _RENDER_FALLBACK


def environment_static_result_exit_code(result: Any) -> int:
    """Return 0/2/3 only after exact replay validation."""
    try:
        replayed, _raw = _freeze_document(result, "exit-result", MAX_RESULT_BYTES)
        return _EXIT_CODES[_validate_result(replayed)["status"]]
    except BaseException:
        return _EXIT_CODES[STATUS_BLOCKED]

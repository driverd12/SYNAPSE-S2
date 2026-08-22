"""Pure Phase-5B2a environment-evidence document contract.

This module assigns closed documentary meanings to the eight evidence digest
slots reserved by ``release_environment.py``.  It performs no observation and
confers no authority: no filesystem, process, interpreter, dependency, model,
network, clock, compatibility-ticket, receipt, journal, or activation work is
performed here.  Dynamic probe roles are deliberately uninhabited in v1.
"""

import hashlib
import json
import math
import re


CONTRACT_SCHEMA = "synapse-s2.release-environment-evidence-contract.v1"
POLICY_SCHEMA = "synapse-s2.release-environment-policy.v1"
EVIDENCE_SET_SCHEMA = "synapse-s2.release-environment-evidence-set.v1"
MODEL_SNAPSHOT_PLAN_SCHEMA = (
    "synapse-s2.release-environment-model-snapshot-plan.v1"
)
INSTALLED_DISTRIBUTION_MANIFEST_SCHEMA = (
    "synapse-s2.release-environment-installed-distribution-manifest.v1"
)
NATIVE_FILE_MANIFEST_SCHEMA = (
    "synapse-s2.release-environment-native-file-manifest.v1"
)
DEPENDENCY_PROBE_SCHEMA = "synapse-s2.release-environment-dependency-probe.v1"
INTERPRETER_OBSERVATION_SCHEMA = (
    "synapse-s2.release-environment-interpreter-observation.v1"
)
TOOLCHAIN_OBSERVATION_SCHEMA = (
    "synapse-s2.release-environment-toolchain-observation.v1"
)
MODEL_MANIFEST_SCHEMA = "synapse-s2.release-environment-model-manifest.v1"
MODEL_PROBE_SCHEMA = "synapse-s2.release-environment-model-probe.v1"
RESULT_SCHEMA = "synapse-s2.release-environment-evidence-result.v1"
RENDER_SCHEMA = "synapse-s2.release-environment-evidence-render.v1"

MODE = "dormant-source-only-evidence-contract"
PROFILE = "exact-build-only"
PROFILE_VERSION = 1
COMPATIBILITY_PROFILE_VERSION = 3

PHASE5A_SOURCE_SHA256 = (
    "42da38a8710ebdeaaabf11741859f4822a943df3d6b9d8deff2236fa64672308"
)
PHASE5A_CONTRACT_ID = (
    "environment-contract-"
    "fec40398c01456d33b1bf5980b737987d1825fea8194d102af7d0afd939cfe3e"
)
PHASE5B1_SOURCE_SHA256 = (
    "3aa1fbc1042ddc05b3482ad657d8e41d8f62e02debcc2c897e4ca3ba20574bb0"
)
PHASE5B1_CONTRACT_ID = (
    "environment-storage-contract-"
    "9d10496d94003ad2d46905f19155de31c48a3834914c60469a739a73298c20aa"
)
ACTIVATION_CONTRACT_ID = (
    "activation-contract-"
    "db5a82b45bfc11d9a56a81fb7f0710e95d429fdfd313aac3743bd6d31abad276"
)

PHASE5A_REQUEST_SCHEMA = "synapse-s2.release-environment-request.v1"
PHASE5A_REQUEST_MODE = "dormant-source-only-environment-contract"
PHASE5A_REQUEST_DOMAIN = b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-REQUEST\0v1\0"
TREE_MANIFEST_SCHEMA = "synapse-s2.release-environment-tree-manifest.v1"
STORAGE_REQUEST_SCHEMA = "synapse-s2.release-environment-storage-request.v1"
STORAGE_PREPARE_SCHEMA = "synapse-s2.release-environment-storage-prepare.v1"

_DOMAINS = {
    "contract": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-CONTRACT\0v1\0",
    "policy": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-POLICY\0v1\0",
    "evidence_set": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-SET\0v1\0",
    "model_snapshot_plan": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-MODEL-SNAPSHOT-PLAN\0v1\0"
    ),
    "installed_distribution_manifest": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-"
        b"INSTALLED-DISTRIBUTION-MANIFEST\0v1\0"
    ),
    "native_file_manifest": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-NATIVE-FILE-MANIFEST\0v1\0"
    ),
    "dependency_probe": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-DEPENDENCY-PROBE\0v1\0"
    ),
    "interpreter_observation": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-"
        b"INTERPRETER-OBSERVATION\0v1\0"
    ),
    "toolchain_observation": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-"
        b"TOOLCHAIN-OBSERVATION\0v1\0"
    ),
    "model_manifest": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-MODEL-MANIFEST\0v1\0"
    ),
    "model_probe": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-MODEL-PROBE\0v1\0"
    ),
    "result": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-EVIDENCE-RESULT\0v1\0",
}
_STORAGE_DOMAINS = {
    "request": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-REQUEST\0v1\0",
    "tree_manifest": (
        b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-TREE-MANIFEST\0v1\0"
    ),
    "prepare": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-PREPARE\0v1\0",
    "storage_digest": b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-STORAGE-DIGEST\0v1\0",
}

MAX_INT = 2**53
MAX_NATIVE_INT = 2**64 - 1
MAX_DEPTH = 12
MAX_KEYS = 96
MAX_KEY_CHARS = 128
MAX_LIST_ITEMS = 20_000
MAX_TOTAL_NODES = 500_000
MAX_STRING_CHARS = 4096
MAX_DOCUMENT_BYTES = 8_000_000
MAX_CONTRACT_BYTES = 96 * 1024
MAX_RESULT_BYTES = 16_000_000
MAX_RENDER_BYTES = 4096
ABSOLUTE_PATH_MIN_CODEPOINT = 32
ABSOLUTE_PATH_MAX_CODEPOINT = 126
PATH_SEPARATOR = "/"
PATH_SYNTAX_VALUES = (
    ("separator", PATH_SEPARATOR),
    ("root", PATH_SEPARATOR),
    ("current_prefix", "." + PATH_SEPARATOR),
    ("double_separator", PATH_SEPARATOR + PATH_SEPARATOR),
)
PATH_FORBIDDEN_COMPONENTS = ("", ".", "..")

_HEX64_PATTERN = r"\A[0-9a-f]{64}\Z"
_CONTRACT_ID_PATTERN = (
    r"\Aenvironment-(?:(?:storage|evidence)-)?contract-[0-9a-f]{64}\Z"
)
_POLICY_ID_PATTERN = r"\Aenvironment-policy-[0-9a-f]{64}\Z"
_PRODUCT_ID_PATTERN = r"\Aproduct-[0-9a-f]{64}\Z"
_COMPONENT_ID_PATTERN = r"\Acomponent-[0-9a-f]{64}\Z"
_INVENTORY_POLICY_PATTERN = r"\Ainventory-policy-[0-9a-f]{64}\Z"
_LAYOUT_ID_PATTERN = r"\Alayout-[0-9a-f]{64}\Z"
_OPERATION_ID_PATTERN = r"\Aoperation-[0-9a-f]{64}\Z"
_SOURCE_BUILD_PATTERN = r"\Asource-[0-9a-f]{24}\Z"
_SOURCE_SHA_PATTERN = r"\A[0-9a-f]{40}\Z"
_ROOT_KEY_PATTERN = r"\Aed25519-[0-9a-f]{64}\Z"
_CHANNEL_PATTERN = r"\A[a-z][a-z0-9-]{0,31}\Z"
_VERSION_PATTERN = r"\A[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z"
_REVISION_PATTERN = r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z"
_LABEL_PATTERN = r"\A[A-Za-z0-9][A-Za-z0-9._/+-]{0,127}\Z"
_NAME_PATTERN = r"\A[a-z0-9][a-z0-9._-]{0,63}\Z"
_RELATIVE_PATH_PATTERN = r"\A[A-Za-z0-9_.+-][A-Za-z0-9_./+-]{0,1023}\Z"
_MODE_PATTERN = r"\A0[0-7]{3}\Z"
_PYTHON_ABI_PATTERN = r"\A[a-z0-9][a-z0-9._-]{0,63}\Z"
_TREE_ENTRY_NAME_PATTERN = r"\A[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}\Z"
_CANONICAL_DISTRIBUTION_NAME_PATTERN = r"\A[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z"
_MODEL_REPOSITORY_PATTERN = (
    r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}/"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z"
)
_SENSITIVE_ASSIGNMENT_KEY_PATTERN = (
    r"(?!(?:token[_-]?count|transport[_-]?token[_-]?stored)\b)"
    r"[_.-]*(?:[A-Za-z0-9]+[_-])*(?:"
    r"api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"auth[_-]?token|bearer[_-]?token|session[_-]?token|"
    r"client[_-]?(?:secret|key)|secret[_-]?key|private[_-]?key|"
    r"secret[_-]?access[_-]?key|access[_-]?key|account[_-]?key|"
    r"signing[_-]?(?:key|secret)|webhook[_-]?secret|"
    r"connection[_-]?string|database[_-]?url|sas[_-]?token|dsn|"
    r"token|secret|password|passwd|passphrase|auth|authentication|"
    r"bearer|authorization|proxy[_-]?authorization|credentials?"
    r")(?:[_-][A-Za-z0-9]+)*"
)
_SECRET_SHAPE_PATTERNS = (
    r"\b(?:sk-[A-Za-z0-9_-]{8,}|rk-[A-Za-z0-9_-]{16,})\b",
    r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{16,}\b",
    r"\bglpat-[A-Za-z0-9_-]{16,}\b",
    r"\bnpm_[A-Za-z0-9]{16,}\b",
    r"\bpypi-[A-Za-z0-9_-]{16,}\b",
    r"\bhf_[A-Za-z0-9]{16,}\b",
    r"\bxox[abprs]-[A-Za-z0-9-]{16,}\b",
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    r"\bAIza[0-9A-Za-z_-]{20,}\b",
    r"\bya29\.[0-9A-Za-z_-]{20,}\b",
    r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    r"(?i)\b(?:Cookie|Set-Cookie)\s*:",
    r"(?i)\b(?:Proxy-Authorization|Authorization)\s*:",
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}",
    rf"(?i)(?P<sensitive_key_quote>['\"]){_SENSITIVE_ASSIGNMENT_KEY_PATTERN}"
    rf"(?P=sensitive_key_quote)\s*[:=]",
    rf"(?i)\b{_SENSITIVE_ASSIGNMENT_KEY_PATTERN}\b\s*[:=]",
    r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@",
)

PHASE5B1_MAX_DOC_BYTES = 1_000_000
PHASE5B1_MAX_PATH_LENGTH = 3500
PHASE5B1_MAX_NAME_LENGTH = 200
PHASE5B1_MAX_TREE_ENTRIES = 20_000
PHASE5B1_MAX_TREE_TOTAL_BYTES = 6 * 1024 * 1024 * 1024
PHASE5B1_MAX_TREE_FILE_BYTES = 1024 * 1024 * 1024
PHASE5B1_MAX_TREE_DEPTH = 24
PHASE5B1_DIRECTORY_MODE = 0o700
PHASE5B1_PREIMAGE_NLINK = 2
PHASE5B1_FORBIDDEN_PATH_SEGMENTS = (
    ".synapse_s2", "current", "latest", "recovery", "live",
)

TREE_ENTRY_KINDS = ("directory", "file")
TREE_DIRECTORY_MODE = "0700"
TREE_REGULAR_FILE_MODE = "0600"
TREE_FILE_DEFAULT_MODE = TREE_REGULAR_FILE_MODE
TREE_EXECUTABLE_FILES = {"bin/python": "0700"}
TREE_REQUIRED_ENTRIES = ("bin", "bin/python")
TREE_REQUIRED_ENTRY_RELATION_METHOD = "issubset"
TREE_FILE_MODE_BINDING_FIELDS = (
    "path_role", "mapping_role", "default_role", "lookup_method",
)
TREE_FILE_MODE_BINDING = (
    "path", "executable_modes", "default_mode", "get",
)
DIRECTORY_ENTRY_EMPTY_SIZE = 0
DIRECTORY_ENTRY_EMPTY_DIGEST = ""
MODEL_ENTRY_KINDS = ("directory", "file")
MODEL_DIRECTORY_MODE = "0700"
MODEL_FILE_MODE = "0600"
MODEL_FORBIDDEN_SUFFIXES = (".py", ".pyc", ".pyo", ".pkl", ".pickle")
MODEL_ALLOWED_FILE_SUFFIXES = (".json", ".safetensors", ".txt")
MODEL_FILE_SUFFIX_RULE_BINDING_FIELDS = (
    "suffixes_role", "match_method", "expected_match",
)
MODEL_FILE_SUFFIX_RULE_BINDINGS = (
    ("forbidden_suffixes", "endswith", False),
    ("allowed_suffixes", "endswith", True),
)
MODEL_CACHE_ROOT_RELATIVE = "share/synapse-s2/model-cache-v1"
MODEL_SNAPSHOT_ROOT_PREFIX = (
    MODEL_CACHE_ROOT_RELATIVE + PATH_SEPARATOR + "snapshots" + PATH_SEPARATOR
)
MODEL_SNAPSHOT_MIN_ENTRIES = 1
MODEL_SNAPSHOT_MIN_TOTAL_BYTES = 1
DISTRIBUTION_SOURCE_KINDS = ("wheel", "git")
DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM_FIELDS = (
    "input_pattern", "substitution_function", "substitution_pattern", "replacement",
    "case_method", "match_function", "match_pattern",
)
DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM = (
    _NAME_PATTERN, "sub", r"[-_.]+", "-", "lower", "fullmatch",
    _CANONICAL_DISTRIBUTION_NAME_PATTERN,
)
DISTRIBUTION_NAME_NORMALIZATION_CHECK_FIELDS = (
    "target_role", "operand_role", "comparison_method", "expected",
)
DISTRIBUTION_NAME_NORMALIZATION_CHECKS = (
    ("value", "canonical", "__eq__", True),
    ("pattern_match_type_name", "none_type_name", "__eq__", False),
)
INSTALLED_FILE_MODES = ("0600", "0700")
NATIVE_FILE_MODES = ("0600", "0700")
NATIVE_BASE_INTERPRETER_OWNER = "base-interpreter"
NATIVE_BASE_INTERPRETER_PATH = "bin/python"
NATIVE_SUBLIST_FIELDS = ("architectures", "dependencies", "rpaths")
NATIVE_SORTED_UNIQUE_FIELDS = NATIVE_SUBLIST_FIELDS
NATIVE_SUBLIST_STRING_PATTERN_BINDINGS = (
    ("architectures", _NAME_PATTERN),
)
NATIVE_TEXT_SUBLIST_FIELDS = ("dependencies", "rpaths")
NATIVE_SUBLIST_MAX_ITEMS = 128
NATIVE_TEXT_MIN_CHARS = 1
STORAGE_DIGEST_COMPONENT_ROLES = (
    "request_sha256", "manifest_sha256", "prepare_sha256",
)
DISTRIBUTION_DIGEST_RELATION_ROLES = (
    "source_identity_digest", "metadata_digest", "wheel_digest",
    "record_digest",
)
PARENT_DIRECTORY_KIND_BY_ROLE = (
    ("tree_manifest", TREE_ENTRY_KINDS[0]),
    ("model_snapshot_plan", MODEL_ENTRY_KINDS[0]),
)
CORE_CONFIG_SCHEMA = "synapse-core-config.v1"
EMBEDDING_RUNTIME_CONFIG_SCHEMA = "synapse-s2.embedding-runtime-config.v1"
SECRET_SHAPE_DOCUMENT_BINDING_FIELDS = (
    "document_role", "schema_field", "schema_value", "field_roles",
)
SECRET_SHAPE_DOCUMENT_BINDINGS = (
    (
        "core_config", "protocol_version", CORE_CONFIG_SCHEMA,
        ("provider", "model_id", "model_revision"),
    ),
    (
        "model_snapshot_plan", "schema", MODEL_SNAPSHOT_PLAN_SCHEMA,
        ("model_id", "model_revision"),
    ),
)
SECRET_SHAPE_DOCUMENT_EXACT_MATCHES = 1
CORE_PROVIDER_ALIASES = ("mlx-neural", "mlx-neural-v1")
EMBEDDING_RUNTIME_PROVIDER = "mlx-neural-v1"
CORE_REQUIRED_MLX_DEVICE = "gpu"
CORE_REQUIRED_NATIVE = True
CORE_CONFIG_MAX_NEURAL_MATRIX_BYTES = 384 * 1024 * 1024
CORE_CONFIG_NEURAL_BYTES_PER_ELEMENT = 4
CORE_CONFIG_MIN_FRAME_BYTES = 4096
CORE_CONFIG_MAX_FRAME_BYTES = 4_194_304
CORE_CONFIG_MAX_SOCKET_BYTES = 103
CORE_CONFIG_PATH_ROLE_BINDINGS = (
    ("socket_path", False),
    ("state_path", False),
    ("memory_path", False),
    ("capture_root", True),
    ("cache_dir", False),
)
CORE_CONFIG_DISTINCT_PATH_ROLES = (
    "socket_path", "state_path", "memory_path",
)
CORE_CONFIG_PARENT_SUFFIX_BINDINGS = (
    ("state_path", "memory_path", "runtime_state.json"),
    ("socket_path", "memory_path", "core/service.sock"),
)
CORE_CONFIG_SUFFIX_BINDINGS = (
    ("cache_dir", MODEL_CACHE_ROOT_RELATIVE),
)
CORE_CONFIG_PATH_BYTE_BOUNDS = (
    ("socket_path", CORE_CONFIG_MAX_SOCKET_BYTES),
)
NEURAL_POOLING_VALUES = ("first", "last", "mean")
EMBEDDING_SPACE_SCHEMA = "synapse-s2.embedding-space.v1"
EMBEDDING_SPIKE_ENCODER = "zscore-top-k-v1"
EMBEDDING_NEURON_PROJECTION = "synaptic-matrix-v1"
EMBEDDING_SPACE_OUTER_BINDINGS = (
    ("schema", "constant:embedding-space-schema"),
    ("provider", "constant:embedding-runtime-provider"),
    ("dimensions", "core-config:dimension"),
    ("num_neurons", "core-config:num_neurons"),
    ("spike_encoder", "constant:embedding-spike-encoder"),
    ("default_top_k", "core-config:default_top_k"),
    ("neuron_projection", "constant:embedding-neuron-projection"),
    ("neural", "nested:embedding-space-neural-bindings"),
)
EMBEDDING_SPACE_NEURAL_BINDINGS = (
    ("model_id", "core-config:embedding_neural_model_id"),
    ("revision", "core-config:embedding_neural_revision"),
    ("pooling", "core-config:embedding_neural_pooling"),
    ("max_tokens", "core-config:embedding_neural_max_tokens"),
    ("normalize", "core-config:embedding_neural_normalize"),
)
EMBEDDING_SPACE_CONSTANT_VALUES = (
    ("embedding-space-schema", EMBEDDING_SPACE_SCHEMA),
    ("embedding-runtime-provider", EMBEDDING_RUNTIME_PROVIDER),
    ("embedding-spike-encoder", EMBEDDING_SPIKE_ENCODER),
    ("embedding-neuron-projection", EMBEDDING_NEURON_PROJECTION),
)
EMBEDDING_RUNTIME_CONFIG_BINDINGS = (
    ("schema", "constant:embedding-runtime-config-schema"),
    ("provider", "constant:embedding-runtime-provider"),
    ("model_id", "request:model_id"),
    ("revision", "request:model_revision"),
    ("cache_dir", "core-config:embedding_neural_cache_dir"),
    ("pooling", "core-config:embedding_neural_pooling"),
    ("max_tokens", "core-config:embedding_neural_max_tokens"),
    ("normalize", "core-config:embedding_neural_normalize"),
    ("local_files_only", "constant:local-files-only"),
)
EMBEDDING_RUNTIME_CONSTANT_VALUES = (
    ("embedding-runtime-config-schema", EMBEDDING_RUNTIME_CONFIG_SCHEMA),
    ("embedding-runtime-provider", EMBEDDING_RUNTIME_PROVIDER),
    ("local-files-only", True),
)
CORE_CONFIG_INTEGER_BOUNDS = {
    "dimension": (1, 65_536),
    "num_neurons": (1, 131_072),
    "default_top_k": (1, 65_536),
    "recall_count": (1, 10_000),
    "embedding_neural_max_tokens": (1, MAX_INT),
    "capture_max_files": (1, 1_000),
    "max_transcript_bytes": (1_024, 16_777_216),
    "max_frame_bytes": (CORE_CONFIG_MIN_FRAME_BYTES, CORE_CONFIG_MAX_FRAME_BYTES),
}
CORE_CONFIG_FLOAT_BOUNDS = {
    "quick_pruning_interval_seconds": (0.0, 86_400.0),
    "idle_deep_sleep_seconds": (0.0, 604_800.0),
    "capture_poll_seconds": (0.25, 300.0),
    "authority_timeout_seconds": (0.0, 300.0),
}
CORE_CONFIG_INTEGER_BOUND_ROLES = (
    ("dimension", "dimension"),
    ("num_neurons", "num_neurons"),
    ("default_top_k", "default_top_k"),
    ("recall_count", "recall_count"),
    ("max_tokens", "embedding_neural_max_tokens"),
    ("capture_max_files", "capture_max_files"),
    ("max_transcript_bytes", "max_transcript_bytes"),
    ("max_frame_bytes", "max_frame_bytes"),
)
CORE_CONFIG_FLOAT_BOUND_ROLES = (
    ("quick_pruning_interval", "quick_pruning_interval_seconds"),
    ("idle_deep_sleep", "idle_deep_sleep_seconds"),
    ("capture_poll", "capture_poll_seconds"),
    ("authority_timeout", "authority_timeout_seconds"),
)
CORE_CONFIG_BOOLEAN_ROLES = (
    "normalize", "local_files_only", "require_native",
    "poll_transcript_sources",
)
CORE_CONFIG_ORDER_RELATIONS = (
    ("default_top_k", "num_neurons", "less-than-or-equal"),
)
CORE_CONFIG_COMPARATOR_BINDINGS = (
    ("less-than-or-equal", "__le__"),
)
NUMERIC_BOUND_COMPARATOR_BINDINGS = (
    ("value", "minimum", "__ge__"),
    ("value", "maximum", "__le__"),
)
CORE_CONFIG_NEURAL_MATRIX_TERMS = (
    ("dimension", "num_neurons", 1),
    ("num_neurons", "num_neurons", 1),
    ("num_neurons", None, 3),
)

RUNTIME_INTEGRITY_FUNCTION_NAMES = (
    "_native", "_canonical", "_domain_hash", "_exact_dict", "_string",
    "_exact_value_equal", "_resolved_document_bindings",
    "_require_document_bindings",
    "_relation_fields", "_document_string_pattern_values",
    "_helper_string_pattern",
    "_require_document_aggregations",
    "_document_value_relation_matches", "_require_document_value_relation",
    "_require_optional_value_presence", "_collection_relation",
    "_sorted_collection", "_require_ordered_unique_values",
    "_require_entry_fixed_fields", "_validate_model_directory_entry",
    "_validate_model_file_entry", "_validate_tree_directory_entry",
    "_validate_tree_file_entry", "_validate_entry_kind",
    "_path_syntax", "_path_rejection_matches", "_parent_directory_kind",
    "_numeric_bounds_include", "_integer", "_boolean",
    "_relative_path", "_tree_relative_path",
    "_unique_ordered_paths", "_phase5b1_tree_order",
    "_require_parent_directories", "_hex64", "_fingerprint",
    "_normalized_distribution_name", "_canonical_json_string",
    "_finite_float", "_absolute_path", "_reject_secret_shape",
    "_require_document_secret_shapes",
    "_core_config", "_embedding_runtime_config", "_embedded_native",
    "_policy_body", "environment_policy_id",
    "environment_policy_projection", "_phase5a_fixed_policy",
    "_contract_body", "environment_evidence_contract_projection",
    "_runtime_projection_intact", "_phase5a_request",
    "_model_snapshot_plan", "_tree_manifest", "_storage_request",
    "_storage_prepare", "_storage_digest",
    "_crosscheck_storage_fingerprints",
    "_installed_manifest", "_native_manifest", "_model_manifest",
    "_crosscheck_static_documents", "_evidence_set", "_flags", "_result",
    "_result_reason", "_result_document_valid", "_result_derived",
    "_unsupported",
)
RUNTIME_INTEGRITY_MODULE_NAMES = ("hashlib", "json", "math", "re")
RUNTIME_INTEGRITY_BUILTIN_NAMES = (
    "BaseException", "TypeError", "UnicodeError", "ValueError", "all", "any",
    "bool", "dict", "float", "getattr", "int", "len", "list", "locals", "ord", "set",
    "sorted", "str", "sum", "tuple", "type", "zip", "globals",
)
RUNTIME_INTEGRITY_GLOBAL_NAMES = (
    RUNTIME_INTEGRITY_MODULE_NAMES + RUNTIME_INTEGRITY_FUNCTION_NAMES
)


EVIDENCE_SLOTS = (
    "environment_manifest_sha256",
    "installed_distribution_manifest_sha256",
    "native_file_manifest_sha256",
    "dependency_probe_sha256",
    "interpreter_observation_sha256",
    "toolchain_observation_sha256",
    "model_manifest_sha256",
    "model_probe_sha256",
)
STATIC_SLOTS = (
    "environment_manifest_sha256",
    "installed_distribution_manifest_sha256",
    "native_file_manifest_sha256",
    "model_manifest_sha256",
)
STATIC_SLOT_VALIDATOR_BINDINGS = (
    (
        "environment_manifest_sha256", "tree_manifest", "_tree_manifest",
        ("request", "request_sha256"),
    ),
    (
        "installed_distribution_manifest_sha256", "installed_manifest",
        "_installed_manifest",
        ("request", "request_sha256", "storage_digest"),
    ),
    (
        "native_file_manifest_sha256", "native_manifest",
        "_native_manifest", ("request", "request_sha256", "storage_digest"),
    ),
    (
        "model_manifest_sha256", "model_manifest", "_model_manifest",
        ("request", "request_sha256", "storage_digest"),
    ),
)
STATIC_SLOT_VALIDATOR_BINDING_FIELDS = (
    "slot", "document_role", "validator_function", "argument_roles",
)
STATIC_SLOT_VALIDATOR_ROLES = tuple(
    (slot, role) for slot, role, _function_name, _argument_roles
    in STATIC_SLOT_VALIDATOR_BINDINGS
)
STATIC_VALIDATOR_CONTEXT_BINDINGS = (
    ("request", "request"),
    ("request_sha256", "request_sha"),
    ("storage_digest", "storage_digest"),
)
STATIC_VALIDATOR_CONTEXT_ROLES = tuple(
    role for role, _local_name in STATIC_VALIDATOR_CONTEXT_BINDINGS
)
STATIC_PRIMARY_STORAGE_ROLE = "tree_manifest"
DYNAMIC_PENDING_SLOTS = (
    "dependency_probe_sha256",
    "interpreter_observation_sha256",
    "toolchain_observation_sha256",
    "model_probe_sha256",
)

SLOT_SCHEMAS = {
    "environment_manifest_sha256": TREE_MANIFEST_SCHEMA,
    "installed_distribution_manifest_sha256": (
        INSTALLED_DISTRIBUTION_MANIFEST_SCHEMA
    ),
    "native_file_manifest_sha256": NATIVE_FILE_MANIFEST_SCHEMA,
    "dependency_probe_sha256": DEPENDENCY_PROBE_SCHEMA,
    "interpreter_observation_sha256": INTERPRETER_OBSERVATION_SCHEMA,
    "toolchain_observation_sha256": TOOLCHAIN_OBSERVATION_SCHEMA,
    "model_manifest_sha256": MODEL_MANIFEST_SCHEMA,
    "model_probe_sha256": MODEL_PROBE_SCHEMA,
}

NONCLAIMS = (
    "document-validation-is-not-evidence-verification",
    "no-filesystem-or-held-root-observation",
    "no-phase5b1-storage-invocation-or-continuous-lock",
    "no-profile-3-ticket-or-result-verification",
    "no-activation-policy-or-trust-verification",
    "no-build-install-materialization-or-artifact-provenance",
    "no-interpreter-dependency-import-native-or-candidate-execution",
    "no-network-denial-clock-freshness-or-process-environment-proof",
    "no-model-load-inference-or-runtime-proof",
    "no-authentication-signature-ownership-durability-or-immutability",
    "no-evidence-truth-claim",
    "no-phase5a-observation-environment-id-or-receipt",
    "no-receipt-issuance-or-publication",
    "no-live-state-config-service-selector-floor-or-activation-access",
    "no-activation-journal-write",
    "no-blocker-5-completion",
    "dynamic-probe-roles-remain-pending-null",
    "ordinary-uv-venv-not-admissible-without-sanitized-materialization",
    "no-filesystem-path-resolution-or-symlink-normalization",
    "no-authoritative-core-config-loadability-proof",
    "no-hostile-same-process-monkeypatch-or-interpreter-integrity-proof",
    "no-self-source-byte-authentication-preimport-source-pin-is-external",
)

FALSE_FLAGS = (
    "filesystem_observed",
    "held_root_verified",
    "storage_invoked",
    "compatibility_verified",
    "activation_policy_verified",
    "build_verified",
    "materialization_verified",
    "dependency_verified",
    "interpreter_verified",
    "toolchain_verified",
    "model_verified",
    "network_denial_verified",
    "freshness_verified",
    "authentication_verified",
    "evidence_verified",
    "receipt_issuable",
    "receipt_published",
    "candidate_executed",
    "activation_performed",
    "live_state_accessed",
    "blocker_5_complete",
)
FALSE_FLAG_BINDINGS = tuple((key, False) for key in FALSE_FLAGS)

COMMAND_MODEL_PLAN = "validate-model-snapshot-plan-document"
COMMAND_EVIDENCE_SET = "validate-environment-evidence-set-document"
STATUS_DOCUMENT_VALID = "document_valid"
STATUS_UNSUPPORTED = "unsupported"
STATUS_INVALID = "invalid"
RESULT_EXIT_CODE_BINDINGS = (
    (STATUS_DOCUMENT_VALID, 0),
    (STATUS_UNSUPPORTED, 1),
    (STATUS_INVALID, 2),
)
RESULT_EXIT_PATH_BINDING_FIELDS = (
    "path_role", "predicate_function", "predicate_expected",
    "source_kind", "source_role",
)
RESULT_EXIT_PREDICATE_COMPARATOR_METHOD = "__eq__"
RESULT_EXIT_PREDICATE_ACTION_BINDING_FIELDS = (
    "comparison_result", "selection_count",
)
RESULT_EXIT_PREDICATE_ACTION_BINDINGS = (
    (False, 0),
    (True, 1),
)
RESULT_EXIT_SELECTION_SEQUENCE_METHOD = "__mul__"
RESULT_EXIT_SELECTION_COLLECTION_METHOD = "extend"
RESULT_EXIT_TRAVERSAL_METHOD = "__iter__"
RESULT_EXIT_SELECTED_PATH_BINDING_FIELDS = (
    "selection_method", "selection_index",
)
RESULT_EXIT_SELECTED_PATH_BINDING = ("__getitem__", 0)
RESULT_EXIT_EXCEPTION_PREDICATE_FUNCTION = ""
RESULT_EXIT_PATH_BINDINGS = (
    (
        "unsupported-template", "exit_matches_unsupported",
        True, "result-field", "status",
    ),
    (
        "valid-result", "valid_result", True,
        "result-field", "status",
    ),
    (
        "invalid-result", "exit_matches_any", True,
        "constant-status", STATUS_INVALID,
    ),
    (
        "exception", RESULT_EXIT_EXCEPTION_PREDICATE_FUNCTION, None,
        "constant-status", STATUS_INVALID,
    ),
)
RESULT_EXIT_SOURCE_KINDS = ("result-field", "constant-status")
RESULT_EXIT_NORMAL_PATH_ROLES = (
    "unsupported-template", "valid-result", "invalid-result",
)
RESULT_EXIT_EXCEPTION_PATH_ROLE = "exception"
RESULT_UNSUPPORTED_RENDER_BINDING_FIELDS = (
    "template_command", "line_command",
)
RESULT_UNSUPPORTED_RENDER_BINDINGS = (
    (COMMAND_MODEL_PLAN, COMMAND_MODEL_PLAN),
    (COMMAND_EVIDENCE_SET, COMMAND_EVIDENCE_SET),
)
RESULT_UNSUPPORTED_RENDER_MATCH_EXPECTED = True
RESULT_RENDER_VALIDITY_BINDING_FIELDS = (
    "valid_result", "renderer_function",
)
RESULT_RENDER_VALIDITY_BINDINGS = (
    (False, "render_fallback"),
    (True, "render_valid"),
)
RESULT_RENDER_VALIDITY_SELECTOR_BINDING_FIELDS = (
    "value_role", "selector_method", "expected_result", "comparator_method",
)
RESULT_RENDER_VALIDITY_SELECTOR_BINDING = (
    "valid", "__bool__", True, "__eq__",
)
RESULT_RENDER_LINE_SOURCE_BINDING_FIELDS = (
    "line_within_bounds", "line_source",
)
RESULT_RENDER_LINE_SOURCE_BINDINGS = (
    (False, "fallback"),
    (True, "rendered"),
)
RESULT_RENDER_LINE_SOURCE_ROLES = ("fallback", "rendered")
RESULT_RENDER_DYNAMIC_CANDIDATE_ACTION_RESULT = True
REASON_MODEL_PLAN_VALID = "model-snapshot-plan-document-valid-not-verified"
REASON_EVIDENCE_SET_VALID = "evidence-set-document-valid-not-verified"
REASON_MODEL_PLAN_UNSUPPORTED = "unsupported-model-snapshot-plan-document"
REASON_EVIDENCE_SET_UNSUPPORTED = "unsupported-environment-evidence-set-document"
RESULT_COMMANDS = (COMMAND_MODEL_PLAN, COMMAND_EVIDENCE_SET)
RESULT_STATUSES = (STATUS_DOCUMENT_VALID, STATUS_UNSUPPORTED)
RESULT_REASON_BINDINGS = (
    (COMMAND_MODEL_PLAN, STATUS_DOCUMENT_VALID, REASON_MODEL_PLAN_VALID),
    (COMMAND_MODEL_PLAN, STATUS_UNSUPPORTED, REASON_MODEL_PLAN_UNSUPPORTED),
    (COMMAND_EVIDENCE_SET, STATUS_DOCUMENT_VALID, REASON_EVIDENCE_SET_VALID),
    (
        COMMAND_EVIDENCE_SET,
        STATUS_UNSUPPORTED,
        REASON_EVIDENCE_SET_UNSUPPORTED,
    ),
)
RESULT_DOCUMENT_VALID_BINDING = (
    "status", "__eq__", STATUS_DOCUMENT_VALID,
)
RESULT_DERIVED_SOURCE_KINDS = ("call", "global", "list-global")
RESULT_DERIVED_BINDINGS = (
    ("reason", "call", "_result_reason", ("command", "status")),
    (
        "evidence_contract_id", "global", "EVIDENCE_CONTRACT_ID", (),
    ),
    (
        "environment_policy_id", "call", "environment_policy_id", (),
    ),
    (
        "document_valid", "call", "_result_document_valid", ("status",),
    ),
    ("flags", "call", "_flags", ()),
    ("nonclaims", "list-global", "NONCLAIMS", ()),
)
RESULT_DERIVED_BINDING_FIELDS = (
    "target_role", "source_kind", "source_name", "argument_roles",
)
RESULT_REPLAY_BINDINGS = (
    (COMMAND_MODEL_PLAN, "validate_plan", ("model_snapshot_plan",)),
    (
        COMMAND_EVIDENCE_SET,
        "validate_evidence",
        ("environment_request", "evidence_set"),
    ),
)
RESULT_REPLAY_BINDING_FIELDS = (
    "command", "validator_role", "result_argument_fields",
)
UNSUPPORTED_TEMPLATE_MATCH_ROLE = "exact-native-tree"
UNSUPPORTED_TEMPLATE_MATCH_BINDING = (
    UNSUPPORTED_TEMPLATE_MATCH_ROLE, "__eq__",
)


PHASE5A_BINDING_KEYS = (
    "activation_policy_receipt_sha256", "root_key_id", "trust_generation",
    "trust_bundle_sha256", "release_envelope_sha256",
    "compatibility_ticket_sha256", "compatibility_result_sha256", "channel",
    "version", "release_sequence", "source_sha",
    "candidate_source_build_id", "candidate_product_id",
    "inventory_policy_id", "candidate_dependency_component_id",
    "surfaces_digest", "layout_schema", "layout_mode",
    "layout_contract_id", "layout_id", "stage_result_sha256",
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

_PHASE5A_PATTERNS = {
    "activation_policy_receipt_sha256": _HEX64_PATTERN,
    "root_key_id": _ROOT_KEY_PATTERN,
    "trust_bundle_sha256": _HEX64_PATTERN,
    "release_envelope_sha256": _HEX64_PATTERN,
    "compatibility_ticket_sha256": _HEX64_PATTERN,
    "compatibility_result_sha256": _HEX64_PATTERN,
    "channel": _CHANNEL_PATTERN,
    "version": _VERSION_PATTERN,
    "source_sha": _SOURCE_SHA_PATTERN,
    "candidate_source_build_id": _SOURCE_BUILD_PATTERN,
    "candidate_product_id": _PRODUCT_ID_PATTERN,
    "inventory_policy_id": _INVENTORY_POLICY_PATTERN,
    "candidate_dependency_component_id": _COMPONENT_ID_PATTERN,
    "surfaces_digest": _HEX64_PATTERN,
    "layout_schema": _NAME_PATTERN,
    "layout_mode": _NAME_PATTERN,
    "layout_contract_id": r"\Alayout-contract-[0-9a-f]{64}\Z",
    "layout_id": _LAYOUT_ID_PATTERN,
    "stage_result_sha256": _HEX64_PATTERN,
    "stage_journal_head_sha256": _HEX64_PATTERN,
    "staged_product_id": _PRODUCT_ID_PATTERN,
    "staged_source_build_id": _SOURCE_BUILD_PATTERN,
    "host_id_sha256": _HEX64_PATTERN,
    "core_config_fingerprint": _HEX64_PATTERN,
    "embedding_space_identity": _LABEL_PATTERN,
    "embedding_provider": _LABEL_PATTERN,
    "model_id": _LABEL_PATTERN,
    "model_revision": _REVISION_PATTERN,
    "embedding_runtime_config_sha256": _HEX64_PATTERN,
    "expected_model_snapshot_sha256": _HEX64_PATTERN,
    "dependency_lock_sha256": _HEX64_PATTERN,
    "project_metadata_sha256": _HEX64_PATTERN,
    "environment_policy_id": _POLICY_ID_PATTERN,
    "target_system": _NAME_PATTERN,
    "target_machine": _NAME_PATTERN,
    "target_python_implementation": _NAME_PATTERN,
    "target_python_abi": _PYTHON_ABI_PATTERN,
    "target_base_executable_sha256": _HEX64_PATTERN,
}

TREE_MANIFEST_KEYS = (
    "schema", "storage_contract_id", "request_sha256", "operation_id",
    "product_id", "inventory_policy_id", "entry_count", "total_bytes",
    "entries",
)
TREE_ENTRY_KEYS = ("path", "kind", "mode", "size", "sha256")
FINGERPRINT_KEYS = ("device", "inode", "mode", "nlink")
STORAGE_REQUEST_KEYS = (
    "schema", "storage_contract_id", "phase5a_contract_id", "request",
    "request_sha256", "layout_id", "layout_plan_sha256",
    "stage_result_sha256", "stage_journal_entry_sha256", "operation_id",
    "environment_preimage_fingerprint", "operation_fingerprint",
    "request_record_sha256",
)
STORAGE_PREPARE_KEYS = (
    "schema", "storage_contract_id", "request_record_sha256",
    "request_sha256", "operation_id", "layout_id", "manifest_sha256",
    "manifest_entry_count", "manifest_total_bytes",
    "environment_preimage_fingerprint", "operation_fingerprint",
    "stage_result_sha256", "stage_journal_entry_sha256", "prepare_sha256",
)
MODEL_SNAPSHOT_ENTRY_KEYS = ("path", "kind", "mode", "size", "sha256")
MODEL_SNAPSHOT_PLAN_KEYS = (
    "schema", "environment_policy_id", "model_id", "model_revision",
    "cache_root_relative", "snapshot_root_relative", "entry_count",
    "total_bytes", "entries",
)
DISTRIBUTION_ENTRY_KEYS = (
    "normalized_name", "version", "source_kind", "source_identity_sha256",
    "metadata_sha256", "wheel_sha256", "record_sha256",
    "direct_url_sha256",
)
INSTALLED_FILE_ENTRY_KEYS = (
    "path", "distribution", "mode", "size", "sha256", "record_sha256",
)
INSTALLED_DISTRIBUTION_MANIFEST_KEYS = (
    "schema", "evidence_contract_id", "environment_policy_id",
    "request_sha256", "storage_digest", "candidate_product_id",
    "dependency_component_id", "dependency_lock_sha256",
    "project_metadata_sha256", "distribution_count", "file_count",
    "total_bytes", "distributions", "files",
)
NATIVE_ENTRY_KEYS = (
    "path", "owner", "mode", "size", "sha256", "architectures",
    "minimum_os", "load_commands_sha256", "dependencies", "rpaths",
)
NATIVE_FILE_MANIFEST_KEYS = (
    "schema", "evidence_contract_id", "environment_policy_id",
    "request_sha256", "storage_digest", "candidate_product_id",
    "target_machine", "file_count", "files",
)
CORE_CONFIG_KEYS = (
    "protocol_version", "socket_path", "state_path", "memory_path",
    "capture_root", "dimension", "num_neurons", "default_top_k",
    "recall_count", "quick_pruning_interval_seconds",
    "idle_deep_sleep_seconds", "embedding_provider_name",
    "embedding_neural_model_id", "embedding_neural_revision",
    "embedding_neural_cache_dir", "embedding_neural_pooling",
    "embedding_neural_max_tokens", "embedding_neural_normalize",
    "embedding_neural_local_files_only", "mlx_device", "require_native",
    "capture_poll_seconds", "capture_max_files",
    "poll_transcript_sources", "max_transcript_bytes", "max_frame_bytes",
    "authority_timeout_seconds",
)
EMBEDDING_RUNTIME_CONFIG_KEYS = (
    "schema", "provider", "model_id", "revision", "cache_dir", "pooling",
    "max_tokens", "normalize", "local_files_only",
)
MODEL_MANIFEST_KEYS = (
    "schema", "evidence_contract_id", "environment_policy_id",
    "request_sha256", "storage_digest", "candidate_product_id",
    "core_config_canonical_json", "core_config_fingerprint",
    "embedding_space_identity", "embedding_runtime_config_canonical_json",
    "embedding_runtime_config_sha256", "embedding_provider", "model_id",
    "model_revision", "cache_root_relative", "snapshot_plan",
    "snapshot_plan_sha256", "post_publication_snapshot_sha256",
)
EVIDENCE_SET_KEYS = (
    "schema", "mode", "evidence_contract_id", "environment_policy_id",
    "phase5a_source_sha256", "phase5a_contract_id",
    "phase5b1_source_sha256", "phase5b1_contract_id", "environment_request",
    "environment_request_sha256", "storage_request_record",
    "storage_request_record_sha256", "storage_prepare_record",
    "storage_prepare_sha256", "storage_manifest", "storage_manifest_sha256",
    "storage_digest", "documents_by_slot", "digests_by_slot",
)

DOCUMENT_BINDING_CONSTANT_VALUES = (
    ("mode", MODE),
    ("result-schema", RESULT_SCHEMA),
    ("render-schema", RENDER_SCHEMA),
    ("false", False),
    ("core-config-schema", CORE_CONFIG_SCHEMA),
    ("required-mlx-device", CORE_REQUIRED_MLX_DEVICE),
    ("required-native", CORE_REQUIRED_NATIVE),
    ("local-files-only", True),
    ("model-snapshot-plan-schema", MODEL_SNAPSHOT_PLAN_SCHEMA),
    ("model-cache-root-relative", MODEL_CACHE_ROOT_RELATIVE),
    ("tree-executable-files", TREE_EXECUTABLE_FILES),
    ("tree-file-default-mode", TREE_FILE_DEFAULT_MODE),
    ("model-forbidden-suffixes", MODEL_FORBIDDEN_SUFFIXES),
    ("model-allowed-suffixes", MODEL_ALLOWED_FILE_SUFFIXES),
    ("tree-manifest-schema", TREE_MANIFEST_SCHEMA),
    ("storage-request-schema", STORAGE_REQUEST_SCHEMA),
    ("storage-prepare-schema", STORAGE_PREPARE_SCHEMA),
    ("installed-manifest-schema", INSTALLED_DISTRIBUTION_MANIFEST_SCHEMA),
    ("native-manifest-schema", NATIVE_FILE_MANIFEST_SCHEMA),
    ("model-manifest-schema", MODEL_MANIFEST_SCHEMA),
    ("evidence-set-schema", EVIDENCE_SET_SCHEMA),
    ("phase5a-source-sha256", PHASE5A_SOURCE_SHA256),
    ("phase5a-contract-id", PHASE5A_CONTRACT_ID),
    ("phase5b1-source-sha256", PHASE5B1_SOURCE_SHA256),
    ("phase5b1-contract-id", PHASE5B1_CONTRACT_ID),
)
DOCUMENT_BINDING_COMPARATOR_METHOD = "__eq__"
POLICY_MEMBERSHIP_METHOD = "__contains__"
PATH_PREFIX_MATCH_METHOD = "startswith"
DOCUMENT_BINDING_TABLES = {
    "distribution_name_normalization": (
        ("value", "argument:value"),
        ("canonical", "derived:canonical"),
        (
            "pattern_match_type_name",
            "derived:pattern_match_type_name",
        ),
        ("none_type_name", "derived:none_type_name"),
    ),
    "tree_file_mode_sources": (
        ("path", "context:path"),
        ("executable_modes", "constant:tree-executable-files"),
        ("default_mode", "constant:tree-file-default-mode"),
    ),
    "model_file_suffix_sources": (
        ("value", "context:lowered_path"),
        ("forbidden_suffixes", "constant:model-forbidden-suffixes"),
        ("allowed_suffixes", "constant:model-allowed-suffixes"),
    ),
    "render_line_values": (
        ("fallback", "local:fallback_line"),
        ("rendered", "local:line"),
    ),
    "render_fallback_value": (
        ("line", "local:fallback_line"),
    ),
    "render_precomputed_value": (
        ("line", "argument:line"),
    ),
    "core_request": (
        ("protocol_version", "constant:core-config-schema"),
        ("embedding_provider_name", "request:embedding_provider"),
        ("embedding_neural_model_id", "request:model_id"),
        ("embedding_neural_revision", "request:model_revision"),
        (
            "embedding_neural_local_files_only",
            "constant:local-files-only",
        ),
        ("mlx_device", "constant:required-mlx-device"),
        ("require_native", "constant:required-native"),
    ),
    "request_embedding_space_identity": (
        ("embedding_space_identity", "derived:embedding_space_identity"),
    ),
    "model_snapshot_plan": (
        ("schema", "constant:model-snapshot-plan-schema"),
        ("environment_policy_id", "derived:environment_policy_id"),
        ("cache_root_relative", "constant:model-cache-root-relative"),
        ("snapshot_root_relative", "derived:snapshot_root_relative"),
    ),
    "tree_manifest": (
        ("schema", "constant:tree-manifest-schema"),
        ("storage_contract_id", "constant:phase5b1-contract-id"),
        ("request_sha256", "derived:request_sha256"),
        ("operation_id", "derived:operation_id"),
        ("product_id", "request:candidate_product_id"),
        ("inventory_policy_id", "request:inventory_policy_id"),
    ),
    "storage_request": (
        ("schema", "constant:storage-request-schema"),
        ("storage_contract_id", "constant:phase5b1-contract-id"),
        ("phase5a_contract_id", "constant:phase5a-contract-id"),
        ("request_sha256", "derived:request_sha256"),
        ("layout_id", "request:layout_id"),
        ("stage_result_sha256", "request:stage_result_sha256"),
        (
            "stage_journal_entry_sha256",
            "request:stage_journal_head_sha256",
        ),
        ("operation_id", "derived:operation_id"),
    ),
    "storage_prepare": (
        ("schema", "constant:storage-prepare-schema"),
        ("storage_contract_id", "constant:phase5b1-contract-id"),
        (
            "request_record_sha256",
            "request_record:request_record_sha256",
        ),
        ("request_sha256", "derived:request_sha256"),
        ("operation_id", "request_record:operation_id"),
        ("layout_id", "request:layout_id"),
        ("manifest_sha256", "derived:manifest_sha256"),
        ("manifest_entry_count", "manifest:entry_count"),
        ("manifest_total_bytes", "manifest:total_bytes"),
        (
            "environment_preimage_fingerprint",
            "request_record:environment_preimage_fingerprint",
        ),
        ("operation_fingerprint", "request_record:operation_fingerprint"),
        ("stage_result_sha256", "request:stage_result_sha256"),
        (
            "stage_journal_entry_sha256",
            "request:stage_journal_head_sha256",
        ),
    ),
    "installed_manifest": (
        ("schema", "constant:installed-manifest-schema"),
        ("evidence_contract_id", "derived:evidence_contract_id"),
        ("environment_policy_id", "derived:environment_policy_id"),
        ("request_sha256", "derived:request_sha256"),
        ("storage_digest", "derived:storage_digest"),
        ("candidate_product_id", "request:candidate_product_id"),
        (
            "dependency_component_id",
            "request:candidate_dependency_component_id",
        ),
        ("dependency_lock_sha256", "request:dependency_lock_sha256"),
        ("project_metadata_sha256", "request:project_metadata_sha256"),
    ),
    "installed_record_relation": (
        ("left", "file:record_sha256"),
        ("right", "distribution:record_sha256"),
    ),
    "installed_owner_completeness_relation": (
        ("left", "derived:file_owners"),
        ("right", "derived:distribution_names"),
    ),
    "native_manifest": (
        ("schema", "constant:native-manifest-schema"),
        ("evidence_contract_id", "derived:evidence_contract_id"),
        ("environment_policy_id", "derived:environment_policy_id"),
        ("request_sha256", "derived:request_sha256"),
        ("storage_digest", "derived:storage_digest"),
        ("candidate_product_id", "request:candidate_product_id"),
        ("target_machine", "request:target_machine"),
    ),
    "native_base_interpreter_relation": (
        ("left", "derived:observed_paths"),
        ("right", "derived:expected_paths"),
    ),
    "native_base_owner_classification_relation": (
        ("left", "native:owner"),
        ("right", "derived:base_owner"),
    ),
    "native_installed_owner_relation": (
        ("left", "installed:distribution"),
        ("right", "native:owner"),
    ),
    "native_distribution_owner_membership_relation": (
        ("left", "derived:distribution_names"),
        ("right", "native:owner"),
    ),
    "native_architecture_membership_relation": (
        ("left", "native:architectures"),
        ("right", "manifest_relation:target_machine"),
    ),
    "distribution_source_kind_membership_relation": (
        ("left", "derived:allowed_source_kinds"),
        ("right", "distribution:source_kind"),
    ),
    "installed_owner_membership_relation": (
        ("left", "derived:distribution_names"),
        ("right", "file:distribution"),
    ),
    "installed_mode_membership_relation": (
        ("left", "derived:allowed_modes"),
        ("right", "file:mode"),
    ),
    "native_mode_membership_relation": (
        ("left", "derived:allowed_modes"),
        ("right", "native:mode"),
    ),
    "cross_file_field_relation": (
        ("left", "observed:value"),
        ("right", "expected:value"),
    ),
    "tree_file_kind_relation": (
        ("left", "observed:kind"),
        ("right", "derived:file_kind"),
    ),
    "model_cache_paths_relation": (
        ("left", "derived:actual_paths"),
        ("right", "derived:expected_paths"),
    ),
    "storage_device_relation": (
        ("left", "preimage:device"),
        ("right", "operation:device"),
    ),
    "storage_inode_relation": (
        ("left", "preimage:inode"),
        ("right", "operation:inode"),
    ),
    "storage_operation_nlink_relation": (
        ("left", "operation:nlink"),
        ("right", "derived:expected_nlink"),
    ),
    "fingerprint_mode_relation": (
        ("left", "fingerprint:mode"),
        ("right", "derived:expected_mode"),
    ),
    "fingerprint_preimage_nlink_relation": (
        ("left", "fingerprint:nlink"),
        ("right", "derived:expected_nlink"),
    ),
    "parent_directory_kind_relation": (
        ("left", "parent:kind"),
        ("right", "derived:directory_kind"),
    ),
    "model_manifest": (
        ("schema", "constant:model-manifest-schema"),
        ("evidence_contract_id", "derived:evidence_contract_id"),
        ("environment_policy_id", "derived:environment_policy_id"),
        ("request_sha256", "derived:request_sha256"),
        ("storage_digest", "derived:storage_digest"),
        ("candidate_product_id", "request:candidate_product_id"),
        ("core_config_fingerprint", "request:core_config_fingerprint"),
        ("embedding_space_identity", "request:embedding_space_identity"),
        (
            "embedding_runtime_config_sha256",
            "request:embedding_runtime_config_sha256",
        ),
        ("embedding_provider", "request:embedding_provider"),
        ("model_id", "request:model_id"),
        ("model_revision", "request:model_revision"),
        ("cache_root_relative", "constant:model-cache-root-relative"),
    ),
    "model_plan_request": (
        ("model_id", "request:model_id"),
        ("model_revision", "request:model_revision"),
    ),
    "model_embedded_digests": (
        ("core_config_fingerprint", "derived:core_config_sha256"),
        (
            "embedding_runtime_config_sha256",
            "derived:runtime_config_sha256",
        ),
    ),
    "model_manifest_plan_digests": (
        ("snapshot_plan_sha256", "derived:model_plan_sha256"),
        (
            "post_publication_snapshot_sha256",
            "derived:model_plan_sha256",
        ),
    ),
    "request_model_plan_digest": (
        (
            "expected_model_snapshot_sha256",
            "derived:model_plan_sha256",
        ),
    ),
    "evidence_set": (
        ("schema", "constant:evidence-set-schema"),
        ("mode", "constant:mode"),
        ("evidence_contract_id", "derived:evidence_contract_id"),
        ("environment_policy_id", "derived:environment_policy_id"),
        ("phase5a_source_sha256", "constant:phase5a-source-sha256"),
        ("phase5a_contract_id", "constant:phase5a-contract-id"),
        ("phase5b1_source_sha256", "constant:phase5b1-source-sha256"),
        ("phase5b1_contract_id", "constant:phase5b1-contract-id"),
        ("environment_request_sha256", "derived:request_sha256"),
    ),
    "evidence_storage_digests": (
        (
            "storage_request_record_sha256",
            "derived:request_record_sha256",
        ),
        ("storage_manifest_sha256", "derived:manifest_sha256"),
        ("storage_prepare_sha256", "derived:prepare_sha256"),
        ("storage_digest", "derived:storage_digest"),
    ),
    "storage_digest_components": (
        ("request_sha256", "derived:request_sha256"),
        ("manifest_sha256", "derived:manifest_sha256"),
        ("prepare_sha256", "derived:prepare_sha256"),
    ),
    "result": (
        ("schema", "constant:result-schema"),
        ("command", "argument:command"),
        ("status", "argument:status"),
        ("reason", "derived:reason"),
        ("evidence_contract_id", "derived:evidence_contract_id"),
        ("environment_policy_id", "derived:environment_policy_id"),
        ("model_snapshot_plan", "argument:plan"),
        ("environment_request", "argument:request"),
        ("evidence_set", "argument:evidence"),
        ("model_snapshot_plan_sha256", "argument:plan_sha"),
        ("environment_request_sha256", "argument:request_sha"),
        ("evidence_set_sha256", "argument:evidence_sha"),
        ("document_valid", "derived:document_valid"),
        ("evidence_verified", "constant:false"),
        ("receipt_issuable", "constant:false"),
        ("receipt_published", "constant:false"),
        ("blocker_5_complete", "constant:false"),
        ("flags", "derived:flags"),
        ("nonclaims", "derived:nonclaims"),
    ),
    "render": (
        ("schema", "constant:render-schema"),
        ("result_schema", "constant:result-schema"),
        ("command", "result:command"),
        ("status", "result:status"),
        ("reason", "result:reason"),
        ("evidence_contract_id", "result:evidence_contract_id"),
        ("environment_policy_id", "result:environment_policy_id"),
        (
            "model_snapshot_plan_sha256",
            "result:model_snapshot_plan_sha256",
        ),
        ("environment_request_sha256", "result:environment_request_sha256"),
        ("evidence_set_sha256", "result:evidence_set_sha256"),
        ("document_valid", "result:document_valid"),
        ("evidence_verified", "constant:false"),
        ("receipt_issuable", "constant:false"),
        ("receipt_published", "constant:false"),
        ("blocker_5_complete", "constant:false"),
        ("result_sha256", "result:result_sha256"),
    ),
}
CROSS_MANIFEST_TREE_FILE_FIELDS = ("mode", "size", "sha256")
CROSS_MANIFEST_MODEL_FILE_FIELDS = ("kind", "mode", "size", "sha256")
DOCUMENT_RELATION_FIELDS = {
    "core_config": (
        ("socket_path", "socket_path"),
        ("state_path", "state_path"),
        ("memory_path", "memory_path"),
        ("capture_root", "capture_root"),
        ("provider", "embedding_provider_name"),
        ("model_id", "embedding_neural_model_id"),
        ("model_revision", "embedding_neural_revision"),
        ("cache_dir", "embedding_neural_cache_dir"),
        ("pooling", "embedding_neural_pooling"),
        ("max_tokens", "embedding_neural_max_tokens"),
        ("normalize", "embedding_neural_normalize"),
        ("local_files_only", "embedding_neural_local_files_only"),
        ("mlx_device", "mlx_device"),
        ("require_native", "require_native"),
        ("dimension", "dimension"),
        ("num_neurons", "num_neurons"),
        ("default_top_k", "default_top_k"),
        ("recall_count", "recall_count"),
        ("quick_pruning_interval", "quick_pruning_interval_seconds"),
        ("idle_deep_sleep", "idle_deep_sleep_seconds"),
        ("capture_poll", "capture_poll_seconds"),
        ("capture_max_files", "capture_max_files"),
        ("poll_transcript_sources", "poll_transcript_sources"),
        ("max_transcript_bytes", "max_transcript_bytes"),
        ("max_frame_bytes", "max_frame_bytes"),
        ("authority_timeout", "authority_timeout_seconds"),
    ),
    "model_snapshot_plan": (
        ("model_id", "model_id"),
        ("entries", "entries"),
        ("entry_count", "entry_count"),
        ("total_bytes", "total_bytes"),
        ("model_revision", "model_revision"),
        ("snapshot_root", "snapshot_root_relative"),
        ("entry_path", "path"),
        ("entry_kind", "kind"),
        ("entry_mode", "mode"),
        ("entry_size", "size"),
        ("entry_digest", "sha256"),
    ),
    "tree_manifest": (
        ("operation_id", "operation_id"),
        ("entries", "entries"),
        ("entry_count", "entry_count"),
        ("total_bytes", "total_bytes"),
        ("entry_path", "path"),
        ("entry_kind", "kind"),
        ("entry_mode", "mode"),
        ("entry_size", "size"),
        ("entry_digest", "sha256"),
    ),
    "storage_fingerprints": (
        ("preimage", "environment_preimage_fingerprint"),
        ("operation", "operation_fingerprint"),
        ("entries", "entries"),
        ("entry_kind", "kind"),
        ("entry_path", "path"),
    ),
    "fingerprint": (
        ("device", "device"),
        ("inode", "inode"),
        ("mode", "mode"),
        ("nlink", "nlink"),
    ),
    "storage_request": (
        ("request", "request"),
        ("layout_plan_digest", "layout_plan_sha256"),
        ("operation_id", "operation_id"),
        ("preimage_fingerprint", "environment_preimage_fingerprint"),
        ("operation_fingerprint", "operation_fingerprint"),
        ("self_digest", "request_record_sha256"),
    ),
    "storage_prepare": (
        ("preimage_fingerprint", "environment_preimage_fingerprint"),
        ("operation_fingerprint", "operation_fingerprint"),
        ("self_digest", "prepare_sha256"),
    ),
    "installed_manifest": (
        ("distributions", "distributions"),
        ("files", "files"),
        ("distribution_count", "distribution_count"),
        ("file_count", "file_count"),
        ("total_bytes", "total_bytes"),
        ("distribution_name", "normalized_name"),
        ("distribution_version", "version"),
        ("source_kind", "source_kind"),
        ("source_identity_digest", "source_identity_sha256"),
        ("metadata_digest", "metadata_sha256"),
        ("wheel_digest", "wheel_sha256"),
        ("direct_url", "direct_url_sha256"),
        ("record_digest", "record_sha256"),
        ("file_path", "path"),
        ("file_owner", "distribution"),
        ("file_mode", "mode"),
        ("file_size", "size"),
        ("file_digest", "sha256"),
    ),
    "native_manifest": (
        ("files", "files"),
        ("file_count", "file_count"),
        ("target_machine", "target_machine"),
        ("entry_path", "path"),
        ("entry_owner", "owner"),
        ("entry_mode", "mode"),
        ("entry_size", "size"),
        ("entry_digest", "sha256"),
        ("entry_architectures", "architectures"),
        ("entry_minimum_os", "minimum_os"),
        ("entry_load_commands_digest", "load_commands_sha256"),
    ),
    "model_manifest": (
        ("core_json", "core_config_canonical_json"),
        ("runtime_json", "embedding_runtime_config_canonical_json"),
        ("snapshot_plan", "snapshot_plan"),
    ),
    "cross_manifest": (
        ("tree_document_role", "tree_manifest"),
        ("installed_document_role", "installed_manifest"),
        ("native_document_role", "native_manifest"),
        ("model_document_role", "model_manifest"),
        ("tree_entries", "entries"),
        ("installed_files", "files"),
        ("installed_distributions", "distributions"),
        ("native_files", "files"),
        ("model_plan", "snapshot_plan"),
        ("model_entries", "entries"),
        ("cache_root", "cache_root_relative"),
        ("snapshot_root", "snapshot_root_relative"),
        ("path", "path"),
        ("kind", "kind"),
        ("owner", "owner"),
        ("distribution", "distribution"),
        ("distribution_name", "normalized_name"),
    ),
    "evidence_set": (
        ("environment_request", "environment_request"),
        ("request_record", "storage_request_record"),
        ("manifest", "storage_manifest"),
        ("prepare", "storage_prepare_record"),
        ("documents", "documents_by_slot"),
        ("digests", "digests_by_slot"),
    ),
}
DOCUMENT_STRING_PATTERN_BINDING_FIELDS = (
    "field_role", "pattern",
)
DOCUMENT_STRING_PATTERN_BINDINGS = {
    "core_config": (
        ("provider", _NAME_PATTERN),
        ("model_id", _MODEL_REPOSITORY_PATTERN),
        ("model_revision", _REVISION_PATTERN),
        ("pooling", _NAME_PATTERN),
        ("mlx_device", _NAME_PATTERN),
    ),
    "model_snapshot_plan": (
        ("model_id", _MODEL_REPOSITORY_PATTERN),
        ("model_revision", _REVISION_PATTERN),
    ),
    "model_snapshot_entry": (
        ("entry_mode", _MODE_PATTERN),
    ),
    "tree_manifest": (
        ("operation_id", _OPERATION_ID_PATTERN),
    ),
    "tree_entry": (
        ("entry_mode", _MODE_PATTERN),
    ),
    "storage_request": (
        ("operation_id", _OPERATION_ID_PATTERN),
    ),
    "installed_distribution_entry": (
        ("distribution_version", _VERSION_PATTERN),
    ),
    "installed_file_entry": (
        ("file_mode", _MODE_PATTERN),
    ),
    "native_entry": (
        ("entry_owner", _LABEL_PATTERN),
        ("entry_mode", _MODE_PATTERN),
        ("entry_minimum_os", _VERSION_PATTERN),
    ),
}
HELPER_STRING_PATTERN_BINDINGS = (
    ("relative_path", _RELATIVE_PATH_PATTERN),
    ("tree_component", _TREE_ENTRY_NAME_PATTERN),
    ("hex64", _HEX64_PATTERN),
)
DOCUMENT_AGGREGATION_OPERATIONS = (
    "length", "sum-field", "sum-field-where-equal",
)
DOCUMENT_AGGREGATION_BINDING_FIELDS = (
    "target_role", "collection_role", "operation", "selection_role",
    "selection_value", "value_role",
)
DOCUMENT_AGGREGATION_COMPARATOR_METHOD = "__eq__"
DOCUMENT_AGGREGATION_BINDINGS = {
    "model_snapshot_plan": (
        ("entry_count", "entries", "length", None, None, None),
        (
            "total_bytes", "entries", "sum-field-where-equal",
            "entry_kind", MODEL_ENTRY_KINDS[1], "entry_size",
        ),
    ),
    "tree_manifest": (
        ("entry_count", "entries", "length", None, None, None),
        (
            "total_bytes", "entries", "sum-field-where-equal",
            "entry_kind", TREE_ENTRY_KINDS[1], "entry_size",
        ),
    ),
    "installed_manifest": (
        (
            "distribution_count", "distributions", "length",
            None, None, None,
        ),
        ("file_count", "files", "length", None, None, None),
        ("total_bytes", "files", "sum-field", None, None, "file_size"),
    ),
    "native_manifest": (
        ("file_count", "files", "length", None, None, None),
    ),
}
DOCUMENT_VALUE_RELATION_BINDING_FIELDS = (
    "relation_name", "binding_table", "comparator_method", "expected_result",
)
DOCUMENT_VALUE_RELATION_BINDINGS = (
    (
        "storage-device-equality", "storage_device_relation", "__eq__", True,
    ),
    (
        "storage-inode-distinctness", "storage_inode_relation", "__eq__", False,
    ),
    (
        "storage-operation-nlink-equality",
        "storage_operation_nlink_relation", "__eq__", True,
    ),
    (
        "installed-record-owner-equality",
        "installed_record_relation", "__eq__", True,
    ),
    (
        "installed-owner-completeness",
        "installed_owner_completeness_relation", "__eq__", True,
    ),
    (
        "native-base-interpreter-cardinality",
        "native_base_interpreter_relation", "__eq__", True,
    ),
    (
        "native-base-owner-classification",
        "native_base_owner_classification_relation", "__eq__", True,
    ),
    (
        "native-installed-owner-equality",
        "native_installed_owner_relation", "__eq__", True,
    ),
    (
        "native-distribution-owner-membership",
        "native_distribution_owner_membership_relation",
        "__contains__", True,
    ),
    (
        "native-architecture-membership",
        "native_architecture_membership_relation", "__contains__", True,
    ),
    (
        "distribution-source-kind-membership",
        "distribution_source_kind_membership_relation", "__contains__", True,
    ),
    (
        "installed-owner-membership",
        "installed_owner_membership_relation", "__contains__", True,
    ),
    (
        "installed-mode-membership",
        "installed_mode_membership_relation", "__contains__", True,
    ),
    (
        "native-mode-membership",
        "native_mode_membership_relation", "__contains__", True,
    ),
    (
        "cross-file-field-equality",
        "cross_file_field_relation", "__eq__", True,
    ),
    (
        "tree-file-kind-equality",
        "tree_file_kind_relation", "__eq__", True,
    ),
    (
        "model-cache-path-completeness",
        "model_cache_paths_relation", "__eq__", True,
    ),
    (
        "fingerprint-mode-equality",
        "fingerprint_mode_relation", "__eq__", True,
    ),
    (
        "fingerprint-preimage-nlink-equality",
        "fingerprint_preimage_nlink_relation", "__eq__", True,
    ),
    (
        "parent-directory-kind-equality",
        "parent_directory_kind_relation", "__eq__", True,
    ),
)
COLLECTION_ORDER_DIRECTION_BINDINGS = (
    ("ascending", False),
)
COLLECTION_RELATION_BINDING_FIELDS = (
    "relation_name", "order_direction", "unique", "ascii_casefold_unique",
)
COLLECTION_RELATION_BINDINGS = (
    ("model", "ascending", True, True),
    ("installed-file", "ascending", True, True),
    ("native-file", "ascending", True, True),
    ("distribution-name", "ascending", True, False),
    ("native-sublist", "ascending", True, False),
    ("tree-path", None, True, True),
    ("tree-child", "ascending", False, False),
)
COLLECTION_RELATION_COMPARATOR_METHOD = "__eq__"
DISTRIBUTION_DIRECT_URL_BINDINGS = (
    (DISTRIBUTION_SOURCE_KINDS[0], "absent"),
    (DISTRIBUTION_SOURCE_KINDS[1], "present-sha256"),
)
OPTIONAL_VALUE_PRESENCE_BINDING_FIELDS = (
    "presence_role", "none_comparator_method", "validate_sha256",
)
OPTIONAL_VALUE_PRESENCE_BINDINGS = (
    ("absent", "__eq__", False),
    ("present-sha256", "__ne__", True),
)
OPTIONAL_PATH_ACTION_BINDING_FIELDS = (
    "value_kind", "action",
)
OPTIONAL_PATH_NONE_KIND = "none"
OPTIONAL_PATH_STRING_KIND = "string"
OPTIONAL_PATH_RETURN_ACTION = "return-null"
OPTIONAL_PATH_VALIDATE_ACTION = "validate-path"
OPTIONAL_PATH_ACTION_BINDINGS = (
    (OPTIONAL_PATH_NONE_KIND, OPTIONAL_PATH_RETURN_ACTION),
    (OPTIONAL_PATH_STRING_KIND, OPTIONAL_PATH_VALIDATE_ACTION),
)
OPTIONAL_PATH_ALLOWED_ACTIONS = (
    (False, (OPTIONAL_PATH_VALIDATE_ACTION,)),
    (True, (OPTIONAL_PATH_RETURN_ACTION, OPTIONAL_PATH_VALIDATE_ACTION)),
)
EXECUTABLE_MODE_CLASSIFICATION_METHOD = "__eq__"
EXECUTABLE_PATH_MEMBERSHIP_METHOD = "__contains__"
STORAGE_TOP_LEVEL_DIRECTORY_BINDING_FIELDS = (
    "kind_role", "kind_value", "kind_comparator_method",
    "path_role", "path_membership_method", "separator_expected",
)
STORAGE_TOP_LEVEL_DIRECTORY_BINDING = (
    "entry_kind", TREE_ENTRY_KINDS[0], "__eq__",
    "entry_path", "__contains__", False,
)
STORAGE_NLINK_COMBINE_METHOD = "__add__"
ENTRY_KIND_VALIDATOR_BINDING_FIELDS = (
    "document_role", "entry_kind", "validator_function", "fixed_rule",
)
ENTRY_KIND_VALIDATOR_BINDINGS = (
    (
        "model_snapshot_plan", MODEL_ENTRY_KINDS[0],
        "_validate_model_directory_entry", "model-directory",
    ),
    (
        "model_snapshot_plan", MODEL_ENTRY_KINDS[1],
        "_validate_model_file_entry", "model-file",
    ),
    (
        "tree_manifest", TREE_ENTRY_KINDS[0],
        "_validate_tree_directory_entry", "tree-directory",
    ),
    (
        "tree_manifest", TREE_ENTRY_KINDS[1],
        "_validate_tree_file_entry", "tree-file",
    ),
)
ENTRY_VALIDATOR_CONTEXT_KEYS = (
    "path", "full_path", "mode", "size", "digest",
)
ENTRY_FIXED_FIELD_BINDINGS = (
    (
        "model-directory",
        (("mode", MODEL_DIRECTORY_MODE),
         ("size", DIRECTORY_ENTRY_EMPTY_SIZE),
         ("digest", DIRECTORY_ENTRY_EMPTY_DIGEST)),
    ),
    ("model-file", (("mode", MODEL_FILE_MODE),)),
    (
        "tree-directory",
        (("mode", TREE_DIRECTORY_MODE),
         ("size", DIRECTORY_ENTRY_EMPTY_SIZE),
         ("digest", DIRECTORY_ENTRY_EMPTY_DIGEST)),
    ),
    ("tree-file", ()),
)
ENTRY_FIELD_COMPARATOR_METHOD = "__eq__"
ENTRY_SUFFIX_MATCH_METHOD = "endswith"
PATH_REJECTION_PREDICATE_BINDING_FIELDS = (
    "target_role", "method", "operand_role", "rejected_result",
)
PATH_REJECTION_PREDICATE_BINDINGS = {
    "relative_path": (
        ("value", PATH_PREFIX_MATCH_METHOD, "root", True),
        ("value", PATH_PREFIX_MATCH_METHOD, "current_prefix", True),
        ("value", ENTRY_SUFFIX_MATCH_METHOD, "separator", True),
    ),
    "tree_relative_path": (
        ("value", PATH_PREFIX_MATCH_METHOD, "root", True),
        ("value", ENTRY_SUFFIX_MATCH_METHOD, "separator", True),
    ),
    "absolute_path": (
        ("value", PATH_PREFIX_MATCH_METHOD, "root", False),
        ("value", "__eq__", "root", True),
        ("value", ENTRY_SUFFIX_MATCH_METHOD, "separator", True),
        ("value", POLICY_MEMBERSHIP_METHOD, "double_separator", True),
    ),
}
PATH_REJECTION_PREDICATE_COMPARATOR_METHOD = "__eq__"
PATH_REJECTION_PREDICATE_COMBINER = "reject-on-any-predicate-match"
PATH_REJECTION_PREDICATE_COMBINER_BINDING_FIELDS = (
    "combiner", "method", "operand",
)
PATH_REJECTION_PREDICATE_COMBINER_BINDINGS = (
    (PATH_REJECTION_PREDICATE_COMBINER, POLICY_MEMBERSHIP_METHOD, True),
)
RESULT_KEYS = (
    "schema", "command", "status", "reason", "evidence_contract_id",
    "environment_policy_id", "model_snapshot_plan", "environment_request",
    "evidence_set", "model_snapshot_plan_sha256",
    "environment_request_sha256", "evidence_set_sha256", "document_valid",
    "evidence_verified", "receipt_issuable", "receipt_published",
    "blocker_5_complete", "flags", "nonclaims", "result_sha256",
)
RENDER_KEYS = (
    "schema", "result_schema", "command", "status", "reason",
    "evidence_contract_id", "environment_policy_id",
    "model_snapshot_plan_sha256", "environment_request_sha256",
    "evidence_set_sha256", "document_valid", "evidence_verified",
    "receipt_issuable", "receipt_published", "blocker_5_complete",
    "result_sha256",
)
RESULT_SELF_HASH_FIELD = "result_sha256"
RESULT_BODY_KEYS = RESULT_KEYS[:-1]
RESULT_FALSE_FIELDS = (
    "evidence_verified", "receipt_issuable", "receipt_published",
    "blocker_5_complete",
)

_FALLBACK_LINE = (
    '{"blocker_5_complete":false,"document_valid":false,'
    '"evidence_verified":false,"receipt_issuable":false,'
    '"receipt_published":false,'
    '"schema":"synapse-s2.release-environment-evidence-render.v1",'
    '"status":"unsupported"}'
)


class _Reject(ValueError):
    pass


def _native(value, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    if not _numeric_bounds_include(
        counter[0], 0, MAX_TOTAL_NODES
    ) or not _numeric_bounds_include(depth, 0, MAX_DEPTH):
        raise _Reject("bounds")
    kind = type(value)
    if kind is str:
        if not _numeric_bounds_include(len(value), 0, MAX_STRING_CHARS):
            raise _Reject("string")
        return
    if kind is int:
        if not _numeric_bounds_include(
            value, -MAX_NATIVE_INT, MAX_NATIVE_INT
        ):
            raise _Reject("integer")
        return
    if kind is bool or value is None:
        return
    if kind is list:
        if not _numeric_bounds_include(len(value), 0, MAX_LIST_ITEMS):
            raise _Reject("list")
        for item in value:
            _native(item, depth + 1, counter)
        return
    if kind is dict:
        if not _numeric_bounds_include(len(value), 0, MAX_KEYS):
            raise _Reject("keys")
        for key in value:
            if type(key) is not str or not _numeric_bounds_include(
                len(key), 0, MAX_KEY_CHARS
            ):
                raise _Reject("key")
        for key in sorted(value):
            _native(value[key], depth + 1, counter)
        return
    raise _Reject("type")


def _canonical(value, limit=MAX_DOCUMENT_BYTES):
    _native(value)
    try:
        data = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise _Reject("canonical")
    if not _numeric_bounds_include(len(data), 0, limit):
        raise _Reject("bytes")
    return data


def _domain_hash(domain, value, limit=MAX_DOCUMENT_BYTES):
    return hashlib.sha256(domain + _canonical(value, limit)).hexdigest()


def _exact_dict(value, keys):
    if type(value) is not dict or not _exact_value_equal(
        len(value), len(keys)
    ):
        raise _Reject("keyset")
    for key in value:
        if type(key) is not str:
            raise _Reject("key")
    if not _exact_value_equal(tuple(sorted(value)), tuple(sorted(keys))):
        raise _Reject("keyset")
    return value


def _exact_value_equal(left, right):
    return getattr(left, DOCUMENT_BINDING_COMPARATOR_METHOD)(right) is True


def _resolved_document_bindings(table_name, sources, reason):
    if type(sources) is not dict:
        raise _Reject(reason)
    table = DOCUMENT_BINDING_TABLES.get(table_name)
    if type(table) is not tuple:
        raise _Reject(reason)
    constants = dict(DOCUMENT_BINDING_CONSTANT_VALUES)
    if not _exact_value_equal(
        len(constants), len(DOCUMENT_BINDING_CONSTANT_VALUES)
    ):
        raise _Reject(reason)
    available = {"constant": constants}
    for source_name, source_document in sources.items():
        if (
            type(source_name) is not str
            or type(source_document) is not dict
            or source_name in available
        ):
            raise _Reject(reason)
        available[source_name] = source_document
    resolved = {}
    for target_key, descriptor in table:
        if (
            type(target_key) is not str
            or type(descriptor) is not str
            or target_key in resolved
        ):
            raise _Reject(reason)
        source_name, separator, source_key = descriptor.partition(":")
        if not _exact_value_equal(separator, ":") or not source_name or not source_key:
            raise _Reject(reason)
        source_document = available.get(source_name)
        if (
            source_document is None
            or source_key not in source_document
        ):
            raise _Reject(reason)
        resolved[target_key] = source_document[source_key]
    if not _exact_value_equal(len(resolved), len(table)):
        raise _Reject(reason)
    return resolved


def _require_document_bindings(document, table_name, sources, reason):
    if type(document) is not dict:
        raise _Reject(reason)
    resolved = _resolved_document_bindings(table_name, sources, reason)
    for target_key, expected in resolved.items():
        if target_key not in document:
            raise _Reject(reason)
        if type(document[target_key]) is not type(expected) or not (
            _exact_value_equal(document[target_key], expected)
        ):
            raise _Reject(reason)
    return document


def _relation_fields(name):
    table = DOCUMENT_RELATION_FIELDS.get(name)
    if type(table) is not tuple:
        raise _Reject("relation-policy")
    fields = dict(table)
    if not _exact_value_equal(len(fields), len(table)):
        raise _Reject("relation-policy")
    for role, field in table:
        if type(role) is not str or type(field) is not str or not field:
            raise _Reject("relation-policy")
    return fields


def _document_string_pattern_values(
    document, relation_name, binding_name, reason,
):
    if (
        type(document) is not dict
        or type(relation_name) is not str
        or type(binding_name) is not str
        or type(reason) is not str
    ):
        raise _Reject("string-pattern-policy")
    bindings = DOCUMENT_STRING_PATTERN_BINDINGS.get(binding_name)
    if type(bindings) is not tuple:
        raise _Reject("string-pattern-policy")
    relations = _relation_fields(relation_name)
    values = {}
    for binding in bindings:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(DOCUMENT_STRING_PATTERN_BINDING_FIELDS)
            )
        ):
            raise _Reject("string-pattern-policy")
        field_role, pattern = binding
        if (
            type(field_role) is not str
            or type(pattern) is not str
            or field_role in values
            or field_role not in relations
            or relations[field_role] not in document
        ):
            raise _Reject("string-pattern-policy")
        values[field_role] = _string(
            document[relations[field_role]], pattern
        )
    if not _exact_value_equal(len(values), len(bindings)):
        raise _Reject(reason)
    return values


def _helper_string_pattern(role):
    if type(role) is not str:
        raise _Reject("string-pattern-policy")
    bindings = dict(HELPER_STRING_PATTERN_BINDINGS)
    if (
        not _exact_value_equal(
            len(bindings), len(HELPER_STRING_PATTERN_BINDINGS)
        )
        or role not in bindings
        or type(bindings[role]) is not str
    ):
        raise _Reject("string-pattern-policy")
    return bindings[role]


def _require_document_aggregations(document, relation_name):
    if type(document) is not dict or type(relation_name) is not str:
        raise _Reject("aggregation-policy")
    bindings = DOCUMENT_AGGREGATION_BINDINGS.get(relation_name)
    if type(bindings) is not tuple:
        raise _Reject("aggregation-policy")
    relations = _relation_fields(relation_name)
    seen_targets = set()
    for binding in bindings:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(DOCUMENT_AGGREGATION_BINDING_FIELDS)
            )
        ):
            raise _Reject("aggregation-policy")
        (
            target_role, collection_role, operation, selection_role,
            selection_value, value_role,
        ) = binding
        if (
            type(target_role) is not str
            or type(collection_role) is not str
            or type(operation) is not str
            or not getattr(
                DOCUMENT_AGGREGATION_OPERATIONS, POLICY_MEMBERSHIP_METHOD
            )(operation)
            or target_role in seen_targets
            or target_role not in relations
            or collection_role not in relations
        ):
            raise _Reject("aggregation-policy")
        collection = document[relations[collection_role]]
        if type(collection) is not list:
            raise _Reject("aggregation-policy")
        if _exact_value_equal(operation, DOCUMENT_AGGREGATION_OPERATIONS[0]):
            if selection_role is not None or selection_value is not None or (
                value_role is not None
            ):
                raise _Reject("aggregation-policy")
            expected = len(collection)
        else:
            if type(value_role) is not str or value_role not in relations:
                raise _Reject("aggregation-policy")
            if _exact_value_equal(
                operation, DOCUMENT_AGGREGATION_OPERATIONS[1]
            ):
                if selection_role is not None or selection_value is not None:
                    raise _Reject("aggregation-policy")
                selected = collection
            else:
                if (
                    type(selection_role) is not str
                    or selection_role not in relations
                ):
                    raise _Reject("aggregation-policy")
                selected = [
                    entry for entry in collection
                    if getattr(
                        entry[relations[selection_role]],
                        DOCUMENT_AGGREGATION_COMPARATOR_METHOD,
                    )(selection_value)
                ]
            expected = sum(
                entry[relations[value_role]] for entry in selected
            )
        if not getattr(
            document[relations[target_role]],
            DOCUMENT_AGGREGATION_COMPARATOR_METHOD,
        )(expected):
            raise _Reject("aggregation-relation")
        seen_targets.add(target_role)
    if not _exact_value_equal(len(seen_targets), len(bindings)):
        raise _Reject("aggregation-policy")
    return document


def _document_value_relation_matches(relation_name, sources, reason):
    if type(relation_name) is not str or type(sources) is not dict:
        raise _Reject(reason)
    relations = {}
    binding_tables = set()
    for binding in DOCUMENT_VALUE_RELATION_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(DOCUMENT_VALUE_RELATION_BINDING_FIELDS)
            )
        ):
            raise _Reject("value-relation-policy")
        name, binding_table, comparator_method, expected_result = binding
        if (
            type(name) is not str
            or type(binding_table) is not str
            or type(comparator_method) is not str
            or type(expected_result) is not bool
            or name in relations
            or binding_table in binding_tables
        ):
            raise _Reject("value-relation-policy")
        relations[name] = (
            binding_table, comparator_method, expected_result
        )
        binding_tables.add(binding_table)
    relation = relations.get(relation_name)
    if relation is None:
        raise _Reject("value-relation-policy")
    binding_table, comparator_method, expected_result = relation
    values = _resolved_document_bindings(binding_table, sources, reason)
    if not _exact_value_equal(tuple(values), ("left", "right")):
        raise _Reject("value-relation-policy")
    observed = getattr(values["left"], comparator_method)(values["right"])
    return observed is expected_result


def _require_document_value_relation(relation_name, sources, reason):
    if not _document_value_relation_matches(relation_name, sources, reason):
        raise _Reject(reason)
    return sources


def _require_optional_value_presence(value, presence_role, reason):
    if type(presence_role) is not str:
        raise _Reject("optional-value-policy")
    policies = {}
    for binding in OPTIONAL_VALUE_PRESENCE_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(OPTIONAL_VALUE_PRESENCE_BINDING_FIELDS)
            )
        ):
            raise _Reject("optional-value-policy")
        role, comparator_method, validate_sha256 = binding
        if (
            type(role) is not str
            or type(comparator_method) is not str
            or type(validate_sha256) is not bool
            or role in policies
        ):
            raise _Reject("optional-value-policy")
        policies[role] = (comparator_method, validate_sha256)
    policy = policies.get(presence_role)
    if policy is None:
        raise _Reject("optional-value-policy")
    comparator_method, validate_sha256 = policy
    expected_type = str if validate_sha256 else type(None)
    if type(value) is not expected_type:
        raise _Reject(reason)
    if getattr(value, comparator_method)(None) is not True:
        raise _Reject(reason)
    if validate_sha256:
        _hex64(value)
    return value


def _collection_relation(relation_name):
    if type(relation_name) is not str:
        raise _Reject("collection-relation-policy")
    relations = {}
    for binding in COLLECTION_RELATION_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(COLLECTION_RELATION_BINDING_FIELDS)
            )
        ):
            raise _Reject("collection-relation-policy")
        name, direction, unique, casefold_unique = binding
        if (
            type(name) is not str
            or (direction is not None and type(direction) is not str)
            or type(unique) is not bool
            or type(casefold_unique) is not bool
            or name in relations
        ):
            raise _Reject("collection-relation-policy")
        relations[name] = (direction, unique, casefold_unique)
    relation = relations.get(relation_name)
    if relation is None:
        raise _Reject("collection-relation-policy")
    return relation


def _sorted_collection(values, relation_name):
    if type(values) not in (list, tuple):
        raise _Reject("collection-relation-policy")
    direction, _unique, _casefold_unique = _collection_relation(relation_name)
    directions = dict(COLLECTION_ORDER_DIRECTION_BINDINGS)
    if (
        not _exact_value_equal(
            len(directions), len(COLLECTION_ORDER_DIRECTION_BINDINGS)
        )
        or not getattr(directions, POLICY_MEMBERSHIP_METHOD)(direction)
        or type(directions[direction]) is not bool
    ):
        raise _Reject("collection-relation-policy")
    return sorted(values, reverse=directions[direction])


def _require_ordered_unique_values(values, relation_name, token):
    if type(values) is not list or type(token) is not str:
        raise _Reject("collection-relation-policy")
    direction, unique, casefold_unique = _collection_relation(relation_name)
    if direction is not None and not getattr(
        values, COLLECTION_RELATION_COMPARATOR_METHOD
    )(_sorted_collection(values, relation_name)):
        raise _Reject(token + "-order")
    if unique and not getattr(
        len(values), COLLECTION_RELATION_COMPARATOR_METHOD
    )(len(set(values))):
        raise _Reject(token + "-duplicate")
    if casefold_unique:
        folded = [value.casefold() for value in values]
        if not getattr(
            len(folded), COLLECTION_RELATION_COMPARATOR_METHOD
        )(len(set(folded))):
            raise _Reject(token + "-casefold-alias")
    return values


def _require_entry_fixed_fields(rule_name, context):
    if type(rule_name) is not str:
        raise _Reject("entry-rule-policy")
    _exact_dict(context, ENTRY_VALIDATOR_CONTEXT_KEYS)
    rules = {}
    for name, bindings in ENTRY_FIXED_FIELD_BINDINGS:
        if (
            type(name) is not str
            or type(bindings) is not tuple
            or name in rules
        ):
            raise _Reject("entry-rule-policy")
        fields = {}
        for field, expected in bindings:
            if (
                type(field) is not str
                or field not in ENTRY_VALIDATOR_CONTEXT_KEYS
                or field in fields
            ):
                raise _Reject("entry-rule-policy")
            fields[field] = expected
        rules[name] = fields
    expected_fields = rules.get(rule_name)
    if expected_fields is None:
        raise _Reject("entry-rule-policy")
    for field, expected in expected_fields.items():
        if not getattr(
            context[field], ENTRY_FIELD_COMPARATOR_METHOD
        )(expected):
            raise _Reject("entry-fixed-field")
    return context


def _validate_model_directory_entry(context, fixed_rule):
    _require_entry_fixed_fields(fixed_rule, context)
    separator = _path_syntax()["separator"]
    if not _numeric_bounds_include(
        len(context["full_path"].split(separator)),
        0,
        PHASE5B1_MAX_TREE_DEPTH,
    ):
        raise _Reject("model-directory-depth")
    return context


def _validate_model_file_entry(context, fixed_rule):
    _require_entry_fixed_fields(fixed_rule, context)
    _hex64(context["digest"])
    lowered = context["path"].lower()
    sources = _resolved_document_bindings(
        "model_file_suffix_sources",
        {"context": {"lowered_path": lowered}},
        "model-file-suffix-policy",
    )
    seen_roles = set()
    for binding in MODEL_FILE_SUFFIX_RULE_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(MODEL_FILE_SUFFIX_RULE_BINDING_FIELDS)
            )
        ):
            raise _Reject("model-file-suffix-policy")
        suffixes_role, match_method, expected_match = binding
        if (
            type(suffixes_role) is not str
            or type(match_method) is not str
            or type(expected_match) is not bool
            or suffixes_role in seen_roles
            or suffixes_role not in sources
        ):
            raise _Reject("model-file-suffix-policy")
        observed = getattr(sources["value"], match_method)(
            sources[suffixes_role]
        )
        if observed is not expected_match:
            raise _Reject("model-file-suffix")
        seen_roles.add(suffixes_role)
    if not _exact_value_equal(
        len(seen_roles), len(MODEL_FILE_SUFFIX_RULE_BINDINGS)
    ):
        raise _Reject("model-file-suffix-policy")
    return context


def _validate_tree_directory_entry(context, fixed_rule):
    _require_entry_fixed_fields(fixed_rule, context)
    separator = _path_syntax()["separator"]
    if not _numeric_bounds_include(
        len(context["path"].split(separator)),
        0,
        PHASE5B1_MAX_TREE_DEPTH,
    ):
        raise _Reject("tree-directory-depth")
    return context


def _validate_tree_file_entry(context, fixed_rule):
    _require_entry_fixed_fields(fixed_rule, context)
    if (
        type(TREE_FILE_MODE_BINDING) is not tuple
        or not _exact_value_equal(
            len(TREE_FILE_MODE_BINDING), len(TREE_FILE_MODE_BINDING_FIELDS)
        )
    ):
        raise _Reject("tree-file-mode-policy")
    path_role, mapping_role, default_role, lookup_method = (
        TREE_FILE_MODE_BINDING
    )
    sources = _resolved_document_bindings(
        "tree_file_mode_sources", {"context": context},
        "tree-file-mode-policy",
    )
    if (
        type(path_role) is not str
        or type(mapping_role) is not str
        or type(default_role) is not str
        or type(lookup_method) is not str
        or path_role not in sources
        or mapping_role not in sources
        or default_role not in sources
        or type(sources[mapping_role]) is not dict
    ):
        raise _Reject("tree-file-mode-policy")
    expected_mode = getattr(
        sources[mapping_role], lookup_method
    )(sources[path_role], sources[default_role])
    if not getattr(
        context["mode"], ENTRY_FIELD_COMPARATOR_METHOD
    )(expected_mode):
        raise _Reject("tree-file-mode")
    _hex64(context["digest"])
    return context


def _validate_entry_kind(document_role, kind, context):
    if type(document_role) is not str or type(kind) is not str:
        raise _Reject("entry-kind-policy")
    _exact_dict(context, ENTRY_VALIDATOR_CONTEXT_KEYS)
    dispatch = {}
    observed_kinds = {}
    functions = set()
    module_globals = globals()
    for binding in ENTRY_KIND_VALIDATOR_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(ENTRY_KIND_VALIDATOR_BINDING_FIELDS)
            )
        ):
            raise _Reject("entry-kind-policy")
        role, entry_kind, function_name, fixed_rule = binding
        key = (role, entry_kind)
        if (
            type(role) is not str
            or type(entry_kind) is not str
            or type(function_name) is not str
            or type(fixed_rule) is not str
            or key in dispatch
            or function_name in functions
            or function_name not in RUNTIME_INTEGRITY_FUNCTION_NAMES
        ):
            raise _Reject("entry-kind-policy")
        validator = module_globals.get(function_name)
        if validator is None:
            raise _Reject("entry-kind-policy")
        dispatch[key] = (validator, fixed_rule)
        observed_kinds.setdefault(role, []).append(entry_kind)
        functions.add(function_name)
    expected_kinds = {
        "model_snapshot_plan": list(MODEL_ENTRY_KINDS),
        "tree_manifest": list(TREE_ENTRY_KINDS),
    }
    if not _exact_value_equal(observed_kinds, expected_kinds):
        raise _Reject("entry-kind-policy")
    selected = dispatch.get((document_role, kind))
    if selected is None:
        raise _Reject("entry-kind")
    validator, fixed_rule = selected
    return validator(context, fixed_rule)


def _path_syntax():
    values = dict(PATH_SYNTAX_VALUES)
    if not _exact_value_equal(len(values), len(PATH_SYNTAX_VALUES)):
        raise _Reject("path-syntax-policy")
    for role, value in PATH_SYNTAX_VALUES:
        if type(role) is not str or type(value) is not str:
            raise _Reject("path-syntax-policy")
    return values


def _path_rejection_matches(rule_name, value):
    if type(rule_name) is not str or type(value) is not str:
        raise _Reject("path-predicate-policy")
    bindings = PATH_REJECTION_PREDICATE_BINDINGS.get(rule_name)
    if type(bindings) is not tuple:
        raise _Reject("path-predicate-policy")
    context = _path_syntax()
    context["value"] = value
    seen = set()
    matches = []
    for binding in bindings:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding),
                len(PATH_REJECTION_PREDICATE_BINDING_FIELDS),
            )
        ):
            raise _Reject("path-predicate-policy")
        target_role, method, operand_role, rejected_result = binding
        if (
            type(target_role) is not str
            or type(method) is not str
            or type(operand_role) is not str
            or type(rejected_result) is not bool
            or binding in seen
            or target_role not in context
            or operand_role not in context
        ):
            raise _Reject("path-predicate-policy")
        observed = getattr(context[target_role], method)(
            context[operand_role]
        )
        if type(observed) is not bool:
            raise _Reject("path-predicate-policy")
        matches.append(getattr(
            observed, PATH_REJECTION_PREDICATE_COMPARATOR_METHOD
        )(rejected_result))
        seen.add(binding)
    if not _exact_value_equal(len(seen), len(bindings)):
        raise _Reject("path-predicate-policy")
    combiners = {}
    for binding in PATH_REJECTION_PREDICATE_COMBINER_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding),
                len(PATH_REJECTION_PREDICATE_COMBINER_BINDING_FIELDS),
            )
        ):
            raise _Reject("path-predicate-policy")
        combiner, method, operand = binding
        if (
            type(combiner) is not str
            or type(method) is not str
            or type(operand) is not bool
            or combiner in combiners
        ):
            raise _Reject("path-predicate-policy")
        combiners[combiner] = (method, operand)
    selected = combiners.get(PATH_REJECTION_PREDICATE_COMBINER)
    if (
        not _exact_value_equal(
            len(combiners),
            len(PATH_REJECTION_PREDICATE_COMBINER_BINDINGS),
        )
        or selected is None
    ):
        raise _Reject("path-predicate-policy")
    method, operand = selected
    combined = getattr(matches, method)(operand)
    if type(combined) is not bool:
        raise _Reject("path-predicate-policy")
    return combined


def _parent_directory_kind(role):
    values = dict(PARENT_DIRECTORY_KIND_BY_ROLE)
    if (
        not _exact_value_equal(
            len(values), len(PARENT_DIRECTORY_KIND_BY_ROLE)
        )
        or type(role) is not str
        or role not in values
        or type(values[role]) is not str
    ):
        raise _Reject("parent-kind-policy")
    return values[role]


def _string(value, pattern=None):
    if type(value) is not str or not _numeric_bounds_include(
        len(value), 0, MAX_STRING_CHARS
    ):
        raise _Reject("string")
    try:
        value.encode("ascii")
    except UnicodeError:
        raise _Reject("ascii")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise _Reject("pattern")
    return value


def _reject_secret_shape(value):
    value = _string(value)
    for pattern in _SECRET_SHAPE_PATTERNS:
        if re.search(pattern, value) is not None:
            raise _Reject("secret-shape")
    return value


def _require_document_secret_shapes(document):
    if type(document) is not dict:
        raise _Reject("secret-field-policy")
    matches = []
    seen_document_roles = set()
    for binding in SECRET_SHAPE_DOCUMENT_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(SECRET_SHAPE_DOCUMENT_BINDING_FIELDS)
            )
        ):
            raise _Reject("secret-field-policy")
        document_role, schema_field, schema_value, field_roles = binding
        if (
            type(document_role) is not str
            or document_role in seen_document_roles
            or type(schema_field) is not str
            or type(schema_value) is not str
            or type(field_roles) is not tuple
            or not field_roles
        ):
            raise _Reject("secret-field-policy")
        relations = _relation_fields(document_role)
        if (
            schema_field in document
            and type(document[schema_field]) is str
            and _exact_value_equal(document[schema_field], schema_value)
        ):
            matches.append((relations, field_roles))
        seen_document_roles.add(document_role)
    if (
        not _exact_value_equal(
            len(seen_document_roles), len(SECRET_SHAPE_DOCUMENT_BINDINGS)
        )
        or not _exact_value_equal(
            len(matches), SECRET_SHAPE_DOCUMENT_EXACT_MATCHES
        )
    ):
        raise _Reject("secret-field-policy")
    relations, field_roles = matches[0]
    seen_field_roles = set()
    for field_role in field_roles:
        if (
            type(field_role) is not str
            or field_role in seen_field_roles
            or field_role not in relations
            or relations[field_role] not in document
        ):
            raise _Reject("secret-field-policy")
        _reject_secret_shape(document[relations[field_role]])
        seen_field_roles.add(field_role)
    if not _exact_value_equal(len(seen_field_roles), len(field_roles)):
        raise _Reject("secret-field-policy")


def _numeric_bounds_include(value, minimum, maximum):
    context = locals()
    expected_context_roles = set()
    seen_operand_roles = set()
    for target_role, operand_role, method_name in (
        NUMERIC_BOUND_COMPARATOR_BINDINGS
    ):
        expected_context_roles.add(target_role)
        expected_context_roles.add(operand_role)
        if (
            type(target_role) is not str
            or type(operand_role) is not str
            or operand_role in seen_operand_roles
            or target_role not in context
            or operand_role not in context
            or type(method_name) is not str
            or not getattr(context[target_role], method_name)(
                context[operand_role]
            )
        ):
            return False
        seen_operand_roles.add(operand_role)
    return (
        _exact_value_equal(set(context), expected_context_roles)
        and _exact_value_equal(
            len(seen_operand_roles), len(NUMERIC_BOUND_COMPARATOR_BINDINGS)
        )
    )


def _integer(value, minimum=0, maximum=MAX_INT):
    if type(value) is not int or not _numeric_bounds_include(
        value, minimum, maximum
    ):
        raise _Reject("integer")
    return value


def _boolean(value, expected=None):
    if type(value) is not bool or (expected is not None and value is not expected):
        raise _Reject("boolean")
    return value


def _relative_path(value):
    value = _string(value, _helper_string_pattern("relative_path"))
    syntax = _path_syntax()
    separator = syntax["separator"]
    if _path_rejection_matches("relative_path", value):
        raise _Reject("path")
    parts = value.split(separator)
    for part in parts:
        if getattr(
            PATH_FORBIDDEN_COMPONENTS, POLICY_MEMBERSHIP_METHOD
        )(part):
            raise _Reject("path")
    return value


def _tree_relative_path(value):
    value = _string(value)
    syntax = _path_syntax()
    separator = syntax["separator"]
    if not _numeric_bounds_include(
        len(value), 0, PHASE5B1_MAX_PATH_LENGTH
    ):
        raise _Reject("tree-path-length")
    if _path_rejection_matches("tree_relative_path", value):
        raise _Reject("tree-path")
    parts = value.split(separator)
    if not _numeric_bounds_include(
        len(parts), 1, PHASE5B1_MAX_TREE_DEPTH + 1
    ):
        raise _Reject("tree-depth")
    for part in parts:
        if re.fullmatch(
            _helper_string_pattern("tree_component"), part
        ) is None:
            raise _Reject("tree-name")
        if getattr(
            PHASE5B1_FORBIDDEN_PATH_SEGMENTS, POLICY_MEMBERSHIP_METHOD
        )(part.casefold()):
            raise _Reject("tree-forbidden")
    return value


def _unique_ordered_paths(paths, token):
    return _require_ordered_unique_values(paths, token, token)


def _phase5b1_tree_order(entries, path_field, kind_field, document_role):
    """Replay the storage scanner's sorted-per-directory DFS order."""
    directory_kind = _parent_directory_kind(document_role)
    separator = _path_syntax()["separator"]
    paths = [entry[path_field] for entry in entries]
    _require_ordered_unique_values(paths, "tree-path", "tree")
    by_path = {entry[path_field]: entry for entry in entries}
    children = {}
    for path in paths:
        parent = path.rpartition(separator)[0]
        if parent:
            parent_entry = by_path.get(parent)
            if parent_entry is None:
                raise _Reject("tree-parent")
            _require_document_value_relation(
                "parent-directory-kind-equality",
                {
                    "parent": {"kind": parent_entry[kind_field]},
                    "derived": {"directory_kind": directory_kind},
                },
                "tree-parent",
            )
        children.setdefault(parent, []).append(path)
    expected = []

    def visit(parent):
        for path in _sorted_collection(
            children.get(parent, ()), "tree-child"
        ):
            expected.append(path)
            if getattr(
                by_path[path][kind_field],
                COLLECTION_RELATION_COMPARATOR_METHOD,
            )(directory_kind):
                visit(path)

    visit("")
    if not getattr(
        expected, COLLECTION_RELATION_COMPARATOR_METHOD
    )(paths):
        raise _Reject("tree-order")


def _require_parent_directories(
    entries, path_field, kind_field, document_role, token
):
    directory_kind = _parent_directory_kind(document_role)
    separator = _path_syntax()["separator"]
    by_path = {entry[path_field]: entry for entry in entries}
    for path in by_path:
        parent = path.rpartition(separator)[0]
        if parent:
            parent_entry = by_path.get(parent)
            if parent_entry is None:
                raise _Reject(token + "-parent")
            _require_document_value_relation(
                "parent-directory-kind-equality",
                {
                    "parent": {"kind": parent_entry[kind_field]},
                    "derived": {"directory_kind": directory_kind},
                },
                token + "-parent",
            )


def _hex64(value):
    return _string(value, _helper_string_pattern("hex64"))


def _fingerprint(value, *, empty_preimage=False):
    _exact_dict(value, FINGERPRINT_KEYS)
    relations = _relation_fields("fingerprint")
    _integer(value[relations["device"]], 1, MAX_NATIVE_INT)
    _integer(value[relations["inode"]], 1, MAX_NATIVE_INT)
    _integer(value[relations["mode"]], 0)
    minimum_nlink = PHASE5B1_PREIMAGE_NLINK
    _integer(
        value[relations["nlink"]], minimum_nlink, MAX_NATIVE_INT
    )
    _require_document_value_relation(
        "fingerprint-mode-equality",
        {
            "fingerprint": value,
            "derived": {"expected_mode": PHASE5B1_DIRECTORY_MODE},
        },
        "fingerprint-mode",
    )
    if empty_preimage:
        _require_document_value_relation(
            "fingerprint-preimage-nlink-equality",
            {
                "fingerprint": value,
                "derived": {"expected_nlink": PHASE5B1_PREIMAGE_NLINK},
            },
            "fingerprint-preimage-nlink",
        )
    return value


def _normalized_distribution_name(value):
    transform = DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM
    if (
        type(transform) is not tuple
        or not _exact_value_equal(
            len(transform),
            len(DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM_FIELDS),
        )
    ):
        raise _Reject("distribution-name-policy")
    (
        input_pattern, substitution_function, substitution_pattern, replacement,
        case_method, match_function, match_pattern,
    ) = transform
    for item in (
        input_pattern, substitution_function, substitution_pattern, replacement,
        case_method, match_function, match_pattern,
    ):
        if type(item) is not str:
            raise _Reject("distribution-name-policy")
    value = _string(value, input_pattern)
    canonical = getattr(
        getattr(re, substitution_function)(substitution_pattern, replacement, value),
        case_method,
    )()
    pattern_match = getattr(re, match_function)(match_pattern, value)
    context = _resolved_document_bindings(
        "distribution_name_normalization",
        {
            "argument": {"value": value},
            "derived": {
                "canonical": canonical,
                "pattern_match_type_name": type(pattern_match).__name__,
                "none_type_name": type(None).__name__,
            },
        },
        "distribution-name-policy",
    )
    seen_targets = set()
    for binding in DISTRIBUTION_NAME_NORMALIZATION_CHECKS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(DISTRIBUTION_NAME_NORMALIZATION_CHECK_FIELDS)
            )
        ):
            raise _Reject("distribution-name-policy")
        target_role, operand_role, comparison_method, expected = binding
        if (
            type(target_role) is not str
            or target_role in seen_targets
            or target_role not in context
            or type(operand_role) is not str
            or operand_role not in context
            or type(comparison_method) is not str
            or type(expected) is not bool
        ):
            raise _Reject("distribution-name-policy")
        observed = getattr(
            context[target_role], comparison_method
        )(context[operand_role])
        if type(observed) is not bool or not _exact_value_equal(
            observed, expected
        ):
            raise _Reject("distribution-name")
        seen_targets.add(target_role)
    if not _exact_value_equal(
        len(seen_targets), len(DISTRIBUTION_NAME_NORMALIZATION_CHECKS)
    ):
        raise _Reject("distribution-name-policy")
    return value


def _canonical_json_string(value):
    text = _string(value)
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        raise _Reject("embedded-json")
    if type(parsed) is not dict:
        raise _Reject("embedded-json")
    _embedded_native(parsed)
    try:
        replay = json.dumps(
            parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeError):
        raise _Reject("embedded-json")
    if not _exact_value_equal(replay, text):
        raise _Reject("embedded-json")
    return parsed


def _finite_float(value, minimum, maximum):
    if (
        type(value) is not float
        or not math.isfinite(value)
        or not _numeric_bounds_include(value, minimum, maximum)
    ):
        raise _Reject("float")
    return value


def _absolute_path(value, *, optional=False):
    if type(optional) is not bool:
        raise _Reject("optional-path-policy")
    actions = {}
    for binding in OPTIONAL_PATH_ACTION_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(OPTIONAL_PATH_ACTION_BINDING_FIELDS)
            )
        ):
            raise _Reject("optional-path-policy")
        value_kind, action = binding
        if (
            type(value_kind) is not str
            or type(action) is not str
            or value_kind in actions
        ):
            raise _Reject("optional-path-policy")
        actions[value_kind] = action
    allowed_actions = dict(OPTIONAL_PATH_ALLOWED_ACTIONS)
    if (
        not _exact_value_equal(len(actions), len(OPTIONAL_PATH_ACTION_BINDINGS))
        or not _exact_value_equal(
            len(allowed_actions), len(OPTIONAL_PATH_ALLOWED_ACTIONS)
        )
        or not getattr(allowed_actions, POLICY_MEMBERSHIP_METHOD)(optional)
    ):
        raise _Reject("optional-path-policy")
    if type(value) is type(None):
        value_kind = OPTIONAL_PATH_ACTION_BINDINGS[0][0]
    elif type(value) is str:
        value_kind = OPTIONAL_PATH_ACTION_BINDINGS[1][0]
    else:
        raise _Reject("absolute-path")
    action = actions.get(value_kind)
    if (
        action is None
        or not getattr(
            allowed_actions[optional], POLICY_MEMBERSHIP_METHOD
        )(action)
    ):
        raise _Reject("absolute-path")
    if _exact_value_equal(action, OPTIONAL_PATH_ACTION_BINDINGS[0][1]):
        return None
    if not _exact_value_equal(action, OPTIONAL_PATH_ACTION_BINDINGS[1][1]):
        raise _Reject("optional-path-policy")
    value = _string(value)
    _reject_secret_shape(value)
    syntax = _path_syntax()
    separator = syntax["separator"]
    if not _numeric_bounds_include(
        len(value), 0, PHASE5B1_MAX_PATH_LENGTH
    ):
        raise _Reject("absolute-path")
    if _path_rejection_matches("absolute_path", value):
        raise _Reject("absolute-path")
    for character in value:
        if not _numeric_bounds_include(
            ord(character),
            ABSOLUTE_PATH_MIN_CODEPOINT,
            ABSOLUTE_PATH_MAX_CODEPOINT,
        ):
            raise _Reject("absolute-path")
    parts = value[len(syntax["root"]):].split(separator)
    for part in parts:
        if getattr(
            PATH_FORBIDDEN_COMPONENTS, POLICY_MEMBERSHIP_METHOD
        )(part):
            raise _Reject("absolute-path")
        if not _numeric_bounds_include(
            len(part), 0, PHASE5B1_MAX_NAME_LENGTH
        ):
            raise _Reject("absolute-path")
    return value


def _core_config(document, request):
    _exact_dict(document, CORE_CONFIG_KEYS)
    _require_document_bindings(
        document, "core_request", {"request": request}, "core-config-binding"
    )
    relations = _relation_fields("core_config")
    path_values = {}
    for role, optional in CORE_CONFIG_PATH_ROLE_BINDINGS:
        if (
            type(role) is not str
            or type(optional) is not bool
            or role in path_values
            or role not in relations
        ):
            raise _Reject("core-config-path-policy")
        path_values[role] = _absolute_path(
            document[relations[role]], optional=optional
        )
    if not _exact_value_equal(
        len(path_values), len(CORE_CONFIG_PATH_ROLE_BINDINGS)
    ):
        raise _Reject("core-config-path-policy")
    separator = _path_syntax()["separator"]
    parent_targets = set()
    for target_role, parent_role, suffix in CORE_CONFIG_PARENT_SUFFIX_BINDINGS:
        if (
            type(target_role) is not str
            or type(parent_role) is not str
            or type(suffix) is not str
            or target_role in parent_targets
            or target_role not in path_values
            or parent_role not in path_values
        ):
            raise _Reject("core-config-path-policy")
        _relative_path(suffix)
        parent = path_values[parent_role].rpartition(separator)[0]
        if not _exact_value_equal(
            path_values[target_role], parent + separator + suffix
        ):
            raise _Reject("core-config-path-relation")
        parent_targets.add(target_role)
    if not _exact_value_equal(
        len(parent_targets), len(CORE_CONFIG_PARENT_SUFFIX_BINDINGS)
    ):
        raise _Reject("core-config-path-policy")
    suffix_targets = set()
    for target_role, suffix in CORE_CONFIG_SUFFIX_BINDINGS:
        if (
            type(target_role) is not str
            or type(suffix) is not str
            or target_role in suffix_targets
            or target_role not in path_values
        ):
            raise _Reject("core-config-path-policy")
        _relative_path(suffix)
        if not getattr(
            path_values[target_role], ENTRY_SUFFIX_MATCH_METHOD
        )(separator + suffix):
            raise _Reject("core-config-path-relation")
        suffix_targets.add(target_role)
    if not _exact_value_equal(
        len(suffix_targets), len(CORE_CONFIG_SUFFIX_BINDINGS)
    ):
        raise _Reject("core-config-path-policy")
    bounded_roles = set()
    for role, maximum_bytes in CORE_CONFIG_PATH_BYTE_BOUNDS:
        if (
            type(role) is not str
            or type(maximum_bytes) is not int
            or role in bounded_roles
            or role not in path_values
            or not _numeric_bounds_include(
                len(path_values[role].encode("ascii")), 0, maximum_bytes
            )
        ):
            raise _Reject("core-config-path-bound")
        bounded_roles.add(role)
    if not _exact_value_equal(
        len(bounded_roles), len(CORE_CONFIG_PATH_BYTE_BOUNDS)
    ):
        raise _Reject("core-config-path-policy")
    if not _exact_value_equal(
        len({path_values[role] for role in CORE_CONFIG_DISTINCT_PATH_ROLES}),
        len(CORE_CONFIG_DISTINCT_PATH_ROLES),
    ):
        raise _Reject("core-config-path-alias")

    pattern_values = _document_string_pattern_values(
        document, "core_config", "core_config", "core-config-pattern"
    )
    provider = pattern_values["provider"]
    if not getattr(CORE_PROVIDER_ALIASES, POLICY_MEMBERSHIP_METHOD)(provider):
        raise _Reject("core-config-provider")
    model_id = pattern_values["model_id"]
    revision = pattern_values["model_revision"]
    _require_document_secret_shapes(document)
    pooling = pattern_values["pooling"]
    if not getattr(NEURAL_POOLING_VALUES, POLICY_MEMBERSHIP_METHOD)(pooling):
        raise _Reject("core-config-pooling")
    integer_values = {}
    integer_bound_keys = set()
    for role, bound_key in CORE_CONFIG_INTEGER_BOUND_ROLES:
        if (
            type(role) is not str
            or type(bound_key) is not str
            or role in integer_values
            or bound_key in integer_bound_keys
            or role not in relations
            or bound_key not in CORE_CONFIG_INTEGER_BOUNDS
        ):
            raise _Reject("core-config-integer-policy")
        integer_values[role] = _integer(
            document[relations[role]], *CORE_CONFIG_INTEGER_BOUNDS[bound_key]
        )
        integer_bound_keys.add(bound_key)
    if (
        not _exact_value_equal(
            len(integer_values), len(CORE_CONFIG_INTEGER_BOUND_ROLES)
        )
        or not _exact_value_equal(
            integer_bound_keys, set(CORE_CONFIG_INTEGER_BOUNDS)
        )
    ):
        raise _Reject("core-config-integer-policy")
    float_values = {}
    float_bound_keys = set()
    for role, bound_key in CORE_CONFIG_FLOAT_BOUND_ROLES:
        if (
            type(role) is not str
            or type(bound_key) is not str
            or role in float_values
            or bound_key in float_bound_keys
            or role not in relations
            or bound_key not in CORE_CONFIG_FLOAT_BOUNDS
        ):
            raise _Reject("core-config-float-policy")
        float_values[role] = _finite_float(
            document[relations[role]], *CORE_CONFIG_FLOAT_BOUNDS[bound_key]
        )
        float_bound_keys.add(bound_key)
    if (
        not _exact_value_equal(
            len(float_values), len(CORE_CONFIG_FLOAT_BOUND_ROLES)
        )
        or not _exact_value_equal(
            float_bound_keys, set(CORE_CONFIG_FLOAT_BOUNDS)
        )
    ):
        raise _Reject("core-config-float-policy")
    boolean_roles = set()
    for role in CORE_CONFIG_BOOLEAN_ROLES:
        if (
            type(role) is not str
            or role in boolean_roles
            or role not in relations
        ):
            raise _Reject("core-config-boolean-policy")
        _boolean(document[relations[role]])
        boolean_roles.add(role)
    if not _exact_value_equal(
        len(boolean_roles), len(CORE_CONFIG_BOOLEAN_ROLES)
    ):
        raise _Reject("core-config-boolean-policy")
    comparators = dict(CORE_CONFIG_COMPARATOR_BINDINGS)
    if not _exact_value_equal(
        len(comparators), len(CORE_CONFIG_COMPARATOR_BINDINGS)
    ):
        raise _Reject("core-config-order-policy")
    for comparator, method_name in CORE_CONFIG_COMPARATOR_BINDINGS:
        if type(comparator) is not str or type(method_name) is not str:
            raise _Reject("core-config-order-policy")
    compared_relations = set()
    for left_role, right_role, comparator in CORE_CONFIG_ORDER_RELATIONS:
        method_name = comparators.get(comparator)
        if (
            type(left_role) is not str
            or type(right_role) is not str
            or type(comparator) is not str
            or (left_role, right_role) in compared_relations
            or left_role not in integer_values
            or right_role not in integer_values
            or method_name is None
        ):
            raise _Reject("core-config-order-policy")
        comparison = getattr(integer_values[left_role], method_name)(
            integer_values[right_role]
        )
        if comparison is not True:
            raise _Reject("core-config-order")
        compared_relations.add((left_role, right_role))
    if not _exact_value_equal(
        len(compared_relations), len(CORE_CONFIG_ORDER_RELATIONS)
    ):
        raise _Reject("core-config-order-policy")
    matrix_elements = 0
    matrix_terms = set()
    for left_role, right_role, coefficient in CORE_CONFIG_NEURAL_MATRIX_TERMS:
        term_identity = (left_role, right_role)
        if (
            type(left_role) is not str
            or (right_role is not None and type(right_role) is not str)
            or type(coefficient) is not int
            or term_identity in matrix_terms
            or left_role not in integer_values
            or (
                right_role is not None
                and right_role not in integer_values
            )
        ):
            raise _Reject("core-config-matrix-policy")
        term = coefficient * integer_values[left_role]
        if right_role is not None:
            term *= integer_values[right_role]
        matrix_elements += term
        matrix_terms.add(term_identity)
    if not _exact_value_equal(
        len(matrix_terms), len(CORE_CONFIG_NEURAL_MATRIX_TERMS)
    ):
        raise _Reject("core-config-matrix-policy")
    matrix_bytes = CORE_CONFIG_NEURAL_BYTES_PER_ELEMENT * matrix_elements
    if not _numeric_bounds_include(
        matrix_bytes, 0, CORE_CONFIG_MAX_NEURAL_MATRIX_BYTES
    ):
        raise _Reject("core-config-matrix")

    constant_values = dict(EMBEDDING_SPACE_CONSTANT_VALUES)
    if not _exact_value_equal(
        len(constant_values), len(EMBEDDING_SPACE_CONSTANT_VALUES)
    ):
        raise _Reject("embedding-space-policy")
    neural = {}
    for key, descriptor in EMBEDDING_SPACE_NEURAL_BINDINGS:
        if (
            type(key) is not str
            or type(descriptor) is not str
            or key in neural
            or not getattr(descriptor, PATH_PREFIX_MATCH_METHOD)("core-config:")
        ):
            raise _Reject("embedding-space-policy")
        source_key = descriptor[len("core-config:"):]
        if source_key not in document:
            raise _Reject("embedding-space-policy")
        neural[key] = document[source_key]
    identity = {}
    for key, descriptor in EMBEDDING_SPACE_OUTER_BINDINGS:
        if type(key) is not str or type(descriptor) is not str or key in identity:
            raise _Reject("embedding-space-policy")
        if getattr(descriptor, PATH_PREFIX_MATCH_METHOD)("constant:"):
            source_key = descriptor[len("constant:"):]
            if source_key not in constant_values:
                raise _Reject("embedding-space-policy")
            value = constant_values[source_key]
        elif getattr(descriptor, PATH_PREFIX_MATCH_METHOD)("core-config:"):
            source_key = descriptor[len("core-config:"):]
            if source_key not in document:
                raise _Reject("embedding-space-policy")
            value = document[source_key]
        elif _exact_value_equal(
            descriptor, "nested:embedding-space-neural-bindings"
        ):
            value = neural
        else:
            raise _Reject("embedding-space-policy")
        identity[key] = value
    if (
        not _exact_value_equal(
            len(neural), len(EMBEDDING_SPACE_NEURAL_BINDINGS)
        )
        or not _exact_value_equal(
            len(identity), len(EMBEDDING_SPACE_OUTER_BINDINGS)
        )
    ):
        raise _Reject("embedding-space-policy")
    embedding_space_identity = hashlib.sha256(_canonical(identity)).hexdigest()
    _require_document_bindings(
        request,
        "request_embedding_space_identity",
        {"derived": {"embedding_space_identity": embedding_space_identity}},
        "core-config-embedding-space",
    )
    return document, embedding_space_identity


def _embedding_runtime_config(document, request, core_config):
    _exact_dict(document, EMBEDDING_RUNTIME_CONFIG_KEYS)
    constant_values = dict(EMBEDDING_RUNTIME_CONSTANT_VALUES)
    if not _exact_value_equal(
        len(constant_values), len(EMBEDDING_RUNTIME_CONSTANT_VALUES)
    ):
        raise _Reject("runtime-config-policy")
    fixed = {}
    for key, descriptor in EMBEDDING_RUNTIME_CONFIG_BINDINGS:
        if type(key) is not str or type(descriptor) is not str or key in fixed:
            raise _Reject("runtime-config-policy")
        if getattr(descriptor, PATH_PREFIX_MATCH_METHOD)("constant:"):
            source_key = descriptor[len("constant:"):]
            source = constant_values
        elif getattr(descriptor, PATH_PREFIX_MATCH_METHOD)("request:"):
            source_key = descriptor[len("request:"):]
            source = request
        elif getattr(descriptor, PATH_PREFIX_MATCH_METHOD)("core-config:"):
            source_key = descriptor[len("core-config:"):]
            source = core_config
        else:
            raise _Reject("runtime-config-policy")
        if source_key not in source:
            raise _Reject("runtime-config-policy")
        fixed[key] = source[source_key]
    if not _exact_value_equal(tuple(fixed), EMBEDDING_RUNTIME_CONFIG_KEYS):
        raise _Reject("runtime-config-policy")
    for key, expected in fixed.items():
        if type(document[key]) is not type(expected) or not (
            _exact_value_equal(document[key], expected)
        ):
            raise _Reject("runtime-config-binding")
    return document


def _embedded_native(value, depth=0, counter=None):
    if counter is None:
        counter = [0]
    if type(value) is float:
        counter[0] += 1
        if not _numeric_bounds_include(
            counter[0], 0, MAX_TOTAL_NODES
        ) or not _numeric_bounds_include(depth, 0, MAX_DEPTH):
            raise _Reject("embedded-bounds")
        if not math.isfinite(value):
            raise _Reject("embedded-float")
        return
    kind = type(value)
    if kind is list:
        counter[0] += 1
        if (
            not _numeric_bounds_include(counter[0], 0, MAX_TOTAL_NODES)
            or not _numeric_bounds_include(depth, 0, MAX_DEPTH)
            or not _numeric_bounds_include(len(value), 0, MAX_LIST_ITEMS)
        ):
            raise _Reject("embedded-bounds")
        for item in value:
            _embedded_native(item, depth + 1, counter)
        return
    if kind is dict:
        counter[0] += 1
        if (
            not _numeric_bounds_include(counter[0], 0, MAX_TOTAL_NODES)
            or not _numeric_bounds_include(depth, 0, MAX_DEPTH)
            or not _numeric_bounds_include(len(value), 0, MAX_KEYS)
        ):
            raise _Reject("embedded-bounds")
        for key in value:
            if type(key) is not str or not _numeric_bounds_include(
                len(key), 0, MAX_KEY_CHARS
            ):
                raise _Reject("embedded-key")
        for key in sorted(value):
            _embedded_native(value[key], depth + 1, counter)
        return
    _native(value, depth, counter)


def _policy_body():
    return {
        "schema": POLICY_SCHEMA,
        "mode": "future-sanitized-materialization-evidence-policy",
        "compatibility_profile_version": COMPATIBILITY_PROFILE_VERSION,
        "phase5a_contract_id": PHASE5A_CONTRACT_ID,
        "phase5b1_contract_id": PHASE5B1_CONTRACT_ID,
        "numeric_bound_comparator_bindings": [
            list(binding) for binding in NUMERIC_BOUND_COMPARATOR_BINDINGS
        ],
        "secret_shape_document_binding_fields": list(
            SECRET_SHAPE_DOCUMENT_BINDING_FIELDS
        ),
        "secret_shape_document_bindings": [
            [document_role, schema_field, schema_value, list(field_roles)]
            for document_role, schema_field, schema_value, field_roles
            in SECRET_SHAPE_DOCUMENT_BINDINGS
        ],
        "secret_shape_document_exact_matches": (
            SECRET_SHAPE_DOCUMENT_EXACT_MATCHES
        ),
        "all_non_null_absolute_paths_secret_shape_checked": True,
        "distribution_name_normalization_transform_fields": list(
            DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM_FIELDS
        ),
        "distribution_name_normalization_transform": list(
            DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM
        ),
        "distribution_name_normalization_check_fields": list(
            DISTRIBUTION_NAME_NORMALIZATION_CHECK_FIELDS
        ),
        "distribution_name_normalization_checks": [
            list(binding)
            for binding in DISTRIBUTION_NAME_NORMALIZATION_CHECKS
        ],
        "distribution_name_normalization_combiner": "all-checks-required",
        "document_string_pattern_binding_fields": list(
            DOCUMENT_STRING_PATTERN_BINDING_FIELDS
        ),
        "document_string_pattern_bindings": {
            name: [list(binding) for binding in bindings]
            for name, bindings in DOCUMENT_STRING_PATTERN_BINDINGS.items()
        },
        "helper_string_pattern_bindings": [
            list(binding) for binding in HELPER_STRING_PATTERN_BINDINGS
        ],
        "path_rejection_predicate_binding_fields": list(
            PATH_REJECTION_PREDICATE_BINDING_FIELDS
        ),
        "path_rejection_predicate_bindings": {
            name: [list(binding) for binding in bindings]
            for name, bindings in PATH_REJECTION_PREDICATE_BINDINGS.items()
        },
        "path_rejection_predicate_comparator_method": (
            PATH_REJECTION_PREDICATE_COMPARATOR_METHOD
        ),
        "path_rejection_predicate_combiner": (
            PATH_REJECTION_PREDICATE_COMBINER
        ),
        "path_rejection_predicate_combiner_binding_fields": list(
            PATH_REJECTION_PREDICATE_COMBINER_BINDING_FIELDS
        ),
        "path_rejection_predicate_combiner_bindings": [
            list(binding)
            for binding in PATH_REJECTION_PREDICATE_COMBINER_BINDINGS
        ],
        "native_sublist_string_pattern_bindings": [
            list(binding)
            for binding in NATIVE_SUBLIST_STRING_PATTERN_BINDINGS
        ],
        "materialization_profile": {
            "implementation_status": "not-implemented",
            "owner": "effective-user",
            "same_device_required": True,
            "directory_mode": TREE_DIRECTORY_MODE,
            "regular_file_mode": TREE_REGULAR_FILE_MODE,
            "file_default_mode": TREE_FILE_DEFAULT_MODE,
            "executable_file_modes": dict(TREE_EXECUTABLE_FILES),
            "single_link_regular_files": True,
            "symlinks_allowed": False,
            "hardlinks_allowed": False,
            "special_files_allowed": False,
            "special_mode_bits_allowed": False,
            "ordinary_uv_venv_automatically_admissible": False,
        },
        "model_snapshot_profile": {
            "cache_root_relative": MODEL_CACHE_ROOT_RELATIVE,
            "snapshot_root_prefix": MODEL_SNAPSHOT_ROOT_PREFIX,
            "path_independent": True,
            "single_model_and_revision": True,
            "extra_revision_or_fallback_allowed": False,
            "python_or_pickle_artifacts_allowed": False,
            "executable_artifacts_allowed": False,
            "allowed_file_suffixes": list(MODEL_ALLOWED_FILE_SUFFIXES),
            "pre_and_post_publication_digest_equal": True,
            "request_bindings": [
                "model_id", "model_revision",
                "expected_model_snapshot_sha256=model-snapshot-plan-digest",
            ],
        },
        "configuration_profile": {
            "core_config_schema": CORE_CONFIG_SCHEMA,
            "core_config_keys": list(CORE_CONFIG_KEYS),
            "runtime_config_schema": EMBEDDING_RUNTIME_CONFIG_SCHEMA,
            "runtime_config_keys": list(EMBEDDING_RUNTIME_CONFIG_KEYS),
            "runtime_config_bindings": [
                list(binding) for binding in EMBEDDING_RUNTIME_CONFIG_BINDINGS
            ],
            "runtime_config_constant_values": [
                list(binding) for binding in EMBEDDING_RUNTIME_CONSTANT_VALUES
            ],
            "provider_aliases": list(CORE_PROVIDER_ALIASES),
            "runtime_provider": EMBEDDING_RUNTIME_PROVIDER,
            "required_mlx_device": CORE_REQUIRED_MLX_DEVICE,
            "require_native": CORE_REQUIRED_NATIVE,
            "local_files_only": True,
            "cache_path_suffix": MODEL_CACHE_ROOT_RELATIVE,
            "legacy_socket_path": "memory-parent/core/service.sock",
            "max_socket_bytes": CORE_CONFIG_MAX_SOCKET_BYTES,
            "path_validation": (
                "ascii-absolute-lexically-normal-no-root-no-dot-components-"
                "no-trailing-or-double-slash-no-filesystem-resolution"
            ),
            "path_characters_maximum": PHASE5B1_MAX_PATH_LENGTH,
            "path_component_characters_maximum": PHASE5B1_MAX_NAME_LENGTH,
            "path_codepoint_minimum": ABSOLUTE_PATH_MIN_CODEPOINT,
            "path_codepoint_maximum": ABSOLUTE_PATH_MAX_CODEPOINT,
            "path_syntax_values": [
                list(binding) for binding in PATH_SYNTAX_VALUES
            ],
            "path_forbidden_components": list(PATH_FORBIDDEN_COMPONENTS),
            "path_role_bindings": [
                [role, optional]
                for role, optional in CORE_CONFIG_PATH_ROLE_BINDINGS
            ],
            "path_byte_bounds": [
                list(binding) for binding in CORE_CONFIG_PATH_BYTE_BOUNDS
            ],
            "secret_shape_patterns": list(_SECRET_SHAPE_PATTERNS),
            "model_repository_pattern": _MODEL_REPOSITORY_PATTERN,
            "pooling_values": list(NEURAL_POOLING_VALUES),
            "integer_bounds": {
                key: list(bounds)
                for key, bounds in CORE_CONFIG_INTEGER_BOUNDS.items()
            },
            "integer_bound_roles": [
                list(binding) for binding in CORE_CONFIG_INTEGER_BOUND_ROLES
            ],
            "float_bounds": {
                key: [str(bounds[0]), str(bounds[1])]
                for key, bounds in CORE_CONFIG_FLOAT_BOUNDS.items()
            },
            "float_bound_roles": [
                list(binding) for binding in CORE_CONFIG_FLOAT_BOUND_ROLES
            ],
            "neural_matrix_bytes_maximum": (
                CORE_CONFIG_MAX_NEURAL_MATRIX_BYTES
            ),
            "neural_bytes_per_element": (
                CORE_CONFIG_NEURAL_BYTES_PER_ELEMENT
            ),
            "neural_matrix_terms": [
                list(binding) for binding in CORE_CONFIG_NEURAL_MATRIX_TERMS
            ],
            "boolean_roles": list(CORE_CONFIG_BOOLEAN_ROLES),
            "state_path": "memory-parent/runtime_state.json",
            "distinct_paths": list(CORE_CONFIG_DISTINCT_PATH_ROLES),
            "parent_suffix_bindings": [
                list(binding)
                for binding in CORE_CONFIG_PARENT_SUFFIX_BINDINGS
            ],
            "suffix_bindings": [
                list(binding) for binding in CORE_CONFIG_SUFFIX_BINDINGS
            ],
            "order_relations": [
                list(binding) for binding in CORE_CONFIG_ORDER_RELATIONS
            ],
            "comparator_bindings": [
                list(binding) for binding in CORE_CONFIG_COMPARATOR_BINDINGS
            ],
            "embedding_space_schema": EMBEDDING_SPACE_SCHEMA,
            "spike_encoder": EMBEDDING_SPIKE_ENCODER,
            "neuron_projection": EMBEDDING_NEURON_PROJECTION,
            "embedding_space_identity": (
                "plain-sha256-canonical-core-derived-embedding-space-v1"
            ),
            "embedding_space_outer_bindings": [
                list(binding) for binding in EMBEDDING_SPACE_OUTER_BINDINGS
            ],
            "embedding_space_neural_bindings": [
                list(binding) for binding in EMBEDDING_SPACE_NEURAL_BINDINGS
            ],
            "embedding_space_constant_values": [
                list(binding) for binding in EMBEDDING_SPACE_CONSTANT_VALUES
            ],
            "embedding_space_hash_preimage": (
                "exact-canonical-ascii-json-object-with-outer-bindings-and-"
                "nested-neural-bindings-in-declared-keysets"
            ),
            "request_core_bindings": [
                "embedding_provider_name=embedding_provider",
                "embedding_neural_model_id=model_id",
                "embedding_neural_revision=model_revision",
                "core_config_fingerprint=plain-sha256-canonical-core-config",
                "embedding_space_identity=derived-core-embedding-space",
            ],
            "runtime_core_bindings": [
                "model_id", "revision", "cache_dir", "pooling",
                "max_tokens", "normalize", "local_files_only",
            ],
        },
        "document_binding_constants": [
            [
                name,
                list(value) if type(value) is tuple else value,
            ]
            for name, value in DOCUMENT_BINDING_CONSTANT_VALUES
        ],
        "document_binding_comparator_method": (
            DOCUMENT_BINDING_COMPARATOR_METHOD
        ),
        "policy_membership_method": POLICY_MEMBERSHIP_METHOD,
        "path_prefix_match_method": PATH_PREFIX_MATCH_METHOD,
        "document_binding_tables": {
            name: [list(binding) for binding in bindings]
            for name, bindings in DOCUMENT_BINDING_TABLES.items()
        },
        "cross_manifest_tree_file_fields": list(
            CROSS_MANIFEST_TREE_FILE_FIELDS
        ),
        "cross_manifest_model_file_fields": list(
            CROSS_MANIFEST_MODEL_FILE_FIELDS
        ),
        "storage_digest_component_roles": list(
            STORAGE_DIGEST_COMPONENT_ROLES
        ),
        "distribution_digest_relation_roles": list(
            DISTRIBUTION_DIGEST_RELATION_ROLES
        ),
        "parent_directory_kind_by_role": [
            list(binding) for binding in PARENT_DIRECTORY_KIND_BY_ROLE
        ],
        "document_relation_fields": {
            name: [list(binding) for binding in bindings]
            for name, bindings in DOCUMENT_RELATION_FIELDS.items()
        },
        "document_aggregation_operations": list(
            DOCUMENT_AGGREGATION_OPERATIONS
        ),
        "document_aggregation_binding_fields": list(
            DOCUMENT_AGGREGATION_BINDING_FIELDS
        ),
        "document_aggregation_comparator_method": (
            DOCUMENT_AGGREGATION_COMPARATOR_METHOD
        ),
        "document_aggregation_bindings": {
            name: [list(binding) for binding in bindings]
            for name, bindings in DOCUMENT_AGGREGATION_BINDINGS.items()
        },
        "document_value_relation_binding_fields": list(
            DOCUMENT_VALUE_RELATION_BINDING_FIELDS
        ),
        "document_value_relation_bindings": [
            list(binding) for binding in DOCUMENT_VALUE_RELATION_BINDINGS
        ],
        "collection_order_direction_bindings": [
            list(binding) for binding in COLLECTION_ORDER_DIRECTION_BINDINGS
        ],
        "collection_relation_binding_fields": list(
            COLLECTION_RELATION_BINDING_FIELDS
        ),
        "collection_relation_bindings": [
            list(binding) for binding in COLLECTION_RELATION_BINDINGS
        ],
        "collection_relation_comparator_method": (
            COLLECTION_RELATION_COMPARATOR_METHOD
        ),
        "distribution_direct_url_bindings": [
            list(binding) for binding in DISTRIBUTION_DIRECT_URL_BINDINGS
        ],
        "optional_value_presence_binding_fields": list(
            OPTIONAL_VALUE_PRESENCE_BINDING_FIELDS
        ),
        "optional_value_presence_bindings": [
            list(binding) for binding in OPTIONAL_VALUE_PRESENCE_BINDINGS
        ],
        "optional_path_action_binding_fields": list(
            OPTIONAL_PATH_ACTION_BINDING_FIELDS
        ),
        "optional_path_action_bindings": [
            list(binding) for binding in OPTIONAL_PATH_ACTION_BINDINGS
        ],
        "optional_path_allowed_actions": [
            [optional, list(actions)]
            for optional, actions in OPTIONAL_PATH_ALLOWED_ACTIONS
        ],
        "executable_mode_classification_method": (
            EXECUTABLE_MODE_CLASSIFICATION_METHOD
        ),
        "executable_path_membership_method": (
            EXECUTABLE_PATH_MEMBERSHIP_METHOD
        ),
        "storage_top_level_directory_binding_fields": list(
            STORAGE_TOP_LEVEL_DIRECTORY_BINDING_FIELDS
        ),
        "storage_top_level_directory_binding": list(
            STORAGE_TOP_LEVEL_DIRECTORY_BINDING
        ),
        "storage_nlink_combine_method": STORAGE_NLINK_COMBINE_METHOD,
        "tree_file_mode_binding_fields": list(
            TREE_FILE_MODE_BINDING_FIELDS
        ),
        "tree_file_mode_binding": list(TREE_FILE_MODE_BINDING),
        "entry_kind_validator_binding_fields": list(
            ENTRY_KIND_VALIDATOR_BINDING_FIELDS
        ),
        "entry_kind_validator_bindings": [
            list(binding) for binding in ENTRY_KIND_VALIDATOR_BINDINGS
        ],
        "entry_validator_context_keys": list(ENTRY_VALIDATOR_CONTEXT_KEYS),
        "entry_fixed_field_bindings": [
            [name, [list(binding) for binding in bindings]]
            for name, bindings in ENTRY_FIXED_FIELD_BINDINGS
        ],
        "entry_field_comparator_method": ENTRY_FIELD_COMPARATOR_METHOD,
        "entry_suffix_match_method": ENTRY_SUFFIX_MATCH_METHOD,
        "model_file_suffix_rule_binding_fields": list(
            MODEL_FILE_SUFFIX_RULE_BINDING_FIELDS
        ),
        "model_file_suffix_rule_bindings": [
            list(binding) for binding in MODEL_FILE_SUFFIX_RULE_BINDINGS
        ],
        "slot_states": {
            slot: ("static-document-only" if slot in STATIC_SLOTS else "pending-null")
            for slot in EVIDENCE_SLOTS
        },
        "dynamic_authority_requirements": [
            "authenticated-one-shot-execution-ticket",
            "externally-enforced-network-denial",
            "freshness-challenge",
            "continuous-held-root-or-final-boundary-revalidation",
            "durable-authenticated-evidence-publisher",
        ],
        "nonclaims": list(NONCLAIMS),
    }


def environment_policy_id():
    """Return the deterministic policy identity; performs no I/O."""
    return "environment-policy-" + _domain_hash(
        _DOMAINS["policy"], _policy_body(), MAX_CONTRACT_BYTES
    )


def environment_policy_projection():
    """Return the closed future materialization/evidence policy projection."""
    body = _policy_body()
    body["environment_policy_id"] = environment_policy_id()
    return body


ENVIRONMENT_POLICY_ID = environment_policy_id()


def _phase5a_fixed_policy():
    return {
        "fixed": {
            "schema": PHASE5A_REQUEST_SCHEMA,
            "mode": PHASE5A_REQUEST_MODE,
            "profile": "exact-build-only",
            "profile_version": 1,
            "environment_contract_id": PHASE5A_CONTRACT_ID,
            "activation_contract_id": ACTIVATION_CONTRACT_ID,
            "compatibility_profile_version": COMPATIBILITY_PROFILE_VERSION,
        },
        "binding_fixed": {
            "layout_schema": "synapse-s2.installed-layout-contract.v1",
            "layout_mode": "inactive-versioned-v1",
            "layout_contract_id": (
                "layout-contract-"
                "027363aa3a7a97a6dda522d869ef09a25471ce60161a56d063f0c1164b385ada"
            ),
            "target_system": "darwin",
            "target_machine": "arm64",
            "target_python_implementation": "cpython",
            "environment_policy_id": environment_policy_id(),
        },
        "binding_keys": list(PHASE5A_BINDING_KEYS),
        "integer_fields": {
            "trust_generation": [1, MAX_INT],
            "release_sequence": [1, MAX_INT],
        },
        "equality_requirements": [
            ["candidate_product_id", "staged_product_id"],
            ["candidate_source_build_id", "staged_source_build_id"],
        ],
    }


def _contract_body():
    return {
        "schema": CONTRACT_SCHEMA,
        "mode": MODE,
        "profile": PROFILE,
        "profile_version": PROFILE_VERSION,
        "compatibility_profile_version": COMPATIBILITY_PROFILE_VERSION,
        "upstream": {
            "phase5a_source_sha256": PHASE5A_SOURCE_SHA256,
            "phase5a_contract_id": PHASE5A_CONTRACT_ID,
            "phase5b1_source_sha256": PHASE5B1_SOURCE_SHA256,
            "phase5b1_contract_id": PHASE5B1_CONTRACT_ID,
            "activation_contract_id": ACTIVATION_CONTRACT_ID,
        },
        "schemas": {
            "contract": CONTRACT_SCHEMA,
            "policy": POLICY_SCHEMA,
            "evidence_set": EVIDENCE_SET_SCHEMA,
            "model_snapshot_plan": MODEL_SNAPSHOT_PLAN_SCHEMA,
            "phase5a_request": PHASE5A_REQUEST_SCHEMA,
            "storage_request": STORAGE_REQUEST_SCHEMA,
            "storage_prepare": STORAGE_PREPARE_SCHEMA,
            "tree_manifest": TREE_MANIFEST_SCHEMA,
            "installed_distribution_manifest": INSTALLED_DISTRIBUTION_MANIFEST_SCHEMA,
            "native_file_manifest": NATIVE_FILE_MANIFEST_SCHEMA,
            "dependency_probe": DEPENDENCY_PROBE_SCHEMA,
            "interpreter_observation": INTERPRETER_OBSERVATION_SCHEMA,
            "toolchain_observation": TOOLCHAIN_OBSERVATION_SCHEMA,
            "model_manifest": MODEL_MANIFEST_SCHEMA,
            "model_probe": MODEL_PROBE_SCHEMA,
            "core_config": CORE_CONFIG_SCHEMA,
            "embedding_runtime_config": EMBEDDING_RUNTIME_CONFIG_SCHEMA,
            "result": RESULT_SCHEMA,
            "render": RENDER_SCHEMA,
        },
        "domains_hex": {
            **{key: value.hex() for key, value in _DOMAINS.items()},
            **{"storage_" + key: value.hex() for key, value in _STORAGE_DOMAINS.items()},
            "phase5a_request": PHASE5A_REQUEST_DOMAIN.hex(),
        },
        "canonicalization": {
            "hash_algorithm": "sha256",
            "encoding": "ascii",
            "sort_keys": True,
            "separators": [",", ":"],
            "ensure_ascii": True,
            "allow_nan": False,
            "trailing_newline": False,
            "outer_document_floats_allowed": False,
            "embedded_core_and_runtime_json_finite_floats_allowed": True,
        },
        "implementation_identity": {
            "contract_id_self_authenticates_source_bytes": False,
            "source_sha256_authority": "external-release-inventory",
            "preimport_source_replacement_requires_external_sha256_check": True,
            "runtime_guard_scope": (
                "post-import-global-rebinding-and-projection-drift"
            ),
        },
        "limits": {
            "default_schema_integer_maximum": MAX_INT,
            "max_native_document_integer_abs": MAX_NATIVE_INT,
            "max_depth": MAX_DEPTH,
            "max_keys": MAX_KEYS,
            "max_key_characters": MAX_KEY_CHARS,
            "max_list_items": MAX_LIST_ITEMS,
            "max_total_nodes": MAX_TOTAL_NODES,
            "max_string_characters": MAX_STRING_CHARS,
            "max_document_bytes": MAX_DOCUMENT_BYTES,
            "max_contract_bytes": MAX_CONTRACT_BYTES,
            "max_result_bytes": MAX_RESULT_BYTES,
            "max_render_bytes": MAX_RENDER_BYTES,
            "phase5b1_tree_entries": PHASE5B1_MAX_TREE_ENTRIES,
            "phase5b1_document_bytes": PHASE5B1_MAX_DOC_BYTES,
            "phase5b1_path_length": PHASE5B1_MAX_PATH_LENGTH,
            "phase5b1_name_length": PHASE5B1_MAX_NAME_LENGTH,
            "phase5b1_tree_depth": PHASE5B1_MAX_TREE_DEPTH,
            "phase5b1_tree_total_bytes": PHASE5B1_MAX_TREE_TOTAL_BYTES,
            "phase5b1_tree_file_bytes": PHASE5B1_MAX_TREE_FILE_BYTES,
            "model_snapshot_minimum_entries": MODEL_SNAPSHOT_MIN_ENTRIES,
            "model_snapshot_minimum_total_bytes": (
                MODEL_SNAPSHOT_MIN_TOTAL_BYTES
            ),
            "native_sublist_items": NATIVE_SUBLIST_MAX_ITEMS,
            "native_text_minimum_characters": NATIVE_TEXT_MIN_CHARS,
        },
        "keysets": {
            "phase5a_request": list(PHASE5A_REQUEST_KEYS),
            "storage_request": list(STORAGE_REQUEST_KEYS),
            "storage_prepare": list(STORAGE_PREPARE_KEYS),
            "tree_manifest": list(TREE_MANIFEST_KEYS),
            "tree_entry": list(TREE_ENTRY_KEYS),
            "fingerprint": list(FINGERPRINT_KEYS),
            "model_snapshot_plan": list(MODEL_SNAPSHOT_PLAN_KEYS),
            "model_snapshot_entry": list(MODEL_SNAPSHOT_ENTRY_KEYS),
            "installed_distribution_manifest": list(INSTALLED_DISTRIBUTION_MANIFEST_KEYS),
            "distribution_entry": list(DISTRIBUTION_ENTRY_KEYS),
            "installed_file_entry": list(INSTALLED_FILE_ENTRY_KEYS),
            "native_file_manifest": list(NATIVE_FILE_MANIFEST_KEYS),
            "native_entry": list(NATIVE_ENTRY_KEYS),
            "core_config": list(CORE_CONFIG_KEYS),
            "embedding_runtime_config": list(EMBEDDING_RUNTIME_CONFIG_KEYS),
            "model_manifest": list(MODEL_MANIFEST_KEYS),
            "evidence_set": list(EVIDENCE_SET_KEYS),
            "result": list(RESULT_KEYS),
            "render": list(RENDER_KEYS),
        },
        "patterns": {
            "hex64": _HEX64_PATTERN,
            "contract_id": _CONTRACT_ID_PATTERN,
            "policy_id": _POLICY_ID_PATTERN,
            "product_id": _PRODUCT_ID_PATTERN,
            "component_id": _COMPONENT_ID_PATTERN,
            "inventory_policy_id": _INVENTORY_POLICY_PATTERN,
            "layout_id": _LAYOUT_ID_PATTERN,
            "operation_id": _OPERATION_ID_PATTERN,
            "source_build_id": _SOURCE_BUILD_PATTERN,
            "source_sha": _SOURCE_SHA_PATTERN,
            "root_key_id": _ROOT_KEY_PATTERN,
            "channel": _CHANNEL_PATTERN,
            "version": _VERSION_PATTERN,
            "revision": _REVISION_PATTERN,
            "label": _LABEL_PATTERN,
            "name": _NAME_PATTERN,
            "relative_path": _RELATIVE_PATH_PATTERN,
            "mode": _MODE_PATTERN,
            "python_abi": _PYTHON_ABI_PATTERN,
            "tree_entry_name": _TREE_ENTRY_NAME_PATTERN,
            "canonical_distribution_name": (
                _CANONICAL_DISTRIBUTION_NAME_PATTERN
            ),
            "model_repository_id": _MODEL_REPOSITORY_PATTERN,
            "sensitive_assignment_key": _SENSITIVE_ASSIGNMENT_KEY_PATTERN,
            "secret_shapes": list(_SECRET_SHAPE_PATTERNS),
            "phase5a_fields": dict(_PHASE5A_PATTERNS),
            "regex_api": "re.fullmatch",
            "regex_flags": 0,
        },
        "phase5a_request_policy": _phase5a_fixed_policy(),
        "evidence_slots": list(EVIDENCE_SLOTS),
        "static_slots": list(STATIC_SLOTS),
        "static_slot_validator_roles": [
            list(binding) for binding in STATIC_SLOT_VALIDATOR_ROLES
        ],
        "static_slot_validator_bindings": [
            [slot, role, function_name, list(argument_roles)]
            for slot, role, function_name, argument_roles
            in STATIC_SLOT_VALIDATOR_BINDINGS
        ],
        "static_slot_validator_binding_fields": list(
            STATIC_SLOT_VALIDATOR_BINDING_FIELDS
        ),
        "static_validator_context_roles": list(
            STATIC_VALIDATOR_CONTEXT_ROLES
        ),
        "static_validator_context_bindings": [
            list(binding) for binding in STATIC_VALIDATOR_CONTEXT_BINDINGS
        ],
        "static_primary_storage_role": STATIC_PRIMARY_STORAGE_ROLE,
        "dynamic_pending_slots": list(DYNAMIC_PENDING_SLOTS),
        "slot_schemas": dict(SLOT_SCHEMAS),
        "slot_meanings": {
            "environment_manifest_sha256": (
                "existing-phase5b1-tree-manifest-domain-digest-from-one-"
                "continuously-held-rescan-equal-to-persisted-manifest-and-prepare"
            ),
            "installed_distribution_manifest_sha256": (
                "static-dist-info-metadata-wheel-record-direct-url-and-recorded-byte-manifest"
            ),
            "native_file_manifest_sha256": (
                "static-magic-detected-mach-o-byte-architecture-load-command-manifest"
            ),
            "dependency_probe_sha256": "pending-authenticated-runtime-import-origin-proof",
            "interpreter_observation_sha256": "pending-authenticated-interpreter-abi-origin-proof",
            "toolchain_observation_sha256": "pending-authenticated-build-toolchain-artifact-proof",
            "model_manifest_sha256": "static-request-bound-post-publication-model-snapshot-manifest",
            "model_probe_sha256": "pending-authenticated-model-load-inference-proof",
        },
        "hash_bindings": {
            "environment_policy_id": "policy-domain + policy-body-without-id",
            "contract_id": "contract-domain + contract-body-without-id",
            "phase5a_request_sha256": "phase5a-request-domain + exact-request",
            "model_snapshot_plan_sha256": "model-snapshot-plan-domain + exact-plan",
            "storage_request_record_sha256": (
                "phase5b1-storage-request-domain + exact-storage-request-"
                "record-without-request-record-sha256"
            ),
            "storage_prepare_sha256": (
                "phase5b1-storage-prepare-domain + exact-storage-prepare-"
                "record-without-prepare-sha256"
            ),
            "storage_digest": (
                "sha256-of-phase5b1-storage-digest-domain-concatenated-with-"
                "ascii-phase5a-request-sha256-tree-manifest-sha256-and-"
                "storage-prepare-sha256"
            ),
            "static_slot_digests": "role-domain + exact-role-document",
            "environment_manifest_sha256": "phase5b1-tree-manifest-domain + exact-tree-manifest",
            "core_config_fingerprint": (
                "plain-sha256-of-exact-canonical-ascii-core-config-json"
            ),
            "embedding_runtime_config_sha256": (
                "plain-sha256-of-exact-canonical-ascii-runtime-config-json"
            ),
            "embedding_space_identity": (
                "plain-sha256-of-exact-canonical-ascii-json-object-defined-"
                "by-policy-embedding-space-outer-and-neural-bindings"
            ),
            "evidence_set_sha256": "evidence-set-domain + exact-evidence-set",
            "result_sha256": "result-domain + exact-result-without-result-sha256",
        },
        "validator_policy": {
            "document_aggregation_operations": list(
                DOCUMENT_AGGREGATION_OPERATIONS
            ),
            "document_aggregation_comparator_method": (
                DOCUMENT_AGGREGATION_COMPARATOR_METHOD
            ),
            "document_aggregation_bindings": {
                name: [list(binding) for binding in bindings]
                for name, bindings in DOCUMENT_AGGREGATION_BINDINGS.items()
            },
            "document_value_relation_bindings": [
                list(binding) for binding in DOCUMENT_VALUE_RELATION_BINDINGS
            ],
            "collection_order_direction_bindings": [
                list(binding)
                for binding in COLLECTION_ORDER_DIRECTION_BINDINGS
            ],
            "collection_relation_bindings": [
                list(binding) for binding in COLLECTION_RELATION_BINDINGS
            ],
            "collection_relation_comparator_method": (
                COLLECTION_RELATION_COMPARATOR_METHOD
            ),
            "distribution_direct_url_bindings": [
                list(binding) for binding in DISTRIBUTION_DIRECT_URL_BINDINGS
            ],
            "distribution_name_normalization_transform": list(
                DISTRIBUTION_NAME_NORMALIZATION_TRANSFORM
            ),
            "distribution_name_normalization_checks": [
                list(binding)
                for binding in DISTRIBUTION_NAME_NORMALIZATION_CHECKS
            ],
            "distribution_name_normalization_combiner": (
                "all-checks-required"
            ),
            "string_and_path_pattern_policy": {
                "document_binding_fields": list(
                    DOCUMENT_STRING_PATTERN_BINDING_FIELDS
                ),
                "document_bindings": {
                    name: [list(binding) for binding in bindings]
                    for name, bindings
                    in DOCUMENT_STRING_PATTERN_BINDINGS.items()
                },
                "helper_bindings": [
                    list(binding)
                    for binding in HELPER_STRING_PATTERN_BINDINGS
                ],
                "path_predicate_binding_fields": list(
                    PATH_REJECTION_PREDICATE_BINDING_FIELDS
                ),
                "path_predicate_bindings": {
                    name: [list(binding) for binding in bindings]
                    for name, bindings
                    in PATH_REJECTION_PREDICATE_BINDINGS.items()
                },
                "path_predicate_comparator_method": (
                    PATH_REJECTION_PREDICATE_COMPARATOR_METHOD
                ),
                "path_predicate_combiner": (
                    PATH_REJECTION_PREDICATE_COMBINER
                ),
                "path_predicate_combiner_binding_fields": list(
                    PATH_REJECTION_PREDICATE_COMBINER_BINDING_FIELDS
                ),
                "path_predicate_combiner_bindings": [
                    list(binding)
                    for binding
                    in PATH_REJECTION_PREDICATE_COMBINER_BINDINGS
                ],
                "native_sublist_bindings": [
                    list(binding)
                    for binding in NATIVE_SUBLIST_STRING_PATTERN_BINDINGS
                ],
            },
            "optional_value_presence_bindings": [
                list(binding) for binding in OPTIONAL_VALUE_PRESENCE_BINDINGS
            ],
            "optional_path_action_bindings": [
                list(binding) for binding in OPTIONAL_PATH_ACTION_BINDINGS
            ],
            "optional_path_allowed_actions": [
                [optional, list(actions)]
                for optional, actions in OPTIONAL_PATH_ALLOWED_ACTIONS
            ],
            "executable_mode_classification_method": (
                EXECUTABLE_MODE_CLASSIFICATION_METHOD
            ),
            "executable_path_membership_method": (
                EXECUTABLE_PATH_MEMBERSHIP_METHOD
            ),
            "storage_top_level_directory_binding": list(
                STORAGE_TOP_LEVEL_DIRECTORY_BINDING
            ),
            "storage_nlink_combine_method": STORAGE_NLINK_COMBINE_METHOD,
            "tree_file_mode_binding": list(TREE_FILE_MODE_BINDING),
            "entry_kind_validator_bindings": [
                list(binding) for binding in ENTRY_KIND_VALIDATOR_BINDINGS
            ],
            "entry_fixed_field_bindings": [
                [name, [list(binding) for binding in bindings]]
                for name, bindings in ENTRY_FIXED_FIELD_BINDINGS
            ],
            "entry_field_comparator_method": ENTRY_FIELD_COMPARATOR_METHOD,
            "entry_suffix_match_method": ENTRY_SUFFIX_MATCH_METHOD,
            "model_file_suffix_rule_bindings": [
                list(binding) for binding in MODEL_FILE_SUFFIX_RULE_BINDINGS
            ],
            "secret_shape_document_binding_fields": list(
                SECRET_SHAPE_DOCUMENT_BINDING_FIELDS
            ),
            "secret_shape_document_bindings": [
                [document_role, schema_field, schema_value, list(field_roles)]
                for document_role, schema_field, schema_value, field_roles
                in SECRET_SHAPE_DOCUMENT_BINDINGS
            ],
            "secret_shape_document_exact_matches": (
                SECRET_SHAPE_DOCUMENT_EXACT_MATCHES
            ),
            "all_non_null_absolute_paths_secret_shape_checked": True,
            "policy_membership_method": POLICY_MEMBERSHIP_METHOD,
            "path_prefix_match_method": PATH_PREFIX_MATCH_METHOD,
            "tree_entry_kinds": list(TREE_ENTRY_KINDS),
            "tree_directory_mode": TREE_DIRECTORY_MODE,
            "tree_regular_file_mode": TREE_REGULAR_FILE_MODE,
            "tree_file_default_mode": TREE_FILE_DEFAULT_MODE,
            "directory_entry_empty_size": DIRECTORY_ENTRY_EMPTY_SIZE,
            "directory_entry_empty_digest": DIRECTORY_ENTRY_EMPTY_DIGEST,
            "tree_executable_files": dict(TREE_EXECUTABLE_FILES),
            "tree_required_entries": list(TREE_REQUIRED_ENTRIES),
            "tree_required_entry_relation_method": (
                TREE_REQUIRED_ENTRY_RELATION_METHOD
            ),
            "tree_forbidden_path_segments": list(
                PHASE5B1_FORBIDDEN_PATH_SEGMENTS
            ),
            "tree_path_components_maximum": PHASE5B1_MAX_TREE_DEPTH + 1,
            "tree_directory_path_components_maximum": PHASE5B1_MAX_TREE_DEPTH,
            "tree_order": "sorted-names-per-directory-depth-first-preorder",
            "tree_parent_directories_required": True,
            "relative_path_policy": {
                "syntax": (
                    "ascii-relative-no-leading-or-trailing-slash-no-dot-or-"
                    "empty-components"
                ),
                "tree_components_match_tree-entry-name-pattern": True,
                "model-entry-components_match-relative-path-pattern": True,
                "ascii_casefold_aliases_forbidden": True,
                "syntax_values": [
                    list(binding) for binding in PATH_SYNTAX_VALUES
                ],
                "forbidden_components": list(PATH_FORBIDDEN_COMPONENTS),
            },
            "numeric_field_bounds": {
                "fingerprint.device": [1, MAX_NATIVE_INT],
                "fingerprint.inode": [1, MAX_NATIVE_INT],
                "fingerprint.mode": [0, MAX_INT],
                "fingerprint.nlink": [
                    PHASE5B1_PREIMAGE_NLINK, MAX_NATIVE_INT,
                ],
                "model_snapshot_plan.entry_count": [
                    MODEL_SNAPSHOT_MIN_ENTRIES,
                    PHASE5B1_MAX_TREE_ENTRIES,
                ],
                "model_snapshot_plan.total_bytes": [
                    MODEL_SNAPSHOT_MIN_TOTAL_BYTES,
                    PHASE5B1_MAX_TREE_TOTAL_BYTES,
                ],
                "model_snapshot_entry.size": [
                    0, PHASE5B1_MAX_TREE_FILE_BYTES,
                ],
                "tree_manifest.entry_count": [
                    0, PHASE5B1_MAX_TREE_ENTRIES,
                ],
                "tree_manifest.total_bytes": [
                    0, PHASE5B1_MAX_TREE_TOTAL_BYTES,
                ],
                "tree_entry.size": [0, PHASE5B1_MAX_TREE_FILE_BYTES],
                "installed_distribution_manifest.distribution_count": [
                    0, MAX_LIST_ITEMS,
                ],
                "installed_distribution_manifest.file_count": [
                    0, MAX_LIST_ITEMS,
                ],
                "installed_distribution_manifest.total_bytes": [0, MAX_INT],
                "installed_file_entry.size": [
                    0, PHASE5B1_MAX_TREE_FILE_BYTES,
                ],
                "native_file_manifest.file_count": [0, MAX_LIST_ITEMS],
                "native_entry.size": [0, PHASE5B1_MAX_TREE_FILE_BYTES],
                "native_entry.sublists": [0, NATIVE_SUBLIST_MAX_ITEMS],
            },
            "persisted_fingerprint": {
                "device_minimum": 1,
                "inode_minimum": 1,
                "mode": PHASE5B1_DIRECTORY_MODE,
                "nlink_minimum": PHASE5B1_PREIMAGE_NLINK,
                "environment_preimage_nlink": PHASE5B1_PREIMAGE_NLINK,
                "devices_equal": True,
                "inodes_distinct": True,
                "operation_nlink": (
                    "preimage-nlink-plus-top-level-directory-count"
                ),
            },
            "storage_operation_id": "operation-prefix-plus-phase5a-request-sha256",
            "model_entry_kinds": list(MODEL_ENTRY_KINDS),
            "model_directory_mode": MODEL_DIRECTORY_MODE,
            "model_file_mode": MODEL_FILE_MODE,
            "model_forbidden_suffixes": list(MODEL_FORBIDDEN_SUFFIXES),
            "model_allowed_file_suffixes": list(MODEL_ALLOWED_FILE_SUFFIXES),
            "model_snapshot_root_form": (
                "share/synapse-s2/model-cache-v1/snapshots/<model_revision>"
            ),
            "model_snapshot_minimum_entries": MODEL_SNAPSHOT_MIN_ENTRIES,
            "model_snapshot_minimum_total_bytes": (
                MODEL_SNAPSHOT_MIN_TOTAL_BYTES
            ),
            "model_snapshot_count_relation": (
                "entry-count-equals-entry-list-length"
            ),
            "model_snapshot_total_relation": (
                "total-bytes-equals-sum-of-file-entry-sizes"
            ),
            "model_plan_parent_directories_required": True,
            "distribution_source_kinds": list(DISTRIBUTION_SOURCE_KINDS),
            "distribution_direct_url": (
                "required-for-git-and-null-for-wheel"
            ),
            "distribution_name_normalization": (
                "pep503-lowercase-collapse-runs-of-hyphen-underscore-dot-to-hyphen"
            ),
            "installed_file_modes": list(INSTALLED_FILE_MODES),
            "installed_executable_files": list(TREE_EXECUTABLE_FILES),
            "native_file_modes": list(NATIVE_FILE_MODES),
            "native_executable_files": list(TREE_EXECUTABLE_FILES),
            "native_target_architecture_required": True,
            "native_sublist_fields": list(NATIVE_SUBLIST_FIELDS),
            "native_sublist_items_maximum": NATIVE_SUBLIST_MAX_ITEMS,
            "native_sorted_unique_fields": list(
                NATIVE_SORTED_UNIQUE_FIELDS
            ),
            "native_text_sublist_fields": list(NATIVE_TEXT_SUBLIST_FIELDS),
            "native_text_minimum_characters": NATIVE_TEXT_MIN_CHARS,
            "native_base_interpreter_owner": NATIVE_BASE_INTERPRETER_OWNER,
            "native_base_interpreter_path": NATIVE_BASE_INTERPRETER_PATH,
            "native_base_interpreter_cardinality": "exactly-one",
            "embedded_core_config_digest": (
                "plain-sha256-exact-canonical-ascii-json-with-finite-floats"
            ),
            "embedded_runtime_config_digest": (
                "plain-sha256-exact-canonical-ascii-json-with-finite-floats"
            ),
            "core_config": {
                "protocol": CORE_CONFIG_SCHEMA,
                "provider_aliases": list(CORE_PROVIDER_ALIASES),
                "required_mlx_device": CORE_REQUIRED_MLX_DEVICE,
                "require_native": CORE_REQUIRED_NATIVE,
                "neural_matrix_bytes_maximum": (
                    CORE_CONFIG_MAX_NEURAL_MATRIX_BYTES
                ),
                "neural_bytes_per_element": (
                    CORE_CONFIG_NEURAL_BYTES_PER_ELEMENT
                ),
                "integer_bound_roles": [
                    list(binding)
                    for binding in CORE_CONFIG_INTEGER_BOUND_ROLES
                ],
                "float_bound_roles": [
                    list(binding) for binding in CORE_CONFIG_FLOAT_BOUND_ROLES
                ],
                "boolean_roles": list(CORE_CONFIG_BOOLEAN_ROLES),
                "order_relations": [
                    list(binding) for binding in CORE_CONFIG_ORDER_RELATIONS
                ],
                "comparator_bindings": [
                    list(binding)
                    for binding in CORE_CONFIG_COMPARATOR_BINDINGS
                ],
                "neural_matrix_terms": [
                    list(binding)
                    for binding in CORE_CONFIG_NEURAL_MATRIX_TERMS
                ],
                "frame_bytes": [
                    CORE_CONFIG_MIN_FRAME_BYTES,
                    CORE_CONFIG_MAX_FRAME_BYTES,
                ],
                "socket_path": "memory-parent/core/service.sock",
                "socket_path_bytes_maximum": CORE_CONFIG_MAX_SOCKET_BYTES,
                "state_path": "memory-parent/runtime_state.json",
                "cache_path_suffix": MODEL_CACHE_ROOT_RELATIVE,
                "embedding_space_schema": EMBEDDING_SPACE_SCHEMA,
                "spike_encoder": EMBEDDING_SPIKE_ENCODER,
                "neuron_projection": EMBEDDING_NEURON_PROJECTION,
                "embedding_space_identity": (
                    "plain-sha256-canonical-core-derived-embedding-space-v1"
                ),
                "embedding_space_outer_bindings": [
                    list(binding)
                    for binding in EMBEDDING_SPACE_OUTER_BINDINGS
                ],
                "embedding_space_neural_bindings": [
                    list(binding)
                    for binding in EMBEDDING_SPACE_NEURAL_BINDINGS
                ],
                "embedding_space_constant_values": [
                    list(binding)
                    for binding in EMBEDDING_SPACE_CONSTANT_VALUES
                ],
            },
            "embedding_runtime_config": {
                "schema": EMBEDDING_RUNTIME_CONFIG_SCHEMA,
                "provider": EMBEDDING_RUNTIME_PROVIDER,
                "pooling_values": list(NEURAL_POOLING_VALUES),
                "local_files_only": True,
                "bindings": [
                    list(binding)
                    for binding in EMBEDDING_RUNTIME_CONFIG_BINDINGS
                ],
                "constant_values": [
                    list(binding)
                    for binding in EMBEDDING_RUNTIME_CONSTANT_VALUES
                ],
            },
            "dynamic_documents_and_digests": "exact-null",
            "static_document_order": (
                "strict-path-or-name-sort-exact-and-ascii-casefold-unique"
            ),
            "installed_record_binding": (
                "each-file-record-sha256-equals-owning-distribution-record-sha256"
            ),
            "cross_manifest_binding": (
                "installed-native-and-model-path-kind-mode-size-sha256-"
                "must-match-phase5b1-tree-manifest"
            ),
            "model_cache_completeness": (
                "tree-paths-under-cache-root-exactly-cache-snapshots-single-"
                "revision-root-and-model-snapshot-plan-entries"
            ),
            "native_architectures": "sorted-unique-and-contains-target-machine",
            "document_relations": {
                "model_snapshot_plan": [
                    "entry-count-equals-entry-list-length-and-is-nonempty",
                    "total-bytes-equals-sum-of-file-entry-sizes-and-is-positive",
                    "entry-paths-sorted-unique-and-ascii-casefold-unique",
                    "every-nested-entry-has-a-directory-parent-entry",
                    "snapshot-root-is-cache-root-snapshots-model-revision",
                    "directory-mode-size-and-empty-digest-are-exact",
                    "file-mode-digest-and-case-insensitive-allowed-and-forbidden-"
                    "suffix-rules-are-exact",
                    "full-model-entry-paths-obey-phase5b1-tree-depth",
                ],
                "storage_request_record": [
                    "embedded-phase5a-request-replays-and-is-canonical-equal",
                    "request-layout-stage-result-and-stage-journal-bind-phase5a-request",
                    "operation-id-is-operation-prefix-plus-request-digest",
                    "layout-plan-digest-is-lowercase-sha256",
                    "preimage-and-operation-fingerprints-obey-projected-policy",
                    "self-hash-excludes-only-request-record-sha256",
                ],
                "storage_prepare_record": [
                    "request-record-request-operation-layout-manifest-stage-and-"
                    "fingerprints-equal-replayed-inputs",
                    "manifest-count-and-total-equal-tree-manifest",
                    "self-hash-excludes-only-prepare-sha256",
                ],
                "tree_manifest": [
                    "contract-request-operation-product-and-inventory-policy-bind-"
                    "replayed-phase5a-and-storage-records",
                    "entry-count-equals-entry-list-length",
                    "total-bytes-equals-sum-of-file-entry-sizes",
                    "sorted-names-per-directory-depth-first-preorder",
                    "required-bin-directory-and-bin-python-file",
                    "directories-use-exact-mode-zero-size-empty-digest-and-depth",
                    "files-use-path-specific-mode-bounded-size-and-sha256-digest",
                ],
                "installed_distribution_manifest": [
                    "contract-policy-request-storage-product-dependency-lock-and-"
                    "project-digests-bind-replayed-inputs",
                    "distribution-count-equals-distribution-list-length",
                    "file-count-equals-file-list-length",
                    "total-bytes-equals-sum-of-file-entry-sizes",
                    "distribution-names-canonical-sorted-unique",
                    "distribution-version-source-and-required-digests-are-closed",
                    "git-requires-direct-url-and-wheel-forbids-direct-url",
                    "file-owner-exists-and-record-digest-equals-owner-record",
                    "every-declared-distribution-owns-at-least-one-file-record",
                    "file-paths-sorted-unique-and-ascii-casefold-unique",
                    "file-mode-size-and-content-digest-obey-projected-tree-policy",
                ],
                "native_file_manifest": [
                    "contract-policy-request-storage-product-and-target-machine-"
                    "bind-replayed-inputs",
                    "file-count-equals-file-list-length",
                    "file-paths-sorted-unique-and-ascii-casefold-unique",
                    "all-native-sublists-exact-lists-with-projected-cap",
                    "all-projected-native-sublists-sorted-unique",
                    "architectures-match-name-pattern-and-dependencies-and-rpaths-"
                    "are-nonempty-bounded-ascii-strings",
                    "architectures-contain-request-target-machine",
                    "owner-mode-size-content-minimum-os-and-load-command-digest-"
                    "obey-projected-grammars",
                    "exactly-one-base-interpreter-owned-bin-python",
                    "other-owners-reference-installed-distributions",
                    "every-distribution-owned-native-file-is-the-same-installed-"
                    "file-record-with-the-same-owner",
                ],
                "model_manifest": [
                    "contract-policy-request-storage-product-config-provider-model-"
                    "revision-and-cache-root-bind-replayed-inputs",
                    "core-and-runtime-json-exact-canonical-digest-replay",
                    "core-config-and-runtime-config-obey-configuration-profile",
                    "snapshot-plan-model-and-revision-equal-request",
                    "pre-request-post-publication-and-request-snapshot-digests-equal",
                    "model-cache-tree-path-set-exactly-single-snapshot-plan",
                ],
                "evidence_set": [
                    "contract-policy-mode-and-upstream-source-and-contract-pins-are-exact",
                    "phase5a-request-replayed-and-canonical-equal",
                    "storage-request-manifest-prepare-and-storage-digest-replayed",
                    "environment-manifest-role-is-canonical-equal-to-storage-manifest",
                    "four-static-role-documents-and-digests-replayed",
                    "four-dynamic-role-documents-and-digests-exact-null",
                ],
            },
            "runtime_integrity_function_names": list(
                RUNTIME_INTEGRITY_FUNCTION_NAMES
            ),
            "runtime_integrity_module_names": list(
                RUNTIME_INTEGRITY_MODULE_NAMES
            ),
            "runtime_integrity_builtin_names": list(
                RUNTIME_INTEGRITY_BUILTIN_NAMES
            ),
            "runtime_integrity_global_names": list(
                RUNTIME_INTEGRITY_GLOBAL_NAMES
            ),
        },
        "forbidden_upstream_fields": [
            "observation_sha256", "environment_id", "environment_receipt_sha256",
            "transaction_id", "intent_sha256", "activation_journal_entry_sha256",
        ],
        "result_truth": {
            "commands": list(RESULT_COMMANDS),
            "statuses": list(RESULT_STATUSES),
            "reason_bindings": [
                list(binding) for binding in RESULT_REASON_BINDINGS
            ],
            "reasons_by_command_status": {
                command: {
                    status: reason
                    for bound_command, status, reason
                    in RESULT_REASON_BINDINGS
                    if _exact_value_equal(bound_command, command)
                }
                for command in RESULT_COMMANDS
            },
            "document_valid_binding": list(
                RESULT_DOCUMENT_VALID_BINDING
            ),
            "derived_source_kinds": list(RESULT_DERIVED_SOURCE_KINDS),
            "derived_bindings": [
                [target, kind, source, list(argument_roles)]
                for target, kind, source, argument_roles
                in RESULT_DERIVED_BINDINGS
            ],
            "derived_binding_fields": list(RESULT_DERIVED_BINDING_FIELDS),
            "replay_bindings": [
                [command, validator_role, list(argument_fields)]
                for command, validator_role, argument_fields
                in RESULT_REPLAY_BINDINGS
            ],
            "replay_binding_fields": list(RESULT_REPLAY_BINDING_FIELDS),
            "unsupported_template_match_binding": list(
                UNSUPPORTED_TEMPLATE_MATCH_BINDING
            ),
            "exit_codes": dict(RESULT_EXIT_CODE_BINDINGS),
            "exit_path_binding_fields": list(
                RESULT_EXIT_PATH_BINDING_FIELDS
            ),
            "exit_path_bindings": [
                list(binding) for binding in RESULT_EXIT_PATH_BINDINGS
            ],
            "exit_predicate_comparator_method": (
                RESULT_EXIT_PREDICATE_COMPARATOR_METHOD
            ),
            "exit_predicate_action_binding_fields": list(
                RESULT_EXIT_PREDICATE_ACTION_BINDING_FIELDS
            ),
            "exit_predicate_action_bindings": [
                list(binding)
                for binding in RESULT_EXIT_PREDICATE_ACTION_BINDINGS
            ],
            "exit_selection_sequence_method": (
                RESULT_EXIT_SELECTION_SEQUENCE_METHOD
            ),
            "exit_selection_collection_method": (
                RESULT_EXIT_SELECTION_COLLECTION_METHOD
            ),
            "exit_traversal_method": RESULT_EXIT_TRAVERSAL_METHOD,
            "exit_selected_path_binding_fields": list(
                RESULT_EXIT_SELECTED_PATH_BINDING_FIELDS
            ),
            "exit_selected_path_binding": list(
                RESULT_EXIT_SELECTED_PATH_BINDING
            ),
            "exit_source_kinds": list(RESULT_EXIT_SOURCE_KINDS),
            "exit_normal_path_roles": list(RESULT_EXIT_NORMAL_PATH_ROLES),
            "exit_exception_path_role": RESULT_EXIT_EXCEPTION_PATH_ROLE,
            "exit_exception_predicate_function": (
                RESULT_EXIT_EXCEPTION_PREDICATE_FUNCTION
            ),
            "unsupported_render_binding_fields": list(
                RESULT_UNSUPPORTED_RENDER_BINDING_FIELDS
            ),
            "unsupported_render_bindings": [
                list(binding)
                for binding in RESULT_UNSUPPORTED_RENDER_BINDINGS
            ],
            "unsupported_render_match_expected": (
                RESULT_UNSUPPORTED_RENDER_MATCH_EXPECTED
            ),
            "render_validity_binding_fields": list(
                RESULT_RENDER_VALIDITY_BINDING_FIELDS
            ),
            "render_validity_bindings": [
                list(binding) for binding in RESULT_RENDER_VALIDITY_BINDINGS
            ],
            "render_validity_selector_binding_fields": list(
                RESULT_RENDER_VALIDITY_SELECTOR_BINDING_FIELDS
            ),
            "render_validity_selector_binding": list(
                RESULT_RENDER_VALIDITY_SELECTOR_BINDING
            ),
            "render_line_source_binding_fields": list(
                RESULT_RENDER_LINE_SOURCE_BINDING_FIELDS
            ),
            "render_line_source_bindings": [
                list(binding)
                for binding in RESULT_RENDER_LINE_SOURCE_BINDINGS
            ],
            "render_line_source_roles": list(
                RESULT_RENDER_LINE_SOURCE_ROLES
            ),
            "render_dynamic_candidate_action_result": (
                RESULT_RENDER_DYNAMIC_CANDIDATE_ACTION_RESULT
            ),
            "self_hash_field": RESULT_SELF_HASH_FIELD,
            "body_keys": list(RESULT_BODY_KEYS),
            "false_fields": list(RESULT_FALSE_FIELDS),
            "result_field_bindings": [
                list(binding) for binding in DOCUMENT_BINDING_TABLES["result"]
            ],
            "render_field_bindings": [
                list(binding) for binding in DOCUMENT_BINDING_TABLES["render"]
            ],
            "document_valid_is_documentary_only": True,
            "all_authority_execution_publication_flags_false": True,
            "runtime_contract_integrity_required_before_document_success": True,
            "false_flags": list(FALSE_FLAGS),
            "false_flag_bindings": [
                list(binding) for binding in FALSE_FLAG_BINDINGS
            ],
            "unsupported_population": "all-input-documents-and-derived-identities-null",
            "document_valid_population": "command-specific-full-document-replay",
        },
        "fallback_line": _FALLBACK_LINE,
        "policy": environment_policy_projection(),
        "nonclaims": list(NONCLAIMS),
    }


def environment_evidence_contract_projection():
    """Return the closed Phase-5B2a contract projection."""
    body = _contract_body()
    contract_id = "environment-evidence-contract-" + _domain_hash(
        _DOMAINS["contract"], body, MAX_CONTRACT_BYTES
    )
    projection = dict(body)
    projection["contract_id"] = contract_id
    if not _numeric_bounds_include(
        len(_canonical(projection, MAX_CONTRACT_BYTES)),
        0,
        MAX_CONTRACT_BYTES,
    ):
        raise _Reject("contract-size")
    return projection


EVIDENCE_CONTRACT_ID = environment_evidence_contract_projection()["contract_id"]


def _runtime_projection_intact():
    try:
        return (
            PHASE5A_REQUEST_KEYS == (
                "schema", "mode", "profile", "profile_version",
                "environment_contract_id", "activation_contract_id",
                "compatibility_profile_version",
            ) + PHASE5A_BINDING_KEYS
            and MODEL_SNAPSHOT_ROOT_PREFIX
            == (
                MODEL_CACHE_ROOT_RELATIVE + PATH_SEPARATOR
                + "snapshots" + PATH_SEPARATOR
            )
            and environment_policy_id() == ENVIRONMENT_POLICY_ID
            and environment_evidence_contract_projection()["contract_id"]
            == EVIDENCE_CONTRACT_ID
        )
    except BaseException:
        return False


def _phase5a_request(document):
    _exact_dict(document, PHASE5A_REQUEST_KEYS)
    _native(document)
    policy = _phase5a_fixed_policy()
    fixed = policy["fixed"]
    for key, expected in fixed.items():
        if type(document[key]) is not type(expected) or not (
            _exact_value_equal(document[key], expected)
        ):
            raise _Reject("phase5a-fixed")
    integer_fields = policy["integer_fields"]
    for key in PHASE5A_BINDING_KEYS:
        if key in integer_fields:
            _integer(document[key], *integer_fields[key])
        else:
            _string(document[key], _PHASE5A_PATTERNS[key])
    fixed_bindings = policy["binding_fixed"]
    for key, expected in fixed_bindings.items():
        if not _exact_value_equal(document[key], expected):
            raise _Reject("phase5a-binding")
    for left, right in policy["equality_requirements"]:
        if not _exact_value_equal(document[left], document[right]):
            raise _Reject("phase5a-equality")
    _canonical(document)
    return _domain_hash(PHASE5A_REQUEST_DOMAIN, document)


def _model_snapshot_plan(document):
    _exact_dict(document, MODEL_SNAPSHOT_PLAN_KEYS)
    _native(document)
    relations = _relation_fields("model_snapshot_plan")
    _document_string_pattern_values(
        document,
        "model_snapshot_plan",
        "model_snapshot_plan",
        "model-plan-pattern",
    )
    _require_document_secret_shapes(document)
    _relative_path(document[relations["snapshot_root"]])
    expected_snapshot_root = (
        MODEL_SNAPSHOT_ROOT_PREFIX + document[relations["model_revision"]]
    )
    _require_document_bindings(
        document,
        "model_snapshot_plan",
        {"derived": {
            "environment_policy_id": environment_policy_id(),
            "snapshot_root_relative": expected_snapshot_root,
        }},
        "model-plan-binding",
    )
    entries = document[relations["entries"]]
    if type(entries) is not list or not _numeric_bounds_include(
        len(entries), 0, PHASE5B1_MAX_TREE_ENTRIES
    ):
        raise _Reject("model-entries")
    _integer(
        document[relations["entry_count"]],
        MODEL_SNAPSHOT_MIN_ENTRIES,
        PHASE5B1_MAX_TREE_ENTRIES,
    )
    _integer(
        document[relations["total_bytes"]],
        MODEL_SNAPSHOT_MIN_TOTAL_BYTES,
        PHASE5B1_MAX_TREE_TOTAL_BYTES,
    )
    separator = _path_syntax()["separator"]
    paths = []
    for entry in entries:
        _exact_dict(entry, MODEL_SNAPSHOT_ENTRY_KEYS)
        path = _relative_path(entry[relations["entry_path"]])
        full_path = _tree_relative_path(
            document[relations["snapshot_root"]] + separator + path
        )
        kind = _string(entry[relations["entry_kind"]])
        mode = _document_string_pattern_values(
            entry,
            "model_snapshot_plan",
            "model_snapshot_entry",
            "model-entry-pattern",
        )["entry_mode"]
        size = _integer(
            entry[relations["entry_size"]], 0, PHASE5B1_MAX_TREE_FILE_BYTES
        )
        digest = _string(entry[relations["entry_digest"]])
        _validate_entry_kind(
            "model_snapshot_plan",
            kind,
            {
                "path": path,
                "full_path": full_path,
                "mode": mode,
                "size": size,
                "digest": digest,
            },
        )
        paths.append(path)
    _unique_ordered_paths(paths, "model")
    _require_parent_directories(
        entries, relations["entry_path"], relations["entry_kind"],
        "model_snapshot_plan", "model"
    )
    _require_document_aggregations(document, "model_snapshot_plan")
    _canonical(document)
    return _domain_hash(_DOMAINS["model_snapshot_plan"], document)


def _tree_manifest(document, request, request_sha256):
    _exact_dict(document, TREE_MANIFEST_KEYS)
    _native(document)
    relations = _relation_fields("tree_manifest")
    _document_string_pattern_values(
        document, "tree_manifest", "tree_manifest", "tree-pattern"
    )
    _require_document_bindings(
        document,
        "tree_manifest",
        {
            "request": request,
            "derived": {
                "request_sha256": request_sha256,
                "operation_id": "operation-" + request_sha256,
            },
        },
        "tree-binding",
    )
    entries = document[relations["entries"]]
    if type(entries) is not list or not _numeric_bounds_include(
        len(entries), 0, PHASE5B1_MAX_TREE_ENTRIES
    ):
        raise _Reject("tree-entries")
    _integer(
        document[relations["entry_count"]], 0, PHASE5B1_MAX_TREE_ENTRIES
    )
    _integer(
        document[relations["total_bytes"]], 0, PHASE5B1_MAX_TREE_TOTAL_BYTES
    )
    paths = []
    for entry in entries:
        _exact_dict(entry, TREE_ENTRY_KEYS)
        path = _tree_relative_path(entry[relations["entry_path"]])
        kind = _string(entry[relations["entry_kind"]])
        mode = _document_string_pattern_values(
            entry, "tree_manifest", "tree_entry", "tree-entry-pattern"
        )["entry_mode"]
        size = _integer(
            entry[relations["entry_size"]], 0, PHASE5B1_MAX_TREE_FILE_BYTES
        )
        digest = _string(entry[relations["entry_digest"]])
        _validate_entry_kind(
            "tree_manifest",
            kind,
            {
                "path": path,
                "full_path": path,
                "mode": mode,
                "size": size,
                "digest": digest,
            },
        )
        paths.append(path)
    _phase5b1_tree_order(
        entries, relations["entry_path"], relations["entry_kind"],
        "tree_manifest"
    )
    _require_document_aggregations(document, "tree_manifest")
    if not getattr(
        set(TREE_REQUIRED_ENTRIES), TREE_REQUIRED_ENTRY_RELATION_METHOD
    )(set(paths)):
        raise _Reject("tree-required-entry")
    return _domain_hash(
        _STORAGE_DOMAINS["tree_manifest"], document,
        PHASE5B1_MAX_DOC_BYTES,
    )


def _storage_request(document, request, request_sha256):
    _exact_dict(document, STORAGE_REQUEST_KEYS)
    _native(document)
    relations = _relation_fields("storage_request")
    embedded_request = document[relations["request"]]
    if not _exact_value_equal(
        _phase5a_request(embedded_request), request_sha256
    ):
        raise _Reject("storage-request-document")
    if not _exact_value_equal(
        _canonical(embedded_request), _canonical(request)
    ):
        raise _Reject("storage-request-document")
    _hex64(document[relations["layout_plan_digest"]])
    _document_string_pattern_values(
        document, "storage_request", "storage_request",
        "storage-request-pattern",
    )
    _require_document_bindings(
        document,
        "storage_request",
        {
            "request": request,
            "derived": {
                "request_sha256": request_sha256,
                "operation_id": "operation-" + request_sha256,
            },
        },
        "storage-request-binding",
    )
    _fingerprint(
        document[relations["preimage_fingerprint"]], empty_preimage=True
    )
    _fingerprint(document[relations["operation_fingerprint"]])
    claimed = _hex64(document[relations["self_digest"]])
    body = {
        key: document[key]
        for key in STORAGE_REQUEST_KEYS
        if not _exact_value_equal(key, relations["self_digest"])
    }
    if not _exact_value_equal(
        _domain_hash(
            _STORAGE_DOMAINS["request"], body, PHASE5B1_MAX_DOC_BYTES
        ),
        claimed,
    ):
        raise _Reject("storage-request-self-hash")
    return claimed


def _storage_prepare(document, request, request_sha256, request_record, manifest, manifest_sha):
    _exact_dict(document, STORAGE_PREPARE_KEYS)
    _native(document)
    relations = _relation_fields("storage_prepare")
    _fingerprint(
        document[relations["preimage_fingerprint"]], empty_preimage=True
    )
    _fingerprint(document[relations["operation_fingerprint"]])
    _require_document_bindings(
        document,
        "storage_prepare",
        {
            "request": request,
            "request_record": request_record,
            "manifest": manifest,
            "derived": {
                "request_sha256": request_sha256,
                "manifest_sha256": manifest_sha,
            },
        },
        "storage-prepare-binding",
    )
    claimed = _hex64(document[relations["self_digest"]])
    body = {
        key: document[key]
        for key in STORAGE_PREPARE_KEYS
        if not _exact_value_equal(key, relations["self_digest"])
    }
    if not _exact_value_equal(
        _domain_hash(
            _STORAGE_DOMAINS["prepare"], body, PHASE5B1_MAX_DOC_BYTES
        ),
        claimed,
    ):
        raise _Reject("storage-prepare-self-hash")
    return claimed


def _storage_digest(components):
    if type(components) is not dict:
        raise _Reject("storage-digest-components")
    if not _exact_value_equal(
        tuple(sorted(components)), tuple(sorted(STORAGE_DIGEST_COMPONENT_ROLES))
    ):
        raise _Reject("storage-digest-components")
    preimage = _STORAGE_DOMAINS["storage_digest"]
    for role in STORAGE_DIGEST_COMPONENT_ROLES:
        preimage += _hex64(components[role]).encode("ascii")
    return hashlib.sha256(preimage).hexdigest()


def _crosscheck_storage_fingerprints(request_record, manifest):
    relations = _relation_fields("storage_fingerprints")
    fingerprint_relations = _relation_fields("fingerprint")
    preimage = request_record[relations["preimage"]]
    operation = request_record[relations["operation"]]
    _require_document_value_relation(
        "storage-device-equality",
        {"preimage": preimage, "operation": operation},
        "storage-fingerprint-device",
    )
    _require_document_value_relation(
        "storage-inode-distinctness",
        {"preimage": preimage, "operation": operation},
        "storage-fingerprint-inode",
    )
    separator = _path_syntax()["separator"]
    if (
        type(STORAGE_TOP_LEVEL_DIRECTORY_BINDING) is not tuple
        or not _exact_value_equal(
            len(STORAGE_TOP_LEVEL_DIRECTORY_BINDING),
            len(STORAGE_TOP_LEVEL_DIRECTORY_BINDING_FIELDS),
        )
    ):
        raise _Reject("storage-nlink-policy")
    (
        kind_role, kind_value, kind_comparator_method,
        path_role, path_membership_method, separator_expected,
    ) = STORAGE_TOP_LEVEL_DIRECTORY_BINDING
    if (
        type(kind_role) is not str
        or kind_role not in relations
        or type(kind_value) is not str
        or type(kind_comparator_method) is not str
        or type(path_role) is not str
        or path_role not in relations
        or type(path_membership_method) is not str
        or type(separator_expected) is not bool
        or type(STORAGE_NLINK_COMBINE_METHOD) is not str
    ):
        raise _Reject("storage-nlink-policy")
    direct_directories = sum(
        1 for entry in manifest[relations["entries"]]
        if getattr(
            entry[relations[kind_role]], kind_comparator_method
        )(kind_value) is True
        and getattr(
            entry[relations[path_role]], path_membership_method
        )(separator) is separator_expected
    )
    expected_nlink = getattr(
        PHASE5B1_PREIMAGE_NLINK, STORAGE_NLINK_COMBINE_METHOD
    )(direct_directories)
    _require_document_value_relation(
        "storage-operation-nlink-equality",
        {
            "operation": operation,
            "derived": {"expected_nlink": expected_nlink},
        },
        "storage-operation-nlink",
    )


def _installed_manifest(document, request, request_sha256, storage_digest):
    _exact_dict(document, INSTALLED_DISTRIBUTION_MANIFEST_KEYS)
    _native(document)
    _require_document_bindings(
        document,
        "installed_manifest",
        {
            "request": request,
            "derived": {
                "evidence_contract_id": EVIDENCE_CONTRACT_ID,
                "environment_policy_id": environment_policy_id(),
                "request_sha256": request_sha256,
                "storage_digest": storage_digest,
            },
        },
        "distribution-binding",
    )
    relations = _relation_fields("installed_manifest")
    distributions = document[relations["distributions"]]
    files = document[relations["files"]]
    if type(distributions) is not list or type(files) is not list:
        raise _Reject("distribution-lists")
    if not _numeric_bounds_include(
        len(distributions), 0, MAX_LIST_ITEMS
    ) or not _numeric_bounds_include(len(files), 0, MAX_LIST_ITEMS):
        raise _Reject("distribution-bounds")
    _integer(document[relations["distribution_count"]], 0, MAX_LIST_ITEMS)
    _integer(document[relations["file_count"]], 0, MAX_LIST_ITEMS)
    _integer(document[relations["total_bytes"]], 0)
    names = []
    record_by_name = {}
    for entry in distributions:
        _exact_dict(entry, DISTRIBUTION_ENTRY_KEYS)
        name = _normalized_distribution_name(
            entry[relations["distribution_name"]]
        )
        _document_string_pattern_values(
            entry,
            "installed_manifest",
            "installed_distribution_entry",
            "distribution-pattern",
        )
        _string(entry[relations["source_kind"]])
        _require_document_value_relation(
            "distribution-source-kind-membership",
            {
                "distribution": entry,
                "derived": {
                    "allowed_source_kinds": DISTRIBUTION_SOURCE_KINDS,
                },
            },
            "distribution-source",
        )
        for role in DISTRIBUTION_DIGEST_RELATION_ROLES:
            _hex64(entry[relations[role]])
        direct_url_policy = dict(DISTRIBUTION_DIRECT_URL_BINDINGS)
        presence_role = direct_url_policy.get(
            entry[relations["source_kind"]]
        )
        if (
            not _exact_value_equal(
                len(direct_url_policy), len(DISTRIBUTION_DIRECT_URL_BINDINGS)
            )
            or type(presence_role) is not str
        ):
            raise _Reject("distribution-direct-url")
        _require_optional_value_presence(
            entry[relations["direct_url"]],
            presence_role,
            "distribution-direct-url",
        )
        names.append(name)
        record_by_name[name] = entry[relations["record_digest"]]
    _require_ordered_unique_values(
        names, "distribution-name", "distribution"
    )
    paths = []
    known = set(names)
    owners = set()
    for entry in files:
        _exact_dict(entry, INSTALLED_FILE_ENTRY_KEYS)
        path = _tree_relative_path(entry[relations["file_path"]])
        owner = _normalized_distribution_name(entry[relations["file_owner"]])
        _require_document_value_relation(
            "installed-owner-membership",
            {
                "file": entry,
                "derived": {"distribution_names": known},
            },
            "file-owner",
        )
        mode = _document_string_pattern_values(
            entry,
            "installed_manifest",
            "installed_file_entry",
            "installed-file-pattern",
        )["file_mode"]
        _require_document_value_relation(
            "installed-mode-membership",
            {
                "file": entry,
                "derived": {"allowed_modes": INSTALLED_FILE_MODES},
            },
            "installed-file-mode",
        )
        if (
            getattr(
                mode, EXECUTABLE_MODE_CLASSIFICATION_METHOD
            )(TREE_EXECUTABLE_FILES[NATIVE_BASE_INTERPRETER_PATH]) is True
            and getattr(
                TREE_EXECUTABLE_FILES, EXECUTABLE_PATH_MEMBERSHIP_METHOD
            )(path) is not True
        ):
            raise _Reject("installed-executable")
        _integer(
            entry[relations["file_size"]], 0, PHASE5B1_MAX_TREE_FILE_BYTES
        )
        _hex64(entry[relations["file_digest"]])
        _hex64(entry[relations["record_digest"]])
        _require_document_value_relation(
            "installed-record-owner-equality",
            {
                "file": entry,
                "distribution": {
                    "record_sha256": record_by_name[owner],
                },
            },
            "file-record-binding",
        )
        owners.add(owner)
        paths.append(path)
    _unique_ordered_paths(paths, "installed-file")
    _require_document_value_relation(
        "installed-owner-completeness",
        {"derived": {
            "file_owners": owners,
            "distribution_names": known,
        }},
        "distribution-without-file",
    )
    _require_document_aggregations(document, "installed_manifest")
    return _domain_hash(_DOMAINS["installed_distribution_manifest"], document)


def _native_manifest(document, request, request_sha256, storage_digest):
    _exact_dict(document, NATIVE_FILE_MANIFEST_KEYS)
    _native(document)
    _require_document_bindings(
        document,
        "native_manifest",
        {
            "request": request,
            "derived": {
                "evidence_contract_id": EVIDENCE_CONTRACT_ID,
                "environment_policy_id": environment_policy_id(),
                "request_sha256": request_sha256,
                "storage_digest": storage_digest,
            },
        },
        "native-binding",
    )
    relations = _relation_fields("native_manifest")
    files = document[relations["files"]]
    if type(files) is not list or not _numeric_bounds_include(
        len(files), 0, MAX_LIST_ITEMS
    ):
        raise _Reject("native-files")
    _integer(document[relations["file_count"]], 0, MAX_LIST_ITEMS)
    paths = []
    base_interpreter_paths = []
    for entry in files:
        _exact_dict(entry, NATIVE_ENTRY_KEYS)
        path = _tree_relative_path(entry[relations["entry_path"]])
        pattern_values = _document_string_pattern_values(
            entry,
            "native_manifest",
            "native_entry",
            "native-entry-pattern",
        )
        mode = pattern_values["entry_mode"]
        _require_document_value_relation(
            "native-mode-membership",
            {
                "native": entry,
                "derived": {"allowed_modes": NATIVE_FILE_MODES},
            },
            "native-mode",
        )
        if (
            getattr(
                mode, EXECUTABLE_MODE_CLASSIFICATION_METHOD
            )(TREE_EXECUTABLE_FILES[NATIVE_BASE_INTERPRETER_PATH]) is True
            and getattr(
                TREE_EXECUTABLE_FILES, EXECUTABLE_PATH_MEMBERSHIP_METHOD
            )(path) is not True
        ):
            raise _Reject("native-mode")
        _integer(
            entry[relations["entry_size"]], 0, PHASE5B1_MAX_TREE_FILE_BYTES
        )
        _hex64(entry[relations["entry_digest"]])
        sublists = {field: entry[field] for field in NATIVE_SUBLIST_FIELDS}
        architectures = entry[relations["entry_architectures"]]
        if any(
            type(value) is not list
            or not _numeric_bounds_include(
                len(value), 0, NATIVE_SUBLIST_MAX_ITEMS
            )
            for value in sublists.values()
        ):
            raise _Reject("native-list")
        seen_pattern_fields = set()
        for field, pattern in NATIVE_SUBLIST_STRING_PATTERN_BINDINGS:
            if (
                type(field) is not str
                or type(pattern) is not str
                or field in seen_pattern_fields
                or field not in sublists
            ):
                raise _Reject("native-sublist")
            for value in sublists[field]:
                _string(value, pattern)
            seen_pattern_fields.add(field)
        if not _exact_value_equal(
            len(seen_pattern_fields),
            len(NATIVE_SUBLIST_STRING_PATTERN_BINDINGS),
        ):
            raise _Reject("native-sublist")
        for field in NATIVE_SORTED_UNIQUE_FIELDS:
            values = sublists[field]
            _require_ordered_unique_values(
                values, "native-sublist", "native"
            )
        _require_document_value_relation(
            "native-architecture-membership",
            {
                "native": entry,
                "manifest_relation": {
                    "target_machine": document[relations["target_machine"]],
                },
            },
            "native-architecture",
        )
        _hex64(entry[relations["entry_load_commands_digest"]])
        for field in NATIVE_TEXT_SUBLIST_FIELDS:
            values = sublists[field]
            for value in values:
                if not _numeric_bounds_include(
                    len(_string(value)),
                    NATIVE_TEXT_MIN_CHARS,
                    MAX_STRING_CHARS,
                ):
                    raise _Reject("native-text")
        paths.append(path)
        if _document_value_relation_matches(
            "native-base-owner-classification",
            {
                "native": entry,
                "derived": {"base_owner": NATIVE_BASE_INTERPRETER_OWNER},
            },
            "native-base-interpreter-policy",
        ):
            base_interpreter_paths.append(path)
    _unique_ordered_paths(paths, "native-file")
    _require_document_aggregations(document, "native_manifest")
    _require_document_value_relation(
        "native-base-interpreter-cardinality",
        {"derived": {
            "observed_paths": base_interpreter_paths,
            "expected_paths": [NATIVE_BASE_INTERPRETER_PATH],
        }},
        "native-base-interpreter",
    )
    return _domain_hash(_DOMAINS["native_file_manifest"], document)


def _model_manifest(document, request, request_sha256, storage_digest):
    _exact_dict(document, MODEL_MANIFEST_KEYS)
    _native(document)
    _require_document_bindings(
        document,
        "model_manifest",
        {
            "request": request,
            "derived": {
                "evidence_contract_id": EVIDENCE_CONTRACT_ID,
                "environment_policy_id": environment_policy_id(),
                "request_sha256": request_sha256,
                "storage_digest": storage_digest,
            },
        },
        "model-binding",
    )
    relations = _relation_fields("model_manifest")
    core_config = _canonical_json_string(document[relations["core_json"]])
    core_config_sha = hashlib.sha256(
        document[relations["core_json"]].encode("ascii")
    ).hexdigest()
    _core_config(core_config, request)
    runtime_config = _canonical_json_string(
        document[relations["runtime_json"]]
    )
    runtime_config_sha = hashlib.sha256(
        document[relations["runtime_json"]].encode("ascii")
    ).hexdigest()
    _require_document_bindings(
        document,
        "model_embedded_digests",
        {"derived": {
            "core_config_sha256": core_config_sha,
            "runtime_config_sha256": runtime_config_sha,
        }},
        "model-embedded-digest",
    )
    _embedding_runtime_config(runtime_config, request, core_config)
    plan_sha = _model_snapshot_plan(document[relations["snapshot_plan"]])
    _require_document_bindings(
        document[relations["snapshot_plan"]],
        "model_plan_request",
        {"request": request},
        "model-plan-binding",
    )
    _require_document_bindings(
        document,
        "model_manifest_plan_digests",
        {"derived": {"model_plan_sha256": plan_sha}},
        "model-plan-digest",
    )
    _require_document_bindings(
        request,
        "request_model_plan_digest",
        {"derived": {"model_plan_sha256": plan_sha}},
        "model-request-snapshot",
    )
    return _domain_hash(_DOMAINS["model_manifest"], document)


def _crosscheck_static_documents(documents_by_role):
    relations = _relation_fields("cross_manifest")
    expected_roles = tuple(
        relations[role]
        for role in (
            "tree_document_role", "installed_document_role",
            "native_document_role", "model_document_role",
        )
    )
    _exact_dict(documents_by_role, expected_roles)
    tree = documents_by_role[relations["tree_document_role"]]
    installed = documents_by_role[relations["installed_document_role"]]
    native = documents_by_role[relations["native_document_role"]]
    model = documents_by_role[relations["model_document_role"]]
    separator = _path_syntax()["separator"]
    tree_by_path = {
        entry[relations["path"]]: entry
        for entry in tree[relations["tree_entries"]]
    }
    installed_by_path = {
        entry[relations["path"]]: entry
        for entry in installed[relations["installed_files"]]
    }
    for entry in installed[relations["installed_files"]]:
        observed = tree_by_path.get(entry[relations["path"]])
        if observed is None:
            raise _Reject("installed-tree-missing")
        _require_document_value_relation(
            "tree-file-kind-equality",
            {
                "observed": observed,
                "derived": {"file_kind": TREE_ENTRY_KINDS[1]},
            },
            "installed-tree-missing",
        )
        for key in CROSS_MANIFEST_TREE_FILE_FIELDS:
            _require_document_value_relation(
                "cross-file-field-equality",
                {
                    "observed": {"value": observed[key]},
                    "expected": {"value": entry[key]},
                },
                "installed-tree-mismatch",
            )
    distribution_names = {
        entry[relations["distribution_name"]]
        for entry in installed[relations["installed_distributions"]]
    }
    for entry in native[relations["native_files"]]:
        is_base_interpreter = _document_value_relation_matches(
            "native-base-owner-classification",
            {
                "native": entry,
                "derived": {"base_owner": NATIVE_BASE_INTERPRETER_OWNER},
            },
            "native-owner-policy",
        )
        if not is_base_interpreter:
            _require_document_value_relation(
                "native-distribution-owner-membership",
                {
                    "native": entry,
                    "derived": {"distribution_names": distribution_names},
                },
                "native-owner",
            )
            installed_entry = installed_by_path.get(entry[relations["path"]])
            if installed_entry is None:
                raise _Reject("native-installed-owner")
            _require_document_value_relation(
                "native-installed-owner-equality",
                {"installed": installed_entry, "native": entry},
                "native-installed-owner",
            )
        observed = tree_by_path.get(entry[relations["path"]])
        if observed is None:
            raise _Reject("native-tree-missing")
        _require_document_value_relation(
            "tree-file-kind-equality",
            {
                "observed": observed,
                "derived": {"file_kind": TREE_ENTRY_KINDS[1]},
            },
            "native-tree-missing",
        )
        for key in CROSS_MANIFEST_TREE_FILE_FIELDS:
            _require_document_value_relation(
                "cross-file-field-equality",
                {
                    "observed": {"value": observed[key]},
                    "expected": {"value": entry[key]},
                },
                "native-tree-mismatch",
            )
    model_plan = model[relations["model_plan"]]
    prefix = model_plan[relations["snapshot_root"]] + separator
    snapshot_container = MODEL_SNAPSHOT_ROOT_PREFIX[:-len(separator)]
    expected_model_tree_paths = {
        model[relations["cache_root"]],
        snapshot_container,
        model_plan[relations["snapshot_root"]],
    }
    for entry in model_plan[relations["model_entries"]]:
        full_path = prefix + entry[relations["path"]]
        expected_model_tree_paths.add(full_path)
        observed = tree_by_path.get(full_path)
        if observed is None:
            raise _Reject("model-tree-missing")
        for key in CROSS_MANIFEST_MODEL_FILE_FIELDS:
            _require_document_value_relation(
                "cross-file-field-equality",
                {
                    "observed": {"value": observed[key]},
                    "expected": {"value": entry[key]},
                },
                "model-tree-mismatch",
            )
    actual_model_tree_paths = {
        path for path in tree_by_path
        if _exact_value_equal(path, model[relations["cache_root"]])
        or getattr(path, PATH_PREFIX_MATCH_METHOD)(
            model[relations["cache_root"]] + separator
        )
    }
    _require_document_value_relation(
        "model-cache-path-completeness",
        {"derived": {
            "actual_paths": actual_model_tree_paths,
            "expected_paths": expected_model_tree_paths,
        }},
        "model-cache-not-complete",
    )


def _evidence_set(request, document):
    request_sha = _phase5a_request(request)
    _exact_dict(document, EVIDENCE_SET_KEYS)
    _native(document)
    relations = _relation_fields("evidence_set")
    _require_document_bindings(
        document,
        "evidence_set",
        {"derived": {
            "evidence_contract_id": EVIDENCE_CONTRACT_ID,
            "environment_policy_id": environment_policy_id(),
            "request_sha256": request_sha,
        }},
        "evidence-binding",
    )
    if not _exact_value_equal(
        _phase5a_request(document[relations["environment_request"]]),
        request_sha,
    ):
        raise _Reject("evidence-request")
    if not _exact_value_equal(
        _canonical(document[relations["environment_request"]]),
        _canonical(request),
    ):
        raise _Reject("evidence-request")
    request_record = document[relations["request_record"]]
    request_record_sha = _storage_request(request_record, request, request_sha)
    manifest = document[relations["manifest"]]
    manifest_sha = _tree_manifest(manifest, request, request_sha)
    _crosscheck_storage_fingerprints(request_record, manifest)
    prepare = document[relations["prepare"]]
    prepare_sha = _storage_prepare(prepare, request, request_sha, request_record, manifest, manifest_sha)
    storage_digest = _storage_digest(_resolved_document_bindings(
        "storage_digest_components",
        {"derived": {
            "request_sha256": request_sha,
            "manifest_sha256": manifest_sha,
            "prepare_sha256": prepare_sha,
        }},
        "storage-digest-binding",
    ))
    _require_document_bindings(
        document,
        "evidence_storage_digests",
        {"derived": {
            "request_record_sha256": request_record_sha,
            "manifest_sha256": manifest_sha,
            "prepare_sha256": prepare_sha,
            "storage_digest": storage_digest,
        }},
        "evidence-storage-binding",
    )
    docs = _exact_dict(document[relations["documents"]], EVIDENCE_SLOTS)
    digests = _exact_dict(document[relations["digests"]], EVIDENCE_SLOTS)
    for slot in DYNAMIC_PENDING_SLOTS:
        _require_optional_value_presence(
            docs[slot], "absent", "dynamic-not-pending"
        )
        _require_optional_value_presence(
            digests[slot], "absent", "dynamic-not-pending"
        )
    available_context = locals()
    context = {}
    for role, local_name in STATIC_VALIDATOR_CONTEXT_BINDINGS:
        if (
            type(role) is not str
            or type(local_name) is not str
            or role in context
            or local_name not in available_context
        ):
            raise _Reject("static-validator-context")
        context[role] = available_context[local_name]
    if (
        not _exact_value_equal(
            len(context), len(STATIC_VALIDATOR_CONTEXT_BINDINGS)
        )
        or not _exact_value_equal(tuple(context), STATIC_VALIDATOR_CONTEXT_ROLES)
    ):
        raise _Reject("static-validator-context")
    module_globals = globals()
    slot_by_role = {}
    documents_by_role = {}
    computed = {}
    function_names = set()
    for binding in STATIC_SLOT_VALIDATOR_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(STATIC_SLOT_VALIDATOR_BINDING_FIELDS)
            )
        ):
            raise _Reject("static-validator-policy")
        slot, role, function_name, argument_roles = binding
        if (
            type(slot) is not str
            or type(role) is not str
            or type(function_name) is not str
            or type(argument_roles) is not tuple
            or slot in computed
            or role in documents_by_role
            or function_name in function_names
            or function_name not in RUNTIME_INTEGRITY_FUNCTION_NAMES
        ):
            raise _Reject("static-validator-policy")
        validator = module_globals.get(function_name)
        if validator is None:
            raise _Reject("static-validator-policy")
        arguments = []
        for argument_role in argument_roles:
            if (
                type(argument_role) is not str
                or argument_role not in context
            ):
                raise _Reject("static-validator-policy")
            arguments.append(context[argument_role])
        role_document = docs[slot]
        computed[slot] = validator(role_document, *arguments)
        documents_by_role[role] = role_document
        slot_by_role[role] = slot
        function_names.add(function_name)
    if (
        not _exact_value_equal(tuple(computed), STATIC_SLOTS)
        or not _exact_value_equal(
            tuple((slot, role) for role, slot in slot_by_role.items()),
            STATIC_SLOT_VALIDATOR_ROLES,
        )
        or not _exact_value_equal(
            tuple(sorted(context)),
            tuple(sorted(STATIC_VALIDATOR_CONTEXT_ROLES)),
        )
    ):
        raise _Reject("static-validator-policy")
    environment_slot = slot_by_role[STATIC_PRIMARY_STORAGE_ROLE]
    if not _exact_value_equal(computed[environment_slot], manifest_sha):
        raise _Reject("tree-slot")
    if not _exact_value_equal(
        _canonical(documents_by_role[STATIC_PRIMARY_STORAGE_ROLE]),
        _canonical(manifest),
    ):
        raise _Reject("tree-slot")
    _crosscheck_static_documents(documents_by_role)
    for slot in STATIC_SLOTS:
        if not _exact_value_equal(digests[slot], computed[slot]):
            raise _Reject("slot-digest")
    _canonical(document)
    return request_sha, _domain_hash(_DOMAINS["evidence_set"], document)


def _flags():
    flags = dict(FALSE_FLAG_BINDINGS)
    if (
        not _exact_value_equal(len(flags), len(FALSE_FLAG_BINDINGS))
        or not _exact_value_equal(tuple(flags), FALSE_FLAGS)
    ):
        raise _Reject("false-flags-policy")
    for key, value in FALSE_FLAG_BINDINGS:
        if type(key) is not str or type(value) is not bool or value is not False:
            raise _Reject("false-flags-policy")
    return flags


def _result_reason(command, status):
    reasons = {}
    for bound_command, bound_status, reason in RESULT_REASON_BINDINGS:
        key = (bound_command, bound_status)
        if (
            type(bound_command) is not str
            or type(bound_status) is not str
            or type(reason) is not str
            or key in reasons
        ):
            raise _Reject("result-reason-policy")
        reasons[key] = reason
    if not _exact_value_equal(len(reasons), len(RESULT_REASON_BINDINGS)):
        raise _Reject("result-reason-policy")
    reason = reasons.get((command, status))
    if reason is None:
        raise _Reject("result-reason-policy")
    return reason


def _result_document_valid(status):
    arguments = locals()
    source_role, method_name, expected = RESULT_DOCUMENT_VALID_BINDING
    if (
        type(source_role) is not str
        or type(method_name) is not str
        or source_role not in arguments
    ):
        raise _Reject("result-valid-policy")
    return getattr(arguments[source_role], method_name)(expected)


def _result_derived(arguments):
    if type(arguments) is not dict:
        raise _Reject("result-derived-policy")
    module_globals = globals()
    resolved = {}
    for binding in RESULT_DERIVED_BINDINGS:
        if (
            type(binding) is not tuple
            or not _exact_value_equal(
                len(binding), len(RESULT_DERIVED_BINDING_FIELDS)
            )
        ):
            raise _Reject("result-derived-policy")
        target, source_kind, source_name, argument_roles = binding
        if (
            type(target) is not str
            or type(source_kind) is not str
            or not getattr(
                RESULT_DERIVED_SOURCE_KINDS, POLICY_MEMBERSHIP_METHOD
            )(source_kind)
            or type(source_name) is not str
            or type(argument_roles) is not tuple
            or target in resolved
            or source_name not in module_globals
        ):
            raise _Reject("result-derived-policy")
        values = []
        for role in argument_roles:
            if type(role) is not str or role not in arguments:
                raise _Reject("result-derived-policy")
            values.append(arguments[role])
        source = module_globals[source_name]
        if _exact_value_equal(source_kind, RESULT_DERIVED_SOURCE_KINDS[0]):
            value = source(*values)
        elif _exact_value_equal(
            source_kind, RESULT_DERIVED_SOURCE_KINDS[1]
        ):
            if values:
                raise _Reject("result-derived-policy")
            value = source
        else:
            if values:
                raise _Reject("result-derived-policy")
            value = list(source)
        resolved[target] = value
    if not _exact_value_equal(len(resolved), len(RESULT_DERIVED_BINDINGS)):
        raise _Reject("result-derived-policy")
    return resolved


def _result(
    command, status, *, plan=None, request=None, evidence=None,
    plan_sha=None, request_sha=None, evidence_sha=None,
):
    arguments = locals()
    derived = _result_derived(arguments)
    body = _resolved_document_bindings(
        "result", {"argument": arguments, "derived": derived},
        "result-policy",
    )
    if not _exact_value_equal(tuple(body), RESULT_BODY_KEYS):
        raise _Reject("result-policy")
    result = dict(body)
    result[RESULT_SELF_HASH_FIELD] = _domain_hash(
        _DOMAINS["result"], body, MAX_RESULT_BYTES
    )
    return result


def _unsupported(command):
    return _result(command, STATUS_UNSUPPORTED)


def _make_runtime_guard():
    module_globals = globals()
    projection_guard = _runtime_projection_intact
    policy_builder = environment_policy_id
    contract_builder = environment_evidence_contract_projection
    expected_policy_id = ENVIRONMENT_POLICY_ID
    expected_contract_id = EVIDENCE_CONTRACT_ID
    native_any = any
    base_exception_type = BaseException
    anchors = tuple(
        (name, module_globals[name]) for name in RUNTIME_INTEGRITY_GLOBAL_NAMES
    )
    builtin_names = RUNTIME_INTEGRITY_BUILTIN_NAMES

    def intact():
        try:
            if native_any(name in module_globals for name in builtin_names):
                return False
            for name, expected in anchors:
                if module_globals.get(name) is not expected:
                    return False
            if policy_builder() != expected_policy_id:
                return False
            if contract_builder()["contract_id"] != expected_contract_id:
                return False
            if not projection_guard():
                return False
            return True
        except base_exception_type:
            return False

    return intact, anchors


_runtime_contract_intact, _RUNTIME_FUNCTION_ANCHORS = _make_runtime_guard()


def _make_public_apis():
    integrity_guard = _runtime_contract_intact
    plan_validator = _model_snapshot_plan
    evidence_validator = _evidence_set
    result_builder = _result
    unsupported_builder = _unsupported
    command_model_plan = COMMAND_MODEL_PLAN
    command_evidence_set = COMMAND_EVIDENCE_SET
    status_document_valid = STATUS_DOCUMENT_VALID
    status_unsupported = STATUS_UNSUPPORTED
    result_exit_codes = dict(RESULT_EXIT_CODE_BINDINGS)
    result_commands = RESULT_COMMANDS
    result_statuses = RESULT_STATUSES
    result_false_fields = RESULT_FALSE_FIELDS
    false_flag_bindings = FALSE_FLAG_BINDINGS
    result_self_hash_field = RESULT_SELF_HASH_FIELD
    result_body_keys = RESULT_BODY_KEYS
    fallback_line = _FALLBACK_LINE
    max_render_bytes = MAX_RENDER_BYTES
    max_result_bytes = MAX_RESULT_BYTES
    canonicalizer = _canonical
    value_equal = _exact_value_equal
    value_comparator_method = DOCUMENT_BINDING_COMPARATOR_METHOD
    result_exit_predicate_comparator_method = (
        RESULT_EXIT_PREDICATE_COMPARATOR_METHOD
    )
    result_exit_selection_sequence_method = (
        RESULT_EXIT_SELECTION_SEQUENCE_METHOD
    )
    result_exit_selection_collection_method = (
        RESULT_EXIT_SELECTION_COLLECTION_METHOD
    )
    result_exit_traversal_method = RESULT_EXIT_TRAVERSAL_METHOD
    unsupported_render_match_expected = (
        RESULT_UNSUPPORTED_RENDER_MATCH_EXPECTED
    )
    render_dynamic_candidate_action_result = (
        RESULT_RENDER_DYNAMIC_CANDIDATE_ACTION_RESULT
    )
    (
        render_validity_value_role,
        render_validity_selector_method,
        render_validity_expected_result,
        render_validity_comparator_method,
    ) = RESULT_RENDER_VALIDITY_SELECTOR_BINDING
    (
        result_exit_selected_path_method,
        result_exit_selected_path_index,
    ) = RESULT_EXIT_SELECTED_PATH_BINDING
    policy_membership_method = POLICY_MEMBERSHIP_METHOD
    document_binding_resolver = _resolved_document_bindings
    json_loader = json.loads
    template_match_role, template_match_method = (
        UNSUPPORTED_TEMPLATE_MATCH_BINDING
    )
    template_match_expected_role = UNSUPPORTED_TEMPLATE_MATCH_ROLE
    native_type = type
    base_exception_type = BaseException
    native_len = len
    native_enumerate = enumerate
    native_tuple = tuple
    native_list = list
    dict_type = dict
    str_type = str
    int_type = int
    bool_type = bool
    none_type = type(None)
    native_getattr = getattr
    native_locals = locals

    if (
        native_type(result_exit_selected_path_method) is not str_type
        or native_type(result_exit_selected_path_index) is not int_type
        or native_type(unsupported_render_match_expected) is not bool_type
        or native_type(render_dynamic_candidate_action_result) is not bool_type
        or native_type(render_validity_value_role) is not str_type
        or native_type(render_validity_selector_method) is not str_type
        or native_type(render_validity_expected_result) is not bool_type
        or native_type(render_validity_comparator_method) is not str_type
        or not value_equal(
            native_len(RESULT_EXIT_SELECTED_PATH_BINDING),
            native_len(RESULT_EXIT_SELECTED_PATH_BINDING_FIELDS),
        )
        or not value_equal(
            native_len(RESULT_RENDER_VALIDITY_SELECTOR_BINDING),
            native_len(RESULT_RENDER_VALIDITY_SELECTOR_BINDING_FIELDS),
        )
    ):
        raise _Reject("result-exit-policy")

    result_exit_paths = {}
    for binding in RESULT_EXIT_PATH_BINDINGS:
        if (
            native_type(binding) is not native_tuple
            or not value_equal(
                native_len(binding), native_len(RESULT_EXIT_PATH_BINDING_FIELDS)
            )
        ):
            raise _Reject("result-exit-policy")
        (
            path_role, predicate_function, predicate_expected,
            source_kind, source_role,
        ) = binding
        if (
            native_type(path_role) is not str_type
            or native_type(predicate_function) is not str_type
            or native_type(source_kind) is not str_type
            or native_type(source_role) is not str_type
            or path_role in result_exit_paths
            or not native_getattr(
                RESULT_EXIT_SOURCE_KINDS, policy_membership_method
            )(source_kind)
        ):
            raise _Reject("result-exit-policy")
        if value_equal(
            predicate_function, RESULT_EXIT_EXCEPTION_PREDICATE_FUNCTION
        ):
            if native_type(predicate_expected) is not none_type:
                raise _Reject("result-exit-policy")
        elif native_type(predicate_expected) is not bool_type:
            raise _Reject("result-exit-policy")
        if native_getattr(
            source_kind, value_comparator_method
        )(RESULT_EXIT_SOURCE_KINDS[0]) is True:
            if source_role not in RESULT_KEYS:
                raise _Reject("result-exit-policy")
        elif source_role not in result_exit_codes:
            raise _Reject("result-exit-policy")
        result_exit_paths[path_role] = (
            predicate_function, predicate_expected, source_kind, source_role
        )
    if not value_equal(
        native_len(result_exit_paths), native_len(RESULT_EXIT_PATH_BINDINGS)
    ) or not value_equal(
        native_tuple(result_exit_paths),
        RESULT_EXIT_NORMAL_PATH_ROLES + (RESULT_EXIT_EXCEPTION_PATH_ROLE,),
    ):
        raise _Reject("result-exit-policy")

    result_exit_predicate_actions = {}
    result_exit_predicate_action_keys = []
    for binding in RESULT_EXIT_PREDICATE_ACTION_BINDINGS:
        if (
            native_type(binding) is not native_tuple
            or not value_equal(
                native_len(binding),
                native_len(RESULT_EXIT_PREDICATE_ACTION_BINDING_FIELDS),
            )
        ):
            raise _Reject("result-exit-policy")
        comparison_result, selection_count = binding
        if (
            native_type(comparison_result) is not bool_type
            or native_type(selection_count) is not int_type
            or comparison_result in result_exit_predicate_actions
        ):
            raise _Reject("result-exit-policy")
        result_exit_predicate_actions[comparison_result] = selection_count
        result_exit_predicate_action_keys.append(comparison_result)
    if (
        not value_equal(
            native_len(result_exit_predicate_actions),
            native_len(RESULT_EXIT_PREDICATE_ACTION_BINDINGS),
        )
        or not value_equal(
            native_tuple(result_exit_predicate_actions),
            native_tuple(result_exit_predicate_action_keys),
        )
    ):
        raise _Reject("result-exit-policy")

    result_render_validity_action_names = {}
    for binding in RESULT_RENDER_VALIDITY_BINDINGS:
        if (
            native_type(binding) is not native_tuple
            or not value_equal(
                native_len(binding),
                native_len(RESULT_RENDER_VALIDITY_BINDING_FIELDS),
            )
        ):
            raise _Reject("render-policy")
        valid, renderer_function = binding
        if (
            native_type(valid) is not bool_type
            or native_type(renderer_function) is not str_type
            or valid in result_render_validity_action_names
        ):
            raise _Reject("render-policy")
        result_render_validity_action_names[valid] = renderer_function
    if not value_equal(
        native_len(result_render_validity_action_names),
        native_len(RESULT_RENDER_VALIDITY_BINDINGS),
    ):
        raise _Reject("render-policy")

    result_render_line_sources = {}
    for binding in RESULT_RENDER_LINE_SOURCE_BINDINGS:
        if (
            native_type(binding) is not native_tuple
            or not value_equal(
                native_len(binding),
                native_len(RESULT_RENDER_LINE_SOURCE_BINDING_FIELDS),
            )
        ):
            raise _Reject("render-policy")
        within_bounds, line_source = binding
        if (
            native_type(within_bounds) is not bool_type
            or native_type(line_source) is not str_type
            or within_bounds in result_render_line_sources
            or not native_getattr(
                RESULT_RENDER_LINE_SOURCE_ROLES, policy_membership_method
            )(line_source)
        ):
            raise _Reject("render-policy")
        result_render_line_sources[within_bounds] = line_source
    if not value_equal(
        native_len(result_render_line_sources),
        native_len(RESULT_RENDER_LINE_SOURCE_BINDINGS),
    ):
        raise _Reject("render-policy")

    render_precomputed_table = DOCUMENT_BINDING_TABLES.get(
        "render_precomputed_value"
    )
    if (
        native_type(render_precomputed_table) is not native_tuple
        or not value_equal(native_len(render_precomputed_table), 1)
        or native_type(render_precomputed_table[0]) is not native_tuple
        or not value_equal(native_len(render_precomputed_table[0]), 2)
    ):
        raise _Reject("render-policy")
    precomputed_target, precomputed_descriptor = render_precomputed_table[0]
    if (
        native_type(precomputed_target) is not str_type
        or native_type(precomputed_descriptor) is not str_type
    ):
        raise _Reject("render-policy")
    descriptor_partition = native_getattr(
        precomputed_descriptor, "partition"
    )
    (
        precomputed_source_role,
        precomputed_separator,
        precomputed_source_key,
    ) = descriptor_partition(":")
    if (
        not value_equal(precomputed_target, "line")
        or not value_equal(precomputed_separator, ":")
        or not value_equal(precomputed_source_role, "argument")
        or not precomputed_source_key
    ):
        raise _Reject("render-policy")

    def exit_code_for(path_role, result):
        selected = result_exit_paths.get(path_role)
        if selected is None:
            raise _Reject("result-exit-policy")
        (
            _predicate_function, _predicate_expected,
            source_kind, source_role,
        ) = selected
        if native_getattr(
            source_kind, value_comparator_method
        )(RESULT_EXIT_SOURCE_KINDS[0]) is True:
            if native_type(result) is not dict_type or source_role not in result:
                raise _Reject("result-exit-policy")
            status = result[source_role]
        else:
            status = source_role
        if native_type(status) is not str_type or status not in result_exit_codes:
            raise _Reject("result-exit-policy")
        return result_exit_codes[status]

    expected_false_flags = dict(false_flag_bindings)
    if (
        not value_equal(len(expected_false_flags), len(false_flag_bindings))
        or not value_equal(tuple(expected_false_flags), FALSE_FLAGS)
    ):
        raise _Reject("false-flags-policy")

    def producer_result_safe(result):
        if native_type(result) is not dict_type:
            return False
        flags = result.get("flags")
        if not value_equal(flags, expected_false_flags):
            return False
        for key in result_false_fields:
            if result.get(key) is not False:
                return False
        return True

    unsupported_templates = {}
    unsupported_template_bytes = {}
    for command in result_commands:
        template = unsupported_builder(command)
        if not producer_result_safe(template):
            raise _Reject("false-flags-policy")
        unsupported_templates[command] = template
        unsupported_template_bytes[command] = canonicalizer(
            template, max_result_bytes
        )
    if (
        not value_equal(native_tuple(unsupported_templates), result_commands)
        or not value_equal(
            native_tuple(unsupported_template_bytes), result_commands
        )
    ):
        raise _Reject("unsupported-template")
    unsupported_plan_template = unsupported_templates[command_model_plan]
    unsupported_evidence_template = unsupported_templates[
        command_evidence_set
    ]

    def clone_template(encoded):
        value = json_loader(encoded.decode("ascii"))
        if native_type(value) is not dict_type:
            raise _Reject("unsupported-template")
        return value

    def matches_native_tree(value, template):
        value_type = native_type(value)
        if value_type is not native_type(template):
            return False
        if value_type in (str_type, int_type, bool_type, none_type):
            return native_getattr(value, template_match_method)(template) is True
        if value_type is native_list:
            if not native_getattr(
                native_len(value), template_match_method
            )(native_len(template)):
                return False
            for index, expected in native_enumerate(template):
                if not matches_native_tree(value[index], expected):
                    return False
            return True
        if value_type is dict_type:
            if not native_getattr(
                native_len(value), template_match_method
            )(native_len(template)):
                return False
            for key in value:
                if native_type(key) is not str_type:
                    return False
            for key, expected in template.items():
                if key not in value or not matches_native_tree(
                    value[key], expected
                ):
                    return False
            return True
        return False

    def matches_template(value, template):
        if (
            native_type(template_match_method) is not str_type
            or native_getattr(
                template_match_role, template_match_method
            )(template_match_expected_role) is not True
        ):
            return False
        return matches_native_tree(value, template)

    def unsupported_plan():
        return clone_template(
            unsupported_template_bytes[command_model_plan]
        )

    def unsupported_evidence():
        return clone_template(
            unsupported_template_bytes[command_evidence_set]
        )

    def rendered_mapping(result):
        return document_binding_resolver(
            "render", {"result": result}, "render-policy"
        )

    unsupported_render_lines = {
        command: canonicalizer(
            rendered_mapping(unsupported_templates[command]),
            max_render_bytes,
        ).decode("ascii")
        for command in result_commands
    }
    unsupported_render_decisions = []
    seen_render_templates = set()
    for binding in RESULT_UNSUPPORTED_RENDER_BINDINGS:
        if (
            native_type(binding) is not native_tuple
            or not value_equal(
                native_len(binding),
                native_len(RESULT_UNSUPPORTED_RENDER_BINDING_FIELDS),
            )
        ):
            raise _Reject("unsupported-render-policy")
        template_command, line_command = binding
        if (
            native_type(template_command) is not str_type
            or native_type(line_command) is not str_type
            or template_command in seen_render_templates
            or template_command not in unsupported_templates
            or line_command not in unsupported_render_lines
        ):
            raise _Reject("unsupported-render-policy")
        seen_render_templates.add(template_command)
        unsupported_render_decisions.append((
            unsupported_templates[template_command],
            unsupported_render_lines[line_command],
        ))
    if (
        not value_equal(
            native_len(unsupported_render_decisions),
            native_len(RESULT_UNSUPPORTED_RENDER_BINDINGS),
        )
        or not value_equal(
            native_len(seen_render_templates), native_len(result_commands)
        )
    ):
        raise _Reject("unsupported-render-policy")

    def validate_plan(document):
        """Validate one path-independent pre-request snapshot-plan document."""
        try:
            if not integrity_guard():
                return unsupported_plan()
            digest = plan_validator(document)
            result = result_builder(
                command_model_plan,
                status_document_valid,
                plan=document,
                plan_sha=digest,
            )
            return result if producer_result_safe(result) else unsupported_plan()
        except base_exception_type:
            return unsupported_plan()

    def validate_evidence(environment_request, evidence_set):
        """Validate documentary cross-bindings; never verify evidence."""
        try:
            if not integrity_guard():
                return unsupported_evidence()
            request_sha, evidence_sha = evidence_validator(
                environment_request, evidence_set
            )
            result = result_builder(
                command_evidence_set,
                status_document_valid,
                request=environment_request,
                evidence=evidence_set,
                request_sha=request_sha,
                evidence_sha=evidence_sha,
            )
            return result if producer_result_safe(result) else unsupported_evidence()
        except base_exception_type:
            return unsupported_evidence()

    maker_context = locals()
    result_replay = {}
    for binding in RESULT_REPLAY_BINDINGS:
        if (
            native_type(binding) is not native_tuple
            or not value_equal(
                native_len(binding), native_len(RESULT_REPLAY_BINDING_FIELDS)
            )
        ):
            raise _Reject("result-replay-policy")
        bound_command, validator_role, argument_fields = binding
        if (
            native_type(bound_command) is not str_type
            or native_type(validator_role) is not str_type
            or native_type(argument_fields) is not native_tuple
            or bound_command in result_replay
            or validator_role not in maker_context
        ):
            raise _Reject("result-replay-policy")
        for field in argument_fields:
            if native_type(field) is not str_type or field not in RESULT_KEYS:
                raise _Reject("result-replay-policy")
        result_replay[bound_command] = (
            maker_context[validator_role], argument_fields
        )
    if not value_equal(native_tuple(result_replay), result_commands):
        raise _Reject("result-replay-policy")

    def valid_result(result):
        try:
            if matches_template(result, unsupported_plan_template) or (
                matches_template(result, unsupported_evidence_template)
            ):
                return True
            if not integrity_guard():
                return False
            _exact_dict(result, RESULT_KEYS)
            _native(result)
            if not value_equal(result["schema"], RESULT_SCHEMA):
                return False
            command = result["command"]
            if type(command) is not str or not native_getattr(
                result_commands, policy_membership_method
            )(command):
                return False
            status = result["status"]
            if type(status) is not str or not native_getattr(
                result_statuses, policy_membership_method
            )(status):
                return False
            if not value_equal(result["reason"], _result_reason(command, status)):
                return False
            claimed = _hex64(result[result_self_hash_field])
            body = {key: result[key] for key in result_body_keys}
            if not value_equal(
                _domain_hash(_DOMAINS["result"], body, MAX_RESULT_BYTES),
                claimed,
            ):
                return False
            if (
                not value_equal(
                    result["evidence_contract_id"], EVIDENCE_CONTRACT_ID
                )
                or not value_equal(
                    result["environment_policy_id"], environment_policy_id()
                )
            ):
                return False
            if (
                not value_equal(result["nonclaims"], list(NONCLAIMS))
                or not value_equal(result["flags"], expected_false_flags)
            ):
                return False
            for key in result_false_fields:
                if result[key] is not False:
                    return False
            if value_equal(status, status_unsupported):
                return False
            if result["document_valid"] is not True:
                return False
            replay_validator, replay_fields = result_replay[command]
            expected = replay_validator(
                *(result[field] for field in replay_fields)
            )
            return type(expected) is dict and value_equal(expected, result)
        except base_exception_type:
            return False

    def exit_matches_unsupported(result):
        return matches_template(result, unsupported_plan_template) or (
            matches_template(result, unsupported_evidence_template)
        )

    def exit_matches_any(_result):
        return True

    exit_predicate_context = locals()
    normal_exit_decisions = []
    for path_role in RESULT_EXIT_NORMAL_PATH_ROLES:
        selected = result_exit_paths.get(path_role)
        if selected is None:
            raise _Reject("result-exit-policy")
        predicate_function, predicate_expected = selected[:2]
        predicate = exit_predicate_context.get(predicate_function)
        if (
            native_type(predicate_function) is not str_type
            or native_type(predicate_expected) is not bool_type
            or predicate is None
        ):
            raise _Reject("result-exit-policy")
        normal_exit_decisions.append(
            (path_role, predicate, predicate_expected)
        )
    if not value_equal(
        native_len(normal_exit_decisions),
        native_len(RESULT_EXIT_NORMAL_PATH_ROLES),
    ):
        raise _Reject("result-exit-policy")
    exception_binding = result_exit_paths.get(RESULT_EXIT_EXCEPTION_PATH_ROLE)
    if exception_binding is None or not value_equal(
        exception_binding[0], RESULT_EXIT_EXCEPTION_PREDICATE_FUNCTION
    ):
        raise _Reject("result-exit-policy")
    exception_exit_code = exit_code_for(
        RESULT_EXIT_EXCEPTION_PATH_ROLE, None
    )

    def render_fallback(_result):
        if native_type(fallback_line) is not str_type:
            raise _Reject("render-policy")
        line_values = document_binding_resolver(
            "render_fallback_value",
            {"local": native_locals()},
            "render-policy",
        )
        line, = native_tuple(line_values.values())
        return line

    def render_valid(result):
        rendered = rendered_mapping(result)
        _exact_dict(rendered, RENDER_KEYS)
        line = canonicalizer(rendered, max_render_bytes).decode("ascii")
        line_within_bounds = _numeric_bounds_include(
            len(line.encode("ascii")), 0, max_render_bytes
        )
        if (
            native_type(line_within_bounds) is not bool_type
            or native_type(fallback_line) is not str_type
            or native_type(line) is not str_type
        ):
            raise _Reject("render-policy")
        line_values = document_binding_resolver(
            "render_line_values", {"local": native_locals()}, "render-policy"
        )
        line_source = result_render_line_sources[line_within_bounds]
        return line_values[line_source]

    render_action_context = locals()
    result_render_validity_actions = {}
    for valid, renderer_function in (
        result_render_validity_action_names.items()
    ):
        renderer = render_action_context.get(renderer_function)
        if renderer is None:
            raise _Reject("render-policy")
        result_render_validity_actions[valid] = renderer
    if not value_equal(
        native_len(result_render_validity_actions),
        native_len(RESULT_RENDER_VALIDITY_BINDINGS),
    ):
        raise _Reject("render-policy")

    def render_dynamic(result):
        valid = valid_result(result)
        if native_type(valid) is not bool_type:
            raise _Reject("render-policy")
        selector_context = native_locals()
        selector_value = selector_context.get(render_validity_value_role)
        if native_type(selector_value) is not bool_type:
            raise _Reject("render-policy")
        selector_result = native_getattr(
            selector_value, render_validity_selector_method
        )()
        if native_type(selector_result) is not bool_type:
            raise _Reject("render-policy")
        validity_key = native_getattr(
            selector_result, render_validity_comparator_method
        )(render_validity_expected_result)
        if native_type(validity_key) is not bool_type:
            raise _Reject("render-policy")
        return result_render_validity_actions[validity_key](result)

    def render_precomputed(line):
        if native_type(line) is not str_type:
            raise _Reject("render-policy")
        arguments = {"line": line}
        if precomputed_source_key not in arguments:
            raise _Reject("render-policy")
        selected_line = arguments[precomputed_source_key]
        return selected_line

    def render_result(result):
        """Return one bounded canonical redacted line; total for any input."""
        try:
            render_candidates = []
            decision_iterator = native_getattr(
                unsupported_render_decisions,
                result_exit_traversal_method,
            )()
            for template, line in decision_iterator:
                matched = matches_template(result, template)
                if native_type(matched) is not bool_type:
                    raise _Reject("unsupported-render-policy")
                matches_expected = native_getattr(
                    matched, result_exit_predicate_comparator_method
                )(unsupported_render_match_expected)
                if native_type(matches_expected) is not bool_type:
                    raise _Reject("unsupported-render-policy")
                selection_count = result_exit_predicate_actions[
                    matches_expected
                ]
                selected_renderers = native_getattr(
                    ((render_precomputed, line),),
                    result_exit_selection_sequence_method,
                )(selection_count)
                native_getattr(
                    render_candidates,
                    result_exit_selection_collection_method,
                )(selected_renderers)
            dynamic_count = result_exit_predicate_actions[
                render_dynamic_candidate_action_result
            ]
            dynamic_renderers = native_getattr(
                ((render_dynamic, result),),
                result_exit_selection_sequence_method,
            )(dynamic_count)
            native_getattr(
                render_candidates,
                result_exit_selection_collection_method,
            )(dynamic_renderers)
            renderer, argument = native_getattr(
                render_candidates, result_exit_selected_path_method
            )(result_exit_selected_path_index)
            selected_line = renderer(argument)
            if native_type(selected_line) is not str_type:
                raise _Reject("render-policy")
            return selected_line
        except base_exception_type:
            return fallback_line

    def result_exit_code(result):
        """Return 0 only for a semantically replayed documentary success."""
        try:
            selected_path_roles = []
            decision_iterator = native_getattr(
                normal_exit_decisions, result_exit_traversal_method
            )()
            for (
                path_role, predicate, predicate_expected
            ) in decision_iterator:
                matched = predicate(result)
                if native_type(matched) is not bool_type:
                    raise _Reject("result-exit-policy")
                matches_expected = native_getattr(
                    matched, result_exit_predicate_comparator_method
                )(predicate_expected)
                if native_type(matches_expected) is not bool_type:
                    raise _Reject("result-exit-policy")
                selection_count = result_exit_predicate_actions[
                    matches_expected
                ]
                selected_paths = native_getattr(
                    (path_role,), result_exit_selection_sequence_method
                )(selection_count)
                native_getattr(
                    selected_path_roles,
                    result_exit_selection_collection_method,
                )(selected_paths)
            selected_path_role = native_getattr(
                selected_path_roles, result_exit_selected_path_method
            )(result_exit_selected_path_index)
            return exit_code_for(selected_path_role, result)
        except base_exception_type:
            return exception_exit_code

    validate_plan.__name__ = "validate_model_snapshot_plan_document"
    validate_evidence.__name__ = "validate_environment_evidence_set_document"
    valid_result.__name__ = "_valid_result"
    render_result.__name__ = "render_environment_evidence_result"
    result_exit_code.__name__ = "environment_evidence_result_exit_code"
    return validate_plan, validate_evidence, valid_result, render_result, result_exit_code


(
    validate_model_snapshot_plan_document,
    validate_environment_evidence_set_document,
    _valid_result,
    render_environment_evidence_result,
    environment_evidence_result_exit_code,
) = _make_public_apis()

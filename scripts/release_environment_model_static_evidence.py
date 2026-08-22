"""Dormant Phase-5B3a held-root model-static evidence fragment.

This module is a read-only bridge between the frozen Phase-5B1 storage
inspector and the frozen Phase-5B2 documentary evidence contract.  It emits
only the environment and model static document roles.  It never completes an
evidence set, runs a model or candidate, performs a dynamic probe, issues a
receipt, or changes configuration, services, selectors, journals, or
activation state.

The two upstream modules are read through held descriptors, hash checked, and
executed in private namespaces.  The model snapshot is independently read
from the descriptor supplied by B1's private held-snapshot seam; no caller may
supply a plan, path, descriptor, or observer.
"""

import hashlib
import json
import os
import re
import stat
import sys
from typing import Any


CONTRACT_SCHEMA = "synapse-s2.release-environment-model-static-contract.v1"
FRAGMENT_SCHEMA = "synapse-s2.release-environment-model-static-fragment.v1"
RESULT_SCHEMA = "synapse-s2.release-environment-model-static-result.v1"
RENDER_SCHEMA = "synapse-s2.release-environment-model-static-render.v1"

MODE = "held-root-model-static-fragment"
COMMAND = "inspect-prebuilt-environment-model-static-evidence"

CONTRACT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-MODEL-STATIC-CONTRACT\0v1\0"
)
FRAGMENT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-MODEL-STATIC-FRAGMENT\0v1\0"
)
RESULT_DOMAIN = (
    b"SYNAPSE-S2\0RELEASE-ENVIRONMENT-MODEL-STATIC-RESULT\0v1\0"
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
SUCCESS_REASON = "produced:model-static-fragment-held-snapshot"
UNSUPPORTED_REASON = "unsupported:model-static-fragment-platform"
BLOCKED_REASON = "blocked:model-static-fragment-refused"
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
STATIC_ROLES_PRESENT = (
    "environment_manifest_sha256",
    "model_manifest_sha256",
)
STATIC_ROLES_PENDING = (
    "installed_distribution_manifest_sha256",
    "native_file_manifest_sha256",
)
FRAGMENT_KEYS = (
    "schema",
    "mode",
    "model_static_contract_id",
    "phase5b1_source_sha256",
    "phase5b1_contract_id",
    "phase5b2_source_sha256",
    "phase5b2_contract_id",
    "environment_policy_id",
    "environment",
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
    "model_static_fragment_produced",
)
RESULT_KEYS = (
    "schema",
    "command",
    "status",
    "reason",
    "model_static_contract_id",
    "environment_policy_id",
    "storage_inspect_result",
    "model_static_fragment",
    "model_static_fragment_sha256",
    "document_valid",
    "held_snapshot_reproved",
    "model_static_fragment_produced",
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
    "model_static_contract_id",
    "environment_policy_id",
    "model_static_fragment_sha256",
    "document_valid",
    "held_snapshot_reproved",
    "model_static_fragment_produced",
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
    "model_fragment_keys",
    "fragment_keys",
    "result_keys",
    "render_keys",
    "static_roles_present",
    "static_roles_pending",
    "fixed_false_result_fields",
    "status_reason_exit_bindings",
    "model_cache_binding",
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
    "no-installed-distribution-manifest",
    "no-native-file-manifest",
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
MAX_NATIVE_INT = 2**64 - 1
DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
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
_TREE_NAME_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9._+-]{0,199}\Z")
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
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
_REQUIRED_OS_FLAGS = ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
_REQUIRED_OS_CALLABLES = (
    "open",
    "close",
    "fstat",
    "stat",
    "read",
    "listdir",
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
        "environment_document_bindings": [
            list(binding) for binding in ENVIRONMENT_DOCUMENT_BINDINGS
        ],
        "domains": {
            "contract": CONTRACT_DOMAIN.decode("ascii"),
            "fragment": FRAGMENT_DOMAIN.decode("ascii"),
            "result": RESULT_DOMAIN.decode("ascii"),
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
        },
        "nonclaims": list(NONCLAIMS),
    }
    _exact_dict(body, CONTRACT_BODY_KEYS, "contract-body")
    return body


def environment_model_static_contract_projection() -> dict[str, Any]:
    """Return the deterministic dormant B3a documentary contract."""
    body = _contract_body()
    projection = dict(body)
    projection["contract_id"] = (
        "environment-model-static-contract-"
        + _domain_hash(CONTRACT_DOMAIN, body, MAX_CONTRACT_BYTES)
    )
    _exact_dict(projection, CONTRACT_KEYS, "contract")
    _canonical_bytes(projection, MAX_CONTRACT_BYTES)
    return projection


MODEL_STATIC_CONTRACT_ID = environment_model_static_contract_projection()[
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
    try:
        scan_fd = os.open(".", _DIR_FLAGS, dir_fd=fd)
        names = os.listdir(scan_fd)
    except OSError:
        raise _refuse(token + "-list")
    finally:
        if scan_fd is not None:
            owned_scan = scan_fd
            scan_fd = None
            _close_owned(owned_scan, token + "-list")
    if type(names) is not list or len(names) > MAX_TREE_ENTRIES:
        raise _refuse(token + "-names")
    for name in names:
        if type(name) is not str or _TREE_NAME_RE.fullmatch(name) is None:
            raise _refuse(token + "-name")
    folded = [name.casefold() for name in names]
    if len(folded) != len(set(folded)):
        raise _refuse(token + "-casefold")
    return sorted(names)


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
    _exact_dict(environment, ENVIRONMENT_FRAGMENT_KEYS, "environment-fragment")
    _exact_dict(model, MODEL_FRAGMENT_KEYS, "model-fragment")
    return {"environment": environment, "model": model}


def _build_fragment(candidate: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": FRAGMENT_SCHEMA,
        "mode": MODE,
        "model_static_contract_id": MODEL_STATIC_CONTRACT_ID,
        "phase5b1_source_sha256": PHASE5B1_SOURCE_SHA256,
        "phase5b1_contract_id": PHASE5B1_CONTRACT_ID,
        "phase5b2_source_sha256": PHASE5B2_SOURCE_SHA256,
        "phase5b2_contract_id": PHASE5B2_CONTRACT_ID,
        "environment_policy_id": ENVIRONMENT_POLICY_ID,
        "environment": candidate["environment"],
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
    reasons = {item_status: reason for item_status, reason, _code in STATUS_REASON_EXIT_BINDINGS}
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
        "model_static_contract_id": MODEL_STATIC_CONTRACT_ID,
        "environment_policy_id": ENVIRONMENT_POLICY_ID,
        "storage_inspect_result": storage_result,
        "model_static_fragment": fragment,
        "model_static_fragment_sha256": fragment_sha256,
        "document_valid": success,
        "held_snapshot_reproved": success,
        "model_static_fragment_produced": success,
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
        "model_static_contract_id": MODEL_STATIC_CONTRACT_ID,
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
    model = _exact_dict(fragment["model"], MODEL_FRAGMENT_KEYS, "model-fragment")
    for key in (
        "environment_request_sha256",
        "storage_request_record_sha256",
        "storage_prepare_sha256",
        "storage_manifest_sha256",
        "storage_digest",
    ):
        _hex64(environment[key])
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
        if key not in result or type(result[key]) is not type(expected) or result[key] != expected:
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
    if model["model_manifest_sha256"] != model_manifest_sha256:
        raise _refuse("fragment-semantic-model")
    _crosscheck_model_plan_tree(
        manifest, model["model_manifest"]["snapshot_plan"]
    )


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
        or result["model_static_contract_id"] != MODEL_STATIC_CONTRACT_ID
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
        fragment = _validate_fragment(result["model_static_fragment"])
        if result["model_static_fragment_sha256"] != fragment["fragment_sha256"]:
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
        or result["model_static_fragment"] is not None
        or result["model_static_fragment_sha256"] is not None
    ):
        raise _refuse("result-failure-payload")
    body = {key: result[key] for key in RESULT_KEYS if key != "result_sha256"}
    if _hex64(result["result_sha256"]) != _domain_hash(
        RESULT_DOMAIN, body, MAX_RESULT_BYTES
    ):
        raise _refuse("result-self-hash")
    return result


def validate_environment_model_static_result(result: Any) -> dict[str, Any]:
    """Replay a result; invalid input becomes the fixed blocked result."""
    try:
        frozen, _raw = _freeze_document(result, "result", MAX_RESULT_BYTES)
        return _validate_result(frozen)
    except BaseException:
        return _build_result(STATUS_BLOCKED)


def inspect_prebuilt_environment_model_static_evidence(
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
    '{"reason":"blocked:model-static-fragment-refused",'
    '"schema":"synapse-s2.release-environment-model-static-render.v1",'
    '"status":"blocked"}'
)


def render_environment_model_static_result(result: Any) -> str:
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
            "model_static_contract_id": MODEL_STATIC_CONTRACT_ID,
            "environment_policy_id": ENVIRONMENT_POLICY_ID,
            "model_static_fragment_sha256": validated[
                "model_static_fragment_sha256"
            ],
            "document_valid": validated["document_valid"],
            "held_snapshot_reproved": validated["held_snapshot_reproved"],
            "model_static_fragment_produced": validated[
                "model_static_fragment_produced"
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


def environment_model_static_result_exit_code(result: Any) -> int:
    """Return 0/2/3 only after exact replay validation."""
    try:
        replayed, _raw = _freeze_document(result, "exit-result", MAX_RESULT_BYTES)
        return _EXIT_CODES[_validate_result(replayed)["status"]]
    except BaseException:
        return _EXIT_CODES[STATUS_BLOCKED]

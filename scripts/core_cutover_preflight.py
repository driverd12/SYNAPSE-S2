#!/usr/bin/env python3
"""Read-only cutover proof for the SYNAPSE-S2 authoritative core.

The preflight deliberately does not import or construct the neural backend.  It
validates a previously produced operator-readiness recovery proof, binds that
proof to the quiescent live SQLite snapshot, and inventories only bounded,
privacy-safe process facts.  It never acknowledges events, opens a writable
SQLite connection, or changes launchd state.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memory_store import (  # noqa: E402
    CORE_AUTHORITY_MARKER_FIELDS,
    CORE_AUTHORITY_METADATA_KEY,
    CORE_ROOT_GENERATION_ID_RE,
    CORE_RUNTIME_PUBLICATION_SCHEMA,
    LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
    SQLITE_APPLICATION_ID,
    SQLITE_USER_VERSION,
    DurableMemoryStore,
)
from core_authority import (  # noqa: E402
    CORE_AUTHORITY_INSTANCE_RE,
    CORE_AUTHORITY_LOCK_GENERATION_RE,
    CORE_AUTHORITY_SCHEMA_VERSION,
)
from core_protocol import contains_secret_shape  # noqa: E402
from capture_daemon import GLOBAL_CAPTURE_LOCK  # noqa: E402
from core_request_journal import (  # noqa: E402
    JOURNAL_BINDING_SCHEMA,
    JOURNAL_SCHEMA_IDENTITY,
    JOURNAL_SCHEMA_VERSION,
)
from recovery_manager import (  # noqa: E402
    LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA,
    RECOVERY_BUNDLE_SCHEMA,
    RECOVERY_BUNDLE_RESTORE_SCHEMA,
    VerifiedRecoveryManager,
)
from redaction import SecretSafeArgumentParser  # noqa: E402
from operator_readiness_contract import (  # noqa: E402
    OPERATOR_READINESS_REQUIRED_PROOF_IDS,
    QUIESCENCE_POLICY_SCHEMA,
    REPLAY_DEBT_COUNTERS,
    quiescence_policy_contract,
    quiescence_policy_digest,
    quiescence_launch_agent_rules,
    ready_operator_proof_contract,
)


_QUIESCENCE_RULES = quiescence_launch_agent_rules()
DEFAULT_CAPTURE_LABEL = _QUIESCENCE_RULES["capture"].label
DEFAULT_DASHBOARD_LABEL = _QUIESCENCE_RULES["dashboard"].label
DEFAULT_CORE_LABEL = _QUIESCENCE_RULES["core"].label
MAX_PROCESS_FINDINGS = 12
MAX_JSON_BYTES = 4 * 1024 * 1024
_GIT_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_PID_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")
_LABEL = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
_DISABLED_SERVICE_LINE = re.compile(
    r'^\s*"?(?P<label>[A-Za-z0-9._-]{1,160})"?\s*=>\s*'
    r'(?P<disabled>true|false|enabled|disabled)\s*,?\s*$'
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STORE_IDENTITY = re.compile(r"^store-[0-9a-f]{24}$")
_STORE_GENERATION = re.compile(r"^epoch-[1-9][0-9]*$")
_REQUEST_JOURNAL_ID = re.compile(r"^journal-[0-9a-f]{24}$")
_BUILD_ID = re.compile(r"^source-[0-9a-f]{24}$")
CUTOVER_ATTESTATION_SCHEMA = "synapse-s2.core-cutover-attestation.v1"
CUTOVER_VERIFICATION_SCHEMA = "synapse-s2.core-cutover-verification.v1"
CUTOVER_ATTESTATION_NAME = "cutover-attestation.json"
CUTOVER_ATTESTATION_MAX_BYTES = 64 * 1024
CUTOVER_ATTESTATION_MAX_TTL_SECONDS = 600.0
CUTOVER_ATTESTATION_MIN_VALIDITY_SECONDS = 120.0
REPLACEMENT_ADMISSION_SCHEMA = "synapse-s2.replacement-admission.v1"
REPLACEMENT_ADMISSION_VERIFICATION_SCHEMA = (
    "synapse-s2.replacement-admission-verification.v1"
)
REPLACEMENT_ADMISSION_NAME = "replacement-admission.json"
REPLACEMENT_ADMISSION_MAX_BYTES = 64 * 1024
REPLACEMENT_ADMISSION_MAX_TTL_SECONDS = 600.0
REPLACEMENT_ADMISSION_MIN_VALIDITY_SECONDS = 120.0
REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX = "replacement-certification:"
MAXIMUM_EVIDENCE_AGE_SECONDS = 86_400.0
MAXIMUM_UNIX_TIMESTAMP_SECONDS = 253_402_300_799.0
MAXIMUM_UNIX_TIMESTAMP_MILLISECONDS = 253_402_300_799_000
MAXIMUM_CLOCK_SKEW_SECONDS = 60.0
CORE_CONFIG_EVIDENCE_SCHEMA = "synapse-s2.core-config-evidence.v1"
RUNTIME_BUILD_IDENTITY_SCHEMA = "synapse-s2.runtime-build-identity-proof.v1"
_SCHEMA_IDENTITY = re.compile(r"^sqlite-[0-9a-f]+-v(?:5|6)$")
_CUTOVER_ATTESTATION_CONTENT_KEYS = {
    "schema",
    "created_at_unix_ms",
    "expires_at_unix_ms",
    "evidence_manifest_path",
    "evidence_manifest_sha256",
    "git_head",
    "build_id",
    "config_fingerprint",
    "governance_mode",
    "store_identity",
    "store_generation",
    "authority_epoch_number",
    "database_schema_identity",
    "database_logical_snapshot_schema",
    "database_logical_snapshot_sha256",
    "capture_manifest_sha256",
    "runtime_state_required",
    "runtime_state_present",
    "runtime_state_canonical_sha256",
    "request_journal_id",
    "request_journal_schema_identity",
    "request_journal_logical_snapshot_schema",
    "request_journal_logical_snapshot_sha256",
    "request_journal_binding_receipt_digest",
    "restored_target",
    "restored_target_binding_receipt_digest",
    "recovery_bundle_receipt_digest",
    "recovery_restore_proof_receipt_digest",
}
_CUTOVER_ATTESTATION_AUTH_KEYS = {
    "auth_algorithm",
    "auth_key_id",
    "signing_public_key",
    "receipt_digest",
    "receipt_signature",
}
_REPLACEMENT_ADMISSION_CONTENT_KEYS = {
    "schema",
    "created_at_unix_ms",
    "expires_at_unix_ms",
    "git_head",
    "candidate_build_id",
    "candidate_config_fingerprint",
    "governance_mode",
    "store_identity",
    "store_generation",
    "authority_epoch_number",
    "next_authority_epoch_number",
    "database_schema_identity",
    "database_logical_snapshot_schema",
    "database_logical_snapshot_sha256",
    "capture_manifest_sha256",
    "runtime_state_required",
    "runtime_state_present",
    "runtime_state_canonical_sha256",
    "request_journal_id",
    "request_journal_schema_identity",
    "request_journal_logical_snapshot_schema",
    "request_journal_logical_snapshot_sha256",
    "request_journal_binding_receipt_digest",
    "restored_target",
    "restored_target_binding_receipt_digest",
    "recovery_bundle_receipt_path",
    "recovery_bundle_receipt_digest",
    "recovery_restore_proof_path",
    "recovery_restore_proof_receipt_digest",
    "predecessor_marker_sha256",
    "predecessor_marker_schema_version",
    "predecessor_service_required",
    "predecessor_instance_id",
    "predecessor_build_id",
    "predecessor_config_fingerprint",
    "predecessor_protocol_version",
    "predecessor_lock_generation_id",
    "predecessor_root_generation_id",
    "predecessor_embedding_space_identity",
    "predecessor_request_journal_id",
    "predecessor_request_journal_binding_schema",
    "predecessor_request_journal_schema_version",
    "predecessor_restored_target_binding_receipt_digest",
    "predecessor_runtime_publication_sha256",
    "delivery_audit_sha256",
    "delivery_audit_revision",
    "delivery_settled_audit_revision",
    "delivery_derivation_source_sha256",
    "delivery_derivation_source_row_count",
    "delivery_target_highwater",
    "delivery_latest_event_id",
}
_REPLACEMENT_ADMISSION_AUTH_KEYS = set(_CUTOVER_ATTESTATION_AUTH_KEYS)
_DELIVERY_AUDIT_KEYS = {
    "protocol_version",
    "status",
    "audit_revision",
    "settled_audit_revision",
    "repair_required",
    "repairable",
    "cursor_mismatch_count",
    "target_reconciliation_needed",
    "target_highwater",
    "latest_event_id",
    "delivery_schema_error_count",
    "unrelated_delivery_error_count",
    "target_canonicalization_needed",
    "target_integrity_error_count",
    "event_ledger_integrity_error_count",
    "target_highwater_error_count",
    "highwater_contract_error_count",
    "derivation_source_sha256",
    "derivation_source_row_count",
    "repair_receipt_integrity_error_count",
    "repair_receipt_semantic_error_count",
    "pending_repair_receipt_semantic_error_count",
    "verified_repair_receipt_semantic_error_count",
    "pending_repair_receipt_count",
}


class CutoverPreflightError(RuntimeError):
    """A content-bounded cutover gate failure."""


def _reject_json_constant(_value: str) -> None:
    """Reject JavaScript-style non-finite constants accepted by json.loads."""

    raise ValueError("non-finite JSON number")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _strict_json_loads(value: str | bytes, *, name: str) -> Any:
    try:
        return json.loads(
            value,
            parse_constant=_reject_json_constant,
            parse_float=_strict_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError) as exc:
        raise CutoverPreflightError(f"{name} is not valid JSON") from exc


def _bounded_finite_number(
    value: Any,
    *,
    name: str,
    minimum: float,
    maximum: float,
    minimum_inclusive: bool = True,
) -> float:
    if type(value) not in {int, float}:
        raise CutoverPreflightError(f"{name} is invalid")
    try:
        parsed = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise CutoverPreflightError(f"{name} is invalid") from exc
    below_minimum = parsed < minimum if minimum_inclusive else parsed <= minimum
    if not math.isfinite(parsed) or below_minimum or parsed > maximum:
        raise CutoverPreflightError(f"{name} is invalid")
    return parsed


def _maximum_evidence_age(value: Any) -> float:
    return _bounded_finite_number(
        value,
        name="evidence maximum age",
        minimum=0.0,
        maximum=MAXIMUM_EVIDENCE_AGE_SECONDS,
        minimum_inclusive=False,
    )


def _unix_timestamp_seconds(value: Any, *, name: str) -> float:
    return _bounded_finite_number(
        value,
        name=name,
        minimum=0.0,
        maximum=MAXIMUM_UNIX_TIMESTAMP_SECONDS,
        minimum_inclusive=False,
    )


def _current_unix_timestamp_seconds() -> float:
    return _unix_timestamp_seconds(time.time(), name="system time")


def _freshness_age_seconds(
    value: Any,
    *,
    name: str,
    now: float,
    maximum_age_seconds: float,
) -> float:
    observed_now = _unix_timestamp_seconds(now, name="system time")
    maximum_age = _maximum_evidence_age(maximum_age_seconds)
    timestamp = _unix_timestamp_seconds(value, name=name)
    age = observed_now - timestamp
    if (
        not math.isfinite(age)
        or age < -MAXIMUM_CLOCK_SKEW_SECONDS
        or age > maximum_age
    ):
        raise CutoverPreflightError(f"{name} is stale")
    return timestamp


def _manifest_build_id(root: Path) -> str:
    """Resolve the deterministic source identity without a module import cycle."""

    from core_service import _manifest_build_id as manifest_build_id

    return manifest_build_id(root)


def core_config_evidence_contract(config: Any) -> dict[str, Any]:
    """Return the exact, self-verifying candidate configuration contract."""

    try:
        from core_service import config_from_wire

        validated = config_from_wire(config.to_wire())
    except Exception as exc:
        raise CutoverPreflightError(
            "candidate authoritative-core configuration is invalid"
        ) from exc
    return {
        "schema": CORE_CONFIG_EVIDENCE_SCHEMA,
        "config_fingerprint": validated.fingerprint,
        "embedding_space_identity": validated.embedding_space_identity,
        "config": validated.to_wire(),
    }


def validate_core_config_evidence_contract(
    value: Any,
    *,
    expected_config_fingerprint: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "config_fingerprint",
        "embedding_space_identity",
        "config",
    }:
        raise CutoverPreflightError(
            "operator-readiness evidence lacks an exact core configuration contract"
        )
    try:
        from core_service import config_from_wire

        config = config_from_wire(value.get("config"))
        canonical = core_config_evidence_contract(config)
    except Exception as exc:
        raise CutoverPreflightError(
            "operator-readiness core configuration contract is invalid"
        ) from exc
    if canonical != value:
        raise CutoverPreflightError(
            "operator-readiness core configuration contract is not canonical"
        )
    if (
        expected_config_fingerprint is not None
        and not secrets.compare_digest(
            str(value["config_fingerprint"]),
            str(expected_config_fingerprint),
        )
    ):
        raise CutoverPreflightError(
            "operator-readiness evidence was produced for a different core configuration"
        )
    return canonical


@dataclass(frozen=True)
class ProcessFinding:
    pid: int
    category: str

    def to_wire(self) -> dict[str, Any]:
        return {"pid": self.pid, "category": self.category}


@dataclass(frozen=True)
class CutoverAttestationRequest:
    path: Path
    build_id: str
    config_fingerprint: str
    ttl_seconds: float = CUTOVER_ATTESTATION_MAX_TTL_SECONDS
    restored_target: bool = False


@dataclass(frozen=True)
class ReplacementAdmissionRequest:
    path: Path
    build_id: str
    config_fingerprint: str
    ttl_seconds: float = REPLACEMENT_ADMISSION_MAX_TTL_SECONDS


def _normal_absolute(path: str | os.PathLike[str], *, name: str) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute() or ".." in value.parts or "\x00" in str(value):
        raise CutoverPreflightError(f"{name} must be a normal absolute path")
    if contains_secret_shape(str(value)):
        raise CutoverPreflightError(f"{name} contains credential material")
    return value


def _assert_no_symlink_components(path: Path, *, name: str) -> None:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise CutoverPreflightError(f"{name} must be a normal absolute path")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            observed = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(observed.st_mode):
            if current == Path("/var") and os.readlink(current) == "private/var":
                continue
            raise CutoverPreflightError(f"{name} contains a symlink component")
        if current != path and not stat.S_ISDIR(observed.st_mode):
            raise CutoverPreflightError(f"{name} contains a non-directory component")


def _safe_regular(
    path: Path,
    *,
    name: str,
    require_private: bool = True,
    max_bytes: int | None = None,
) -> os.stat_result:
    _assert_no_symlink_components(path, name=name)
    try:
        observed = path.lstat()
    except FileNotFoundError as exc:
        raise CutoverPreflightError(f"{name} is missing") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
    ):
        raise CutoverPreflightError(f"{name} must be an owner-controlled regular file")
    if require_private and stat.S_IMODE(observed.st_mode) & 0o077:
        raise CutoverPreflightError(f"{name} must not grant group or other access")
    if max_bytes is not None and observed.st_size > max_bytes:
        raise CutoverPreflightError(f"{name} exceeds its size limit")
    return observed


def _read_json(path: Path, *, name: str) -> dict[str, Any]:
    before = _safe_regular(path, name=name, max_bytes=MAX_JSON_BYTES)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise CutoverPreflightError(f"{name} changed while being opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                raise CutoverPreflightError(f"{name} exceeds its size limit")
            chunks.append(chunk)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    visible = path.lstat()
    identities = {
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns),
        (visible.st_dev, visible.st_ino, visible.st_size, visible.st_mtime_ns),
    }
    if len(identities) != 1 or total != before.st_size:
        raise CutoverPreflightError(f"{name} changed while being read")
    value = _strict_json_loads(b"".join(chunks), name=name)
    if not isinstance(value, dict):
        raise CutoverPreflightError(f"{name} must contain a JSON object")
    return value


def _stable_sha256(path: Path, *, name: str) -> tuple[str, int]:
    before = _safe_regular(path, name=name)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CutoverPreflightError(f"{name} changed while being opened")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    visible = path.lstat()
    identities = {
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        (visible.st_dev, visible.st_ino, visible.st_size, visible.st_mtime_ns),
    }
    if len(identities) != 1 or size != before.st_size:
        raise CutoverPreflightError(f"{name} changed while being hashed")
    return digest.hexdigest(), size


def _fsync_directory(path: Path) -> None:
    _assert_no_symlink_components(path, name="attestation directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise CutoverPreflightError("attestation directory is unsafe")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_json_replace(
    path: Path,
    payload: Mapping[str, Any],
    *,
    name: str = "cutover attestation",
    max_bytes: int = CUTOVER_ATTESTATION_MAX_BYTES,
) -> str:
    """Durably replace one exact private attestation without following links."""

    _assert_no_symlink_components(path, name=name)
    _fsync_directory(path.parent)
    encoded = (
        json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise CutoverPreflightError(f"{name} exceeds its size limit")
    existing = None
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.getuid()
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise CutoverPreflightError(f"existing {name} is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"{name} write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = -1
        current = None
        try:
            current = path.lstat()
        except FileNotFoundError:
            pass
        if existing is None:
            if current is not None:
                raise CutoverPreflightError(f"{name} appeared during publication")
        elif current is None or (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
            current.st_uid,
            current.st_nlink,
            stat.S_IMODE(current.st_mode),
        ) != (
            existing.st_dev,
            existing.st_ino,
            existing.st_size,
            existing.st_mtime_ns,
            existing.st_ctime_ns,
            existing.st_uid,
            existing.st_nlink,
            stat.S_IMODE(existing.st_mode),
        ):
            raise CutoverPreflightError(f"{name} changed during publication")
        os.replace(temporary, path)
        published = path.lstat()
        if (
            stat.S_ISLNK(published.st_mode)
            or not stat.S_ISREG(published.st_mode)
            or published.st_uid != os.getuid()
            or published.st_nlink != 1
            or stat.S_IMODE(published.st_mode) != 0o600
            or (
                published.st_dev,
                published.st_ino,
                published.st_size,
                published.st_mtime_ns,
            )
            != (
                staged.st_dev,
                staged.st_ino,
                staged.st_size,
                staged.st_mtime_ns,
            )
        ):
            raise CutoverPreflightError(f"{name} publication identity changed")
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return hashlib.sha256(encoded).hexdigest()


def _validate_cutover_attestation(
    payload: Mapping[str, Any],
    *,
    store: DurableMemoryStore,
    expected_content: Mapping[str, Any] | None = None,
    now_unix_ms: int | None = None,
    minimum_remaining_seconds: float = 0.0,
) -> str:
    minimum_remaining = _bounded_finite_number(
        minimum_remaining_seconds,
        name="cutover attestation minimum validity",
        minimum=0.0,
        maximum=CUTOVER_ATTESTATION_MAX_TTL_SECONDS,
    )
    if set(payload) != (
        _CUTOVER_ATTESTATION_CONTENT_KEYS | _CUTOVER_ATTESTATION_AUTH_KEYS
    ):
        raise CutoverPreflightError("cutover attestation contract is unsupported")
    if expected_content is not None and (
        set(expected_content) != _CUTOVER_ATTESTATION_CONTENT_KEYS
        or any(payload.get(key) != value for key, value in expected_content.items())
    ):
        raise CutoverPreflightError("cutover attestation content binding changed")
    created = payload.get("created_at_unix_ms")
    expires = payload.get("expires_at_unix_ms")
    if now_unix_ms is None:
        observed_now = int(_current_unix_timestamp_seconds() * 1000)
    elif (
        type(now_unix_ms) is not int
        or now_unix_ms <= 0
        or now_unix_ms > MAXIMUM_UNIX_TIMESTAMP_MILLISECONDS
    ):
        raise CutoverPreflightError("cutover attestation observation time is invalid")
    else:
        observed_now = now_unix_ms
    minimum_remaining_ms = int(minimum_remaining * 1000)
    if (
        payload.get("schema") != CUTOVER_ATTESTATION_SCHEMA
        or type(created) is not int
        or type(expires) is not int
        or created <= 0
        or created > MAXIMUM_UNIX_TIMESTAMP_MILLISECONDS
        or expires <= created
        or expires > MAXIMUM_UNIX_TIMESTAMP_MILLISECONDS
        or expires - created > int(CUTOVER_ATTESTATION_MAX_TTL_SECONDS * 1000)
        or created > observed_now + 60_000
        or expires <= observed_now
        or expires - observed_now < minimum_remaining_ms
        or _GIT_OBJECT_ID.fullmatch(str(payload.get("git_head") or "")) is None
        or _BUILD_ID.fullmatch(str(payload.get("build_id") or "")) is None
        or _SHA256.fullmatch(str(payload.get("config_fingerprint") or "")) is None
        or _SHA256.fullmatch(
            str(payload.get("evidence_manifest_sha256") or "")
        )
        is None
        or _SCHEMA_IDENTITY.fullmatch(
            str(payload.get("database_schema_identity") or "")
        )
        is None
        or payload.get("database_logical_snapshot_schema")
        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or _SHA256.fullmatch(
            str(payload.get("database_logical_snapshot_sha256") or "")
        )
        is None
        or _SHA256.fullmatch(str(payload.get("capture_manifest_sha256") or ""))
        is None
        or _SHA256.fullmatch(
            str(payload.get("recovery_bundle_receipt_digest") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("recovery_restore_proof_receipt_digest") or "")
        )
        is None
        or _STORE_IDENTITY.fullmatch(str(payload.get("store_identity") or ""))
        is None
    ):
        raise CutoverPreflightError("cutover attestation values are invalid")
    _normal_absolute(
        str(payload.get("evidence_manifest_path") or ""),
        name="attested evidence manifest",
    )
    governance = payload.get("governance_mode")
    generation = payload.get("store_generation")
    epoch = payload.get("authority_epoch_number")
    runtime_required = payload.get("runtime_state_required")
    runtime_present = payload.get("runtime_state_present")
    runtime_canonical = payload.get("runtime_state_canonical_sha256")
    if (
        type(runtime_required) is not bool
        or type(runtime_present) is not bool
        or (runtime_required and not runtime_present)
        or (
            runtime_present
            and _SHA256.fullmatch(str(runtime_canonical or "")) is None
        )
        or (not runtime_present and runtime_canonical is not None)
    ):
        raise CutoverPreflightError(
            "cutover attestation runtime-state binding is invalid"
        )
    journal_values = (
        payload.get("request_journal_id"),
        payload.get("request_journal_schema_identity"),
        payload.get("request_journal_logical_snapshot_schema"),
        payload.get("request_journal_logical_snapshot_sha256"),
        payload.get("request_journal_binding_receipt_digest"),
    )
    restored_target = payload.get("restored_target")
    restored_binding_digest = payload.get(
        "restored_target_binding_receipt_digest"
    )
    if (
        type(restored_target) is not bool
        or (
            restored_target
            and _SHA256.fullmatch(str(restored_binding_digest or "")) is None
        )
        or (not restored_target and restored_binding_digest is not None)
    ):
        raise CutoverPreflightError(
            "cutover attestation restored-target binding is invalid"
        )
    if governance == "pre-governed-v5":
        if generation != "legacy-v5" or epoch is not None or any(
            value is not None for value in journal_values
        ):
            raise CutoverPreflightError(
                "pre-governed cutover attestation values are invalid"
            )
    elif governance == "authoritative-v6":
        if (
            not isinstance(generation, str)
            or _STORE_GENERATION.fullmatch(generation) is None
            or type(epoch) is not int
            or epoch < 1
            or generation != f"epoch-{epoch}"
            or _REQUEST_JOURNAL_ID.fullmatch(str(journal_values[0] or "")) is None
            or journal_values[1] != JOURNAL_SCHEMA_IDENTITY
            or journal_values[2] != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            or _SHA256.fullmatch(str(journal_values[3] or "")) is None
            or _SHA256.fullmatch(str(journal_values[4] or "")) is None
        ):
            raise CutoverPreflightError(
                "authoritative cutover attestation values are invalid"
            )
    else:
        raise CutoverPreflightError("cutover attestation governance is invalid")
    if restored_target and governance != "authoritative-v6":
        raise CutoverPreflightError(
            "only authoritative v6 may claim a restored target"
        )
    receipt_digest = str(payload.get("receipt_digest") or "")
    if (
        _SHA256.fullmatch(receipt_digest) is None
        or not secrets.compare_digest(
            receipt_digest,
            store._canonical_payload_digest(dict(payload)),
        )
        or not store._verify_receipt_authenticator(dict(payload))
    ):
        raise CutoverPreflightError("cutover attestation signature is invalid")
    return receipt_digest


def _canonical_mapping_sha256(value: Mapping[str, Any], *, name: str) -> str:
    try:
        encoded = json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CutoverPreflightError(f"{name} is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _validate_ready_delivery_audit(
    audit: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(audit, Mapping) or set(audit) != _DELIVERY_AUDIT_KEYS:
        raise CutoverPreflightError("replacement delivery audit contract is invalid")
    zero_fields = {
        "cursor_mismatch_count",
        "delivery_schema_error_count",
        "unrelated_delivery_error_count",
        "target_integrity_error_count",
        "event_ledger_integrity_error_count",
        "target_highwater_error_count",
        "highwater_contract_error_count",
        "repair_receipt_integrity_error_count",
        "repair_receipt_semantic_error_count",
        "pending_repair_receipt_semantic_error_count",
        "verified_repair_receipt_semantic_error_count",
        "pending_repair_receipt_count",
    }
    nonnegative_fields = {
        "target_highwater",
        "latest_event_id",
        "derivation_source_row_count",
    }
    if (
        audit.get("protocol_version")
        != "context-delivery-publication-repair.v1"
        or audit.get("status") != "ready"
        or audit.get("repair_required") is not False
        or audit.get("repairable") is not True
        or audit.get("target_reconciliation_needed") is not False
        or audit.get("target_canonicalization_needed") is not False
        or _SHA256.fullmatch(str(audit.get("audit_revision") or "")) is None
        or _SHA256.fullmatch(
            str(audit.get("settled_audit_revision") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(audit.get("derivation_source_sha256") or "")
        )
        is None
        or any(type(audit.get(field)) is not int for field in zero_fields)
        or any(int(audit[field]) != 0 for field in zero_fields)
        or any(type(audit.get(field)) is not int for field in nonnegative_fields)
        or any(int(audit[field]) < 0 for field in nonnegative_fields)
        or audit.get("target_highwater") != audit.get("latest_event_id")
    ):
        raise CutoverPreflightError("replacement delivery audit is not ready")
    canonical = dict(audit)
    canonical["sha256"] = _canonical_mapping_sha256(
        audit,
        name="replacement delivery audit",
    )
    return canonical


def _validate_replacement_inspection(
    inspection: Mapping[str, Any],
    *,
    recovery: Mapping[str, Any],
    candidate_build_id: str,
    candidate_config_fingerprint: str,
) -> dict[str, Any]:
    expected_inspection_keys = {
        "governance_mode",
        "schema_identity",
        "previous_epoch",
        "next_epoch",
        "logical_snapshot",
        "marker",
        "runtime_publication",
        "store_identity",
        "new_empty_bootstrap",
    }
    if not isinstance(inspection, Mapping) or set(inspection) != expected_inspection_keys:
        raise CutoverPreflightError(
            "replacement authority inspection contract is invalid"
        )
    marker = inspection.get("marker")
    logical = inspection.get("logical_snapshot")
    publication = inspection.get("runtime_publication")
    if (
        not isinstance(marker, dict)
        or set(marker) != set(CORE_AUTHORITY_MARKER_FIELDS)
        or not isinstance(logical, dict)
        or not isinstance(publication, dict)
    ):
        raise CutoverPreflightError(
            "replacement requires an exact authoritative v6 predecessor"
        )
    try:
        marker_sha256 = DurableMemoryStore._core_authority_marker_sha256(marker)
    except Exception as exc:
        raise CutoverPreflightError(
            "replacement predecessor marker is invalid"
        ) from exc
    logical_count_fields = {
        "table_count",
        "column_count",
        "row_count",
        "value_bytes",
    }
    expected_schema_identity = (
        f"sqlite-{SQLITE_APPLICATION_ID:x}-v{SQLITE_USER_VERSION}"
    )
    epoch = marker.get("epoch")
    restored_binding = marker.get("restored_target_binding_receipt_digest")
    if (
        inspection.get("governance_mode") != "authoritative-v6"
        or inspection.get("schema_identity") != expected_schema_identity
        or inspection.get("new_empty_bootstrap") is not False
        or type(epoch) is not int
        or epoch < 1
        or inspection.get("previous_epoch") != epoch
        or inspection.get("next_epoch") != epoch + 1
        or marker.get("schema_version") != CORE_AUTHORITY_SCHEMA_VERSION
        or marker.get("service_required") is not True
        or CORE_AUTHORITY_INSTANCE_RE.fullmatch(
            str(marker.get("instance_id") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(marker.get("config_fingerprint") or "")
        )
        is None
        or _BUILD_ID.fullmatch(str(marker.get("build_id") or "")) is None
        or CORE_AUTHORITY_INSTANCE_RE.fullmatch(
            str(marker.get("protocol_version") or "")
        )
        is None
        or CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(
            str(marker.get("lock_generation_id") or "")
        )
        is None
        or _STORE_IDENTITY.fullmatch(str(marker.get("store_identity") or ""))
        is None
        or _REQUEST_JOURNAL_ID.fullmatch(
            str(marker.get("request_journal_id") or "")
        )
        is None
        or marker.get("request_journal_binding_schema")
        != JOURNAL_BINDING_SCHEMA
        or marker.get("request_journal_schema_version") != JOURNAL_SCHEMA_VERSION
        or CORE_ROOT_GENERATION_ID_RE.fullmatch(
            str(marker.get("root_generation_id") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(marker.get("embedding_space_identity") or "")
        )
        is None
        or (
            restored_binding is not None
            and _SHA256.fullmatch(str(restored_binding)) is None
        )
        or any(
            type(marker.get(field)) not in {int, float}
            or isinstance(marker.get(field), bool)
            or not math.isfinite(float(marker[field]))
            or float(marker[field]) <= 0.0
            for field in ("claimed_at", "updated_at")
        )
        or float(marker["claimed_at"]) > float(marker["updated_at"])
        or logical.get("schema") != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or _SHA256.fullmatch(str(logical.get("sha256") or "")) is None
        or _SHA256.fullmatch(str(logical.get("schema_sha256") or "")) is None
        or logical.get("application_id") != SQLITE_APPLICATION_ID
        or logical.get("user_version") != SQLITE_USER_VERSION
        or any(type(logical.get(field)) is not int for field in logical_count_fields)
        or any(int(logical[field]) < 0 for field in logical_count_fields)
    ):
        raise CutoverPreflightError(
            "replacement predecessor identity is invalid"
        )
    publication_keys = {
        "schema",
        "status",
        "marker_sha256",
        "authority_epoch_number",
        "lock_generation_id",
        "instance_id",
        "config_fingerprint",
        "build_id",
        "protocol_version",
        "runtime_state_path_sha256",
        "started_at",
        "completed_at",
        "updated_at",
    }
    if (
        set(publication) != publication_keys
        or publication.get("schema") != CORE_RUNTIME_PUBLICATION_SCHEMA
        or publication.get("status") != "complete"
        or publication.get("marker_sha256") != marker_sha256
        or publication.get("authority_epoch_number") != epoch
        or publication.get("lock_generation_id")
        != marker.get("lock_generation_id")
        or publication.get("instance_id") != marker.get("instance_id")
        or publication.get("config_fingerprint")
        != marker.get("config_fingerprint")
        or publication.get("build_id") != marker.get("build_id")
        or publication.get("protocol_version")
        != marker.get("protocol_version")
        or _SHA256.fullmatch(
            str(publication.get("runtime_state_path_sha256") or "")
        )
        is None
        or any(
            type(publication.get(field)) not in {int, float}
            or isinstance(publication.get(field), bool)
            or not math.isfinite(float(publication[field]))
            or float(publication[field]) <= 0.0
            for field in ("started_at", "completed_at", "updated_at")
        )
        or float(publication["started_at"]) > float(publication["completed_at"])
        or float(publication["completed_at"]) != float(publication["updated_at"])
    ):
        raise CutoverPreflightError(
            "replacement predecessor runtime publication is incomplete"
        )
    provisional_resume = (
        candidate_build_id == marker.get("build_id")
        and str(marker.get("instance_id") or "").startswith(
            REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
        )
    )
    if (
        _BUILD_ID.fullmatch(candidate_build_id) is None
        or _SHA256.fullmatch(candidate_config_fingerprint) is None
        or (
            candidate_build_id == marker.get("build_id")
            and not provisional_resume
        )
        or candidate_config_fingerprint != marker.get("config_fingerprint")
    ):
        raise CutoverPreflightError(
            "replacement admission requires a new build or an exact provisional "
            "resume with unchanged configuration"
        )
    if (
        recovery.get("governance_mode") != "authoritative-v6"
        or recovery.get("store_identity") != inspection.get("store_identity")
        or recovery.get("store_identity") != marker.get("store_identity")
        or recovery.get("store_generation") != f"epoch-{epoch}"
        or recovery.get("authority_epoch_number") != epoch
        or recovery.get("database_schema_identity") != expected_schema_identity
        or recovery.get("database_logical_snapshot_schema")
        != logical.get("schema")
        or recovery.get("database_logical_snapshot_sha256")
        != logical.get("sha256")
        or _SHA256.fullmatch(
            str(recovery.get("capture_manifest_sha256") or "")
        )
        is None
        or recovery.get("runtime_state_required") is not True
        or recovery.get("runtime_state_present") is not True
        or _SHA256.fullmatch(
            str(recovery.get("runtime_state_canonical_sha256") or "")
        )
        is None
        or recovery.get("request_journal_id")
        != marker.get("request_journal_id")
        or recovery.get("request_journal_schema_identity")
        != JOURNAL_SCHEMA_IDENTITY
        or recovery.get("request_journal_logical_snapshot_schema")
        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or _SHA256.fullmatch(
            str(
                recovery.get("request_journal_logical_snapshot_sha256") or ""
            )
        )
        is None
        or _SHA256.fullmatch(
            str(recovery.get("request_journal_binding_receipt_digest") or "")
        )
        is None
        or recovery.get("restored_target") is not False
        or recovery.get("restored_target_binding_receipt_digest") is not None
        or _SHA256.fullmatch(
            str(recovery.get("recovery_bundle_receipt_digest") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(recovery.get("recovery_restore_proof_receipt_digest") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(recovery.get("recovery_auth_key_id") or "")
        )
        is None
    ):
        raise CutoverPreflightError(
            "verified recovery does not match the replacement predecessor"
        )
    return {
        "predecessor_marker_sha256": marker_sha256,
        "predecessor_marker_schema_version": int(marker["schema_version"]),
        "predecessor_service_required": True,
        "predecessor_instance_id": str(marker["instance_id"]),
        "predecessor_build_id": str(marker["build_id"]),
        "predecessor_config_fingerprint": str(marker["config_fingerprint"]),
        "predecessor_protocol_version": str(marker["protocol_version"]),
        "predecessor_lock_generation_id": str(marker["lock_generation_id"]),
        "predecessor_root_generation_id": str(marker["root_generation_id"]),
        "predecessor_embedding_space_identity": str(
            marker["embedding_space_identity"]
        ),
        "predecessor_request_journal_id": str(marker["request_journal_id"]),
        "predecessor_request_journal_binding_schema": str(
            marker["request_journal_binding_schema"]
        ),
        "predecessor_request_journal_schema_version": int(
            marker["request_journal_schema_version"]
        ),
        "predecessor_restored_target_binding_receipt_digest": restored_binding,
        "predecessor_runtime_publication_sha256": _canonical_mapping_sha256(
            publication,
            name="predecessor runtime publication",
        ),
    }


def _replacement_recovery_binding(
    *,
    memory_db: Path,
    capture_root: Path,
    receipt_path: Path,
    restore_proof_path: Path,
    maximum_evidence_age_seconds: float,
    guarded_recovery_locks_held: bool = False,
) -> tuple[dict[str, Any], float]:
    maximum_age = _maximum_evidence_age(maximum_evidence_age_seconds)
    if type(guarded_recovery_locks_held) is not bool:
        raise CutoverPreflightError(
            "replacement guarded-recovery lock ownership is invalid"
        )
    for path, name in (
        (memory_db, "live memory database"),
        (capture_root, "capture source root"),
        (receipt_path, "recovery bundle receipt"),
        (restore_proof_path, "isolated restore proof"),
    ):
        _assert_no_symlink_components(path, name=name)
    store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        manager = VerifiedRecoveryManager(store, capture_root=capture_root)
        repository_lock_path = (
            memory_db.parent / "recovery-locks" / "repository.lock"
        )
        if not guarded_recovery_locks_held:
            _assert_no_symlink_components(
                repository_lock_path,
                name="recovery repository lock",
            )
        lock_scope = (
            nullcontext()
            if guarded_recovery_locks_held
            else manager._existing_private_file_lock(
                repository_lock_path,
                mode=fcntl.LOCK_SH,
                timeout_seconds=30.0,
            )
        )
        # Use only the verification half of verify_bundle. Its public wrapper
        # may repair incomplete publication journals. Admission is read-only:
        # the publisher already owns GuardedRecoveryPublication's exclusive
        # lock, while core startup takes this existing lock shared.
        with lock_scope:
            parsed = manager._verify_bundle_locked(receipt_path)
            receipt, identity_trusted = manager._read_bundle_receipt(receipt_path)
            restore_proof = _read_json(
                restore_proof_path,
                name="isolated restore proof",
            )
            observed_now = _current_unix_timestamp_seconds()
            receipt_created = _freshness_age_seconds(
                receipt.get("created_at"),
                name="replacement recovery bundle creation time",
                now=observed_now,
                maximum_age_seconds=maximum_age,
            )
            restore_created = _freshness_age_seconds(
                restore_proof.get("created_at"),
                name="replacement isolated restore time",
                now=observed_now,
                maximum_age_seconds=maximum_age,
            )
            if (
                identity_trusted is not True
                or parsed.get("receipt_identity_trusted") is not True
                or parsed.get("verified") is not True
                or parsed.get("cutover_ready") is not True
                or parsed.get("bundle_receipt_path") != str(receipt_path)
            ):
                raise CutoverPreflightError(
                    "replacement requires trusted cutover-ready recovery evidence"
                )
            recovery = verify_recovery_binding(
                parsed=parsed,
                receipt_path=receipt_path,
                restore_proof=restore_proof,
                restore_proof_path=restore_proof_path,
                memory_db=memory_db,
                capture_root=capture_root,
                restored_target=False,
                repository_lock_held=True,
                capture_maintenance_lock_held=(
                    guarded_recovery_locks_held
                ),
            )
            return recovery, min(receipt_created, restore_created) + maximum_age
    except CutoverPreflightError:
        raise
    except Exception as exc:
        raise CutoverPreflightError(
            "replacement recovery bundle verification failed"
        ) from exc
    finally:
        store.close()


def _replacement_delivery_binding(
    *,
    memory_db: Path,
    delivery_audit: Mapping[str, Any],
) -> dict[str, Any]:
    expected = _validate_ready_delivery_audit(delivery_audit)
    store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        observed = store.audit_context_delivery_publication_repair()
    except Exception as exc:
        raise CutoverPreflightError(
            "live replacement delivery audit failed"
        ) from exc
    finally:
        store.close()
    actual = _validate_ready_delivery_audit(observed)
    if actual != expected:
        raise CutoverPreflightError(
            "replacement delivery audit changed during admission"
        )
    return dict(delivery_audit)


def _replacement_admission_content(
    *,
    created_at_unix_ms: int,
    expires_at_unix_ms: int,
    git_head: str,
    candidate_build_id: str,
    candidate_config_fingerprint: str,
    receipt_path: Path,
    restore_proof_path: Path,
    inspection: Mapping[str, Any],
    delivery_audit: Mapping[str, Any],
    recovery: Mapping[str, Any],
) -> dict[str, Any]:
    predecessor = _validate_replacement_inspection(
        inspection,
        recovery=recovery,
        candidate_build_id=candidate_build_id,
        candidate_config_fingerprint=candidate_config_fingerprint,
    )
    delivery = _validate_ready_delivery_audit(delivery_audit)
    return {
        "schema": REPLACEMENT_ADMISSION_SCHEMA,
        "created_at_unix_ms": created_at_unix_ms,
        "expires_at_unix_ms": expires_at_unix_ms,
        "git_head": git_head,
        "candidate_build_id": candidate_build_id,
        "candidate_config_fingerprint": candidate_config_fingerprint,
        "governance_mode": recovery.get("governance_mode"),
        "store_identity": recovery.get("store_identity"),
        "store_generation": recovery.get("store_generation"),
        "authority_epoch_number": recovery.get("authority_epoch_number"),
        "next_authority_epoch_number": inspection.get("next_epoch"),
        "database_schema_identity": recovery.get("database_schema_identity"),
        "database_logical_snapshot_schema": recovery.get(
            "database_logical_snapshot_schema"
        ),
        "database_logical_snapshot_sha256": recovery.get(
            "database_logical_snapshot_sha256"
        ),
        "capture_manifest_sha256": recovery.get("capture_manifest_sha256"),
        "runtime_state_required": recovery.get("runtime_state_required"),
        "runtime_state_present": recovery.get("runtime_state_present"),
        "runtime_state_canonical_sha256": recovery.get(
            "runtime_state_canonical_sha256"
        ),
        "request_journal_id": recovery.get("request_journal_id"),
        "request_journal_schema_identity": recovery.get(
            "request_journal_schema_identity"
        ),
        "request_journal_logical_snapshot_schema": recovery.get(
            "request_journal_logical_snapshot_schema"
        ),
        "request_journal_logical_snapshot_sha256": recovery.get(
            "request_journal_logical_snapshot_sha256"
        ),
        "request_journal_binding_receipt_digest": recovery.get(
            "request_journal_binding_receipt_digest"
        ),
        "restored_target": False,
        "restored_target_binding_receipt_digest": None,
        "recovery_bundle_receipt_path": str(receipt_path),
        "recovery_bundle_receipt_digest": recovery.get(
            "recovery_bundle_receipt_digest"
        ),
        "recovery_restore_proof_path": str(restore_proof_path),
        "recovery_restore_proof_receipt_digest": recovery.get(
            "recovery_restore_proof_receipt_digest"
        ),
        **predecessor,
        "delivery_audit_sha256": delivery["sha256"],
        "delivery_audit_revision": delivery["audit_revision"],
        "delivery_settled_audit_revision": delivery[
            "settled_audit_revision"
        ],
        "delivery_derivation_source_sha256": delivery[
            "derivation_source_sha256"
        ],
        "delivery_derivation_source_row_count": delivery[
            "derivation_source_row_count"
        ],
        "delivery_target_highwater": delivery["target_highwater"],
        "delivery_latest_event_id": delivery["latest_event_id"],
    }


def _validate_replacement_admission(
    payload: Mapping[str, Any],
    *,
    store: DurableMemoryStore,
    expected_content: Mapping[str, Any] | None = None,
    expected_auth_key_id: str | None = None,
    now_unix_ms: int | None = None,
    minimum_remaining_seconds: float = 0.0,
) -> str:
    minimum_remaining = _bounded_finite_number(
        minimum_remaining_seconds,
        name="replacement admission minimum validity",
        minimum=0.0,
        maximum=REPLACEMENT_ADMISSION_MAX_TTL_SECONDS,
    )
    if set(payload) != (
        _REPLACEMENT_ADMISSION_CONTENT_KEYS | _REPLACEMENT_ADMISSION_AUTH_KEYS
    ):
        raise CutoverPreflightError(
            "replacement admission contract is unsupported"
        )
    if expected_content is not None and (
        set(expected_content) != _REPLACEMENT_ADMISSION_CONTENT_KEYS
        or any(payload.get(key) != value for key, value in expected_content.items())
    ):
        raise CutoverPreflightError("replacement admission content binding changed")
    created = payload.get("created_at_unix_ms")
    expires = payload.get("expires_at_unix_ms")
    if now_unix_ms is None:
        observed_now = int(_current_unix_timestamp_seconds() * 1000)
    elif (
        type(now_unix_ms) is not int
        or now_unix_ms <= 0
        or now_unix_ms > MAXIMUM_UNIX_TIMESTAMP_MILLISECONDS
    ):
        raise CutoverPreflightError(
            "replacement admission observation time is invalid"
        )
    else:
        observed_now = now_unix_ms
    if (
        payload.get("schema") != REPLACEMENT_ADMISSION_SCHEMA
        or type(created) is not int
        or type(expires) is not int
        or created <= 0
        or created > MAXIMUM_UNIX_TIMESTAMP_MILLISECONDS
        or expires <= created
        or expires > MAXIMUM_UNIX_TIMESTAMP_MILLISECONDS
        or expires - created
        > int(REPLACEMENT_ADMISSION_MAX_TTL_SECONDS * 1000)
        or created > observed_now + 60_000
        or expires <= observed_now
        or expires - observed_now < int(minimum_remaining * 1000)
        or _GIT_OBJECT_ID.fullmatch(str(payload.get("git_head") or "")) is None
        or _BUILD_ID.fullmatch(
            str(payload.get("candidate_build_id") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("candidate_config_fingerprint") or "")
        )
        is None
        or payload.get("governance_mode") != "authoritative-v6"
        or _STORE_IDENTITY.fullmatch(str(payload.get("store_identity") or ""))
        is None
        or _STORE_GENERATION.fullmatch(
            str(payload.get("store_generation") or "")
        )
        is None
        or type(payload.get("authority_epoch_number")) is not int
        or int(payload["authority_epoch_number"]) < 1
        or payload.get("store_generation")
        != f"epoch-{payload['authority_epoch_number']}"
        or payload.get("next_authority_epoch_number")
        != int(payload["authority_epoch_number"]) + 1
        or payload.get("database_schema_identity")
        != f"sqlite-{SQLITE_APPLICATION_ID:x}-v{SQLITE_USER_VERSION}"
        or payload.get("database_logical_snapshot_schema")
        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or _SHA256.fullmatch(
            str(payload.get("database_logical_snapshot_sha256") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("capture_manifest_sha256") or "")
        )
        is None
        or payload.get("runtime_state_required") is not True
        or payload.get("runtime_state_present") is not True
        or _SHA256.fullmatch(
            str(payload.get("runtime_state_canonical_sha256") or "")
        )
        is None
        or _REQUEST_JOURNAL_ID.fullmatch(
            str(payload.get("request_journal_id") or "")
        )
        is None
        or payload.get("request_journal_schema_identity")
        != JOURNAL_SCHEMA_IDENTITY
        or payload.get("request_journal_logical_snapshot_schema")
        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or _SHA256.fullmatch(
            str(
                payload.get("request_journal_logical_snapshot_sha256") or ""
            )
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("request_journal_binding_receipt_digest") or "")
        )
        is None
        or payload.get("restored_target") is not False
        or payload.get("restored_target_binding_receipt_digest") is not None
        or _SHA256.fullmatch(
            str(payload.get("recovery_bundle_receipt_digest") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("recovery_restore_proof_receipt_digest") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("predecessor_marker_sha256") or "")
        )
        is None
        or payload.get("predecessor_marker_schema_version")
        != CORE_AUTHORITY_SCHEMA_VERSION
        or payload.get("predecessor_service_required") is not True
        or CORE_AUTHORITY_INSTANCE_RE.fullmatch(
            str(payload.get("predecessor_instance_id") or "")
        )
        is None
        or _BUILD_ID.fullmatch(
            str(payload.get("predecessor_build_id") or "")
        )
        is None
        or (
            payload.get("candidate_build_id")
            == payload.get("predecessor_build_id")
            and not str(payload.get("predecessor_instance_id") or "").startswith(
                REPLACEMENT_CERTIFICATION_INSTANCE_PREFIX
            )
        )
        or _SHA256.fullmatch(
            str(payload.get("predecessor_config_fingerprint") or "")
        )
        is None
        or payload.get("candidate_config_fingerprint")
        != payload.get("predecessor_config_fingerprint")
        or CORE_AUTHORITY_INSTANCE_RE.fullmatch(
            str(payload.get("predecessor_protocol_version") or "")
        )
        is None
        or CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(
            str(payload.get("predecessor_lock_generation_id") or "")
        )
        is None
        or CORE_ROOT_GENERATION_ID_RE.fullmatch(
            str(payload.get("predecessor_root_generation_id") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(payload.get("predecessor_embedding_space_identity") or "")
        )
        is None
        or payload.get("predecessor_request_journal_id")
        != payload.get("request_journal_id")
        or payload.get("predecessor_request_journal_binding_schema")
        != JOURNAL_BINDING_SCHEMA
        or payload.get("predecessor_request_journal_schema_version")
        != JOURNAL_SCHEMA_VERSION
        or (
            payload.get("predecessor_restored_target_binding_receipt_digest")
            is not None
            and _SHA256.fullmatch(
                str(
                    payload.get(
                        "predecessor_restored_target_binding_receipt_digest"
                    )
                )
            )
            is None
        )
        or _SHA256.fullmatch(
            str(payload.get("predecessor_runtime_publication_sha256") or "")
        )
        is None
        or any(
            _SHA256.fullmatch(str(payload.get(field) or "")) is None
            for field in (
                "delivery_audit_sha256",
                "delivery_audit_revision",
                "delivery_settled_audit_revision",
                "delivery_derivation_source_sha256",
            )
        )
        or any(
            type(payload.get(field)) is not int or int(payload[field]) < 0
            for field in (
                "delivery_derivation_source_row_count",
                "delivery_target_highwater",
                "delivery_latest_event_id",
            )
        )
        or payload.get("delivery_target_highwater")
        != payload.get("delivery_latest_event_id")
    ):
        raise CutoverPreflightError("replacement admission values are invalid")
    for field, name in (
        ("recovery_bundle_receipt_path", "recovery bundle receipt"),
        ("recovery_restore_proof_path", "isolated restore proof"),
    ):
        _normal_absolute(str(payload.get(field) or ""), name=name)
    receipt_digest = str(payload.get("receipt_digest") or "")
    if (
        _SHA256.fullmatch(receipt_digest) is None
        or not secrets.compare_digest(
            receipt_digest,
            store._canonical_payload_digest(dict(payload)),
        )
        or not store._verify_receipt_authenticator(dict(payload))
        or (
            expected_auth_key_id is not None
            and payload.get("auth_key_id") != expected_auth_key_id
        )
    ):
        raise CutoverPreflightError("replacement admission signature is invalid")
    return receipt_digest


def publish_cutover_attestation(
    *,
    request: CutoverAttestationRequest,
    root: Path,
    memory_db: Path,
    evidence_manifest: Path,
    maximum_evidence_age_seconds: float,
    recovery: Mapping[str, Any],
) -> dict[str, Any]:
    maximum_age = _maximum_evidence_age(maximum_evidence_age_seconds)
    if type(request.restored_target) is not bool:
        raise CutoverPreflightError("restored-target request must be boolean")
    if recovery.get("restored_target") is not request.restored_target:
        raise CutoverPreflightError(
            "cutover attestation restored-target request does not match recovery"
        )
    canonical_path = memory_db.parent / "core" / CUTOVER_ATTESTATION_NAME
    if request.path != canonical_path:
        raise CutoverPreflightError(
            "cutover attestation must use the canonical core path"
        )
    ttl_seconds = _bounded_finite_number(
        request.ttl_seconds,
        name="cutover attestation TTL",
        minimum=CUTOVER_ATTESTATION_MIN_VALIDITY_SECONDS,
        maximum=CUTOVER_ATTESTATION_MAX_TTL_SECONDS,
    )
    head, dirty = _git_snapshot(root)
    if dirty:
        raise CutoverPreflightError(
            "cutover attestation requires a clean repository"
        )
    evidence = _read_json(evidence_manifest, name="evidence manifest")
    evidence_sha256, _evidence_size = _stable_sha256(
        evidence_manifest,
        name="evidence manifest",
    )
    observed_now = _current_unix_timestamp_seconds()
    evidence_created = _freshness_age_seconds(
        evidence.get("created_at"),
        name="evidence creation time",
        now=observed_now,
        maximum_age_seconds=maximum_age,
    )
    created_at_unix_ms = int(observed_now * 1000)
    evidence_expires_at_unix_ms = int(
        (evidence_created + maximum_age) * 1000
    )
    expires_at_unix_ms = min(
        created_at_unix_ms + int(ttl_seconds * 1000),
        evidence_expires_at_unix_ms,
    )
    if (
        expires_at_unix_ms - created_at_unix_ms
        < int(CUTOVER_ATTESTATION_MIN_VALIDITY_SECONDS * 1000)
    ):
        raise CutoverPreflightError(
            "operator-readiness evidence expires too soon for cutover"
        )
    expected_content: dict[str, Any] = {
        "schema": CUTOVER_ATTESTATION_SCHEMA,
        "created_at_unix_ms": created_at_unix_ms,
        "expires_at_unix_ms": expires_at_unix_ms,
        "evidence_manifest_path": str(evidence_manifest.resolve()),
        "evidence_manifest_sha256": evidence_sha256,
        "git_head": head,
        "build_id": request.build_id,
        "config_fingerprint": request.config_fingerprint,
        "governance_mode": recovery.get("governance_mode"),
        "store_identity": recovery.get("store_identity"),
        "store_generation": recovery.get("store_generation"),
        "authority_epoch_number": recovery.get("authority_epoch_number"),
        "database_schema_identity": recovery.get("database_schema_identity"),
        "database_logical_snapshot_schema": recovery.get(
            "database_logical_snapshot_schema"
        ),
        "database_logical_snapshot_sha256": recovery.get(
            "database_logical_snapshot_sha256"
        ),
        "capture_manifest_sha256": recovery.get("capture_manifest_sha256"),
        "runtime_state_required": recovery.get("runtime_state_required"),
        "runtime_state_present": recovery.get("runtime_state_present"),
        "runtime_state_canonical_sha256": recovery.get(
            "runtime_state_canonical_sha256"
        ),
        "request_journal_id": recovery.get("request_journal_id"),
        "request_journal_schema_identity": recovery.get(
            "request_journal_schema_identity"
        ),
        "request_journal_logical_snapshot_schema": recovery.get(
            "request_journal_logical_snapshot_schema"
        ),
        "request_journal_logical_snapshot_sha256": recovery.get(
            "request_journal_logical_snapshot_sha256"
        ),
        "request_journal_binding_receipt_digest": recovery.get(
            "request_journal_binding_receipt_digest"
        ),
        "restored_target": recovery.get("restored_target"),
        "restored_target_binding_receipt_digest": recovery.get(
            "restored_target_binding_receipt_digest"
        ),
        "recovery_bundle_receipt_digest": recovery.get(
            "recovery_bundle_receipt_digest"
        ),
        "recovery_restore_proof_receipt_digest": recovery.get(
            "recovery_restore_proof_receipt_digest"
        ),
    }
    store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        private_key, public_key, existing_key_id = (
            store._backup_receipt_signing_key(create=False)
        )
        expected_auth_key = recovery.get("recovery_auth_key_id")
        if (
            private_key is None
            or public_key is None
            or not isinstance(existing_key_id, str)
            or not isinstance(expected_auth_key, str)
            or _SHA256.fullmatch(expected_auth_key) is None
            or existing_key_id != expected_auth_key
        ):
            raise CutoverPreflightError(
                "existing recovery signing authority is unavailable"
            )
        attestation = dict(expected_content)
        store._authenticate_receipt(attestation)
        if attestation.get("auth_key_id") != expected_auth_key:
            raise CutoverPreflightError(
                "cutover attestation signer does not match recovery evidence"
            )
        receipt_digest = _validate_cutover_attestation(
            attestation,
            store=store,
            expected_content=expected_content,
            now_unix_ms=created_at_unix_ms,
            minimum_remaining_seconds=CUTOVER_ATTESTATION_MIN_VALIDITY_SECONDS,
        )
        artifact_sha256 = _atomic_private_json_replace(
            request.path,
            attestation,
        )
        persisted = _read_json(request.path, name="cutover attestation")
        persisted_receipt_digest = _validate_cutover_attestation(
            persisted,
            store=store,
            expected_content=expected_content,
            minimum_remaining_seconds=CUTOVER_ATTESTATION_MIN_VALIDITY_SECONDS,
        )
        persisted_sha256, _persisted_size = _stable_sha256(
            request.path,
            name="cutover attestation",
        )
        if (
            persisted != attestation
            or persisted_receipt_digest != receipt_digest
            or persisted_sha256 != artifact_sha256
        ):
            raise CutoverPreflightError(
                "cutover attestation changed after publication"
            )
        return {
            "schema": CUTOVER_ATTESTATION_SCHEMA,
            "path": str(request.path),
            "receipt_digest": receipt_digest,
            "artifact_sha256": artifact_sha256,
            "expires_at_unix_ms": expires_at_unix_ms,
            "verified": True,
        }
    except CutoverPreflightError:
        raise
    except Exception as exc:
        raise CutoverPreflightError(
            "cutover attestation signing or publication failed"
        ) from exc
    finally:
        store.close()


def verify_cutover_attestation_for_core(
    *,
    root: Path,
    memory_db: Path,
    capture_root: Path,
    attestation_path: Path,
    evidence_manifest: Path,
    expected_build_id: str,
    expected_config_fingerprint: str,
    expected_git_head: str,
    expected_evidence_manifest_sha256: str,
    maximum_evidence_age_seconds: float = 7200.0,
    minimum_remaining_seconds: float = 0.0,
) -> dict[str, Any]:
    """Reverify one signed cutover ticket before authoritative-core startup.

    The caller owns the core authority lease.  This function never acquires or
    creates that lease and never publishes, repairs, acknowledges, or mutates
    state.  Recovery helpers may join their already-established repository,
    capture, runtime, and journal locks to obtain a coherent read-only view.
    """

    canonical_path = memory_db.parent / "core" / CUTOVER_ATTESTATION_NAME
    for path, name in (
        (root, "repository root"),
        (memory_db, "live memory database"),
        (capture_root, "capture source root"),
        (attestation_path, "cutover attestation"),
        (evidence_manifest, "evidence manifest"),
    ):
        _assert_no_symlink_components(path, name=name)
    if attestation_path != canonical_path:
        raise CutoverPreflightError(
            "core startup requires the canonical cutover attestation"
        )
    if (
        _BUILD_ID.fullmatch(expected_build_id) is None
        or _SHA256.fullmatch(expected_config_fingerprint) is None
        or _GIT_OBJECT_ID.fullmatch(expected_git_head) is None
        or _SHA256.fullmatch(expected_evidence_manifest_sha256) is None
    ):
        raise CutoverPreflightError("expected cutover identity is invalid")
    maximum_age = _maximum_evidence_age(maximum_evidence_age_seconds)

    payload = _read_json(attestation_path, name="cutover attestation")
    head, dirty = _git_snapshot(root)
    evidence_sha256, _evidence_size = _stable_sha256(
        evidence_manifest,
        name="evidence manifest",
    )
    if (
        dirty
        or head != expected_git_head
        or payload.get("git_head") != expected_git_head
        or payload.get("build_id") != expected_build_id
        or payload.get("config_fingerprint") != expected_config_fingerprint
        or payload.get("evidence_manifest_path")
        != str(evidence_manifest.resolve())
        or evidence_sha256 != expected_evidence_manifest_sha256
        or payload.get("evidence_manifest_sha256")
        != expected_evidence_manifest_sha256
    ):
        raise CutoverPreflightError(
            "cutover attestation does not match current source, config, or evidence"
        )

    signature_store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        receipt_digest = _validate_cutover_attestation(
            payload,
            store=signature_store,
            minimum_remaining_seconds=minimum_remaining_seconds,
        )
    finally:
        signature_store.close()

    parsed, receipt_path, restore_proof, restore_proof_path = (
        validate_evidence_contract(
            evidence_manifest,
            root=root,
            maximum_age_seconds=maximum_age,
            expected_config_fingerprint=expected_config_fingerprint,
        )
    )
    recovery = verify_recovery_binding(
        parsed=parsed,
        receipt_path=receipt_path,
        restore_proof=restore_proof,
        restore_proof_path=restore_proof_path,
        memory_db=memory_db,
        capture_root=capture_root,
        restored_target=bool(payload.get("restored_target")),
    )
    expected_content = {
        "schema": CUTOVER_ATTESTATION_SCHEMA,
        "created_at_unix_ms": payload.get("created_at_unix_ms"),
        "expires_at_unix_ms": payload.get("expires_at_unix_ms"),
        "evidence_manifest_path": str(evidence_manifest.resolve()),
        "evidence_manifest_sha256": expected_evidence_manifest_sha256,
        "git_head": expected_git_head,
        "build_id": expected_build_id,
        "config_fingerprint": expected_config_fingerprint,
        "governance_mode": recovery.get("governance_mode"),
        "store_identity": recovery.get("store_identity"),
        "store_generation": recovery.get("store_generation"),
        "authority_epoch_number": recovery.get("authority_epoch_number"),
        "database_schema_identity": recovery.get("database_schema_identity"),
        "database_logical_snapshot_schema": recovery.get(
            "database_logical_snapshot_schema"
        ),
        "database_logical_snapshot_sha256": recovery.get(
            "database_logical_snapshot_sha256"
        ),
        "capture_manifest_sha256": recovery.get("capture_manifest_sha256"),
        "runtime_state_required": recovery.get("runtime_state_required"),
        "runtime_state_present": recovery.get("runtime_state_present"),
        "runtime_state_canonical_sha256": recovery.get(
            "runtime_state_canonical_sha256"
        ),
        "request_journal_id": recovery.get("request_journal_id"),
        "request_journal_schema_identity": recovery.get(
            "request_journal_schema_identity"
        ),
        "request_journal_logical_snapshot_schema": recovery.get(
            "request_journal_logical_snapshot_schema"
        ),
        "request_journal_logical_snapshot_sha256": recovery.get(
            "request_journal_logical_snapshot_sha256"
        ),
        "request_journal_binding_receipt_digest": recovery.get(
            "request_journal_binding_receipt_digest"
        ),
        "restored_target": recovery.get("restored_target"),
        "restored_target_binding_receipt_digest": recovery.get(
            "restored_target_binding_receipt_digest"
        ),
        "recovery_bundle_receipt_digest": recovery.get(
            "recovery_bundle_receipt_digest"
        ),
        "recovery_restore_proof_receipt_digest": recovery.get(
            "recovery_restore_proof_receipt_digest"
        ),
    }
    verification_store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        verified_digest = _validate_cutover_attestation(
            payload,
            store=verification_store,
            expected_content=expected_content,
            minimum_remaining_seconds=minimum_remaining_seconds,
        )
    finally:
        verification_store.close()
    if verified_digest != receipt_digest:
        raise CutoverPreflightError(
            "cutover attestation identity changed during verification"
        )
    return {
        "schema": CUTOVER_VERIFICATION_SCHEMA,
        "verified": True,
        "receipt_digest": receipt_digest,
        "expires_at_unix_ms": int(payload["expires_at_unix_ms"]),
        "git_head": expected_git_head,
        "build_id": expected_build_id,
        "config_fingerprint": expected_config_fingerprint,
        "evidence_manifest_sha256": expected_evidence_manifest_sha256,
        "governance_mode": recovery["governance_mode"],
        "store_identity": recovery["store_identity"],
        "store_generation": recovery["store_generation"],
        "authority_epoch_number": recovery["authority_epoch_number"],
        "database_schema_identity": recovery["database_schema_identity"],
        "database_logical_snapshot_schema": recovery[
            "database_logical_snapshot_schema"
        ],
        "database_logical_snapshot_sha256": recovery[
            "database_logical_snapshot_sha256"
        ],
        "capture_manifest_sha256": recovery["capture_manifest_sha256"],
        "runtime_state_required": recovery["runtime_state_required"],
        "runtime_state_present": recovery["runtime_state_present"],
        "runtime_state_canonical_sha256": recovery[
            "runtime_state_canonical_sha256"
        ],
        "request_journal_id": recovery["request_journal_id"],
        "request_journal_schema_identity": recovery[
            "request_journal_schema_identity"
        ],
        "request_journal_logical_snapshot_schema": recovery[
            "request_journal_logical_snapshot_schema"
        ],
        "request_journal_logical_snapshot_sha256": recovery[
            "request_journal_logical_snapshot_sha256"
        ],
        "request_journal_binding_receipt_digest": recovery[
            "request_journal_binding_receipt_digest"
        ],
        "restored_target": recovery["restored_target"],
        "restored_target_binding_receipt_digest": recovery[
            "restored_target_binding_receipt_digest"
        ],
        "recovery_bundle_receipt_digest": recovery[
            "recovery_bundle_receipt_digest"
        ],
        "recovery_restore_proof_receipt_digest": recovery[
            "recovery_restore_proof_receipt_digest"
        ],
    }


def publish_replacement_admission(
    *,
    request: ReplacementAdmissionRequest,
    root: Path,
    memory_db: Path,
    capture_root: Path,
    recovery_bundle_receipt: Path,
    recovery_restore_proof: Path,
    inspection: Mapping[str, Any],
    delivery_audit: Mapping[str, Any],
    maximum_evidence_age_seconds: float = 7200.0,
) -> dict[str, Any]:
    """Publish one signed, short-lived build-only v6 successor admission."""

    canonical_path = memory_db.parent / "core" / REPLACEMENT_ADMISSION_NAME
    for path, name in (
        (root, "repository root"),
        (memory_db, "live memory database"),
        (capture_root, "capture source root"),
        (recovery_bundle_receipt, "recovery bundle receipt"),
        (recovery_restore_proof, "isolated restore proof"),
        (request.path, "replacement admission"),
    ):
        _assert_no_symlink_components(path, name=name)
    if request.path != canonical_path:
        raise CutoverPreflightError(
            "replacement admission must use the canonical core path"
        )
    ttl_seconds = _bounded_finite_number(
        request.ttl_seconds,
        name="replacement admission TTL",
        minimum=REPLACEMENT_ADMISSION_MIN_VALIDITY_SECONDS,
        maximum=REPLACEMENT_ADMISSION_MAX_TTL_SECONDS,
    )
    if (
        _BUILD_ID.fullmatch(request.build_id) is None
        or _SHA256.fullmatch(request.config_fingerprint) is None
    ):
        raise CutoverPreflightError("replacement candidate identity is invalid")
    head, dirty = _git_snapshot(root)
    if dirty:
        raise CutoverPreflightError(
            "replacement admission requires a clean repository"
        )
    try:
        current_build_id = _manifest_build_id(root)
    except Exception as exc:
        raise CutoverPreflightError(
            "current deterministic source build could not be verified"
        ) from exc
    if not secrets.compare_digest(current_build_id, request.build_id):
        raise CutoverPreflightError(
            "replacement candidate build does not match current source"
        )
    recovery, recovery_expires_at = _replacement_recovery_binding(
        memory_db=memory_db,
        capture_root=capture_root,
        receipt_path=recovery_bundle_receipt,
        restore_proof_path=recovery_restore_proof,
        maximum_evidence_age_seconds=maximum_evidence_age_seconds,
        guarded_recovery_locks_held=True,
    )
    delivery = _replacement_delivery_binding(
        memory_db=memory_db,
        delivery_audit=delivery_audit,
    )
    observed_now = _current_unix_timestamp_seconds()
    created_at_unix_ms = int(observed_now * 1000)
    expires_at_unix_ms = min(
        created_at_unix_ms + int(ttl_seconds * 1000),
        int(recovery_expires_at * 1000),
    )
    if (
        expires_at_unix_ms - created_at_unix_ms
        < int(REPLACEMENT_ADMISSION_MIN_VALIDITY_SECONDS * 1000)
    ):
        raise CutoverPreflightError(
            "verified replacement recovery expires too soon for admission"
        )
    expected_content = _replacement_admission_content(
        created_at_unix_ms=created_at_unix_ms,
        expires_at_unix_ms=expires_at_unix_ms,
        git_head=head,
        candidate_build_id=request.build_id,
        candidate_config_fingerprint=request.config_fingerprint,
        receipt_path=recovery_bundle_receipt,
        restore_proof_path=recovery_restore_proof,
        inspection=inspection,
        delivery_audit=delivery,
        recovery=recovery,
    )
    store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        private_key, public_key, existing_key_id = (
            store._backup_receipt_signing_key(create=False)
        )
        expected_auth_key = recovery.get("recovery_auth_key_id")
        if (
            private_key is None
            or public_key is None
            or not isinstance(existing_key_id, str)
            or not isinstance(expected_auth_key, str)
            or _SHA256.fullmatch(expected_auth_key) is None
            or existing_key_id != expected_auth_key
        ):
            raise CutoverPreflightError(
                "existing recovery signing authority is unavailable"
            )
        admission = dict(expected_content)
        store._authenticate_receipt(admission)
        receipt_digest = _validate_replacement_admission(
            admission,
            store=store,
            expected_content=expected_content,
            expected_auth_key_id=expected_auth_key,
            now_unix_ms=created_at_unix_ms,
            minimum_remaining_seconds=(
                REPLACEMENT_ADMISSION_MIN_VALIDITY_SECONDS
            ),
        )
        artifact_sha256 = _atomic_private_json_replace(
            request.path,
            admission,
            name="replacement admission",
            max_bytes=REPLACEMENT_ADMISSION_MAX_BYTES,
        )
        persisted = _read_json(request.path, name="replacement admission")
        persisted_digest = _validate_replacement_admission(
            persisted,
            store=store,
            expected_content=expected_content,
            expected_auth_key_id=expected_auth_key,
            minimum_remaining_seconds=(
                REPLACEMENT_ADMISSION_MIN_VALIDITY_SECONDS
            ),
        )
        persisted_sha256, _persisted_size = _stable_sha256(
            request.path,
            name="replacement admission",
        )
        if (
            persisted != admission
            or persisted_digest != receipt_digest
            or persisted_sha256 != artifact_sha256
        ):
            raise CutoverPreflightError(
                "replacement admission changed after publication"
            )
        return {
            "schema": REPLACEMENT_ADMISSION_SCHEMA,
            "path": str(request.path),
            "receipt_digest": receipt_digest,
            "artifact_sha256": artifact_sha256,
            "expires_at_unix_ms": expires_at_unix_ms,
            "candidate_build_id": request.build_id,
            "candidate_config_fingerprint": request.config_fingerprint,
            "predecessor_build_id": expected_content[
                "predecessor_build_id"
            ],
            "authority_epoch_number": expected_content[
                "authority_epoch_number"
            ],
            "next_authority_epoch_number": expected_content[
                "next_authority_epoch_number"
            ],
            "delivery_audit_revision": expected_content[
                "delivery_audit_revision"
            ],
            "verified": True,
        }
    except CutoverPreflightError:
        raise
    except Exception as exc:
        raise CutoverPreflightError(
            "replacement admission signing or publication failed"
        ) from exc
    finally:
        store.close()


def verify_replacement_admission_for_core(
    *,
    root: Path,
    memory_db: Path,
    capture_root: Path,
    attestation_path: Path,
    expected_build_id: str,
    expected_config_fingerprint: str,
    inspection: Mapping[str, Any],
    delivery_audit: Mapping[str, Any],
    maximum_evidence_age_seconds: float = 7200.0,
    minimum_remaining_seconds: float = 0.0,
) -> dict[str, Any]:
    """Reverify a signed successor admission under the acquired core lease."""

    canonical_path = memory_db.parent / "core" / REPLACEMENT_ADMISSION_NAME
    for path, name in (
        (root, "repository root"),
        (memory_db, "live memory database"),
        (capture_root, "capture source root"),
        (attestation_path, "replacement admission"),
    ):
        _assert_no_symlink_components(path, name=name)
    if attestation_path != canonical_path:
        raise CutoverPreflightError(
            "core startup requires the canonical replacement admission"
        )
    if (
        _BUILD_ID.fullmatch(expected_build_id) is None
        or _SHA256.fullmatch(expected_config_fingerprint) is None
    ):
        raise CutoverPreflightError("expected replacement identity is invalid")
    head, dirty = _git_snapshot(root)
    try:
        current_build_id = _manifest_build_id(root)
    except Exception as exc:
        raise CutoverPreflightError(
            "current deterministic source build could not be verified"
        ) from exc
    payload = _read_json(attestation_path, name="replacement admission")
    if (
        dirty
        or current_build_id != expected_build_id
        or payload.get("git_head") != head
        or payload.get("candidate_build_id") != expected_build_id
        or payload.get("candidate_config_fingerprint")
        != expected_config_fingerprint
    ):
        raise CutoverPreflightError(
            "replacement admission does not match current source or configuration"
        )
    signature_store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        receipt_digest = _validate_replacement_admission(
            payload,
            store=signature_store,
            minimum_remaining_seconds=minimum_remaining_seconds,
        )
    finally:
        signature_store.close()
    receipt_path = _normal_absolute(
        str(payload["recovery_bundle_receipt_path"]),
        name="recovery bundle receipt",
    )
    restore_proof_path = _normal_absolute(
        str(payload["recovery_restore_proof_path"]),
        name="isolated restore proof",
    )
    recovery, _recovery_expires_at = _replacement_recovery_binding(
        memory_db=memory_db,
        capture_root=capture_root,
        receipt_path=receipt_path,
        restore_proof_path=restore_proof_path,
        maximum_evidence_age_seconds=maximum_evidence_age_seconds,
    )
    delivery = _replacement_delivery_binding(
        memory_db=memory_db,
        delivery_audit=delivery_audit,
    )
    expected_content = _replacement_admission_content(
        created_at_unix_ms=int(payload["created_at_unix_ms"]),
        expires_at_unix_ms=int(payload["expires_at_unix_ms"]),
        git_head=head,
        candidate_build_id=expected_build_id,
        candidate_config_fingerprint=expected_config_fingerprint,
        receipt_path=receipt_path,
        restore_proof_path=restore_proof_path,
        inspection=inspection,
        delivery_audit=delivery,
        recovery=recovery,
    )
    verification_store = DurableMemoryStore.open_existing_for_audit(memory_db)
    try:
        verified_digest = _validate_replacement_admission(
            payload,
            store=verification_store,
            expected_content=expected_content,
            expected_auth_key_id=str(recovery["recovery_auth_key_id"]),
            minimum_remaining_seconds=minimum_remaining_seconds,
        )
    finally:
        verification_store.close()
    if not secrets.compare_digest(verified_digest, receipt_digest):
        raise CutoverPreflightError(
            "replacement admission identity changed during verification"
        )
    result_keys = (
        "git_head",
        "candidate_build_id",
        "candidate_config_fingerprint",
        "governance_mode",
        "store_identity",
        "store_generation",
        "authority_epoch_number",
        "next_authority_epoch_number",
        "database_schema_identity",
        "database_logical_snapshot_schema",
        "database_logical_snapshot_sha256",
        "capture_manifest_sha256",
        "runtime_state_required",
        "runtime_state_present",
        "runtime_state_canonical_sha256",
        "request_journal_id",
        "request_journal_schema_identity",
        "request_journal_logical_snapshot_schema",
        "request_journal_logical_snapshot_sha256",
        "request_journal_binding_receipt_digest",
        "restored_target",
        "restored_target_binding_receipt_digest",
        "recovery_bundle_receipt_digest",
        "recovery_restore_proof_receipt_digest",
        "predecessor_marker_sha256",
        "predecessor_marker_schema_version",
        "predecessor_service_required",
        "predecessor_instance_id",
        "predecessor_build_id",
        "predecessor_config_fingerprint",
        "predecessor_protocol_version",
        "predecessor_lock_generation_id",
        "predecessor_root_generation_id",
        "predecessor_embedding_space_identity",
        "predecessor_request_journal_id",
        "predecessor_request_journal_binding_schema",
        "predecessor_request_journal_schema_version",
        "predecessor_restored_target_binding_receipt_digest",
        "predecessor_runtime_publication_sha256",
        "delivery_audit_sha256",
        "delivery_audit_revision",
        "delivery_settled_audit_revision",
        "delivery_derivation_source_sha256",
        "delivery_derivation_source_row_count",
        "delivery_target_highwater",
        "delivery_latest_event_id",
    )
    return {
        "schema": REPLACEMENT_ADMISSION_VERIFICATION_SCHEMA,
        "verified": True,
        "receipt_digest": receipt_digest,
        "expires_at_unix_ms": int(payload["expires_at_unix_ms"]),
        **{key: expected_content[key] for key in result_keys},
    }


def _run_read_only(
    command: Sequence[str],
    *,
    timeout: float = 5.0,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CutoverPreflightError("read-only inventory command failed") from exc


def collect_process_inventory(
    *,
    ps_bin: str | os.PathLike[str] = "/bin/ps",
    lines: Iterable[str] | None = None,
) -> list[ProcessFinding]:
    """Return only PID and a fixed category; never return command text."""

    if lines is None:
        completed = _run_read_only([str(ps_bin), "-axo", "pid=,command="])
        if completed.returncode != 0:
            raise CutoverPreflightError("process inventory is unavailable")
        lines = completed.stdout.splitlines()
    categories = (
        ("authoritative-core", ("core_service.py",)),
        ("legacy-capture", ("capture_daemon.py",)),
        ("legacy-dashboard", ("neural_dashboard.py", "dashboard_server.py")),
        ("legacy-mcp-wrapper", ("mcp_client_wrapper.py",)),
    )
    findings: list[ProcessFinding] = []
    seen: set[int] = set()
    for line in lines:
        match = _PID_LINE.match(str(line))
        if match is None:
            continue
        pid = int(match.group(1))
        command = match.group(2)
        if pid in {os.getpid(), os.getppid()} or pid in seen:
            continue
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()
        basenames = {Path(token).name for token in tokens}
        category = next(
            (
                name
                for name, needles in categories
                if any(needle in basenames for needle in needles)
            ),
            None,
        )
        if category is None:
            continue
        findings.append(ProcessFinding(pid=pid, category=category))
        seen.add(pid)
        if len(findings) >= MAX_PROCESS_FINDINGS:
            break
    return findings


def _parse_launchctl_snapshot(text: str) -> dict[str, Any]:
    state = None
    pid = None
    for raw_line in text.splitlines()[:256]:
        parts = raw_line.strip().split()
        if len(parts) == 3 and parts[1] == "=":
            if parts[0] == "state" and parts[2] in {"running", "waiting", "exited"}:
                state = parts[2]
            elif parts[0] == "pid" and parts[2].isdigit():
                pid = int(parts[2])
    return {"loaded": True, "state": state, "pid": pid}


def _launchctl_domain_contains_label(text: str, *, label: str) -> bool:
    """Match one exact service label in a bounded launchd domain inventory."""

    if len(text.encode("utf-8", errors="replace")) > MAX_JSON_BYTES:
        raise CutoverPreflightError("launchd domain inventory exceeds its size limit")
    for raw_line in text.splitlines():
        fields = raw_line.strip().split()
        if fields and fields[-1] == label and "=" not in fields:
            return True
    return False


def _parse_launchctl_disabled_services(
    text: str,
    *,
    labels: Iterable[str],
) -> dict[str, bool | None]:
    """Parse exact launchd disabled overrides without inferring absence."""

    if len(text.encode("utf-8", errors="replace")) > MAX_JSON_BYTES:
        raise CutoverPreflightError(
            "launchd disabled-state inventory exceeds its size limit"
        )
    selected = set(labels)
    states: dict[str, bool | None] = {label: None for label in selected}
    observed: set[str] = set()
    for raw_line in text.splitlines():
        match = _DISABLED_SERVICE_LINE.fullmatch(raw_line)
        if match is None:
            continue
        label = match.group("label")
        if label not in selected:
            continue
        if label in observed:
            raise CutoverPreflightError(
                "launchd disabled-state inventory contains a duplicate service"
            )
        states[label] = match.group("disabled") in {"true", "disabled"}
        observed.add(label)
    return states


def launchctl_disabled_service_states(
    *,
    launchctl_bin: str | os.PathLike[str],
    uid: int,
    labels: Iterable[str],
) -> dict[str, bool | None]:
    """Return exact disabled overrides; ``None`` means not positively disabled."""

    selected = tuple(labels)
    if any(
        not isinstance(label, str)
        or _LABEL.fullmatch(label) is None
        or contains_secret_shape(label)
        for label in selected
    ):
        raise CutoverPreflightError("LaunchAgent inventory label is invalid")
    result = _run_read_only(
        [str(launchctl_bin), "print-disabled", f"gui/{int(uid)}"]
    )
    if result.returncode != 0:
        raise CutoverPreflightError(
            "launchd disabled-state inventory is unavailable"
        )
    return _parse_launchctl_disabled_services(result.stdout, labels=selected)


def launchctl_service_snapshot(
    *,
    launchctl_bin: str | os.PathLike[str],
    uid: int,
    label: str,
) -> dict[str, Any]:
    """Classify one service as loaded or positively proven absent."""

    if _LABEL.fullmatch(label) is None or contains_secret_shape(label):
        raise CutoverPreflightError("LaunchAgent inventory label is invalid")
    domain = f"gui/{int(uid)}"
    exact = _run_read_only([str(launchctl_bin), "print", f"{domain}/{label}"])
    if exact.returncode == 0:
        return {**_parse_launchctl_snapshot(exact.stdout), "classification": "loaded"}
    # A failed exact print is ambiguous: launchctl uses non-zero statuses for
    # both absence and operational failures.  Only a successful domain listing
    # that lacks the exact label is positive absence evidence.
    domain_result = _run_read_only([str(launchctl_bin), "print", domain])
    if domain_result.returncode != 0:
        raise CutoverPreflightError("launchd service absence could not be proven")
    if _launchctl_domain_contains_label(domain_result.stdout, label=label):
        raise CutoverPreflightError("launchd exact service lookup was inconsistent")
    return {
        "loaded": False,
        "state": None,
        "pid": None,
        "classification": "proven-absent",
    }


def collect_launchagent_inventory(
    *,
    launchctl_bin: str | os.PathLike[str] = "/bin/launchctl",
    uid: int | None = None,
    labels: Mapping[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    uid_value = os.getuid() if uid is None else int(uid)
    rules = quiescence_launch_agent_rules()
    selected = {category: rule.label for category, rule in rules.items()}
    if labels is not None:
        selected.update(dict(labels))
    # The reviewed external respawner cannot be renamed or omitted by a caller
    # supplying test/deployment overrides for the three SYNAPSE-S2 labels.
    respawner_category = "master_mold_capture_respawner"
    selected[respawner_category] = rules[respawner_category].label
    disabled_states = launchctl_disabled_service_states(
        launchctl_bin=launchctl_bin,
        uid=uid_value,
        labels=selected.values(),
    )
    inventory: dict[str, dict[str, Any]] = {}
    for category, label in selected.items():
        snapshot = launchctl_service_snapshot(
            launchctl_bin=launchctl_bin,
            uid=uid_value,
            label=label,
        )
        disabled = disabled_states[label]
        rule = rules.get(category)
        inventory[category] = {
            "label": label,
            **snapshot,
            "disabled": disabled,
            "enabled": None if disabled is None else not disabled,
            "quiescence_policy_schema": QUIESCENCE_POLICY_SCHEMA,
            "require_disabled_when_unloaded": bool(
                rule is not None and rule.require_disabled_when_unloaded
            ),
        }
    return inventory


def launchagent_quiescence_blockers(
    inventory: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    """Return loaded services and respawners not positively disabled."""

    blockers: list[str] = []
    for category, snapshot in inventory.items():
        loaded = snapshot.get("loaded") is True
        require_disabled = snapshot.get("require_disabled_when_unloaded") is True
        if loaded or (require_disabled and snapshot.get("disabled") is not True):
            blockers.append(category)
    return sorted(blockers)


@contextmanager
def exclusive_authority_lock(memory_db: Path):
    """Prove no cooperating authority is active without creating state."""

    _assert_no_symlink_components(memory_db, name="live memory database")
    core_directory = memory_db.parent / "core"
    _assert_no_symlink_components(
        core_directory,
        name="authoritative-core lock directory",
    )
    try:
        directory_stat = core_directory.lstat()
    except FileNotFoundError as exc:
        raise CutoverPreflightError("authoritative-core lock directory is missing") from exc
    if (
        stat.S_ISLNK(directory_stat.st_mode)
        or not stat.S_ISDIR(directory_stat.st_mode)
        or directory_stat.st_uid != os.getuid()
        or stat.S_IMODE(directory_stat.st_mode) != 0o700
    ):
        raise CutoverPreflightError("authoritative-core lock directory is unsafe")
    lock_path = core_directory / "authority.lock"
    lock_stat = _safe_regular(lock_path, name="authoritative-core authority lock")
    if stat.S_IMODE(lock_stat.st_mode) != 0o600:
        raise CutoverPreflightError("authoritative-core authority lock has an unsafe mode")
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags)
    except OSError as exc:
        raise CutoverPreflightError("authoritative-core authority lock is unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (lock_stat.st_dev, lock_stat.st_ino)
        ):
            raise CutoverPreflightError("authoritative-core authority lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CutoverPreflightError(
                "authoritative-core authority lock is held; writers are not quiescent"
            ) from exc
        yield
        visible = lock_path.lstat()
        if (
            (visible.st_dev, visible.st_ino) != (opened.st_dev, opened.st_ino)
            or visible.st_nlink != 1
        ):
            raise CutoverPreflightError(
                "authoritative-core authority lock changed during preflight"
            )
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _git_snapshot(root: Path) -> tuple[str, str]:
    head = _run_read_only(["/usr/bin/git", "-C", str(root), "rev-parse", "HEAD"])
    status = _run_read_only(
        ["/usr/bin/git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"]
    )
    if head.returncode != 0 or status.returncode != 0:
        raise CutoverPreflightError("repository identity is unavailable")
    observed_head = head.stdout.strip()
    if _GIT_OBJECT_ID.fullmatch(observed_head) is None:
        raise CutoverPreflightError("repository HEAD is invalid")
    return observed_head, status.stdout


def _check_by_id(manifest: Mapping[str, Any], check_id: str) -> Mapping[str, Any]:
    checks = manifest.get("checks")
    if not isinstance(checks, list):
        raise CutoverPreflightError("evidence manifest checks are invalid")
    matches = [
        item
        for item in checks
        if isinstance(item, dict) and item.get("check_id") == check_id
    ]
    if len(matches) != 1:
        raise CutoverPreflightError(f"evidence manifest lacks one {check_id} check")
    result = matches[0]
    if result.get("required") is not True or result.get("status") != "ready":
        raise CutoverPreflightError(f"evidence check {check_id} is not ready")
    return result


def _validate_operator_readiness_proof_contract(
    manifest: Mapping[str, Any],
) -> dict[str, Mapping[str, Any]]:
    """Validate the complete producer/consumer proof contract exactly."""

    checks = manifest.get("checks")
    if not isinstance(checks, list):
        raise CutoverPreflightError("evidence manifest checks are invalid")
    by_id: dict[str, Mapping[str, Any]] = {}
    for item in checks:
        if not isinstance(item, dict):
            raise CutoverPreflightError("evidence manifest checks are invalid")
        check_id = item.get("check_id")
        if (
            not isinstance(check_id, str)
            or _LABEL.fullmatch(check_id) is None
            or contains_secret_shape(check_id)
        ):
            raise CutoverPreflightError("evidence manifest check identity is invalid")
        if type(item.get("required")) is not bool:
            raise CutoverPreflightError("evidence manifest check requirement is invalid")
        if check_id in by_id:
            raise CutoverPreflightError(
                "evidence manifest check identities are not unique"
            )
        by_id[check_id] = item

    expected_ids = tuple(OPERATOR_READINESS_REQUIRED_PROOF_IDS)
    expected_set = set(expected_ids)
    required_set = {
        check_id
        for check_id, item in by_id.items()
        if item.get("required") is True
    }
    if required_set != expected_set:
        raise CutoverPreflightError(
            "evidence manifest required proof set does not match its contract"
        )
    if any(by_id[check_id].get("status") != "ready" for check_id in expected_ids):
        raise CutoverPreflightError("one or more required evidence checks are not ready")

    if manifest.get("required_proof_contract") != ready_operator_proof_contract():
        raise CutoverPreflightError(
            "evidence manifest required proof contract is invalid"
        )
    expected_total = len(expected_ids)
    if (
        type(manifest.get("required_total")) is not int
        or manifest.get("required_total") != expected_total
        or type(manifest.get("required_ready")) is not int
        or manifest.get("required_ready") != expected_total
        or manifest.get("failed_required") != []
    ):
        raise CutoverPreflightError(
            "evidence manifest required proof totals are invalid"
        )
    proofs = manifest.get("proofs")
    if not isinstance(proofs, dict) or set(proofs) != expected_set:
        raise CutoverPreflightError("evidence manifest proof summary is invalid")
    if any(proofs[check_id] != by_id[check_id] for check_id in expected_ids):
        raise CutoverPreflightError(
            "evidence manifest proof summary does not match its checks"
        )
    return by_id


def _validate_runtime_build_identity_proof(
    check: Mapping[str, Any],
    *,
    root: Path,
    expected_config_fingerprint: str,
    expected_authority_mode: str,
) -> str:
    """Reject a ready pack whose functional probes came from another build."""

    metrics = check.get("metrics")
    if not isinstance(metrics, dict):
        raise CutoverPreflightError("runtime build identity proof is invalid")
    expected_keys = {
        "schema",
        "proof_mode",
        "authority_mode",
        "expected_source_build_id",
        "observed_runtime_build_id",
        "expected_config_fingerprint",
        "observed_config_fingerprint",
        "matched",
    }
    allowed_keys = expected_keys | {"exact_matches"}
    metric_keys = frozenset(metrics)
    if metric_keys not in {frozenset(expected_keys), frozenset(allowed_keys)}:
        raise CutoverPreflightError("runtime build identity proof is invalid")
    try:
        # Keep the preflight module import-light: the wrapper imports
        # core_service only at proof-validation time.
        current_build_id = _manifest_build_id(root)
    except Exception as exc:
        raise CutoverPreflightError(
            "current deterministic source build could not be verified"
        ) from exc
    if (
        metrics.get("schema") != RUNTIME_BUILD_IDENTITY_SCHEMA
        or metrics.get("proof_mode")
        not in {"authoritative-core-health", "candidate-local-source"}
        or not isinstance(metrics.get("authority_mode"), str)
        or metrics.get("authority_mode") != expected_authority_mode
        or _BUILD_ID.fullmatch(
            str(metrics.get("expected_source_build_id") or "")
        )
        is None
        or _BUILD_ID.fullmatch(
            str(metrics.get("observed_runtime_build_id") or "")
        )
        is None
        or metrics.get("matched") is not True
        or not secrets.compare_digest(
            str(metrics.get("expected_source_build_id")), current_build_id
        )
        or not secrets.compare_digest(
            str(metrics.get("observed_runtime_build_id")), current_build_id
        )
        or not secrets.compare_digest(
            str(metrics.get("expected_config_fingerprint") or ""),
            expected_config_fingerprint,
        )
        or not secrets.compare_digest(
            str(metrics.get("observed_config_fingerprint") or ""),
            expected_config_fingerprint,
        )
    ):
        raise CutoverPreflightError(
            "runtime build identity does not match the current deterministic source"
        )
    exact_matches = metrics.get("exact_matches")
    if metrics.get("proof_mode") == "authoritative-core-health":
        if (
            expected_authority_mode == "candidate-local-v5"
            or not isinstance(exact_matches, dict)
            or set(exact_matches)
            != {
                "command_succeeded",
                "health_ready",
                "build_id_shape",
                "source_build",
                "config_fingerprint",
            }
            or any(value is not True for value in exact_matches.values())
        ):
            raise CutoverPreflightError(
                "authoritative runtime build identity proof is incomplete"
            )
    elif (
        expected_authority_mode != "candidate-local-v5"
        or exact_matches is not None
    ):
        raise CutoverPreflightError("runtime build identity proof is invalid")
    return current_build_id


def _validate_zero_replay_debt(
    reconciliation: Any,
    *,
    name: str,
) -> None:
    if not isinstance(reconciliation, dict):
        raise CutoverPreflightError(f"{name} is missing")
    for key in REPLAY_DEBT_COUNTERS:
        value = reconciliation.get(key)
        if type(value) is not int or value != 0:
            raise CutoverPreflightError(f"{name} contains unresolved work")


def _validate_recovery_metrics(check: Mapping[str, Any], *, restore: bool = False) -> None:
    metrics = check.get("metrics")
    if not isinstance(metrics, dict):
        raise CutoverPreflightError("recovery evidence metrics are invalid")
    if metrics.get("cutover_ready") is not True:
        raise CutoverPreflightError("recovery evidence is not cutover-ready")
    if restore and metrics.get("verified") is not True:
        raise CutoverPreflightError("isolated recovery restore is not verified")
    binding = metrics.get("capture_ledger_binding")
    if not isinstance(binding, dict) or binding.get("verified") is not True:
        raise CutoverPreflightError("capture ledger binding is not verified")
    _validate_zero_replay_debt(
        metrics.get("reconciliation"),
        name="recovery reconciliation",
    )


def _validate_restore_governance(proof: Mapping[str, Any]) -> str:
    schema_name = proof.get("schema")
    governance_mode = proof.get("governance_mode")
    store_identity = proof.get("store_identity")
    store_generation = proof.get("store_generation")
    if (
        schema_name
        not in {
            LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA,
            RECOVERY_BUNDLE_RESTORE_SCHEMA,
        }
        or governance_mode not in {"pre-governed-v5", "authoritative-v6"}
        or not isinstance(store_identity, str)
        or _STORE_IDENTITY.fullmatch(store_identity) is None
        or not isinstance(store_generation, str)
    ):
        raise CutoverPreflightError("isolated restore governance is invalid")
    if schema_name == LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA:
        if (
            governance_mode != "pre-governed-v5"
            or store_generation != "legacy-v5"
            or proof.get("authority_epoch_number") is not None
        ):
            raise CutoverPreflightError(
                "legacy restore proof is allowed only for a pre-governed v5 store"
            )
        return governance_mode
    if (
        proof.get("database_logical_snapshot_schema")
        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or _SHA256.fullmatch(
            str(proof.get("database_logical_snapshot_sha256") or "")
        )
        is None
        or _SHA256.fullmatch(str(proof.get("capture_manifest_sha256") or ""))
        is None
    ):
        raise CutoverPreflightError(
            "isolated restore lacks exact database or capture evidence"
        )
    runtime_required = proof.get("runtime_state_required")
    runtime_present = proof.get("runtime_state_present")
    runtime_fields = (
        proof.get("runtime_state_artifact_relative"),
        proof.get("runtime_state_sha256"),
        proof.get("runtime_state_canonical_sha256"),
        proof.get("source_runtime_state_sha256"),
        proof.get("source_runtime_state_canonical_sha256"),
    )
    if (
        type(runtime_required) is not bool
        or type(runtime_present) is not bool
        or runtime_required != runtime_present
        or (
            runtime_present
            and (
                runtime_fields[0] != "runtime_state.json"
                or any(
                    _SHA256.fullmatch(str(value or "")) is None
                    for value in runtime_fields[1:]
                )
            )
        )
        or (not runtime_present and any(value is not None for value in runtime_fields))
    ):
        raise CutoverPreflightError(
            "isolated restore runtime-state evidence is invalid"
        )
    if governance_mode == "pre-governed-v5":
        if (
            store_generation != "legacy-v5"
            or proof.get("authority_epoch_number") is not None
            or proof.get("request_journal_sha256") is not None
            or proof.get("request_journal_binding_receipt_digest") is not None
            or proof.get("source_request_journal_binding_receipt_digest") is not None
            or proof.get("request_journal_id") is not None
            or proof.get("request_journal_schema_identity") is not None
            or proof.get("request_journal_logical_snapshot_schema") is not None
            or proof.get("request_journal_logical_snapshot_sha256") is not None
            or proof.get("request_journal_artifact_relative") is not None
            or proof.get("request_journal_binding_receipt_relative") is not None
            or proof.get("request_journal_binding_verified") not in {None, False}
        ):
            raise CutoverPreflightError("pre-governed restore generation is invalid")
        return governance_mode
    epoch_number = proof.get("authority_epoch_number")
    if (
        _STORE_GENERATION.fullmatch(store_generation) is None
        or type(epoch_number) is not int
        or epoch_number < 1
        or store_generation != f"epoch-{epoch_number}"
        or _SHA256.fullmatch(str(proof.get("request_journal_sha256") or "")) is None
        or _SHA256.fullmatch(
            str(proof.get("request_journal_binding_receipt_digest") or "")
        )
        is None
        or _SHA256.fullmatch(
            str(proof.get("source_request_journal_binding_receipt_digest") or "")
        )
        is None
        or _REQUEST_JOURNAL_ID.fullmatch(
            str(proof.get("request_journal_id") or "")
        )
        is None
        or proof.get("request_journal_schema_identity")
        != JOURNAL_SCHEMA_IDENTITY
        or proof.get("request_journal_logical_snapshot_schema")
        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or _SHA256.fullmatch(
            str(proof.get("request_journal_logical_snapshot_sha256") or "")
        )
        is None
        or proof.get("request_journal_artifact_relative") != "core/requests.sqlite3"
        or proof.get("request_journal_binding_receipt_relative")
        != "core/requests.sqlite3.binding.receipt.json"
        or proof.get("request_journal_binding_verified") is not True
    ):
        raise CutoverPreflightError(
            "authoritative v6 restore proof lacks verified request-journal evidence"
        )
    return governance_mode


def validate_evidence_contract(
    manifest_path: Path,
    *,
    root: Path,
    maximum_age_seconds: float,
    require_git_binding: bool = True,
    expected_config_fingerprint: str | None = None,
) -> tuple[dict[str, Any], Path, dict[str, Any], Path]:
    maximum_age = _maximum_evidence_age(maximum_age_seconds)
    observed_now = _current_unix_timestamp_seconds()
    manifest = _read_json(manifest_path, name="evidence manifest")
    if (
        manifest.get("overall_status") != "ready"
        or manifest.get("operator_trustworthy") is not True
    ):
        raise CutoverPreflightError("operator-readiness evidence is not ready")
    _freshness_age_seconds(
        manifest.get("created_at"),
        name="operator-readiness evidence",
        now=observed_now,
        maximum_age_seconds=maximum_age,
    )
    git = manifest.get("git")
    if not isinstance(git, dict) or git.get("status_short") != "":
        raise CutoverPreflightError("evidence was not produced from a clean repository")
    if require_git_binding:
        head, dirty = _git_snapshot(root)
        if dirty or git.get("head") != head:
            raise CutoverPreflightError("evidence is not bound to the current clean HEAD")
    core_config_contract = validate_core_config_evidence_contract(
        manifest.get("core_config_contract"),
        expected_config_fingerprint=expected_config_fingerprint,
    )
    if (
        manifest.get("quiescence_policy_contract")
        != quiescence_policy_contract()
        or manifest.get("quiescence_policy_digest")
        != quiescence_policy_digest()
    ):
        raise CutoverPreflightError(
            "operator-readiness quiescence policy binding is invalid"
        )
    by_id = _validate_operator_readiness_proof_contract(manifest)
    authority_route = manifest.get("authority_route")
    if (
        not isinstance(authority_route, dict)
        or authority_route.get("mode")
        not in {
            "candidate-local-v5",
            "authoritative-core-v6",
            "explicit-socket",
            "durable-marker",
        }
        or authority_route.get("candidate_config_fingerprint")
        != core_config_contract["config_fingerprint"]
    ):
        raise CutoverPreflightError(
            "operator-readiness authority route binding is invalid"
        )
    current_build_id = _validate_runtime_build_identity_proof(
        by_id["runtime_build_identity"],
        root=root,
        expected_config_fingerprint=str(
            core_config_contract["config_fingerprint"]
        ),
        expected_authority_mode=str(authority_route["mode"]),
    )
    if manifest.get("expected_source_build_id") != current_build_id:
        raise CutoverPreflightError(
            "operator-readiness source build binding is invalid"
        )

    backup = _check_by_id(manifest, "recovery_backup")
    verify = _check_by_id(manifest, "recovery_verify")
    restore = _check_by_id(manifest, "recovery_restore")
    _validate_recovery_metrics(backup)
    _validate_recovery_metrics(verify)
    _validate_recovery_metrics(restore, restore=True)
    verify_metrics = verify.get("metrics")
    if not isinstance(verify_metrics, dict) or verify_metrics.get("verified") is not True:
        raise CutoverPreflightError("signed recovery verification is not ready")
    artifact_paths = verify.get("artifact_paths")
    if not isinstance(artifact_paths, dict) or not isinstance(artifact_paths.get("parsed"), str):
        raise CutoverPreflightError("recovery verification artifact is missing")
    parsed_path = _normal_absolute(artifact_paths["parsed"], name="recovery verification artifact")
    expected_artifact_root = manifest_path.parent / "artifacts"
    if parsed_path.parent.resolve() != expected_artifact_root.resolve():
        raise CutoverPreflightError("recovery verification artifact escaped its evidence pack")
    parsed = _read_json(parsed_path, name="recovery verification artifact")
    if (
        parsed.get("verified") is not True
        or parsed.get("cutover_ready") is not True
        or parsed.get("receipt_identity_trusted") is not True
    ):
        raise CutoverPreflightError("recovery verification artifact is not trusted")
    _freshness_age_seconds(
        parsed.get("verified_at"),
        name="recovery verification",
        now=observed_now,
        maximum_age_seconds=maximum_age,
    )
    parsed_binding = parsed.get("capture_ledger_binding")
    if not isinstance(parsed_binding, dict) or parsed_binding.get("verified") is not True:
        raise CutoverPreflightError("verified capture ledger binding is missing")
    _validate_zero_replay_debt(
        parsed.get("reconciliation"),
        name="verified recovery reconciliation",
    )
    receipt_raw = parsed.get("bundle_receipt_path")
    if not isinstance(receipt_raw, str):
        raise CutoverPreflightError("verified recovery receipt path is missing")
    restore_artifacts = restore.get("artifact_paths")
    if (
        not isinstance(restore_artifacts, dict)
        or not isinstance(restore_artifacts.get("recovery_proof"), str)
    ):
        raise CutoverPreflightError("isolated restore proof artifact is missing")
    restore_path = _normal_absolute(
        restore_artifacts["recovery_proof"],
        name="isolated restore proof",
    )
    if restore_path.parent.resolve() != expected_artifact_root.resolve():
        raise CutoverPreflightError("isolated restore proof escaped its evidence pack")
    restore_proof = _read_json(restore_path, name="isolated restore proof")
    restore_governance = _validate_restore_governance(restore_proof)
    restore_binding = restore_proof.get("capture_ledger_binding")
    if (
        restore_proof.get("mode") != "isolated-recovery-proof"
        or restore_proof.get("verified") is not True
        or restore_proof.get("cutover_ready") is not True
        or restore_proof.get("missing_transport_ledger_count") != 0
        or not isinstance(restore_binding, dict)
        or restore_binding.get("verified") is not True
    ):
        raise CutoverPreflightError("isolated restore proof is not cutover-ready")
    _validate_zero_replay_debt(
        restore_proof.get("reconciliation"),
        name="isolated restore reconciliation",
    )
    if (
        parsed.get("governance_mode") != restore_governance
        or parsed.get("store_identity") != restore_proof.get("store_identity")
        or parsed.get("store_generation") != restore_proof.get("store_generation")
    ):
        raise CutoverPreflightError(
            "verified recovery and isolated restore governance do not match"
        )
    if restore_proof.get("schema") == RECOVERY_BUNDLE_RESTORE_SCHEMA:
        parsed_database = parsed.get("database")
        parsed_capture_manifest = parsed.get("capture_manifest_sha256")
        parsed_runtime = parsed.get("runtime_state")
        if (
            not isinstance(parsed_database, dict)
            or parsed_database.get("logical_snapshot_schema")
            != restore_proof.get("database_logical_snapshot_schema")
            or parsed_database.get("logical_snapshot_sha256")
            != restore_proof.get("database_logical_snapshot_sha256")
            or parsed_capture_manifest
            != restore_proof.get("capture_manifest_sha256")
        ):
            raise CutoverPreflightError(
                "verified recovery exact database or capture evidence does not match isolated restore"
            )
        if restore_proof.get("runtime_state_present"):
            if (
                not isinstance(parsed_runtime, dict)
                or parsed_runtime.get("sha256")
                != restore_proof.get("source_runtime_state_sha256")
                or parsed_runtime.get("canonical_sha256")
                != restore_proof.get("source_runtime_state_canonical_sha256")
            ):
                raise CutoverPreflightError(
                    "verified recovery runtime state does not match isolated restore"
                )
        elif parsed_runtime is not None:
            raise CutoverPreflightError(
                "verified recovery claims runtime state absent from isolated restore"
            )
    if restore_governance == "authoritative-v6":
        journal = parsed.get("request_journal")
        journal_binding = parsed.get("request_journal_binding")
        if (
            not isinstance(journal, dict)
            or journal.get("sha256") != restore_proof.get("request_journal_sha256")
            or journal.get("logical_snapshot_schema")
            != restore_proof.get("request_journal_logical_snapshot_schema")
            or journal.get("logical_snapshot_sha256")
            != restore_proof.get("request_journal_logical_snapshot_sha256")
            or journal.get("journal_id")
            != restore_proof.get("request_journal_id")
            or journal.get("schema_identity")
            != restore_proof.get("request_journal_schema_identity")
            or not isinstance(journal_binding, dict)
            or journal_binding.get("verified") is not True
            or journal_binding.get("receipt_digest")
            != restore_proof.get("source_request_journal_binding_receipt_digest")
        ):
            raise CutoverPreflightError(
                "verified recovery request journal does not match isolated restore"
            )
    return (
        parsed,
        _normal_absolute(receipt_raw, name="verified recovery receipt"),
        restore_proof,
        restore_path,
    )


def inspect_database_contract(memory_db: Path) -> dict[str, Any]:
    _safe_regular(memory_db, name="live memory database")
    wal = memory_db.with_name(memory_db.name + "-wal")
    if wal.exists() or wal.is_symlink():
        wal_stat = _safe_regular(wal, name="live SQLite WAL", require_private=False)
        if wal_stat.st_size:
            raise CutoverPreflightError("live SQLite WAL is nonempty; writers are not quiescent")
    journal = memory_db.with_name(memory_db.name + "-journal")
    if journal.exists() or journal.is_symlink():
        journal_stat = _safe_regular(
            journal,
            name="live SQLite rollback journal",
            require_private=False,
        )
        if journal_stat.st_size:
            raise CutoverPreflightError(
                "live SQLite rollback journal is nonempty; writers are not quiescent"
            )
    uri = memory_db.resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=1.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        quick = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        foreign_errors = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        marker = None
        table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='store_metadata'"
        ).fetchone()
        if table is not None:
            row = connection.execute(
                "SELECT value_json FROM store_metadata WHERE key = ?",
                (CORE_AUTHORITY_METADATA_KEY,),
            ).fetchone()
            if row is not None:
                marker = _strict_json_loads(
                    str(row[0]),
                    name="core authority marker",
                )
    except (sqlite3.Error, CutoverPreflightError) as exc:
        raise CutoverPreflightError("live memory database inspection failed") from exc
    finally:
        if "connection" in locals():
            connection.close()
    if quick != ["ok"] or foreign_errors:
        raise CutoverPreflightError("live memory database integrity is not clean")
    if user_version == 5 and marker is not None:
        raise CutoverPreflightError("local schema v5 unexpectedly carries a core marker")
    if user_version == 6:
        if not isinstance(marker, dict) or marker.get("service_required") is not True:
            raise CutoverPreflightError("schema v6 lacks its authoritative-core marker")
    elif user_version != 5:
        raise CutoverPreflightError("live memory database schema is not v5 or v6")
    return {
        "user_version": user_version,
        "authority_marker": marker is not None,
        "quick_check": "ok",
        "foreign_key_error_count": foreign_errors,
    }


def _inspect_database_contract_wal_aware(
    store: DurableMemoryStore,
) -> dict[str, Any]:
    """Read live identity/integrity without immutable SQLite semantics."""

    before = _safe_regular(store.db_path, name="live memory database")
    try:
        connection = store._connect_read_only()
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("BEGIN")
        try:
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            user_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            quick = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
            foreign_errors = sum(
                1 for _row in connection.execute("PRAGMA foreign_key_check")
            )
            marker = store._core_authority_marker(connection)
            store._validate_core_authority_version_pair(connection, marker)
        finally:
            connection.execute("ROLLBACK")
    except Exception as exc:
        raise CutoverPreflightError(
            "WAL-aware live database inspection failed"
        ) from exc
    finally:
        if "connection" in locals():
            connection.close()
    after = store.db_path.lstat()
    if (
        (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or not stat.S_ISREG(after.st_mode)
        or stat.S_ISLNK(after.st_mode)
        or after.st_uid != os.getuid()
        or after.st_nlink != 1
    ):
        raise CutoverPreflightError(
            "live memory database identity changed during inspection"
        )
    if quick != ["ok"] or foreign_errors:
        raise CutoverPreflightError("live memory database integrity is not clean")
    if marker is None:
        governance = {
            "governance_mode": "pre-governed-v5",
            "store_generation": "legacy-v5",
            "authority_epoch_number": None,
        }
    else:
        governance = {
            "governance_mode": "authoritative-v6",
            "store_generation": f"epoch-{int(marker['epoch'])}",
            "authority_epoch_number": int(marker["epoch"]),
        }
    return {
        "restore_eligible": True,
        "schema_identity": f"sqlite-{application_id:x}-v{user_version}",
        "authority_binding": governance,
    }


def _recompute_live_capture_manifest_with_held_repository_lock(
    manager: VerifiedRecoveryManager,
    *,
    database_binding: Mapping[str, Any],
    capture_maintenance_lock_held: bool,
) -> dict[str, Any]:
    """Recompute live capture state without reacquiring the repository lock.

    Replacement publication runs inside ``guarded_recovery_transaction`` and
    therefore already owns both the repository and capture-maintenance locks.
    Replacement verification owns the repository lock shared and acquires only
    the existing capture-maintenance lock here.  Keeping those two ownership
    modes explicit avoids a self-deadlock while preserving repository-before-
    capture lock ordering.
    """

    if type(capture_maintenance_lock_held) is not bool:
        raise CutoverPreflightError(
            "capture-maintenance lock ownership is invalid"
        )
    expected_binding_keys = {
        "artifact_sha256",
        "receipt_digest",
        "auth_key_id",
        "schema_contract_version",
        "snapshot_revision",
        "logical_snapshot_schema",
        "logical_snapshot_sha256",
        "capture_operation_count",
        "capture_operation_highwater_micros",
        "capture_root_provenance",
        "capture_root_identity_digest",
    }
    binding = dict(database_binding) if isinstance(database_binding, Mapping) else {}
    if (
        set(binding) != expected_binding_keys
        or binding.get("logical_snapshot_schema")
        != LOGICAL_SNAPSHOT_DIGEST_SCHEMA
        or any(
            _SHA256.fullmatch(str(binding.get(field) or "")) is None
            for field in (
                "artifact_sha256",
                "receipt_digest",
                "auth_key_id",
                "snapshot_revision",
                "logical_snapshot_sha256",
                "capture_root_identity_digest",
            )
        )
    ):
        raise CutoverPreflightError(
            "capture attestation database binding is invalid"
        )

    paths = manager.daemon.paths()
    capture_lock = paths["lock_dir"] / GLOBAL_CAPTURE_LOCK
    if not capture_maintenance_lock_held:
        _assert_no_symlink_components(
            capture_lock,
            name="capture maintenance lock",
        )
    capture_scope = (
        nullcontext()
        if capture_maintenance_lock_held
        else manager._existing_private_file_lock(
            capture_lock,
            mode=fcntl.LOCK_EX,
            timeout_seconds=30.0,
        )
    )
    with capture_scope:
        root_provenance = manager._validate_capture_source_root()
        if (
            root_provenance["capture_root_provenance"]
            != binding["capture_root_provenance"]
            or root_provenance["capture_root_identity_digest"]
            != binding["capture_root_identity_digest"]
        ):
            raise CutoverPreflightError(
                "live capture root does not match its signed database binding"
            )
        with closing(manager.store._connect_read_only()) as conn:
            with manager.store._transaction(conn):
                ledger_bindings = manager._snapshot_capture_ledger_bindings(conn)
        capture_highwater_micros = int(
            max(
                (
                    float(item["committed_at"])
                    for item in ledger_bindings.values()
                ),
                default=0.0,
            )
            * 1_000_000
        )
        if (
            int(binding["capture_operation_count"]) != len(ledger_bindings)
            or int(binding["capture_operation_highwater_micros"])
            != capture_highwater_micros
        ):
            raise CutoverPreflightError(
                "live capture ledger is newer than its signed database binding"
            )
        manifest = manager._capture_inventory(
            ledger_ids=set(ledger_bindings),
            database_binding=binding,
            initialize_transport=False,
        )
    return {
        "manifest_sha256": str(manifest["manifest_sha256"]),
        "file_count": int(manifest["file_count"]),
        "total_bytes": int(manifest["total_bytes"]),
        "database_binding": dict(manifest["database_binding"]),
        "reconciliation": dict(manifest["reconciliation"]),
        "verified": True,
    }


def verify_recovery_binding(
    *,
    parsed: Mapping[str, Any],
    receipt_path: Path,
    restore_proof: Mapping[str, Any],
    restore_proof_path: Path,
    memory_db: Path,
    capture_root: Path,
    restored_target: bool = False,
    repository_lock_held: bool = False,
    capture_maintenance_lock_held: bool = False,
) -> dict[str, Any]:
    if type(restored_target) is not bool:
        raise CutoverPreflightError("restored-target request must be boolean")
    if (
        type(repository_lock_held) is not bool
        or type(capture_maintenance_lock_held) is not bool
        or (capture_maintenance_lock_held and not repository_lock_held)
    ):
        raise CutoverPreflightError("recovery lock ownership is invalid")
    for path, name in (
        (receipt_path, "recovery bundle receipt"),
        (restore_proof_path, "isolated restore proof"),
        (memory_db, "live memory database"),
        (capture_root, "capture source root"),
    ):
        _assert_no_symlink_components(path, name=name)
    store = DurableMemoryStore.open_existing_for_audit(memory_db)
    manager = VerifiedRecoveryManager(store, capture_root=capture_root)
    try:
        receipt, identity_trusted = manager._read_bundle_receipt(receipt_path)
        if not identity_trusted:
            raise CutoverPreflightError("recovery bundle signer is not trusted locally")
        if (
            receipt.get("schema") != RECOVERY_BUNDLE_SCHEMA
            or restore_proof.get("schema") != RECOVERY_BUNDLE_RESTORE_SCHEMA
        ):
            raise CutoverPreflightError(
                "cutover requires current exact-state recovery evidence"
            )
        database_path = receipt_path.parent / str(receipt["database_artifact_name"])
        database_receipt_path = receipt_path.parent / str(receipt["database_receipt_name"])
        capture_path = receipt_path.parent / str(receipt["capture_artifact_name"])
        for path, name in (
            (database_path, "recovery database"),
            (database_receipt_path, "recovery database receipt"),
            (capture_path, "capture recovery archive"),
        ):
            _assert_no_symlink_components(path, name=name)
        database_receipt, database_identity_trusted = store._read_trusted_backup_receipt(
            database_receipt_path,
            artifact=database_path,
        )
        if not database_identity_trusted:
            raise CutoverPreflightError("recovery database signer is not trusted locally")
        persisted_restore_proof = _read_json(
            restore_proof_path,
            name="isolated restore proof",
        )
        # The isolated drill receipt is signed by the same local recovery key.
        # Its bytes were already read through a stable, private-file check.
        if (
            persisted_restore_proof != dict(restore_proof)
            or restore_proof.get("auth_key_id") != receipt.get("auth_key_id")
            or database_receipt.get("auth_key_id") != receipt.get("auth_key_id")
            or restore_proof.get("receipt_digest")
            != store._canonical_payload_digest(dict(restore_proof))
            or not store._verify_receipt_authenticator(dict(restore_proof))
            or restore_proof.get("bundle_receipt_name") != receipt_path.name
        ):
            raise CutoverPreflightError("isolated restore proof signature is invalid")
        database_sha, database_size = _stable_sha256(database_path, name="recovery database")
        capture_sha, capture_size = _stable_sha256(capture_path, name="capture recovery archive")
        if (
            database_sha != receipt.get("database_sha256")
            or database_sha != database_receipt.get("artifact_sha256")
            or database_size != int(receipt.get("database_size_bytes", -1))
            or capture_sha != receipt.get("capture_sha256")
            or capture_size != int(receipt.get("capture_size_bytes", -1))
            or restore_proof.get("database_sha256") != database_sha
            or restore_proof.get("capture_sha256") != capture_sha
        ):
            raise CutoverPreflightError("signed recovery artifacts changed after verification")
        parsed_database = parsed.get("database")
        parsed_capture = parsed.get("capture")
        parsed_capture_binding = parsed.get("capture_database_binding")
        if (
            not isinstance(parsed_database, dict)
            or parsed_database.get("sha256") != database_sha
            or not isinstance(parsed_capture, dict)
            or parsed_capture.get("sha256") != capture_sha
            or not isinstance(parsed_capture_binding, dict)
        ):
            raise CutoverPreflightError(
                "evidence artifact does not match its signed recovery bundle"
            )
        if (
            parsed_database.get("logical_snapshot_schema")
            != receipt.get("database_logical_snapshot_schema")
            or parsed_database.get("logical_snapshot_sha256")
            != receipt.get("database_logical_snapshot_sha256")
            or database_receipt.get("logical_snapshot_schema")
            != receipt.get("database_logical_snapshot_schema")
            or database_receipt.get("logical_snapshot_sha256")
            != receipt.get("database_logical_snapshot_sha256")
            or restore_proof.get("database_logical_snapshot_schema")
            != receipt.get("database_logical_snapshot_schema")
            or restore_proof.get("database_logical_snapshot_sha256")
            != receipt.get("database_logical_snapshot_sha256")
        ):
            raise CutoverPreflightError(
                "signed recovery database logical snapshots do not match"
            )
        inspection = _inspect_database_contract_wal_aware(store)
        live_database = store.recompute_logical_snapshot_digest()
        live_authority = inspection.get("authority_binding")
        if (
            not inspection.get("restore_eligible")
            or not isinstance(live_authority, dict)
            or live_database.get("schema")
            != receipt.get("database_logical_snapshot_schema")
            or live_database.get("sha256")
            != receipt.get("database_logical_snapshot_sha256")
        ):
            raise CutoverPreflightError("verified recovery is stale relative to the live database")
        governance_mode = str(receipt.get("governance_mode") or "")
        store_identity = manager._store_identity()
        store_generation = str(receipt.get("store_generation") or "")
        authority_epoch = receipt.get("authority_epoch_number")
        if (
            parsed.get("governance_mode") != governance_mode
            or restore_proof.get("governance_mode") != governance_mode
            or live_authority.get("governance_mode") != governance_mode
            or parsed.get("store_identity") != store_identity
            or restore_proof.get("store_identity") != store_identity
            or receipt.get("store_identity") != store_identity
            or parsed.get("store_generation") != store_generation
            or restore_proof.get("store_generation") != store_generation
            or live_authority.get("store_generation") != store_generation
            or parsed_database.get("authority_epoch_number") != authority_epoch
            or restore_proof.get("authority_epoch_number") != authority_epoch
            or live_authority.get("authority_epoch_number") != authority_epoch
            or parsed_database.get("schema_identity")
            != inspection.get("schema_identity")
        ):
            raise CutoverPreflightError(
                "signed recovery governance does not match the live database"
            )

        expected_capture_binding = {
            "artifact_sha256": database_sha,
            "receipt_digest": database_receipt.get("receipt_digest"),
            "auth_key_id": database_receipt.get("auth_key_id"),
            "schema_contract_version": database_receipt.get(
                "schema_contract_version"
            ),
            "snapshot_revision": receipt.get("database_snapshot_revision"),
            "logical_snapshot_schema": receipt.get(
                "database_logical_snapshot_schema"
            ),
            "logical_snapshot_sha256": receipt.get(
                "database_logical_snapshot_sha256"
            ),
            "capture_operation_count": receipt.get("capture_operation_count"),
            "capture_operation_highwater_micros": receipt.get(
                "capture_operation_highwater_micros"
            ),
            "capture_root_provenance": receipt.get("capture_root_provenance"),
            "capture_root_identity_digest": receipt.get(
                "capture_root_identity_digest"
            ),
        }
        if parsed_capture_binding != expected_capture_binding:
            raise CutoverPreflightError(
                "verified capture manifest has the wrong database binding"
            )
        live_capture = (
            _recompute_live_capture_manifest_with_held_repository_lock(
                manager,
                database_binding=dict(parsed_capture_binding),
                capture_maintenance_lock_held=capture_maintenance_lock_held,
            )
            if repository_lock_held
            else manager.recompute_live_capture_manifest(
                database_binding=dict(parsed_capture_binding),
            )
        )
        if (
            live_capture.get("manifest_sha256")
            != receipt.get("capture_manifest_sha256")
            or parsed.get("capture_manifest_sha256")
            != receipt.get("capture_manifest_sha256")
            or parsed_capture.get("manifest_sha256")
            != receipt.get("capture_manifest_sha256")
            or restore_proof.get("capture_manifest_sha256")
            != receipt.get("capture_manifest_sha256")
            or live_capture.get("file_count") != receipt.get("capture_file_count")
            or parsed_capture.get("file_count") != receipt.get("capture_file_count")
            or restore_proof.get("capture_file_count")
            != receipt.get("capture_file_count")
            or live_capture.get("total_bytes") != receipt.get("capture_total_bytes")
            or parsed_capture.get("total_bytes") != receipt.get("capture_total_bytes")
            or live_capture.get("database_binding") != expected_capture_binding
            or live_capture.get("reconciliation") != parsed.get("reconciliation")
            or live_capture.get("reconciliation")
            != restore_proof.get("reconciliation")
        ):
            raise CutoverPreflightError(
                "verified recovery is stale relative to live capture state"
            )

        runtime_required = bool(receipt.get("runtime_state_required"))
        runtime_lock_path = manager.runtime_state_path.with_name(
            f".{manager.runtime_state_path.name}.lock"
        )
        signed_runtime_absence_without_lock = bool(
            not runtime_required
            and not manager.runtime_state_path.exists()
            and not manager.runtime_state_path.is_symlink()
            and not runtime_lock_path.exists()
            and not runtime_lock_path.is_symlink()
        )
        live_runtime = (
            {
                "required": False,
                "present": False,
                "artifact_sha256": None,
                "canonical_sha256": None,
                "state_schema_version": None,
                "size_bytes": 0,
                "verified": True,
            }
            if signed_runtime_absence_without_lock
            else manager.recompute_live_runtime_state_binding(
                required=runtime_required,
            )
        )
        parsed_runtime = parsed.get("runtime_state")
        if (
            live_runtime.get("required") is not runtime_required
            or live_runtime.get("present") is not runtime_required
            or restore_proof.get("runtime_state_required") is not runtime_required
            or restore_proof.get("runtime_state_present") is not runtime_required
        ):
            raise CutoverPreflightError(
                "live runtime-state presence does not match signed recovery"
            )
        runtime_canonical_sha256: str | None = None
        if runtime_required:
            runtime_path = receipt_path.parent / str(
                receipt["runtime_state_artifact_name"]
            )
            _assert_no_symlink_components(
                runtime_path,
                name="recovery runtime state",
            )
            runtime_artifact = manager._verify_runtime_state_artifact(
                runtime_path,
                expected_sha256=str(receipt["runtime_state_sha256"]),
            )
            runtime_canonical_sha256 = str(live_runtime["canonical_sha256"])
            if (
                not isinstance(parsed_runtime, dict)
                or runtime_artifact.get("sha256")
                != receipt.get("runtime_state_sha256")
                or runtime_artifact.get("canonical_sha256")
                != receipt.get("runtime_state_canonical_sha256")
                or parsed_runtime.get("sha256")
                != receipt.get("runtime_state_sha256")
                or parsed_runtime.get("canonical_sha256")
                != receipt.get("runtime_state_canonical_sha256")
                or live_runtime.get("artifact_sha256")
                != receipt.get("runtime_state_sha256")
                or live_runtime.get("canonical_sha256")
                != receipt.get("runtime_state_canonical_sha256")
                or restore_proof.get("source_runtime_state_sha256")
                != receipt.get("runtime_state_sha256")
                or restore_proof.get("source_runtime_state_canonical_sha256")
                != receipt.get("runtime_state_canonical_sha256")
            ):
                raise CutoverPreflightError(
                    "signed recovery is stale relative to live runtime state"
                )
        elif parsed_runtime is not None:
            raise CutoverPreflightError(
                "signed recovery runtime-state absence is inconsistent"
            )

        journal_schema: str | None = None
        journal_sha256: str | None = None
        journal_id: str | None = None
        journal_schema_identity: str | None = None
        journal_binding_digest: str | None = None
        restored_target_binding_digest: str | None = None
        journal_path = memory_db.parent / "core" / "requests.sqlite3"
        journal_binding_path = journal_path.with_name(
            "requests.sqlite3.binding.receipt.json"
        )
        if governance_mode == "authoritative-v6":
            source_journal_path = receipt_path.parent / str(
                receipt["request_journal_artifact_name"]
            )
            source_binding_path = receipt_path.parent / str(
                receipt["request_journal_binding_receipt_name"]
            )
            for path, name in (
                (journal_path, "live request journal"),
                (source_journal_path, "recovery request journal"),
                (source_binding_path, "recovery request-journal binding"),
            ):
                _assert_no_symlink_components(path, name=name)
            source_journal = manager._verify_request_journal_artifact(
                source_journal_path,
                expected_sha256=str(receipt["request_journal_sha256"]),
                maximum_authority_epoch=int(authority_epoch),
            )
            source_binding, source_binding_trusted = (
                manager._read_request_journal_binding_receipt(
                    source_binding_path
                )
            )
            live_journal = manager.recompute_request_journal_logical_digest(
                maximum_authority_epoch=int(authority_epoch),
            )
            parsed_journal = parsed.get("request_journal")
            parsed_journal_binding = parsed.get("request_journal_binding")
            journal_schema = str(live_journal["logical_snapshot_schema"])
            journal_sha256 = str(live_journal["logical_snapshot_sha256"])
            journal_id = str(live_journal["journal_id"])
            journal_schema_identity = str(live_journal["schema_identity"])
            journal_binding_digest = str(source_binding["receipt_digest"])
            if (
                not source_binding_trusted
                or source_binding.get("auth_key_id") != receipt.get("auth_key_id")
                or source_binding.get("receipt_digest")
                != receipt.get("request_journal_binding_receipt_digest")
                or source_binding.get("database_logical_snapshot_schema")
                != live_database.get("schema")
                or source_binding.get("database_logical_snapshot_sha256")
                != live_database.get("sha256")
                or source_binding.get("store_identity") != store_identity
                or source_binding.get("store_generation") != store_generation
                or source_binding.get("authority_epoch_number") != authority_epoch
                or source_binding.get("request_journal_id") != journal_id
                or source_binding.get("journal_schema_identity")
                != journal_schema_identity
                or not isinstance(parsed_journal, dict)
                or not isinstance(parsed_journal_binding, dict)
                or parsed_journal_binding.get("receipt_digest")
                != journal_binding_digest
                or source_journal.get("logical_snapshot_schema") != journal_schema
                or source_journal.get("logical_snapshot_sha256") != journal_sha256
                or source_journal.get("journal_id") != journal_id
                or source_journal.get("schema_identity") != journal_schema_identity
                or parsed_journal.get("logical_snapshot_schema") != journal_schema
                or parsed_journal.get("logical_snapshot_sha256") != journal_sha256
                or parsed_journal.get("journal_id") != journal_id
                or parsed_journal.get("schema_identity") != journal_schema_identity
                or receipt.get("request_journal_id") != journal_id
                or receipt.get("request_journal_schema_identity")
                != journal_schema_identity
                or receipt.get("request_journal_logical_snapshot_schema")
                != journal_schema
                or receipt.get("request_journal_logical_snapshot_sha256")
                != journal_sha256
                or restore_proof.get("request_journal_logical_snapshot_schema")
                != journal_schema
                or restore_proof.get("request_journal_logical_snapshot_sha256")
                != journal_sha256
                or restore_proof.get(
                    "source_request_journal_binding_receipt_digest"
                )
                != journal_binding_digest
                or restore_proof.get("request_journal_id") != journal_id
                or restore_proof.get("request_journal_schema_identity")
                != journal_schema_identity
            ):
                raise CutoverPreflightError(
                    "signed recovery is stale relative to the live request journal"
                )
            if restored_target:
                restored_binding = (
                    manager.verify_restored_request_journal_binding(
                        memory_db.parent,
                        expected_store_identity=store_identity,
                        expected_store_generation=store_generation,
                        expected_source_request_journal_binding_receipt_digest=(
                            journal_binding_digest
                        ),
                    )
                )
                restored_target_binding_digest = str(
                    restored_binding["receipt_digest"]
                )
                if (
                    restored_binding.get("memory_logical_snapshot_sha256")
                    != live_database.get("sha256")
                    or restored_binding.get(
                        "request_journal_logical_snapshot_sha256"
                    )
                    != journal_sha256
                    or restored_binding.get("request_journal_id") != journal_id
                    or restored_binding.get("request_journal_schema_identity")
                    != journal_schema_identity
                    or restored_binding.get("runtime_state_canonical_sha256")
                    != runtime_canonical_sha256
                ):
                    raise CutoverPreflightError(
                        "restored target binding does not match live exact state"
                    )
        elif (
            journal_path.exists()
            or journal_path.is_symlink()
            or journal_binding_path.exists()
            or journal_binding_path.is_symlink()
            or parsed.get("request_journal") is not None
            or parsed.get("request_journal_binding") is not None
        ):
            raise CutoverPreflightError(
                "pre-governed recovery has unexpected request-journal state"
            )
        if restored_target and governance_mode != "authoritative-v6":
            raise CutoverPreflightError(
                "only authoritative v6 may verify a restored target"
            )
        if signed_runtime_absence_without_lock and (
            manager.runtime_state_path.exists()
            or manager.runtime_state_path.is_symlink()
            or runtime_lock_path.exists()
            or runtime_lock_path.is_symlink()
        ):
            raise CutoverPreflightError(
                "runtime-state absence changed during exact verification"
            )
        final_live_database = store.recompute_logical_snapshot_digest()
        if (
            final_live_database.get("schema") != live_database.get("schema")
            or final_live_database.get("sha256") != live_database.get("sha256")
        ):
            raise CutoverPreflightError(
                "live database changed during exact recovery verification"
            )
        return {
            "receipt_identity_trusted": True,
            "database_digest_verified": True,
            "capture_digest_verified": True,
            "live_snapshot_matches": True,
            "restore_eligible": True,
            "isolated_restore_verified": True,
            "isolated_restore_proof": restore_proof_path.name,
            "governance_mode": governance_mode,
            "store_identity": store_identity,
            "store_generation": store_generation,
            "authority_epoch_number": authority_epoch,
            "database_schema_identity": str(
                inspection["schema_identity"]
            ),
            "database_logical_snapshot_schema": str(live_database["schema"]),
            "database_logical_snapshot_sha256": str(live_database["sha256"]),
            "capture_manifest_sha256": str(live_capture["manifest_sha256"]),
            "runtime_state_required": runtime_required,
            "runtime_state_present": bool(live_runtime["present"]),
            "runtime_state_canonical_sha256": runtime_canonical_sha256,
            "request_journal_id": journal_id,
            "request_journal_schema_identity": journal_schema_identity,
            "request_journal_logical_snapshot_schema": journal_schema,
            "request_journal_logical_snapshot_sha256": journal_sha256,
            "request_journal_binding_receipt_digest": journal_binding_digest,
            "restored_target": restored_target,
            "restored_target_binding_receipt_digest": (
                restored_target_binding_digest
            ),
            "recovery_bundle_receipt_digest": str(receipt["receipt_digest"]),
            "recovery_restore_proof_receipt_digest": str(
                restore_proof["receipt_digest"]
            ),
            "recovery_auth_key_id": str(receipt["auth_key_id"]),
        }
    except CutoverPreflightError:
        raise
    except Exception as exc:
        raise CutoverPreflightError("signed recovery binding verification failed") from exc
    finally:
        store.close()


def run_preflight(
    *,
    root: Path,
    memory_db: Path,
    capture_root: Path,
    evidence_manifest: Path | None,
    maximum_evidence_age_seconds: float,
    require_quiescent: bool,
    inventory_only: bool,
    launchctl_bin: str,
    ps_bin: str,
    labels: Mapping[str, str] | None = None,
    attestation_request: CutoverAttestationRequest | None = None,
) -> dict[str, Any]:
    maximum_age = _maximum_evidence_age(maximum_evidence_age_seconds)
    for path, name in (
        (root, "repository root"),
        (memory_db, "live memory database"),
        (capture_root, "capture source root"),
    ):
        _assert_no_symlink_components(path, name=name)
    if evidence_manifest is not None:
        _assert_no_symlink_components(
            evidence_manifest,
            name="evidence manifest",
        )
    if inventory_only and attestation_request is not None:
        raise CutoverPreflightError(
            "inventory-only preflight cannot publish a cutover attestation"
        )
    processes = collect_process_inventory(ps_bin=ps_bin)
    launch_agents = collect_launchagent_inventory(
        launchctl_bin=launchctl_bin,
        labels=labels,
    )
    legacy_loaded = [
        category
        for category in ("capture", "dashboard")
        if bool(launch_agents.get(category, {}).get("loaded"))
    ]
    quiescence_loaded = [
        category
        for category, snapshot in launch_agents.items()
        if snapshot.get("loaded") is True
    ]
    quiescence_blockers = launchagent_quiescence_blockers(launch_agents)
    result: dict[str, Any] = {
        "schema": "synapse-s2.core-cutover-preflight.v1",
        "ready": False,
        "read_only": attestation_request is None,
        "process_findings": [item.to_wire() for item in processes],
        "process_findings_truncated": len(processes) >= MAX_PROCESS_FINDINGS,
        "launch_agents": launch_agents,
        "legacy_loaded_categories": legacy_loaded,
        "quiescence_loaded_categories": quiescence_loaded,
        "quiescence_policy_schema": QUIESCENCE_POLICY_SCHEMA,
        "quiescence_policy_digest": quiescence_policy_digest(),
        "quiescence_policy_blockers": quiescence_blockers,
    }
    if inventory_only:
        result["ready"] = not processes and not quiescence_blockers
        return result
    if require_quiescent and (processes or quiescence_blockers):
        raise CutoverPreflightError(
            "local writers or respawners remain; stop the reported exact PIDs "
            "and disable the reported LaunchAgents"
        )
    if evidence_manifest is None:
        raise CutoverPreflightError("install requires an explicit evidence manifest")
    # Hold the one authoritative lock continuously across database inspection,
    # evidence validation, and live/recovery comparison.  The preflight does
    # not create the lock: a missing lock is an unclassified authority state.
    with exclusive_authority_lock(memory_db):
        database = inspect_database_contract(memory_db)
        result["database"] = database
        parsed, receipt, restore_proof, restore_proof_path = validate_evidence_contract(
            evidence_manifest,
            root=root,
            maximum_age_seconds=maximum_age,
            expected_config_fingerprint=(
                None
                if attestation_request is None
                else attestation_request.config_fingerprint
            ),
        )
        expected_governance = (
            "authoritative-v6"
            if database["user_version"] == 6
            else "pre-governed-v5"
        )
        if restore_proof.get("governance_mode") != expected_governance:
            raise CutoverPreflightError(
                "isolated restore governance does not match the live database"
            )
        result["recovery"] = verify_recovery_binding(
            parsed=parsed,
            receipt_path=receipt,
            restore_proof=restore_proof,
            restore_proof_path=restore_proof_path,
            memory_db=memory_db,
            capture_root=capture_root,
            restored_target=(
                attestation_request.restored_target
                if attestation_request is not None
                else False
            ),
        )
        if attestation_request is not None:
            result["cutover_attestation"] = publish_cutover_attestation(
                request=attestation_request,
                root=root,
                memory_db=memory_db,
                evidence_manifest=evidence_manifest,
                maximum_evidence_age_seconds=maximum_age,
                recovery=result["recovery"],
            )
        result["authority_lock"] = {
            "exclusive": True,
            "identity_stable": True,
        }
    result["ready"] = True
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(
        description="Read-only authoritative-core cutover proof"
    )
    parser.add_argument("--memory-db", default=str(ROOT / ".synapse_s2" / "memory.sqlite3"))
    parser.add_argument("--capture-root", default=str(ROOT / ".synapse_s2"))
    parser.add_argument("--evidence-manifest")
    parser.add_argument("--maximum-evidence-age-seconds", type=float, default=7200.0)
    parser.add_argument("--require-quiescent", action="store_true")
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--launchctl", default=os.getenv("SYNAPSE_S2_LAUNCHCTL", "/bin/launchctl"))
    parser.add_argument("--ps", default=os.getenv("SYNAPSE_S2_PS_BIN", "/bin/ps"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_preflight(
            root=ROOT,
            memory_db=_normal_absolute(args.memory_db, name="memory database"),
            capture_root=_normal_absolute(args.capture_root, name="capture root"),
            evidence_manifest=(
                _normal_absolute(args.evidence_manifest, name="evidence manifest")
                if args.evidence_manifest
                else None
            ),
            maximum_evidence_age_seconds=args.maximum_evidence_age_seconds,
            require_quiescent=args.require_quiescent,
            inventory_only=args.inventory_only,
            launchctl_bin=args.launchctl,
            ps_bin=args.ps,
        )
    except CutoverPreflightError as exc:
        print(json.dumps({"ready": False, "error": str(exc)}, sort_keys=True))
        return 1
    except Exception:
        print(
            json.dumps(
                {"ready": False, "error": "cutover preflight failed safely"},
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("ready") else 1


if __name__ == "__main__":
    raise SystemExit(main())

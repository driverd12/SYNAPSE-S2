#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import platform
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redaction import (
    SecretSafeArgumentParser,
    mask_public_paths,
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    safe_public_error,
    strip_untrusted_raw_digest_fields,
)
from backend_router import database_requires_core
from core_authority import CoreAuthorityLease
from core_client_binding import (
    BINDING_ENV,
    CoreClientBinding,
    default_binding_path,
    load_bound_core_config,
    load_core_client_binding,
)
from scripts.core_agent_installer import (
    DEFAULT_LABEL as DEFAULT_CORE_LABEL,
    build_config as build_candidate_core_config,
    resolve_paths as resolve_candidate_core_paths,
)
from memory_store import DurableMemoryStore
from recovery_manager import VerifiedRecoveryManager
from operator_readiness_contract import (
    OPERATOR_READINESS_REQUIRED_PROOF_IDS,
    QUIESCENCE_POLICY_SCHEMA,
    quiescence_policy_contract,
    quiescence_policy_digest,
    ready_operator_proof_contract,
)
from scripts.core_cutover_preflight import (
    DEFAULT_CAPTURE_LABEL,
    DEFAULT_DASHBOARD_LABEL,
    MAX_PROCESS_FINDINGS,
    collect_launchagent_inventory,
    collect_process_inventory,
    core_config_evidence_contract,
    launchagent_quiescence_blockers,
)


DEFAULT_LAUNCHER = Path.home() / ".local" / "bin" / "synapse-s2-mcp"
DEFAULT_NEURAL_MODEL = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
MCP_CONTRACT_SCHEMA = "synapse-s2.token-contract.v1"
MCP_SAFETY_SCHEMA = "synapse-s2.mcp-safety-summary.v1"
MCP_SAFETY_PREFIX = "SYNAPSE-S2 safety summary: "
MCP_COMPACT_BUDGET = 12_288
MCP_SAFETY_BUDGET = 4_096
EMBEDDING_RUNTIME_CONFIG_SCHEMA = "synapse-s2.embedding-runtime-config.v1"
DOCTOR_TIMEOUT_SECONDS = 60
NEURAL_DOCTOR_TIMEOUT_SECONDS = 300
CAPTURE_DRAIN_BATCH_SIZE = 250
CAPTURE_DRAIN_MAX_PASSES = 12
AUTHORITY_GUARD_TIMEOUT_SECONDS = 30.0
CHILD_ENV_ALLOWLIST = frozenset(
    {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOGNAME",
        "PATH",
        "SHELL",
        "TMPDIR",
        "USER",
    }
)
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RAW_DIGEST_TEXT_RE = re.compile(
    r"(?i)(?:['\"]?)(?:input_sha256|raw_input_sha256|raw_sha256|"
    r"raw_text_sha256|payload_sha256|source_text_sha256|"
    r"raw_[A-Za-z0-9_-]*sha(?:256)?)(?:['\"]?)\s*[:=]\s*"
    r"(?:['\"](?:\\.|[^'\"\\])*['\"]|[^\s,;}\]]+)"
)

_PROVIDER_EXPECTATIONS = {
    "semantic-hash": ("semantic-hash-v1", "semantic-hash"),
    "semantic-hash-v1": ("semantic-hash-v1", "semantic-hash"),
    "lexical-hash": ("lexical-hash-v1", "lexical-hash"),
    "lexical-hash-v1": ("lexical-hash-v1", "lexical-hash"),
    "mlx-neural": ("mlx-neural-v1", "mlx-neural"),
    "mlx-neural-v1": ("mlx-neural-v1", "mlx-neural"),
}
REQUIRED_PROOFS = list(OPERATOR_READINESS_REQUIRED_PROOF_IDS)


@dataclasses.dataclass
class CheckResult:
    check_id: str
    label: str
    status: str
    required: bool
    detail: str
    repair: str = ""
    command: list[str] = dataclasses.field(default_factory=list)
    returncode: int | None = None
    duration_ms: float = 0.0
    artifact_paths: dict[str, str] = dataclasses.field(default_factory=dict)
    parsed: Any = None
    metrics: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_manifest(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "status": self.status,
            "required": self.required,
            "detail": self.detail,
            "repair": self.repair,
            "command": command_to_text(self.command) if self.command else "",
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "artifact_paths": self.artifact_paths,
            "metrics": self.metrics,
        }


Evaluator = Callable[[int, Any, str, str], tuple[str, str, str, dict[str, Any]]]


def command_to_text(command: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in command)


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip()).strip(".-")
    return cleaned or "artifact"


def validate_run_id(value: Any) -> str:
    raw = reject_sensitive_identifier(value, field="readiness run_id").strip()
    if raw in {"", ".", ".."} or RUN_ID_RE.fullmatch(raw) is None:
        raise ValueError(
            "readiness run_id must be one safe basename component"
        )
    return raw


def validate_evidence_path(value: Any, *, field: str) -> Path:
    raw = reject_sensitive_identifier(value, field=field).strip()
    if not raw:
        raise ValueError(f"{field} must not be empty")
    resolved = Path(raw).expanduser().resolve()
    reject_sensitive_identifier(resolved, field=field)
    return resolved


def compact_text(value: Any, *, limit: int = 240) -> str:
    text = " ".join(sanitize_evidence_text(value).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def sanitize_evidence_text(value: Any) -> str:
    redacted, _ = redact_capture_text(str(value or ""))
    return RAW_DIGEST_TEXT_RE.sub("[REMOVED_RAW_DIGEST_FIELD]", redacted)


def sanitize_json_string_values(value: Any) -> Any:
    """Sanitize string values before JSON serialization, never its syntax."""

    if isinstance(value, str):
        return sanitize_evidence_text(value)
    if isinstance(value, dict):
        return {
            key: sanitize_json_string_values(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_json_string_values(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_json_string_values(item) for item in value)
    return value


def json_safe(value: Any) -> Any:
    safe_value, _ = redact_sensitive_value(value)
    safe_value, _ = strip_untrusted_raw_digest_fields(safe_value)
    safe_value = sanitize_json_string_values(safe_value)
    try:
        return json.loads(json.dumps(safe_value, allow_nan=False))
    except (TypeError, ValueError):
        return "[UNSERIALIZABLE]"


def write_private_text(path: Path, text: str) -> None:
    ensure_private_directory(path.parent)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temp_path = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        path.chmod(0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _private_file_identity(observed: os.stat_result) -> tuple[int, ...]:
    return (
        int(observed.st_dev),
        int(observed.st_ino),
        int(observed.st_mode),
        int(observed.st_uid),
        int(observed.st_nlink),
        int(observed.st_size),
        int(observed.st_mtime_ns),
        int(observed.st_ctime_ns),
    )


def _open_private_parent_nofollow(path: Path) -> tuple[Path, int]:
    """Anchor every path component and return an owner-private parent fd."""

    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or "\x00" in str(candidate)
        or ".." in candidate.parts
        or Path(os.path.normpath(str(candidate))) != candidate
        or len(candidate.parts) < 2
    ):
        raise ValueError("signed evidence path must be normal and absolute")
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("signed evidence requires no-follow directory opens")
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    descriptor = os.open(candidate.anchor, directory_flags)
    try:
        for component in candidate.parts[1:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        parent = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise ValueError("signed evidence parent must be owner-private")
        return candidate, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_private_regular_bytes(path: Path, *, max_bytes: int) -> bytes:
    """Read one exact-0600 file through anchored, stable no-follow fds."""

    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("signed evidence size limit must be positive")
    candidate, parent_descriptor = _open_private_parent_nofollow(path)
    descriptor = -1
    try:
        before = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise ValueError(
                "signed evidence source must be one bounded private regular file"
            )
        descriptor = os.open(
            candidate.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(descriptor)
        identity = _private_file_identity(before)
        if _private_file_identity(opened) != identity:
            raise ValueError("signed evidence source changed before open")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_descriptor = os.fstat(descriptor)
        after_path = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            len(payload) != before.st_size
            or len(payload) > max_bytes
            or _private_file_identity(after_descriptor) != identity
            or _private_file_identity(after_path) != identity
        ):
            raise ValueError("signed evidence source changed during read")
        return payload
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_descriptor)


def write_private_bytes(path: Path, payload: bytes) -> None:
    """Publish exact bytes once through an anchored owner-private directory."""

    candidate = Path(path)
    ensure_private_directory(candidate.parent)
    candidate, parent_descriptor = _open_private_parent_nofollow(candidate)
    temporary_name = f".{candidate.name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    published = False
    completed = False
    staged: os.stat_result | None = None
    try:
        try:
            os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(
                "signed evidence artifact already exists; refusing to overwrite it"
            )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("signed evidence artifact write made no progress")
            offset += written
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        if (
            not stat.S_ISREG(staged.st_mode)
            or staged.st_uid != os.getuid()
            or staged.st_nlink != 1
            or stat.S_IMODE(staged.st_mode) != 0o600
            or staged.st_size != len(payload)
        ):
            raise ValueError("signed evidence staging file is not private and exact")
        os.link(
            temporary_name,
            candidate.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        published = True
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        published_stat = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(published_stat.st_mode)
            or published_stat.st_uid != os.getuid()
            or published_stat.st_nlink != 1
            or stat.S_IMODE(published_stat.st_mode) != 0o600
            or published_stat.st_size != len(payload)
            or (published_stat.st_dev, published_stat.st_ino)
            != (staged.st_dev, staged.st_ino)
        ):
            raise ValueError("signed evidence artifact publication is not exact")
        os.fsync(parent_descriptor)
        completed = True
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        if published and not completed and staged is not None:
            try:
                visible = os.stat(
                    candidate.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (visible.st_dev, visible.st_ino) == (
                    staged.st_dev,
                    staged.st_ino,
                ):
                    os.unlink(candidate.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def write_private_evidence_zip(
    archive_path: Path,
    *,
    pack_dir: Path,
    members: set[Path],
    opaque_members: set[Path] | None = None,
    virtual_json_members: dict[str, Any] | None = None,
) -> None:
    """Atomically create a private ZIP from explicit and staged JSON members."""

    root = pack_dir.resolve()
    opaque_resolved = {
        member.resolve(strict=True) for member in (opaque_members or set())
    }
    if not opaque_resolved.issubset(
        {member.resolve(strict=True) for member in members}
    ):
        raise ValueError("opaque evidence ZIP members must be explicit members")
    ensure_private_directory(archive_path.parent)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{archive_path.name}.",
        suffix=".tmp",
        dir=str(archive_path.parent),
    )
    temp_path = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        descriptor = -1
        with zipfile.ZipFile(
            temp_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            archived_names: set[str] = set()
            for member in sorted(members, key=lambda item: str(item)):
                if member.is_symlink() or not member.is_file():
                    raise ValueError("evidence ZIP members must be regular files")
                resolved = member.resolve(strict=True)
                try:
                    relative = resolved.relative_to(root)
                except ValueError as exc:
                    raise ValueError(
                        "evidence ZIP member escapes the run directory"
                    ) from exc
                info = zipfile.ZipInfo(str(relative))
                if info.filename in archived_names:
                    raise ValueError("evidence ZIP member name is duplicated")
                archived_names.add(info.filename)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                if resolved in opaque_resolved:
                    archived_bytes = read_private_regular_bytes(
                        resolved,
                        max_bytes=1024 * 1024,
                    )
                else:
                    source_text = resolved.read_text(encoding="utf-8")
                    archived_bytes = b""
                if resolved not in opaque_resolved and resolved.suffix == ".json":
                    source_payload = json.loads(source_text)
                    archived_text = json.dumps(
                        json_safe(source_payload),
                        indent=2,
                        sort_keys=True,
                    ) + "\n"
                    archived_bytes = archived_text.encode("utf-8")
                elif resolved not in opaque_resolved and resolved.suffix in {".txt", ".md"}:
                    archived_text = sanitize_evidence_text(source_text)
                    archived_bytes = archived_text.encode("utf-8")
                elif resolved not in opaque_resolved:
                    raise ValueError(
                        "evidence ZIP members must use JSON, text, or Markdown"
                    )
                archive.writestr(info, archived_bytes)
            for relative_name, payload in sorted(
                (virtual_json_members or {}).items()
            ):
                relative = Path(relative_name)
                if (
                    relative.is_absolute()
                    or relative.suffix != ".json"
                    or not relative.parts
                    or any(part in {"", ".", ".."} for part in relative.parts)
                    or relative.as_posix() in archived_names
                ):
                    raise ValueError("virtual evidence ZIP member is invalid")
                info = zipfile.ZipInfo(relative.as_posix())
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(
                    info,
                    (
                        json.dumps(
                            json_safe(payload),
                            indent=2,
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8"),
                )
                archived_names.add(info.filename)
        with temp_path.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temp_path, archive_path)
        archive_path.chmod(0o600)
        directory_fd = os.open(archive_path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def ensure_private_directory(path: Path) -> None:
    """Create missing evidence directories privately; preserve existing modes."""

    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            if not directory.is_dir():
                raise


def parse_json_stdout(stdout: str) -> Any:
    text = str(stdout or "").strip()
    if not text:
        return None
    return json.loads(text)


def classify_overall(results: list[CheckResult]) -> str:
    required = [result for result in results if result.required]
    if any(result.status == "blocked" for result in required):
        return "blocked"
    if any(result.status != "ready" for result in required):
        return "needs_attention"
    if any(result.status == "blocked" for result in results):
        return "needs_attention"
    if any(result.status == "degraded" for result in results):
        return "needs_attention"
    return "ready"


def mcp_compact_contract_probe_status(
    returncode: int,
    parsed: Any,
    stdout: str,
    stderr: str,
) -> tuple[str, str, str, dict[str, Any]]:
    """Fail-closed verification of the installed compact MCP wire contract."""

    repair = (
        "Reinstall the local launcher, inspect the MCP contract artifacts, and "
        "rerun the compact contract probe."
    )

    def blocked(reason: str) -> tuple[str, str, str, dict[str, Any]]:
        return "blocked", reason, repair, {}

    def contains_local_path(value: Any) -> bool:
        if isinstance(value, str):
            return mask_public_paths(value) != value
        if isinstance(value, dict):
            return any(
                contains_local_path(key) or contains_local_path(item)
                for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(contains_local_path(item) for item in value)
        return False

    def valid_bounded_text(
        value: Any,
        *,
        max_chars: int,
        allow_empty: bool = True,
    ) -> bool:
        return (
            isinstance(value, str)
            and len(value) <= max_chars
            and (allow_empty or bool(value))
        )

    def valid_nonnegative_integer(value: Any) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, int)
            and value >= 0
        )

    def valid_finite_number(value: Any) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
        )

    def valid_warning(value: Any, *, include_message: bool) -> bool:
        expected = {"code", "severity", "action_required"}
        if include_message:
            expected.add("message")
        if not isinstance(value, dict) or set(value) != expected:
            return False
        if (
            not valid_bounded_text(
                value.get("code"),
                max_chars=80,
                allow_empty=False,
            )
            or re.fullmatch(r"[a-z0-9][a-z0-9_.:-]*", value["code"]) is None
            or value.get("severity") not in {"critical", "high", "warning", "info"}
            or not isinstance(value.get("action_required"), bool)
        ):
            return False
        return not include_message or valid_bounded_text(
            value.get("message"),
            max_chars=240,
            allow_empty=False,
        )

    if returncode != 0:
        return blocked(compact_text(stderr or stdout or "FastMCP contract probe failed"))
    if not isinstance(parsed, dict):
        return blocked("FastMCP contract probe did not return a JSON object.")
    if json_safe(parsed) != parsed:
        return blocked(
            "FastMCP result changes under the independent public-boundary sanitizer."
        )
    if contains_local_path(parsed):
        return blocked("FastMCP result exposes a local filesystem path.")

    error_keys = [key for key in ("is_error", "isError") if key in parsed]
    if len(error_keys) != 1 or parsed.get(error_keys[0]) is not False:
        return blocked("FastMCP contract probe did not prove an unambiguous non-error result.")

    structured_keys = [
        key
        for key in ("structured_content", "structuredContent")
        if key in parsed
    ]
    if len(structured_keys) != 1:
        return blocked("FastMCP contract probe returned missing or ambiguous structured content.")
    error_key = error_keys[0]
    structured_key = structured_keys[0]
    if (error_key, structured_key) not in {
        ("is_error", "structured_content"),
        ("isError", "structuredContent"),
    }:
        return blocked("FastMCP result mixes incompatible wire field conventions.")
    if set(parsed) != {error_key, structured_key, "content"}:
        return blocked("FastMCP result contains missing or unknown top-level fields.")
    structured = parsed.get(structured_keys[0])
    if not isinstance(structured, dict):
        return blocked("FastMCP structured content is not a JSON object.")

    if structured.get("schema") != MCP_CONTRACT_SCHEMA:
        return blocked("MCP compact contract schema is missing or unexpected.")
    version = structured.get("version")
    if isinstance(version, bool) or version != 1:
        return blocked("MCP compact contract version is not exactly integer 1.")
    if structured.get("operation") != "memory-list":
        return blocked("MCP compact contract operation is not memory-list.")
    if structured.get("ok") is not True:
        return blocked("MCP compact contract did not report ok=true.")

    response_contract = structured.get("response_contract")
    if not isinstance(response_contract, dict):
        return blocked("MCP compact response_contract metadata is missing.")
    if response_contract.get("profile") != "compact":
        return blocked("MCP response profile is not compact.")
    effective_budget = response_contract.get("max_output_bytes")
    if (
        isinstance(effective_budget, bool)
        or effective_budget != MCP_COMPACT_BUDGET
    ):
        return blocked("MCP compact structured-content budget is not exactly 12288 bytes.")
    declared_size = response_contract.get("serialized_bytes")
    if (
        isinstance(declared_size, bool)
        or not isinstance(declared_size, int)
        or declared_size < 0
    ):
        return blocked("MCP compact serialized_bytes is not a non-negative integer.")
    try:
        canonical = json.dumps(
            structured,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return blocked("MCP compact structured content is not canonical-JSON encodable.")
    canonical_size = len(canonical)
    if canonical_size != declared_size:
        return blocked("MCP compact declared and independently measured byte counts differ.")
    if canonical_size > MCP_COMPACT_BUDGET:
        return blocked("MCP compact structured content exceeds 12288 bytes.")
    estimated_tokens = response_contract.get("estimated_tokens")
    if (
        isinstance(estimated_tokens, bool)
        or not isinstance(estimated_tokens, int)
        or estimated_tokens != (canonical_size + 3) // 4
        or not isinstance(response_contract.get("truncated"), bool)
    ):
        return blocked("MCP compact token estimate or truncation metadata is invalid.")
    if json_safe(structured) != structured:
        return blocked(
            "MCP compact structured content changes under the independent public-boundary sanitizer."
        )
    if contains_local_path(structured):
        return blocked("MCP compact structured content exposes a local filesystem path.")

    expected_root_keys = {
        "schema",
        "version",
        "operation",
        "ok",
        "data",
        "provenance",
        "warnings",
        "pagination",
        "completeness",
        "continuation",
        "response_contract",
    }
    if set(structured) != expected_root_keys:
        return blocked("MCP compact contract contains missing or unknown top-level fields.")
    if set(response_contract) != {
        "profile",
        "max_output_bytes",
        "serialized_bytes",
        "estimated_tokens",
        "truncated",
        "omissions",
    }:
        return blocked("MCP compact response_contract fields are not allowlisted.")
    omissions = response_contract.get("omissions")
    if not isinstance(omissions, dict) or any(
        not valid_bounded_text(key, max_chars=96, allow_empty=False)
        or re.fullmatch(r"[a-z0-9][a-z0-9_.:-]*", key) is None
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for key, count in omissions.items()
    ):
        return blocked("MCP compact omission accounting is invalid.")
    truncated = response_contract.get("truncated")
    if truncated is not bool(omissions):
        return blocked("MCP compact truncation and omission accounting disagree.")

    data = structured.get("data")
    if not isinstance(data, dict) or set(data) != {
        "context_id",
        "recall_scope",
        "one_hop_only",
        "returned",
        "entries",
    }:
        return blocked("MCP compact memory-list data fields are not allowlisted.")
    entries = data.get("entries")
    returned = data.get("returned")
    if (
        not isinstance(entries, list)
        or isinstance(returned, bool)
        or not isinstance(returned, int)
        or returned != len(entries)
        or returned > 1
    ):
        return blocked("MCP compact memory-list returned-count truth is invalid.")
    if (
        not valid_bounded_text(
            data.get("context_id"),
            max_chars=128,
            allow_empty=False,
        )
        or data.get("recall_scope") != "local"
        or data.get("one_hop_only") is not False
    ):
        return blocked("MCP compact memory-list scope metadata is invalid.")
    expected_entry_keys = {
        "memory_id",
        "tag",
        "context_id",
        "excerpt",
        "trust",
        "embedding_dimensions",
        "spike_count",
        "neuron_count",
        "created_at",
        "updated_at",
        "provenance",
    }
    allowed_entry_provenance = {
        "recall_scope",
        "recall_provenance",
        "via_context_link_id",
        "via_relation_type",
        "via_direction",
        "source_surface",
        "speaker",
    }
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            return blocked("MCP compact memory entry fields are not allowlisted.")
        if (
            not valid_bounded_text(
                entry.get("memory_id"),
                max_chars=256,
                allow_empty=False,
            )
            or not valid_bounded_text(entry.get("tag"), max_chars=160)
            or not valid_bounded_text(entry.get("excerpt"), max_chars=360)
            or any(
                not valid_nonnegative_integer(entry.get(field))
                for field in (
                    "embedding_dimensions",
                    "spike_count",
                    "neuron_count",
                )
            )
            or any(
                not valid_finite_number(entry.get(field))
                for field in ("created_at", "updated_at")
            )
        ):
            return blocked("MCP compact memory entry values are invalid.")
        if entry.get("trust") != "untrusted-memory-evidence":
            return blocked("MCP compact memory entry has a forged or missing trust label.")
        entry_provenance = entry.get("provenance")
        if not isinstance(entry_provenance, dict) or not set(
            entry_provenance
        ).issubset(allowed_entry_provenance):
            return blocked("MCP compact memory entry provenance is not allowlisted.")
        if any(
            not valid_bounded_text(value, max_chars=256, allow_empty=False)
            for value in entry_provenance.values()
        ):
            return blocked("MCP compact memory entry provenance values are invalid.")
        if entry_provenance.get("recall_scope", "local") != "local":
            return blocked("MCP compact memory entry provenance scope is invalid.")
        if entry.get("context_id") != data.get("context_id"):
            return blocked("MCP compact memory entry escaped its requested context.")

    provenance = structured.get("provenance")
    if (
        not isinstance(provenance, dict)
        or set(provenance)
        != {"source", "context_id", "recall_scope", "origin_node"}
        or provenance.get("source") != "sqlite-memory-store"
        or provenance.get("context_id") != data.get("context_id")
        or provenance.get("recall_scope") != data.get("recall_scope")
        or not isinstance(provenance.get("origin_node"), str)
        or re.fullmatch(r"s2origin_[0-9a-f]{32}", provenance["origin_node"])
        is None
    ):
        return blocked("MCP compact memory-list provenance is invalid.")
    warning_rows = structured.get("warnings")
    if not isinstance(warning_rows, list) or any(
        not valid_warning(item, include_message=True)
        for item in warning_rows
    ):
        return blocked("MCP compact warning values are invalid or not allowlisted.")
    warning_codes = {
        item["code"] for item in warning_rows if isinstance(item, dict)
    }
    if "pagination-unsupported" in warning_codes:
        return blocked("MCP compact memory-list still reports legacy pagination.")
    if truncated != ("output-truncated" in warning_codes):
        return blocked("MCP compact truncation warning disagrees with its contract metadata.")
    pagination = structured.get("pagination")
    if not isinstance(pagination, dict) or set(pagination) != {
        "supported",
        "strategy",
        "requested_limit",
        "effective_limit",
        "returned",
        "total",
        "has_more",
        "next_cursor",
        "snapshot_revision",
        "expires_at",
    } or pagination.get("returned") != returned:
        return blocked("MCP compact pagination metadata is invalid.")
    total = pagination.get("total")
    has_more = pagination.get("has_more")
    cursor = pagination.get("next_cursor")
    expiry = pagination.get("expires_at")
    snapshot_revision = pagination.get("snapshot_revision")
    if (
        pagination.get("supported") is not True
        or pagination.get("strategy") != "authenticated-keyset-v2"
        or type(pagination.get("requested_limit")) is not int
        or pagination.get("requested_limit") != 1
        or type(pagination.get("effective_limit")) is not int
        or pagination.get("effective_limit") != 1
        or not isinstance(total, dict)
        or set(total) != {"entries"}
        or not valid_nonnegative_integer(total.get("entries"))
        or total["entries"] < returned
        or type(has_more) is not bool
        or not isinstance(snapshot_revision, str)
        or re.fullmatch(r"[0-9a-f]{64}", snapshot_revision) is None
    ):
        return blocked("MCP compact pagination values are invalid.")
    if has_more:
        if (
            not isinstance(cursor, str)
            or len(cursor.encode("ascii", "ignore")) > 4_096
            or re.fullmatch(
                r"s2rc2\.[A-Za-z0-9_-]{1,4000}\.[A-Za-z0-9_-]{43}",
                cursor,
            )
            is None
            or not valid_nonnegative_integer(expiry)
            or expiry <= 0
        ):
            return blocked("MCP compact continuation cursor is invalid.")
    elif cursor is not None or expiry is not None:
        return blocked("MCP complete compact page exposed a continuation.")
    completeness = structured.get("completeness")
    if not isinstance(completeness, dict) or set(completeness) != {
        "complete",
        "snapshot_bound",
        "authoritative_total",
        "source_limit_reduced",
        "reason",
    }:
        return blocked("MCP compact completeness metadata is invalid.")
    if (
        completeness.get("complete") is not (not has_more)
        or completeness.get("snapshot_bound") is not True
        or completeness.get("authoritative_total") is not True
        or completeness.get("source_limit_reduced") is not False
        or completeness.get("reason")
        != ("more-pages-available" if has_more else "snapshot-page-complete")
    ):
        return blocked("MCP compact completeness values are invalid.")
    continuation = structured.get("continuation")
    if not isinstance(continuation, dict) or set(continuation) != {
        "strategy",
        "cursor",
        "expires_at",
    }:
        return blocked("MCP compact continuation metadata is invalid.")
    if (
        continuation.get("strategy")
        != ("use-authenticated-keyset-cursor" if has_more else "none")
        or continuation.get("cursor") != cursor
        or continuation.get("expires_at") != expiry
    ):
        return blocked("MCP compact continuation values are invalid.")

    content = parsed.get("content")
    if not isinstance(content, list) or len(content) != 1:
        return blocked("MCP safety channel must contain exactly one content item.")
    content_item = content[0]
    if (
        not isinstance(content_item, dict)
        or set(content_item) != {"type", "text"}
        or content_item.get("type") != "text"
        or not isinstance(content_item.get("text"), str)
    ):
        return blocked("MCP safety channel did not return exactly one text item.")
    safety_text = content_item["text"]
    safety_size = len(safety_text.encode("utf-8"))
    if safety_size > MCP_SAFETY_BUDGET:
        return blocked("MCP safety summary exceeds 4096 bytes.")
    if not safety_text.startswith(MCP_SAFETY_PREFIX):
        return blocked("MCP safety summary prefix is missing.")
    if sanitize_evidence_text(safety_text) != safety_text:
        return blocked(
            "MCP safety summary changes under the independent public-boundary sanitizer."
        )
    if mask_public_paths(safety_text) != safety_text:
        return blocked("MCP safety summary exposes a local filesystem path.")
    try:
        safety = json.loads(safety_text[len(MCP_SAFETY_PREFIX) :])
    except (TypeError, ValueError, json.JSONDecodeError):
        return blocked("MCP safety summary suffix is not valid JSON.")
    if not isinstance(safety, dict):
        return blocked("MCP safety summary suffix is not a JSON object.")
    if safety.get("schema") != MCP_SAFETY_SCHEMA:
        return blocked("MCP safety summary schema is missing or unexpected.")
    if set(safety) != {
        "schema",
        "operation",
        "ok",
        "structuredContent_required",
        "warnings",
        "continuation",
        "max_bytes",
    }:
        return blocked("MCP safety summary fields are not allowlisted.")
    if safety.get("operation") != structured.get("operation"):
        return blocked("MCP safety and structured operations do not match.")
    if safety.get("ok") is not True:
        return blocked("MCP safety summary did not report ok=true.")
    if safety.get("structuredContent_required") is not True:
        return blocked("MCP safety summary does not require structuredContent.")
    safety_budget = safety.get("max_bytes")
    if isinstance(safety_budget, bool) or safety_budget != MCP_SAFETY_BUDGET:
        return blocked("MCP safety summary budget is not exactly 4096 bytes.")
    safety_warnings = safety.get("warnings")
    if not isinstance(safety_warnings, list) or any(
        not valid_warning(item, include_message=False)
        for item in safety_warnings
    ):
        return blocked("MCP safety warning values are invalid or not allowlisted.")
    expected_safety_warnings = [
        {
            "code": item["code"],
            "severity": item["severity"],
            "action_required": item["action_required"],
        }
        for item in warning_rows
    ]
    if safety_warnings != expected_safety_warnings:
        return blocked("MCP safety warnings disagree with structured content.")
    safety_continuation = safety.get("continuation")
    if safety_continuation != {"strategy": continuation["strategy"]}:
        return blocked("MCP safety continuation disagrees with structured content.")

    metrics = {
        "contract_schema": structured["schema"],
        "profile": response_contract["profile"],
        "requested_max_output_bytes": MCP_COMPACT_BUDGET,
        "effective_max_output_bytes": effective_budget,
        "declared_serialized_bytes": declared_size,
        "canonical_structured_content_bytes": canonical_size,
        "safety_text_bytes": safety_size,
        "safety_text_max_bytes": safety_budget,
        "component_total_bytes": canonical_size + safety_size,
        "transport_framing_included": False,
    }
    return (
        "ready",
        "Installed MCP compact structured and safety channels passed independent byte and schema verification.",
        "",
        metrics,
    )


def choose_app(apps: list[dict[str, Any]], preferred: str = "") -> dict[str, Any] | None:
    if not apps:
        return None
    preferred_clean = preferred.strip().lower()
    if preferred_clean:
        for app in apps:
            if str(app.get("app_name") or "").strip().lower() == preferred_clean:
                return app
    priority = [
        "google chrome",
        "codex",
        "cursor",
        "terminal",
        "alacritty",
        "slack",
        "notes",
    ]
    by_name = {
        str(app.get("app_name") or "").strip().lower(): app
        for app in apps
        if str(app.get("app_name") or "").strip()
    }
    for name in priority:
        if name in by_name:
            return by_name[name]
    return sorted(apps, key=lambda item: str(item.get("app_name") or "").lower())[0]


def runtime_status_from_mcp_envelope(value: Any) -> dict[str, Any] | None:
    """Decode exactly one non-error FastMCP result channel.

    Status is intentionally a string-returning MCP tool today, but accepting a
    single structured channel keeps this validator compatible with a future
    typed result.  Recursive searching is forbidden: an outer error envelope
    must never be rescued by a stale nested runtime object.
    """

    if not isinstance(value, dict) or value.get("error") not in {None, ""}:
        return None
    error_keys = [key for key in ("is_error", "isError") if key in value]
    if len(error_keys) != 1 or value.get(error_keys[0]) is not False:
        return None
    structured_keys = [
        key
        for key in ("structured_content", "structuredContent")
        if key in value
    ]
    if len(structured_keys) > 1:
        return None
    candidates: list[Any] = []
    mirrored_result = False
    if structured_keys:
        structured = value.get(structured_keys[0])
        if (
            isinstance(structured, dict)
            and set(structured) == {"result"}
            and isinstance(structured.get("result"), str)
            and len(structured["result"].encode("utf-8")) <= 1_048_576
        ):
            try:
                candidates.append(json.loads(structured["result"]))
            except (TypeError, ValueError, json.JSONDecodeError):
                return None
            mirrored_result = True
        else:
            candidates.append(structured)
    if "content" in value:
        content = value.get("content")
        if not isinstance(content, list) or len(content) != 1:
            return None
        item = content[0]
        if (
            not isinstance(item, dict)
            or item.get("type") != "text"
            or not isinstance(item.get("text"), str)
            or len(item["text"].encode("utf-8")) > 1_048_576
        ):
            return None
        text_payload = item["text"].strip()
        try:
            candidates.append(json.loads(text_payload))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
    if mirrored_result and len(candidates) == 2:
        if candidates[0] != candidates[1]:
            return None
        candidates.pop()
    if len(candidates) != 1 or not isinstance(candidates[0], dict):
        return None
    runtime = candidates[0]
    required = {"runtime", "dimension", "num_neurons", "embedding_provider"}
    if not required.issubset(runtime) or runtime.get("error") not in {None, ""}:
        return None
    return runtime


def app_preview_status(parsed: Any) -> tuple[str, str, str, dict[str, Any]]:
    if not isinstance(parsed, dict):
        return (
            "blocked",
            "App Connect preview did not return JSON.",
            "Run App Connect Detect, attach a visible app, and retry preview.",
            {},
        )
    if parsed.get("action") != "preview-app-snapshot":
        return (
            "blocked",
            f"Unexpected preview action: {parsed.get('action')}",
            "Retry with synapse_cli.py app-snapshot-preview for the attached connection.",
            {},
        )
    quality = dict(parsed.get("snapshot_quality") or {})
    quality_badge = dict(parsed.get("quality_badge") or {})
    capability = dict(parsed.get("capability_badge") or {})
    guidance = parsed.get("capture_guidance") or []
    writes_memory = bool(parsed.get("writes_memory"))
    if writes_memory:
        return (
            "blocked",
            "Preview unexpectedly wrote memory.",
            "Fix preview mode before using App Connect in operator workflows.",
            {},
        )
    if not quality_badge or not capability:
        return (
            "blocked",
            "Preview omitted quality or capability badges.",
            "Return snapshot_quality, quality_badge, capability_badge, and capture_guidance.",
            {},
        )
    quality_status = str(quality_badge.get("status") or "blocked")
    signal_chars = int(quality.get("signal_chars") or 0)
    app_name = str(parsed.get("app_name") or "app")
    capability_level = str(capability.get("level") or "unknown")
    repair = ""
    if quality_status != "ready":
        repair = compact_text(
            quality_badge.get("next_action")
            or capability.get("recommended_capture")
            or (guidance[0] if guidance else ""),
            limit=220,
        )
    elif guidance:
        repair = compact_text(guidance[0], limit=220)
    detail = (
        f"{app_name} preview was honest: {quality_status}, "
        f"{signal_chars} signal chars, capability {capability_level}, writes_memory=false."
    )
    return (
        "ready",
        detail,
        repair,
        {
            "app_name": app_name,
            "quality_status": quality_status,
            "signal_chars": signal_chars,
            "capability_level": capability_level,
            "writes_memory": writes_memory,
        },
    )


class OperatorReadinessCertifier:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.context = sanitize_context(args.context)
        self.agent_id = sanitize_agent(args.agent_id)
        self.run_id = validate_run_id(
            args.run_id
            or f"operator-readiness-{time.strftime('%Y%m%d-%H%M%S')}"
        )
        self.output_root = validate_evidence_path(
            args.output_dir,
            field="readiness output_dir",
        ).resolve()
        self.pack_dir = (self.output_root / self.run_id).resolve()
        try:
            relative_pack = self.pack_dir.relative_to(self.output_root)
        except ValueError as exc:  # pragma: no cover - RUN_ID_RE is fail-closed
            raise ValueError("readiness run directory escapes output_dir") from exc
        if len(relative_pack.parts) != 1:
            raise ValueError("readiness run directory must be a direct output_dir child")
        self.artifact_dir = self.pack_dir / "artifacts"
        self.archive_path = self.output_root / f"{self.run_id}.zip"
        self._evidence_files: set[Path] = set()
        self._opaque_evidence_files: set[Path] = set()
        # Keep the venv shim path intact. Resolving it follows uv's interpreter
        # symlink and bypasses the virtualenv site-packages.
        self.python = str(ROOT / ".venv" / "bin" / "python")
        self.launcher = validate_evidence_path(
            args.launcher,
            field="readiness launcher path",
        ).resolve()
        self.args.core_label = reject_sensitive_identifier(
            getattr(args, "core_label", DEFAULT_CORE_LABEL),
            field="readiness core label",
        ).strip()
        raw_layout_manifest = str(
            getattr(args, "noncanonical_layout_manifest", "") or ""
        ).strip()
        layout_manifest = (
            validate_evidence_path(
                raw_layout_manifest,
                field="readiness noncanonical layout manifest",
            )
            if raw_layout_manifest
            else None
        )
        self.core_paths = resolve_candidate_core_paths(
            label=self.args.core_label,
            noncanonical_layout_manifest=layout_manifest,
        )
        self.core_binding_path = self._discover_core_binding(args)
        self.core_binding = (
            load_core_client_binding(self.core_binding_path)
            if self.core_binding_path is not None
            else None
        )
        if self.core_binding is None:
            self.candidate_config = build_candidate_core_config(self.core_paths)
        else:
            try:
                self.candidate_config = load_bound_core_config(self.core_binding)
            except Exception as exc:
                raise ValueError(
                    "readiness core binding fingerprint does not match, or its config "
                    "digest drifted from, "
                    "the private reviewed configuration"
                ) from exc
        self.core_config_contract = core_config_evidence_contract(
            self.candidate_config
        )
        self._validate_candidate_expectations(args)
        if self.core_binding is not None:
            self._validate_core_binding(self.core_binding)
        self.core_config_attestation = {
            "source": "core-binding" if self.core_binding is not None else "legacy",
            "observed_effective_config_fingerprint": (
                self.candidate_config.fingerprint
            ),
            "observed_embedding_space_identity": (
                self.candidate_config.embedding_space_identity
            ),
            "config_digest": (
                self.core_binding.config_digest
                if self.core_binding is not None
                else self.candidate_config.fingerprint
            ),
        }
        self.args.app_name = reject_sensitive_identifier(
            args.app_name,
            field="readiness app name",
        ).strip()
        configured_socket = str(getattr(args, "core_socket", "") or "").strip()
        if configured_socket:
            socket_path = validate_evidence_path(
                configured_socket,
                field="readiness core socket",
            )
            if not socket_path.is_absolute() or ".." in socket_path.parts:
                raise ValueError("readiness core socket must be an absolute normalized path")
            if socket_path != self.candidate_config.socket_path:
                raise ValueError(
                    "readiness core socket does not match the candidate core configuration"
                )
            self.args.core_socket = str(socket_path)
        else:
            self.args.core_socket = ""
        self.results: list[CheckResult] = []
        self.metadata: dict[str, Any] = {}

    @staticmethod
    def _discover_core_binding(args: argparse.Namespace) -> Path | None:
        configured = str(getattr(args, "core_binding", "") or "").strip()
        if not configured:
            configured = str(os.getenv(BINDING_ENV, "") or "").strip()
        if configured:
            reject_sensitive_identifier(
                configured,
                field="readiness core binding",
            )
            path = Path(configured).expanduser()
        else:
            candidate = default_binding_path()
            if not (candidate.exists() or candidate.is_symlink()):
                return None
            path = candidate
        if (
            not path.is_absolute()
            or ".." in path.parts
            or "\x00" in str(path)
            or Path(os.path.normpath(str(path))) != path
        ):
            raise ValueError(
                "readiness core binding must be an absolute normalized path"
            )
        return path

    def _validate_core_binding(self, binding: CoreClientBinding) -> None:
        config = self.candidate_config
        expected_paths = {
            "repo_root": ROOT,
            "data_root": self.core_paths.data_root,
            "config_path": self.core_paths.config,
            "socket_path": config.socket_path,
            "state_path": config.state_path,
            "memory_path": config.memory_path,
            "capture_root": config.capture_root,
            "export_root": self.core_paths.data_root / "exports",
            "backup_root": self.core_paths.data_root / "backups",
            "recovery_root": self.core_paths.data_root / "recovery",
        }
        if any(getattr(binding, field) != path for field, path in expected_paths.items()):
            raise ValueError(
                "readiness core binding layout does not match the candidate core configuration"
            )
        expected_layout = (
            "canonical"
            if self.core_paths.data_root == ROOT / ".synapse_s2"
            else "reviewed-noncanonical"
        )
        if binding.layout != expected_layout:
            raise ValueError(
                "readiness core binding layout mode does not match the candidate layout"
            )
        if binding.core_label != self.args.core_label:
            raise ValueError(
                "readiness core binding label does not match the candidate core label"
            )
        if (
            binding.config_fingerprint != config.fingerprint
            or binding.embedding_space_identity != config.embedding_space_identity
        ):
            raise ValueError(
                "readiness core binding fingerprint does not match the candidate core configuration"
            )
        try:
            governed = database_requires_core(binding.memory_path)
        except Exception as exc:
            raise ValueError(
                "readiness core binding database governance could not be verified"
            ) from exc
        if (
            binding.authority_mode == "candidate-local-v5" and governed
        ) or (
            binding.authority_mode == "authoritative-core-v6" and not governed
        ):
            raise ValueError(
                "readiness core binding authority mode does not match database governance"
            )

    @staticmethod
    def _argument_expectation(
        args: argparse.Namespace,
        preferred: str,
        legacy: str,
    ) -> Any:
        value = getattr(args, preferred, None)
        return value if value is not None else getattr(args, legacy, None)

    def _validate_candidate_expectations(self, args: argparse.Namespace) -> None:
        """Fail closed when a caller's acceptance claims differ from the candidate."""

        provider = self._argument_expectation(
            args,
            "expected_embedding_provider",
            "embedding_provider",
        )
        if provider is not None:
            safe_provider = reject_sensitive_identifier(
                provider,
                field="readiness expected embedding provider",
            ).strip().lower()
            if not safe_provider or safe_provider not in _PROVIDER_EXPECTATIONS:
                raise ValueError("readiness expected embedding provider is invalid")
            candidate_provider = self.candidate_config.embedding_provider_name.strip().lower()
            if _PROVIDER_EXPECTATIONS[safe_provider] != _PROVIDER_EXPECTATIONS[candidate_provider]:
                raise ValueError(
                    "readiness embedding provider expectation does not match candidate config"
                )

        for preferred, legacy, expected, label in (
            (
                "expected_dimension",
                "dimension",
                self.candidate_config.dimension,
                "dimension",
            ),
            (
                "expected_neurons",
                "neurons",
                self.candidate_config.num_neurons,
                "neurons",
            ),
            (
                "expected_top_k",
                "top_k",
                self.candidate_config.default_top_k,
                "top_k",
            ),
        ):
            value = self._argument_expectation(args, preferred, legacy)
            if value is not None and (type(value) is not int or value != expected):
                raise ValueError(
                    f"readiness {label} expectation does not match candidate config"
                )

        neural = self.candidate_config.embedding_provider_name.strip().lower() in {
            "mlx-neural",
            "mlx-neural-v1",
        }
        neural_values = {
            "model": self._argument_expectation(
                args, "expected_neural_model", "neural_model"
            ),
            "revision": getattr(args, "expected_neural_revision", None),
            "pooling": getattr(args, "expected_neural_pooling", None),
            "max_tokens": getattr(args, "expected_neural_max_tokens", None),
            "normalize": getattr(args, "expected_neural_normalize", None),
            "local_files_only": self._argument_expectation(
                args,
                "expected_neural_local_files_only",
                "neural_local_files_only",
            ),
            "cache_dir": self._argument_expectation(
                args, "expected_neural_cache_dir", "neural_cache_dir"
            ),
        }
        for key in ("model", "revision", "pooling"):
            value = neural_values[key]
            if value is not None:
                neural_values[key] = reject_sensitive_identifier(
                    value,
                    field=f"readiness expected neural {key}",
                ).strip()
        if neural_values["cache_dir"] is not None:
            neural_values["cache_dir"] = str(
                validate_evidence_path(
                    neural_values["cache_dir"],
                    field="readiness expected neural cache path",
                )
            )
        if not neural:
            if any(value is not None for value in neural_values.values()):
                raise ValueError(
                    "readiness neural expectations require a neural candidate config"
                )
            return
        expected_neural = {
            "model": self.candidate_config.embedding_neural_model_id,
            "revision": self.candidate_config.embedding_neural_revision,
            "pooling": self.candidate_config.embedding_neural_pooling,
            "max_tokens": self.candidate_config.embedding_neural_max_tokens,
            "normalize": self.candidate_config.embedding_neural_normalize,
            "local_files_only": (
                self.candidate_config.embedding_neural_local_files_only
            ),
            "cache_dir": (
                None
                if self.candidate_config.embedding_neural_cache_dir is None
                else str(self.candidate_config.embedding_neural_cache_dir)
            ),
        }
        for key, value in neural_values.items():
            if value is not None and value != expected_neural[key]:
                raise ValueError(
                    f"readiness neural {key} expectation does not match candidate config"
                )

    def run(self) -> dict[str, Any]:
        if self.pack_dir.exists() or self.pack_dir.is_symlink():
            raise FileExistsError("readiness run directory already exists")
        if self.args.zip and (
            self.archive_path.exists() or self.archive_path.is_symlink()
        ):
            raise FileExistsError("readiness archive already exists")
        ensure_private_directory(self.output_root)
        self.pack_dir.mkdir(mode=0o700)
        self.artifact_dir.mkdir(mode=0o700)
        self.metadata = self._run_metadata()
        self._write_json(self.artifact_dir / "run_metadata.json", self.metadata)

        self._check_local_launcher()
        self._check_client_config()
        self._check_mcp_connect()
        self._check_neural_embedding()
        self._check_doctor()
        self._check_start_work()
        memory = self._check_memory_write()
        self._check_recall(memory)
        self._check_app_preview()
        self._check_wrap_session()
        self._check_dashboard()
        self._check_capture_inbox()
        return self._guarded_recovery_and_finalize()

    def _run_metadata(self) -> dict[str, Any]:
        config = self.candidate_config
        return {
            "action": "operator-readiness-certification",
            "run_id": self.run_id,
            "context_id": self.context,
            "agent_id": self.agent_id,
            "created_at": time.time(),
            "created_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "repo_root": str(ROOT),
            "git": self._git_metadata(),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python": sys.version.split()[0],
            },
            "launcher": str(self.launcher),
            "core_config_contract": self.core_config_contract,
            "quiescence_policy_contract": quiescence_policy_contract(),
            "quiescence_policy_digest": quiescence_policy_digest(),
            "embedding_provider": config.embedding_provider_name,
            "topology": {
                "dimension": config.dimension,
                "neurons": config.num_neurons,
                "top_k": config.default_top_k,
            },
            "neural_model": config.embedding_neural_model_id,
            "neural_revision": config.embedding_neural_revision,
            "neural_pooling": config.embedding_neural_pooling,
            "neural_max_tokens": config.embedding_neural_max_tokens,
            "neural_normalize": config.embedding_neural_normalize,
            "neural_local_files_only": config.embedding_neural_local_files_only,
            "authority_route": {
                "mode": (
                    self.core_binding.authority_mode
                    if self.core_binding is not None
                    else "explicit-socket"
                    if self.args.core_socket
                    else "durable-marker"
                ),
                "source": "core-binding" if self.core_binding is not None else "legacy",
                "socket": str(config.socket_path),
                "candidate_config_fingerprint": config.fingerprint,
                "binding_digest": (
                    self.core_binding.digest
                    if self.core_binding is not None
                    else None
                ),
            },
        }

    def _git_metadata(self) -> dict[str, Any]:
        def git(*parts: str) -> str:
            completed = subprocess.run(
                ["git", *parts],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            return completed.stdout.strip() if completed.returncode == 0 else ""

        return {
            "head": git("rev-parse", "HEAD"),
            "branch": git("branch", "--show-current"),
            "status_short": git("status", "--short"),
        }

    def _base_env(self) -> dict[str, str]:
        # Probes execute a broad dependency surface (FastMCP, Python, MLX).
        # Start from a small operating environment instead of inheriting cloud
        # credentials or Python/DYLD injection controls from the operator shell.
        env = {
            name: value
            for name in CHILD_ENV_ALLOWLIST
            if (value := os.environ.get(name)) is not None
        }
        env.setdefault("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
        env.setdefault("HOME", str(Path.home()))
        env["PYTHONNOUSERSITE"] = "1"
        if self.core_binding is not None:
            env[BINDING_ENV] = str(self.core_binding_path)
        elif self.args.core_socket:
            env["SYNAPSE_S2_CORE_SOCKET"] = self.args.core_socket
        else:
            env["SYNAPSE_S2_STATE_PATH"] = str(self.candidate_config.state_path)
            env["SYNAPSE_S2_MEMORY_DB"] = str(self.candidate_config.memory_path)
            env["SYNAPSE_S2_EXPORT_DIR"] = str(self.core_paths.data_root / "exports")
            env["SYNAPSE_S2_CAPTURE_ROOT"] = str(self.candidate_config.capture_root)
        return env

    def _cli_command(self, *parts: str) -> list[str]:
        return [
            self.python,
            str(ROOT / "synapse_cli.py"),
            "--json",
            *parts,
        ]

    def _record_manual(
        self,
        check_id: str,
        *,
        label: str,
        status: str,
        required: bool,
        detail: str,
        repair: str = "",
        metrics: dict[str, Any] | None = None,
    ) -> CheckResult:
        safe_detail = sanitize_evidence_text(detail)
        safe_repair = sanitize_evidence_text(repair)
        result = CheckResult(
            check_id=check_id,
            label=label,
            status=status,
            required=required,
            detail=safe_detail,
            repair=safe_repair,
            metrics=json_safe(metrics or {}),
        )
        self.results.append(result)
        return result

    def _run_command(
        self,
        check_id: str,
        *,
        label: str,
        command: list[str],
        required: bool,
        timeout: float,
        evaluator: Evaluator,
        env: dict[str, str] | None = None,
    ) -> CheckResult:
        stdout = ""
        stderr = ""
        raw_parsed: Any = None
        parsed: Any = None
        start = time.perf_counter()
        returncode: int | None
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=env if env is not None else self._base_env(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            returncode = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as exc:
            returncode = None
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr if isinstance(exc.stderr, str) else "") + f"\nTimed out after {timeout}s"
        duration_ms = round((time.perf_counter() - start) * 1000.0, 3)

        paths: dict[str, str] = {}
        prefix = self.artifact_dir / safe_filename(check_id)
        stdout_path = prefix.with_suffix(".stdout.txt")
        stderr_path = prefix.with_suffix(".stderr.txt")
        safe_stdout = sanitize_evidence_text(stdout)
        safe_stderr = sanitize_evidence_text(stderr)

        if stdout.strip():
            try:
                raw_parsed = parse_json_stdout(stdout)
                parsed = json_safe(raw_parsed)
                safe_stdout = json.dumps(
                    parsed,
                    indent=2,
                    sort_keys=True,
                ) + "\n"
                parsed_path = prefix.with_suffix(".parsed.json")
                self._write_json(parsed_path, parsed)
                paths["parsed"] = str(parsed_path)
            except Exception:
                parsed = None

        self._write_text(stdout_path, safe_stdout)
        self._write_text(stderr_path, safe_stderr)
        paths["stdout"] = str(stdout_path)
        paths["stderr"] = str(stderr_path)

        status, detail, repair, metrics = evaluator(
            -1 if returncode is None else int(returncode),
            raw_parsed,
            safe_stdout,
            safe_stderr,
        )
        detail = sanitize_evidence_text(detail)
        repair = sanitize_evidence_text(repair)
        result = CheckResult(
            check_id=check_id,
            label=label,
            status=status,
            required=required,
            detail=detail,
            repair=repair,
            command=command,
            returncode=returncode,
            duration_ms=duration_ms,
            artifact_paths=paths,
            parsed=parsed,
            metrics=json_safe(metrics),
        )
        self.results.append(result)
        return result

    def _check_local_launcher(self) -> None:
        exists = self.launcher.exists()
        executable = exists and os.access(self.launcher, os.X_OK)
        status = "ready" if executable else "blocked"
        detail = (
            f"Launcher executable present at {self.launcher}"
            if executable
            else f"Launcher missing or not executable at {self.launcher}"
        )
        self._record_manual(
            "local_launcher",
            label="Local launcher executable",
            status=status,
            required=True,
            detail=detail,
            repair="Run scripts/install_local_launcher.sh, then rerun certification.",
            metrics={"exists": exists, "executable": executable},
        )

    def _check_client_config(self) -> None:
        def evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "client config dry-run failed"),
                    "Run scripts/install_client_configs.py and inspect unreadable config files.",
                    {},
                )
            clients = dict(parsed.get("clients") or {})
            restart_required = bool(parsed.get("restart_required"))
            changed = [
                name
                for name, payload in clients.items()
                if isinstance(payload, dict) and (payload.get("would_change") or payload.get("changed"))
            ]
            status = "degraded" if restart_required or changed else "ready"
            repair = "Run scripts/install_client_configs.py, then restart affected clients." if changed else ""
            return (
                status,
                f"{len(clients)} client config targets checked; pending changes: {', '.join(changed) or 'none'}.",
                repair,
                {"client_count": len(clients), "pending_changes": changed},
            )

        command = [
            self.python,
            str(ROOT / "scripts" / "install_client_configs.py"),
            "--dry-run",
        ]
        if self.core_binding_path is not None:
            command.extend(["--core-binding", str(self.core_binding_path)])
        self._run_command(
            "client_config",
            label="Client config dry-run",
            command=command,
            required=True,
            timeout=30,
            evaluator=evaluate,
        )

    def _check_mcp_connect(self) -> None:
        fastmcp = str(ROOT / ".venv" / "bin" / "fastmcp")
        read_only_launcher = command_to_text(
            [
                "/usr/bin/env",
                "SYNAPSE_S2_CLIENT_SESSION_BRIDGE=0",
                "SYNAPSE_S2_CLIENT_CORTEX=0",
                str(self.launcher),
            ]
        )

        def list_eval(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0:
                return (
                    "blocked",
                    compact_text(stderr or stdout or "FastMCP list failed"),
                    "Run uv sync and scripts/install_local_launcher.sh, then retry.",
                    {},
                )
            expected = "retrieve_spiking_memory_v2"
            if expected not in stdout:
                return (
                    "blocked",
                    f"FastMCP connected but did not list {expected}.",
                    "Inspect mcp_server.py registration and rerun FastMCP list.",
                    {},
                )
            return (
                "ready",
                "FastMCP listed SYNAPSE-S2 tools through the installed launcher.",
                "",
                {"expected_tool_seen": expected},
            )

        self._run_command(
            "mcp_connect",
            label="MCP client connect",
            command=[
                fastmcp,
                "list",
                "--command",
                read_only_launcher,
                "--json",
                "--timeout",
                "20",
            ],
            required=True,
            timeout=45,
            evaluator=list_eval,
        )

        def status_eval(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0:
                return (
                    "blocked",
                    compact_text(stderr or stdout or "FastMCP status call failed"),
                    "Open the parsed artifact and fix the launcher or MCP server import error.",
                    {},
                )
            runtime = runtime_status_from_mcp_envelope(parsed)
            if runtime is None:
                return (
                    "blocked",
                    "FastMCP status call omitted a machine-verifiable runtime payload.",
                    "Inspect the installed launcher status response and restore the closed runtime contract.",
                    {},
                )
            config = self.candidate_config
            provider = dict(runtime.get("embedding_provider") or {})
            expected_provider_id, _provider_type = _PROVIDER_EXPECTATIONS[
                config.embedding_provider_name.strip().lower()
            ]
            exact_matches = {
                "runtime_ready": runtime.get("runtime") == "ready",
                "dimension": runtime.get("dimension") == config.dimension,
                "num_neurons": runtime.get("num_neurons") == config.num_neurons,
                "default_top_k": runtime.get("default_top_k") == config.default_top_k,
                "recall_count": runtime.get("recall_count") == config.recall_count,
                "quick_pruning_interval_seconds": runtime.get(
                    "quick_pruning_interval_seconds"
                )
                == config.quick_pruning_interval_seconds,
                "idle_deep_sleep_seconds": runtime.get("idle_deep_sleep_seconds")
                == config.idle_deep_sleep_seconds,
                "mlx_device": str(runtime.get("mlx_device") or "").lower()
                == config.mlx_device,
                "embedding_provider": provider.get("provider")
                == expected_provider_id,
                "embedding_provider_type": provider.get("provider_type")
                == _provider_type,
            }
            if config.embedding_provider_name.strip().lower() in {
                "mlx-neural",
                "mlx-neural-v1",
            }:
                # ``runtime_config`` is the closed, canonical neural wire
                # contract.  Status also repeats its operator-facing fields at
                # the provider top level; those copies are useful only when
                # they agree exactly with the canonical object.  Do not fall
                # back to embedding-result ``details`` provenance here: the
                # status surface does not emit it, and accepting it would make
                # contradictory wire shapes order-dependent.
                runtime_config_wire = provider.get("runtime_config")
                runtime_config = (
                    runtime_config_wire
                    if type(runtime_config_wire) is dict
                    else {}
                )
                expected_cache_dir = (
                    ""
                    if config.embedding_neural_cache_dir is None
                    else str(config.embedding_neural_cache_dir)
                )
                expected_runtime_config = {
                    "schema": EMBEDDING_RUNTIME_CONFIG_SCHEMA,
                    "provider": expected_provider_id,
                    "model_id": config.embedding_neural_model_id,
                    "revision": config.embedding_neural_revision or "",
                    "cache_dir": expected_cache_dir,
                    "pooling": config.embedding_neural_pooling,
                    "max_tokens": config.embedding_neural_max_tokens,
                    "normalize": config.embedding_neural_normalize,
                    "local_files_only": (
                        config.embedding_neural_local_files_only
                    ),
                }
                exact_matches.update(
                    {
                        "neural_runtime_config": runtime_config
                        == expected_runtime_config,
                        "neural_model_id": runtime_config.get("model_id")
                        == config.embedding_neural_model_id,
                        "neural_revision": runtime_config.get("revision")
                        == (config.embedding_neural_revision or ""),
                        "neural_cache_dir": runtime_config.get("cache_dir")
                        == expected_cache_dir,
                        "neural_pooling": runtime_config.get("pooling")
                        == config.embedding_neural_pooling,
                        "neural_max_tokens": runtime_config.get("max_tokens")
                        == config.embedding_neural_max_tokens,
                        "neural_normalize": runtime_config.get("normalize")
                        is config.embedding_neural_normalize,
                        "neural_local_files_only": runtime_config.get(
                            "local_files_only"
                        )
                        is config.embedding_neural_local_files_only,
                        "neural_top_level_consistent": all(
                            (
                                provider.get("model_id")
                                == runtime_config.get("model_id"),
                                provider.get("revision")
                                == runtime_config.get("revision"),
                                provider.get("cache_dir")
                                == runtime_config.get("cache_dir"),
                                provider.get("pooling")
                                == runtime_config.get("pooling"),
                                provider.get("max_tokens")
                                == runtime_config.get("max_tokens"),
                                provider.get("normalized")
                                is runtime_config.get("normalize"),
                                provider.get("local_files_only")
                                is runtime_config.get("local_files_only"),
                            )
                        ),
                    }
                )
            if config.require_native:
                exact_matches["native_runtime"] = runtime.get("mlx_available") is True
            ready = all(exact_matches.values())
            attestation = dict(self.core_config_attestation)
            return (
                "ready" if ready else "blocked",
                (
                    "Installed launcher runtime exactly matched the reviewed CoreConfig."
                    if ready
                    else "Installed launcher runtime drifted from the reviewed CoreConfig."
                ),
                (
                    ""
                    if ready
                    else "Republish the candidate config and binding, reinstall client configs, then rerun readiness."
                ),
                {
                    "exact_matches": exact_matches,
                    **attestation,
                },
            )

        self._run_command(
            "mcp_status_call",
            label="MCP status tool call",
            command=[
                fastmcp,
                "call",
                "--command",
                read_only_launcher,
                "--target",
                "get_spiking_attention_status",
                "--input-json",
                json.dumps({"context_id": self.context}),
                "--json",
                "--timeout",
                "20",
            ],
            required=True,
            timeout=45,
            evaluator=status_eval,
        )

        self._run_command(
            "mcp_contract_probe",
            label="MCP compact contract probe",
            command=[
                fastmcp,
                "call",
                "--command",
                read_only_launcher,
                "--target",
                "list_spiking_memory",
                "--input-json",
                json.dumps(
                    {
                        "context_id": self.context,
                        "limit": 1,
                        "response_mode": "compact",
                        "max_response_bytes": MCP_COMPACT_BUDGET,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "--json",
                "--timeout",
                "30",
            ],
            required=True,
            timeout=60,
            evaluator=mcp_compact_contract_probe_status,
        )

    def _check_neural_embedding(self) -> None:
        config = self.candidate_config
        provider_id, provider_type_expected = _PROVIDER_EXPECTATIONS[
            config.embedding_provider_name.strip().lower()
        ]
        expected_neural = provider_type_expected == "mlx-neural"

        def evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "embedding benchmark failed"),
                    "Verify SYNAPSE_S2_NEURAL_MODEL, SYNAPSE_S2_NEURAL_CACHE_DIR, and uv sync dependencies.",
                    {},
                )
            provider = dict(parsed.get("embedding_provider") or {})
            provider_type = str(provider.get("provider_type") or "")
            observed_provider_id = str(provider.get("provider") or "")
            nonzero = int(parsed.get("vector_nonzero_count") or 0)
            native = bool(provider.get("native_mlx"))
            details = dict(provider.get("details") or {})
            exact_matches: dict[str, bool] = {
                "provider": observed_provider_id == provider_id,
                "provider_type": provider_type == provider_type_expected,
                "result_dimensions": parsed.get("dimensions") == config.dimension,
                "provider_dimensions": provider.get("dimensions") == config.dimension,
                "local_only": provider.get("local_only") is True,
            }
            if expected_neural:
                exact_matches.update(
                    {
                        "model_id": (
                            provider.get("model_id")
                            == config.embedding_neural_model_id
                        ),
                        "revision": (
                            details.get("revision")
                            == (config.embedding_neural_revision or "")
                        ),
                        "pooling": (
                            provider.get("pooling")
                            == config.embedding_neural_pooling
                        ),
                        "max_tokens": (
                            details.get("max_tokens")
                            == config.embedding_neural_max_tokens
                        ),
                        "normalize": (
                            provider.get("normalized")
                            is config.embedding_neural_normalize
                        ),
                        "local_files_only": (
                            details.get("local_files_only")
                            is config.embedding_neural_local_files_only
                        ),
                        "native_mlx": native,
                    }
                )
            ready = nonzero > 0 and all(exact_matches.values())
            detail = (
                f"{provider_type or observed_provider_id or 'unknown'} produced "
                f"{nonzero} nonzero dims in {parsed.get('average_latency_ms')} ms; "
                f"candidate_config_match={all(exact_matches.values())}."
            )
            repair = ""
            if not ready:
                repair = (
                    "Run the exact candidate core configuration; for neural mode, "
                    "cache its pinned immutable model revision and repair MLX dependencies."
                )
            return (
                "ready" if ready else "blocked",
                detail,
                repair,
                {
                    "provider_type": provider_type,
                    "provider": observed_provider_id,
                    "native_mlx": native,
                    "vector_nonzero_count": nonzero,
                    "average_latency_ms": parsed.get("average_latency_ms"),
                    "model_id": provider.get("model_id"),
                    "runtime_source": (provider.get("details") or {}).get("runtime_source"),
                    "candidate_config_fingerprint": config.fingerprint,
                    "exact_matches": exact_matches,
                },
            )

        routed_to_core = (
            (
                self.core_binding is not None
                and self.core_binding.authority_mode == "authoritative-core-v6"
            )
            or bool(self.args.core_socket)
            or database_requires_core(config.memory_path)
        )
        command = [self.python, str(ROOT / "synapse_cli.py"), "--json"]
        probe_env = self._base_env()
        if not routed_to_core and self.core_binding is None:
            command.extend(
                [
                    "--dimension",
                    str(config.dimension),
                    "--neurons",
                    str(config.num_neurons),
                    "--top-k",
                    str(config.default_top_k),
                    "--embedding-provider",
                    config.embedding_provider_name,
                ]
            )
            if expected_neural:
                probe_env.update(
                    {
                        "SYNAPSE_S2_NEURAL_MODEL": str(
                            config.embedding_neural_model_id
                        ),
                        "SYNAPSE_S2_NEURAL_REVISION": str(
                            config.embedding_neural_revision
                        ),
                        "SYNAPSE_S2_NEURAL_POOLING": str(
                            config.embedding_neural_pooling
                        ),
                        "SYNAPSE_S2_NEURAL_MAX_TOKENS": str(
                            config.embedding_neural_max_tokens
                        ),
                        "SYNAPSE_S2_NEURAL_NORMALIZE": (
                            "true"
                            if config.embedding_neural_normalize
                            else "false"
                        ),
                        "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": (
                            "true"
                            if config.embedding_neural_local_files_only
                            else "false"
                        ),
                    }
                )
                if config.embedding_neural_cache_dir is not None:
                    probe_env["SYNAPSE_S2_NEURAL_CACHE_DIR"] = str(
                        config.embedding_neural_cache_dir
                    )
        command.extend(
            [
                "provider-benchmark",
                "--text",
                f"SYNAPSE-S2 readiness neural embedding proof {self.run_id}",
                "--runs",
                "1",
                "--embedding-dimensions",
                str(config.dimension),
            ]
        )
        self._run_command(
            "neural_embedding",
            label="Embedding provider proof",
            command=command,
            required=True,
            timeout=120,
            evaluator=evaluate,
            env=probe_env,
        )

    def _check_doctor(self) -> None:
        def evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "doctor failed"),
                    "Run synapse_cli.py doctor --repair-plan directly and inspect stderr.",
                    {},
                )
            overall = str(parsed.get("overall_status") or "blocked")
            checks = list(parsed.get("checks") or [])
            repair_plan = list(parsed.get("repair_plan") or [])
            status = "ready" if overall == "ready" else "degraded" if repair_plan else "blocked"
            return (
                status,
                f"Doctor {overall}; {len(checks)} checks; repair plan entries: {len(repair_plan)}.",
                " | ".join(compact_text(item, limit=160) for item in repair_plan[:3]),
                {"overall_status": overall, "check_count": len(checks), "repair_plan": repair_plan},
            )

        provider_type = _PROVIDER_EXPECTATIONS[
            self.candidate_config.embedding_provider_name.strip().lower()
        ][1]
        timeout = (
            NEURAL_DOCTOR_TIMEOUT_SECONDS
            if provider_type == "mlx-neural"
            else DOCTOR_TIMEOUT_SECONDS
        )
        self._run_command(
            "doctor",
            label="SYNAPSE Doctor",
            command=self._cli_command("doctor", "--context", self.context, "--include-apps", "--repair-plan"),
            required=True,
            timeout=timeout,
            evaluator=evaluate,
        )

    def _check_start_work(self) -> None:
        def evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "Start Work failed"),
                    "Run synapse_cli.py start-work and inspect Doctor if this keeps failing.",
                    {},
                )
            sections = list(parsed.get("brief_sections") or [])
            action = parsed.get("action")
            if action != "start-work" or not sections:
                return (
                    "blocked",
                    "Start Work did not return operator sections.",
                    "Repair DashboardRuntime.start_work before relying on morning briefs.",
                    {},
                )
            return (
                "ready",
                f"Start Work generated {len(sections)} sections with context score {parsed.get('score')}.",
                "",
                {
                    "section_count": len(sections),
                    "score": parsed.get("score"),
                    "status": parsed.get("status"),
                    "next_actions": parsed.get("next_actions", [])[:3],
                },
            )

        self._run_command(
            "start_work",
            label="Start Work brief",
            command=self._cli_command(
                "start-work",
                "--context",
                self.context,
                "--agent-id",
                self.agent_id,
                "--prompt",
                f"Monday operator readiness certification {self.run_id}",
            ),
            required=True,
            timeout=90,
            evaluator=evaluate,
        )

    def _check_memory_write(self) -> dict[str, Any]:
        tag = safe_filename(f"{self.run_id}-memory-write")
        git_head = self.metadata.get("git", {}).get("head", "")
        text = (
            f"Readiness certification {self.run_id}: real memory write proof for SYNAPSE-S2 "
            f"context {self.context} on commit {git_head}. This is an operator evidence trace, "
            "not a sample dataset or demo seed."
        )

        def evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "memory write failed"),
                    "Run Doctor and verify the SQLite memory DB is writable.",
                    {},
                )
            memory_id = str(parsed.get("memory_id") or "")
            if not memory_id:
                return (
                    "blocked",
                    "remember-text returned no memory_id.",
                    "Inspect register_text_trace persistence and memory_store writes.",
                    {},
                )
            return (
                "ready",
                f"Wrote trace {parsed.get('tag')} as {memory_id}.",
                "",
                {
                    "memory_id": memory_id,
                    "tag": parsed.get("tag"),
                    "spike_count": parsed.get("spike_count"),
                },
            )

        result = self._run_command(
            "memory_write",
            label="Memory write",
            command=self._cli_command(
                "remember-text",
                "--context",
                self.context,
                "--tag",
                tag,
                "--text",
                text,
                "--metadata",
                json.dumps(
                    {
                        "source": "operator_readiness_certify",
                        "run_id": self.run_id,
                        "git_head": git_head,
                        "operator_evidence": True,
                    },
                    sort_keys=True,
                ),
            ),
            required=True,
            timeout=90,
            evaluator=evaluate,
        )
        return result.parsed if isinstance(result.parsed, dict) else {"tag": tag, "text": text}

    def _check_recall(self, memory: dict[str, Any]) -> None:
        expected = [
            str(memory.get("memory_id") or ""),
            str(memory.get("tag") or ""),
            self.run_id,
        ]
        query = f"readiness certification {self.run_id} real memory write proof"

        def evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "recall query failed"),
                    "Verify embedding provider and memory DB before trusting recall.",
                    {},
                )
            data = parsed.get("data")
            query_metadata = data.get("query") if isinstance(data, dict) else None
            ranker = data.get("ranker") if isinstance(data, dict) else None
            provenance = parsed.get("provenance")
            items = data.get("items") if isinstance(data, dict) else None
            if (
                parsed.get("schema") != "synapse-s2.token-contract.v1"
                or parsed.get("operation") != "memory-retrieval"
                or parsed.get("ok") is not True
                or not isinstance(data, dict)
                or data.get("raw_input_stored") is not False
                or not isinstance(query_metadata, dict)
                or query_metadata.get("context_id") != self.context
                or query_metadata.get("recall_scope") != "local"
                or query_metadata.get("raw_input_stored") is not False
                or not isinstance(ranker, dict)
                or ranker.get("score_semantics") != "uncalibrated-ranking-signal"
                or not isinstance(provenance, dict)
                or provenance.get("source") != "authoritative-retrieval-v2"
                or provenance.get("context_id") != self.context
                or provenance.get("raw_input_stored") is not False
                or not isinstance(items, list)
            ):
                return (
                    "blocked",
                    "Retrieval v2 returned an invalid structured read-only contract.",
                    "Inspect retrieve-v2, its authoritative core route, and token contract projection.",
                    {},
                )
            evidence_fields: list[str] = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                evidence_fields.extend(
                    str(item.get(field) or "")
                    for field in ("memory_id", "tag", "label", "summary", "excerpt")
                )
            matched = [
                value
                for value in expected
                if value and any(value in field for field in evidence_fields)
            ]
            if not matched:
                return (
                    "blocked",
                    "Recall returned but did not include the readiness memory id, tag, or run id.",
                    "Inspect retrieve-v2 output, scope provenance, and memory index consistency.",
                    {"expected": [item for item in expected if item]},
                )
            return (
                "ready",
                f"Retrieval v2 returned the readiness write using {', '.join(matched[:2])}.",
                "",
                {
                    "matched_evidence": matched,
                    "result_count": len(items),
                    "ranker_id": ranker.get("id"),
                    "ranker_version": ranker.get("version"),
                    "snapshot_id": provenance.get("snapshot_id"),
                    "raw_input_stored": False,
                },
            )

        self._run_command(
            "recall",
            label="Retrieval v2 read-only proof",
            command=self._cli_command(
                "retrieve-v2",
                "--context",
                self.context,
                "--prompt",
                query,
                "--scope",
                "local",
                "--result-limit",
                "8",
                "--candidate-limit",
                "64",
                "--response-mode",
                "compact",
                "--max-response-bytes",
                "24576",
            ),
            required=True,
            timeout=90,
            evaluator=evaluate,
        )

    def _check_app_preview(self) -> None:
        def app_list_eval(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "app-list failed"),
                    "Grant Automation permissions or use manual selected-text capture.",
                    {},
                )
            apps = list(parsed.get("apps") or [])
            app = choose_app(apps, preferred=self.args.app_name)
            if app is None:
                return (
                    "blocked",
                    "No running apps were detected for App Connect.",
                    "Open Chrome, Codex, Terminal, or the target app and rerun certification.",
                    {"app_count": 0},
                )
            return (
                "ready",
                f"Detected {len(apps)} apps; selected {app.get('app_name')}.",
                "",
                {"app_count": len(apps), "selected_app": app},
            )

        app_list = self._run_command(
            "app_list",
            label="App Connect detect",
            command=self._cli_command("app-list"),
            required=False,
            timeout=45,
            evaluator=app_list_eval,
        )
        selected = app_list.metrics.get("selected_app") if isinstance(app_list.metrics, dict) else None
        if not isinstance(selected, dict):
            self._record_manual(
                "app_preview",
                label="App Connect honest preview",
                status="blocked",
                required=True,
                detail="Skipped because no attachable app was selected.",
                repair="Open an app and rerun certification.",
            )
            return

        app_name = str(selected.get("app_name") or "")
        bundle_id = str(selected.get("bundle_id") or "")
        pid = str(int(selected.get("pid") or 0))

        def connect_eval(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "app-connect failed"),
                    "Confirm the app is still running or use --app-name for a visible app.",
                    {},
                )
            connection_id = str(parsed.get("connection_id") or "")
            return (
                "ready" if connection_id else "blocked",
                f"Attached {parsed.get('app_name')} as {connection_id or 'missing connection id'}.",
                "Retry App Connect attach if the connection id is missing.",
                {"connection_id": connection_id, "app_name": parsed.get("app_name")},
            )

        connection = self._run_command(
            "app_connect",
            label="App Connect attach",
            command=self._cli_command(
                "app-connect",
                "--context",
                self.context,
                "--app-name",
                app_name,
                "--bundle-id",
                bundle_id,
                "--pid",
                pid,
                "--tag",
                "operator-readiness-app",
                "--speaker",
                "operator",
                "--metadata",
                json.dumps({"source": "operator_readiness_certify", "run_id": self.run_id}),
                "--confirm",
            ),
            required=False,
            timeout=60,
            evaluator=connect_eval,
        )
        connection_id = str(connection.metrics.get("connection_id") or "")
        if not connection_id:
            self._record_manual(
                "app_preview",
                label="App Connect honest preview",
                status="blocked",
                required=True,
                detail="Skipped because App Connect attach did not return a connection id.",
                repair="Repair App Connect attach first.",
            )
            return

        def preview_eval(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0:
                return (
                    "blocked",
                    compact_text(stderr or stdout or "app-snapshot-preview failed"),
                    "Repair App Connect preview before relying on app capture receipts.",
                    {},
                )
            return app_preview_status(parsed)

        self._run_command(
            "app_preview",
            label="App Connect honest preview",
            command=self._cli_command("app-snapshot-preview", "--connection-id", connection_id),
            required=True,
            timeout=60,
            evaluator=preview_eval,
        )

    def _check_wrap_session(self) -> None:
        operation_log = [
            {
                "check_id": result.check_id,
                "status": result.status,
                "detail": result.detail,
            }
            for result in self.results
            if result.check_id in {"mcp_connect", "memory_write", "recall", "app_preview", "doctor"}
        ]
        text = (
            f"Readiness certification {self.run_id}: operator proof run for SYNAPSE-S2 context "
            f"{self.context}. This wrap records which certification checks passed, degraded, or blocked "
            "so future sessions can hydrate the handoff from durable memory."
        )

        def evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "wrap-session failed"),
                    "Use wrap-session --preview first, then rerun with --confirm after Doctor is clean.",
                    {},
                )
            event_count = int(parsed.get("event_count") or 0)
            relationship_count = int(parsed.get("relationship_count") or 0)
            if event_count <= 0:
                return (
                    "blocked",
                    "Wrap Session returned no captured events.",
                    "Ensure wrap-session text is non-empty and memory writes are healthy.",
                    {},
                )
            return (
                "ready",
                f"Wrap Session persisted {event_count} events and {relationship_count} relationships.",
                "",
                {
                    "event_count": event_count,
                    "relationship_count": relationship_count,
                    "source_tag": parsed.get("source_tag"),
                },
            )

        self._run_command(
            "wrap_session",
            label="Wrap Session persistence",
            command=self._cli_command(
                "wrap-session",
                "--context",
                self.context,
                "--agent-id",
                self.agent_id,
                "--source-tag",
                safe_filename(f"{self.run_id}-wrap"),
                "--text",
                text,
                "--operation-log-json",
                json.dumps(operation_log, sort_keys=True),
                "--confirm",
            ),
            required=True,
            timeout=90,
            evaluator=evaluate,
        )

    @staticmethod
    def _capture_status_ready(parsed: Any) -> tuple[bool, dict[str, Any]]:
        status = dict(parsed) if isinstance(parsed, dict) else {}
        zero_fields = (
            "pending_file_count",
            "processing_file_count",
            "inbox_temp_file_count",
            "processing_empty_claim_count",
            "processing_malformed_claim_count",
            "error_file_count",
            "unresolved_error_count",
            "unsafe_error_artifact_count",
            "error_resolution_pending_count",
            "error_resolution_failed_count",
        )
        counts: dict[str, int] = {}
        counts_valid = True
        for field in zero_fields:
            value = status.get(field)
            if type(value) is not int or int(value) < 0:
                counts_valid = False
                counts[field] = -1
            else:
                counts[field] = int(value)
        ready = (
            bool(status)
            and status.get("transport_ready") is True
            and status.get("missing_transport_directories") == []
            and status.get("unsafe_transport_directories") == []
            and counts_valid
            and all(value == 0 for value in counts.values())
        )
        return ready, {
            "transport_ready": status.get("transport_ready") is True,
            "missing_transport_directories": list(
                status.get("missing_transport_directories") or []
            )[:16],
            "unsafe_transport_directories": list(
                status.get("unsafe_transport_directories") or []
            )[:16],
            **counts,
        }

    def _check_capture_inbox(self) -> CheckResult:
        """Drain Phase-A capture debt, then publish one exact required verdict."""

        observed: dict[str, Any] = {}
        total_processed = 0
        drain_passes = 0

        def observe_evaluator(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "capture inbox status failed"),
                    "Repair the capture transport before operator certification.",
                    {},
                )
            return (
                "ready",
                "Observed the capture inbox before or during its bounded drain.",
                "",
                {
                    "pending_file_count": int(parsed.get("pending_file_count") or 0),
                    "processing_file_count": int(
                        parsed.get("processing_file_count") or 0
                    ),
                },
            )

        initial = self._run_command(
            "capture_inbox_observe_00",
            label="Capture inbox pre-drain observation",
            command=self._cli_command("capture-inbox-status"),
            required=False,
            timeout=30,
            evaluator=observe_evaluator,
        )
        if isinstance(initial.parsed, dict):
            observed = dict(initial.parsed)

        while (
            type(observed.get("pending_file_count")) is int
            and int(observed["pending_file_count"]) > 0
            and drain_passes < CAPTURE_DRAIN_MAX_PASSES
        ):
            before_pending = int(observed["pending_file_count"])
            drain_passes += 1

            def drain_evaluator(
                returncode: int,
                parsed: Any,
                stdout: str,
                stderr: str,
            ):
                if returncode != 0 or not isinstance(parsed, dict):
                    return (
                        "blocked",
                        compact_text(
                            stderr or stdout or "capture inbox processing failed"
                        ),
                        "Repair capture processing without deleting or relocating pending drops.",
                        {},
                    )
                error_count = int(parsed.get("error_file_count") or 0)
                return (
                    "ready" if error_count == 0 else "blocked",
                    (
                        "Processed one bounded capture-inbox batch."
                        if error_count == 0
                        else "Capture processing produced terminal error evidence."
                    ),
                    (
                        "Resolve capture error evidence through the governed workflow."
                        if error_count
                        else ""
                    ),
                    {
                        "processed_file_count": int(
                            parsed.get("processed_file_count") or 0
                        ),
                        "deferred_file_count": int(
                            parsed.get("deferred_file_count") or 0
                        ),
                        "error_file_count": error_count,
                    },
                )

            processed = self._run_command(
                f"capture_inbox_drain_{drain_passes:02d}",
                label=f"Capture inbox drain pass {drain_passes}",
                command=self._cli_command(
                    "capture-inbox-process",
                    "--max-files",
                    str(CAPTURE_DRAIN_BATCH_SIZE),
                    "--confirm",
                ),
                required=False,
                timeout=300,
                evaluator=drain_evaluator,
            )
            processed_count = (
                int(processed.parsed.get("processed_file_count") or 0)
                if isinstance(processed.parsed, dict)
                else 0
            )
            total_processed += processed_count
            observed_result = self._run_command(
                f"capture_inbox_observe_{drain_passes:02d}",
                label=f"Capture inbox observation {drain_passes}",
                command=self._cli_command("capture-inbox-status"),
                required=False,
                timeout=30,
                evaluator=observe_evaluator,
            )
            if not isinstance(observed_result.parsed, dict):
                observed = {}
                break
            observed = dict(observed_result.parsed)
            after_pending = observed.get("pending_file_count")
            if (
                type(after_pending) is int
                and int(after_pending) >= before_pending
                and processed_count == 0
            ):
                break

        def final_evaluator(returncode: int, parsed: Any, stdout: str, stderr: str):
            ready, metrics = self._capture_status_ready(parsed)
            metrics.update(
                {
                    "drain_passes": drain_passes,
                    "processed_file_count": total_processed,
                    "maximum_drain_passes": CAPTURE_DRAIN_MAX_PASSES,
                    "batch_size": CAPTURE_DRAIN_BATCH_SIZE,
                }
            )
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "capture inbox status failed"),
                    "Repair the capture transport and rerun a completely new evidence pack.",
                    metrics,
                )
            return (
                "ready" if ready else "blocked",
                (
                    "Capture transport is fully drained with no processing, temporary, or unresolved error debt."
                    if ready
                    else "Capture transport is not quiescent after its bounded drain."
                ),
                (
                    "Keep respawners paused; process replay-required files through the governed inbox and rerun certification."
                    if not ready
                    else ""
                ),
                metrics,
            )

        return self._run_command(
            "capture_inbox",
            label="Capture inbox drain and quiescence",
            command=self._cli_command("capture-inbox-status"),
            required=True,
            timeout=30,
            evaluator=final_evaluator,
        )

    @staticmethod
    def _reconciliation_ready(value: Any) -> bool:
        reconciliation = dict(value) if isinstance(value, dict) else {}
        return all(
            type(reconciliation.get(field)) is int
            and int(reconciliation[field]) == 0
            for field in (
                "missing_authoritative_ledger_count",
                "replay_required_capture_count",
                "replay_required_file_count",
                "identifierless_replay_file_count",
                "unclassified_file_count",
            )
        )

    @staticmethod
    def _capture_binding_ready(value: Any) -> bool:
        binding = dict(value) if isinstance(value, dict) else {}
        count = binding.get("verified_capture_count")
        return (
            binding.get("schema")
            == "synapse-s2.capture-ledger-binding-proof.v1"
            and binding.get("verified") is True
            and type(count) is int
            and int(count) >= 0
            and re.fullmatch(r"[0-9a-f]{64}", str(binding.get("revision") or ""))
            is not None
        )

    def _collect_quiescence_inventory(self) -> tuple[bool, dict[str, Any]]:
        try:
            findings = collect_process_inventory()
            launch_agents = collect_launchagent_inventory(
                labels={
                    "capture": DEFAULT_CAPTURE_LABEL,
                    "dashboard": DEFAULT_DASHBOARD_LABEL,
                    "core": self.args.core_label,
                }
            )
        except Exception as exc:
            return False, {
                "inventory_available": False,
                "error": safe_public_error(
                    exc,
                    fallback="read-only quiescence inventory failed",
                ),
                "process_findings": [],
                "process_findings_truncated": False,
                "loaded_categories": [],
                "quiescence_policy_schema": QUIESCENCE_POLICY_SCHEMA,
                "quiescence_policy_digest": quiescence_policy_digest(),
                "quiescence_policy_blockers": ["inventory-unavailable"],
                "launch_agents": {},
            }
        process_findings = [finding.to_wire() for finding in findings]
        truncated = len(findings) >= MAX_PROCESS_FINDINGS
        loaded = sorted(
            category
            for category, snapshot in launch_agents.items()
            if snapshot.get("loaded") is True
        )
        policy_blockers = launchagent_quiescence_blockers(launch_agents)
        ready = not process_findings and not truncated and not policy_blockers
        return ready, {
            "inventory_available": True,
            "process_findings": process_findings,
            "process_findings_truncated": truncated,
            "loaded_categories": loaded,
            "quiescence_policy_schema": QUIESCENCE_POLICY_SCHEMA,
            "quiescence_policy_digest": quiescence_policy_digest(),
            "quiescence_policy_blockers": policy_blockers,
            "launch_agents": launch_agents,
        }

    def _record_in_process_check(
        self,
        check_id: str,
        *,
        label: str,
        status: str,
        detail: str,
        repair: str,
        parsed: dict[str, Any],
        metrics: dict[str, Any],
        duration_ms: float,
        artifact_paths: dict[str, str] | None = None,
        preserve_crypto_fields: bool = False,
    ) -> CheckResult:
        parsed_path = self.artifact_dir / f"{safe_filename(check_id)}.parsed.json"
        if preserve_crypto_fields:
            parsed_bytes = (
                json.dumps(
                    parsed,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n"
            ).encode("utf-8")
            self._write_opaque_json_artifact(
                parsed_path,
                source_bytes=parsed_bytes,
                expected_payload=parsed,
            )
        else:
            self._write_json(parsed_path, parsed)
        paths = {"parsed": str(parsed_path), **(artifact_paths or {})}
        result = CheckResult(
            check_id=check_id,
            label=label,
            status=status,
            required=True,
            detail=sanitize_evidence_text(detail),
            repair=sanitize_evidence_text(repair),
            command=[],
            returncode=0 if status == "ready" else 1,
            duration_ms=round(float(duration_ms), 3),
            artifact_paths=paths,
            parsed=json_safe(parsed),
            metrics=json_safe(metrics),
        )
        self.results.append(result)
        return result

    def _record_recovery_skips(self, *, detail: str, repair: str) -> None:
        existing = {result.check_id for result in self.results}
        for check_id, label in (
            ("capture_ledger_audit", "Capture ledger integrity audit"),
            ("recovery_backup", "Paired recovery backup"),
            ("recovery_verify", "Recovery bundle verification"),
            ("recovery_restore", "Isolated recovery drill"),
        ):
            if check_id not in existing:
                self._record_manual(
                    check_id,
                    label=label,
                    status="blocked",
                    required=True,
                    detail=detail,
                    repair=repair,
                )

    def _record_guarded_recovery_evidence(
        self,
        evidence: dict[str, Any],
        *,
        duration_ms: float,
    ) -> None:
        before = dict(evidence.get("capture_ledger_before") or {})
        after = dict(evidence.get("capture_ledger_after") or {})
        publication_state = dict(
            evidence.get("capture_transport_at_publication") or {}
        )
        ledger_revision = str(before.get("audit_revision") or "")
        audited_count_fields = (
            "processed_file_count",
            "processed_total_bytes",
            "processed_v2_capture_count",
            "ledger_capture_count",
            "missing_authoritative_ledger_count",
            "ledger_binding_mismatch_count",
            "repairable_capture_count",
            "blocked_capture_count",
        )
        ledger_ready = bool(
            evidence.get("verified") is True
            and before.get("status") == "ready"
            and after.get("status") == "ready"
            and before.get("verification_passed") is True
            and after.get("verification_passed") is True
            and re.fullmatch(r"[0-9a-f]{64}", ledger_revision) is not None
            and ledger_revision == str(after.get("audit_revision") or "")
            and all(
                type(before.get(field)) is int
                and type(after.get(field)) is int
                and before[field] == after[field]
                for field in audited_count_fields
            )
            and publication_state.get("ledger_verification_passed") is True
            and ledger_revision
            == str(publication_state.get("ledger_audit_revision") or "")
        )
        ledger_payload = dict(before)
        ledger_payload.update(
            {
                "status": "ready" if ledger_ready else "blocked",
                "verification_passed": ledger_ready,
                "guarded": True,
                "publication_ledger_audit_revision": str(
                    publication_state.get("ledger_audit_revision") or ""
                ),
            }
        )
        self._record_in_process_check(
            "capture_ledger_audit",
            label="Capture ledger integrity audit",
            status="ready" if ledger_ready else "blocked",
            detail=(
                "Capture ledger and transport revision remained exact through guarded publication."
                if ledger_ready
                else "Guarded capture-ledger evidence was incomplete or drifted."
            ),
            repair=(
                ""
                if ledger_ready
                else "Reconcile the ledger and capture transport, then create a new evidence pack."
            ),
            parsed=ledger_payload,
            metrics=ledger_payload,
            duration_ms=duration_ms,
        )

        bundle = dict(evidence.get("bundle") or {})
        bundle_binding = dict(bundle.get("capture_ledger_binding") or {})
        bundle_reconciliation = dict(bundle.get("reconciliation") or {})
        backup_ready = (
            bundle.get("bundle_verified") is True
            and bundle.get("cutover_ready") is True
            and self._capture_binding_ready(bundle_binding)
            and self._reconciliation_ready(bundle_reconciliation)
        )
        self._record_in_process_check(
            "recovery_backup",
            label="Paired recovery backup",
            status="ready" if backup_ready else "blocked",
            detail=(
                "Created a signed paired SQLite and exactly-once capture recovery point under the exclusive guard."
                if backup_ready
                else "Guarded paired recovery backup was not immediately cutover-ready."
            ),
            repair=(
                ""
                if backup_ready
                else "Resolve capture, ledger, runtime, or backup integrity debt before cutover."
            ),
            parsed=bundle,
            metrics={
                "bundle_verified": bool(bundle.get("bundle_verified")),
                "cutover_ready": bool(bundle.get("cutover_ready")),
                "capture_file_count": int(bundle.get("capture_file_count") or 0),
                "capture_ledger_binding": bundle_binding,
                "reconciliation": bundle_reconciliation,
                "guarded": True,
            },
            duration_ms=duration_ms,
        )

        verification = dict(evidence.get("verification") or {})
        verify_binding = dict(verification.get("capture_ledger_binding") or {})
        verify_reconciliation = dict(verification.get("reconciliation") or {})
        verify_ready = (
            backup_ready
            and verification.get("verified") is True
            and verification.get("cutover_ready") is True
            and verification.get("receipt_identity_trusted") is True
            and self._capture_binding_ready(verify_binding)
            and verify_binding == bundle_binding
            and self._reconciliation_ready(verify_reconciliation)
        )
        self._record_in_process_check(
            "recovery_verify",
            label="Recovery bundle verification",
            status="ready" if verify_ready else "blocked",
            detail=(
                "Reverified the signed database, capture archive, schema, replay state, and signer under the guard."
                if verify_ready
                else "Guarded recovery verification was incomplete or untrusted."
            ),
            repair=(
                ""
                if verify_ready
                else "Inspect the signed recovery receipt and exact bound artifacts."
            ),
            parsed=verification,
            metrics={
                "verified": bool(verification.get("verified")),
                "cutover_ready": bool(verification.get("cutover_ready")),
                "receipt_identity_trusted": bool(
                    verification.get("receipt_identity_trusted")
                ),
                "capture_ledger_binding": verify_binding,
                "reconciliation": verify_reconciliation,
                "guarded": True,
            },
            duration_ms=duration_ms,
            preserve_crypto_fields=True,
        )

        restore = dict(evidence.get("restore") or {})
        restore_binding = dict(restore.get("capture_ledger_binding") or {})
        restore_reconciliation = dict(restore.get("reconciliation") or {})
        proof_source = Path(str(restore.get("recovery_proof_path") or ""))
        proof: dict[str, Any] = {}
        proof_source_bytes = b""
        proof_ready = False
        if proof_source.is_file() and not proof_source.is_symlink():
            try:
                proof_source_bytes = read_private_regular_bytes(
                    proof_source,
                    max_bytes=1024 * 1024,
                )
                loaded = json.loads(proof_source_bytes.decode("utf-8"))
                if isinstance(loaded, dict):
                    proof = loaded
                    proof_ready = (
                        proof.get("schema")
                        in {
                            "synapse-s2.recovery-bundle-restore.v1",
                            "synapse-s2.recovery-bundle-restore.v2",
                        }
                        and proof.get("mode") == "isolated-recovery-proof"
                        and proof.get("verified") is True
                        and proof.get("cutover_ready") is True
                        and int(
                            proof.get("missing_transport_ledger_count") or 0
                        )
                        == 0
                        and proof.get("capture_ledger_binding")
                        == restore_binding
                        and self._reconciliation_ready(
                            proof.get("reconciliation")
                        )
                    )
            except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
                proof_ready = False
        extra_artifacts: dict[str, str] = {}
        if proof_ready:
            durable_proof = (
                self.artifact_dir / "recovery_restore_proof.receipt.json"
            )
            try:
                self._write_signed_json_artifact(
                    durable_proof,
                    source_bytes=proof_source_bytes,
                    expected_payload=proof,
                )
            except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
                proof_ready = False
            else:
                extra_artifacts["recovery_proof"] = str(durable_proof)
        restore_ready = (
            verify_ready
            and restore.get("verified") is True
            and restore.get("cutover_ready") is True
            and int(restore.get("missing_transport_ledger_count") or 0) == 0
            and self._capture_binding_ready(restore_binding)
            and restore_binding == bundle_binding
            and self._reconciliation_ready(restore_reconciliation)
            and proof_ready
        )
        self._record_in_process_check(
            "recovery_restore",
            label="Isolated recovery drill",
            status="ready" if restore_ready else "blocked",
            detail=(
                "Materialized and verified an isolated paired restore without touching live state."
                if restore_ready
                else "Guarded isolated restore proof was incomplete or not cutover-ready."
            ),
            repair=(
                ""
                if restore_ready
                else "Inspect the isolated proof and resolve replay or ledger debt."
            ),
            parsed=restore,
            metrics={
                "verified": bool(restore.get("verified")),
                "cutover_ready": bool(restore.get("cutover_ready")),
                "capture_file_count": int(restore.get("capture_file_count") or 0),
                "missing_transport_ledger_count": int(
                    restore.get("missing_transport_ledger_count") or 0
                ),
                "capture_ledger_binding": restore_binding,
                "reconciliation": restore_reconciliation,
                "guarded": True,
            },
            duration_ms=duration_ms,
            artifact_paths=extra_artifacts,
        )

    def _guarded_recovery_and_finalize(self) -> dict[str, Any]:
        capture_results = [
            result
            for result in self.results
            if result.required and result.check_id == "capture_inbox"
        ]
        if len(capture_results) != 1 or capture_results[0].status != "ready":
            self._record_manual(
                "authority_guard",
                label="Exclusive authority guard",
                status="blocked",
                required=True,
                detail="Skipped because Phase-A capture quiescence did not pass.",
                repair="Drain capture debt and rerun a completely new evidence pack.",
            )
            self._record_manual(
                "guarded_quiescence",
                label="Quiescence under exclusive guard",
                status="blocked",
                required=True,
                detail="No guarded certification was attempted with capture debt present.",
                repair="Keep respawners paused, drain capture, and retry.",
            )
            self._record_recovery_skips(
                detail="Skipped because capture inbox quiescence was not ready.",
                repair="Repair the capture transport before recovery certification.",
            )
            return self._finalize()

        staging_root = (
            self.core_binding.recovery_root
            if self.core_binding is not None
            else self.core_paths.data_root / "recovery"
        )
        ensure_private_directory(staging_root)
        lease: CoreAuthorityLease | None = None
        store: DurableMemoryStore | None = None
        try:
            lease = CoreAuthorityLease.acquire_core(
                self.candidate_config.memory_path,
                timeout_seconds=AUTHORITY_GUARD_TIMEOUT_SECONDS,
                instance_id="readiness-certifier",
            )
            store = DurableMemoryStore.open_existing_for_core_maintenance(
                self.candidate_config.memory_path,
                authority_lease=lease,
            )
            self._record_manual(
                "authority_guard",
                label="Exclusive authority guard",
                status="ready",
                required=True,
                detail="Exclusive core authority fenced all cooperating local writers.",
                metrics={
                    "exclusive": True,
                    "role": "core",
                    "database_identity_bound": (
                        lease.database_device is not None
                        and lease.database_inode is not None
                    ),
                },
            )
        except Exception as exc:
            if store is not None:
                store.close()
            if lease is not None:
                lease.close()
            self._record_manual(
                "authority_guard",
                label="Exclusive authority guard",
                status="blocked",
                required=True,
                detail=safe_public_error(
                    exc,
                    fallback="exclusive authority acquisition failed",
                ),
                repair="Close exact local clients and disable their respawners before retrying.",
            )
            self._record_manual(
                "guarded_quiescence",
                label="Quiescence under exclusive guard",
                status="blocked",
                required=True,
                detail="Quiescence could not be proven without exclusive authority.",
                repair="Resolve the reported authority owner and rerun a new evidence pack.",
            )
            self._record_recovery_skips(
                detail="Skipped because exclusive authority was unavailable.",
                repair="Establish durable zero-writer quiescence first.",
            )
            return self._finalize()

        try:
            initial_ready, initial_inventory = self._collect_quiescence_inventory()
            if not initial_ready:
                self._record_manual(
                    "guarded_quiescence",
                    label="Quiescence under exclusive guard",
                    status="blocked",
                    required=True,
                    detail="A writer process or loaded SYNAPSE-S2 service remained after exclusive authority acquisition.",
                    repair="Stop the exact reported PID or label; never use a broad kill command.",
                    metrics={"initial": initial_inventory},
                )
                self._record_recovery_skips(
                    detail="Skipped because guarded process inventory was not empty.",
                    repair="Stop exact writers and rerun a completely new evidence pack.",
                )
            else:
                manager = VerifiedRecoveryManager(
                    store,
                    capture_root=self.candidate_config.capture_root,
                    runtime_state_path=self.candidate_config.state_path,
                )
                callback_started = False
                transaction_started = time.perf_counter()
                try:
                    with tempfile.TemporaryDirectory(
                        prefix=f"readiness-{safe_filename(self.run_id)}-",
                        dir=staging_root,
                    ) as temporary:
                        restore_root = Path(temporary) / "isolated-restore"
                        with manager.guarded_recovery_transaction(
                            restore_root,
                            purpose="operator-readiness",
                            pinned=True,
                        ) as publication:

                            def publish(guarded_evidence: dict[str, Any]) -> None:
                                nonlocal callback_started
                                callback_started = True
                                final_ready, final_inventory = (
                                    self._collect_quiescence_inventory()
                                )
                                guarded_ready = initial_ready and final_ready
                                self._record_manual(
                                    "guarded_quiescence",
                                    label="Quiescence under exclusive guard",
                                    status=(
                                        "ready" if guarded_ready else "blocked"
                                    ),
                                    required=True,
                                    detail=(
                                        "Process, LaunchAgent, authority, capture, and replay inventories remained empty through guarded publication."
                                        if guarded_ready
                                        else "A writer process or loaded service appeared before guarded publication."
                                    ),
                                    repair=(
                                        ""
                                        if guarded_ready
                                        else "Stop the exact reported process or label, drain capture, and create a new evidence pack."
                                    ),
                                    metrics={
                                        "initial": initial_inventory,
                                        "at_publication": final_inventory,
                                        "capture_transport_at_publication": dict(
                                            guarded_evidence.get(
                                                "capture_transport_at_publication"
                                            )
                                            or {}
                                        ),
                                    },
                                )
                                duration_ms = (
                                    time.perf_counter() - transaction_started
                                ) * 1000.0
                                self._record_guarded_recovery_evidence(
                                    guarded_evidence,
                                    duration_ms=duration_ms,
                                )

                            publication.publish(publish)
                except Exception as exc:
                    if callback_started:
                        # No authoritative manifest has been published yet.
                        # Let guard/temp/lease teardown finish, then fail closed.
                        raise
                    self._record_manual(
                        "guarded_quiescence",
                        label="Quiescence under exclusive guard",
                        status="blocked",
                        required=True,
                        detail=safe_public_error(
                            exc,
                            fallback="guarded recovery transaction failed",
                        ),
                        repair="Resolve the exact capture, runtime, ledger, or recovery drift and rerun a new evidence pack.",
                        metrics={"initial": initial_inventory},
                    )
                    self._record_recovery_skips(
                        detail="Skipped because the guarded recovery transaction did not reach publication.",
                        repair="Repair the guarded recovery failure before cutover.",
                    )
        finally:
            try:
                if store is not None:
                    store.close()
            finally:
                if lease is not None:
                    lease.close()

        # manifest.json is the cutover authority.  It must not exist until the
        # recovery manager, temporary restore, store, and lease contexts have
        # all unwound successfully.
        return self._finalize()

    def _check_dashboard(self) -> None:
        def smoke_eval(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "dashboard smoke failed"),
                    "Run scripts/smoke_dashboard.py directly and inspect static/API failures.",
                    {},
                )
            warnings = list(parsed.get("warnings") or [])
            ready = (
                bool(parsed.get("index_loaded"))
                and bool(parsed.get("ready"))
                and bool(parsed.get("graph_loaded"))
                and bool(parsed.get("namespace_map_loaded"))
                and not warnings
            )
            status = "ready" if ready else "blocked"
            repair = "Fix dashboard warnings or failed asset/API checks before relying on the UI." if not ready else ""
            return (
                status,
                "Dashboard smoke loaded "
                f"index={parsed.get('index_loaded')} graph={parsed.get('graph_loaded')} "
                f"galaxy={parsed.get('namespace_map_loaded')} ready={parsed.get('ready')} "
                f"warnings={len(warnings)}.",
                repair,
                {
                    "url": parsed.get("url"),
                    "warnings": warnings,
                    "memory_entries": parsed.get("memory_entries"),
                    "relationships": parsed.get("relationships"),
                    "graph_loaded": parsed.get("graph_loaded"),
                    "namespace_map_loaded": parsed.get("namespace_map_loaded"),
                    "namespace_count": parsed.get("namespace_count"),
                    "js_syntax_ok": parsed.get("js_syntax_ok"),
                },
            )

        self._run_command(
            "dashboard",
            label="Dashboard render smoke",
            command=[self.python, str(ROOT / "scripts" / "smoke_dashboard.py"), self.context],
            required=True,
            timeout=120,
            evaluator=smoke_eval,
        )

    def _finalize(self) -> dict[str, Any]:
        expected_ids = tuple(OPERATOR_READINESS_REQUIRED_PROOF_IDS)
        expected_set = set(expected_ids)
        all_counts = Counter(result.check_id for result in self.results)
        required = [result for result in self.results if result.required]
        required_counts = Counter(result.check_id for result in required)
        missing_required = sorted(
            check_id for check_id in expected_ids if all_counts[check_id] == 0
        )
        duplicate_required = sorted(
            check_id for check_id, count in all_counts.items() if count != 1
        )
        unexpected_required = sorted(set(required_counts) - expected_set)
        failed_required_ids = sorted(
            {
                *unexpected_required,
                *(
                    check_id
                    for check_id in expected_ids
                    if all_counts[check_id] != 1
                    or next(
                        (
                            result.required is True
                            and result.status == "ready"
                            for result in self.results
                            if result.check_id == check_id
                        ),
                        False,
                    )
                    is not True
                ),
            }
        )
        proof_contract_valid = not (
            missing_required or duplicate_required or unexpected_required
        )
        overall_status = classify_overall(self.results)
        if not proof_contract_valid:
            overall_status = "blocked"
        required_total = len(expected_ids)
        required_ready = sum(
            1
            for check_id in expected_ids
            if all_counts[check_id] == 1
            and next(
                result.required is True and result.status == "ready"
                for result in self.results
                if result.check_id == check_id
            )
        )
        proof_contract = ready_operator_proof_contract()
        if not proof_contract_valid:
            proof_contract.update(
                {
                    "valid": False,
                    "missing": missing_required,
                    "duplicates": duplicate_required,
                    "unexpected_required": unexpected_required,
                }
            )
        manifest = json_safe(
            {
                **self.metadata,
                "overall_status": overall_status,
                "operator_trustworthy": overall_status == "ready",
                "required_ready": required_ready,
                "required_total": required_total,
                "failed_required": failed_required_ids,
                "required_proof_contract": proof_contract,
                "checks": [result.to_manifest() for result in self.results],
                "proofs": self._proof_summary(),
            }
        )
        if not isinstance(manifest, dict):  # pragma: no cover - static shape
            raise RuntimeError("readiness manifest sanitization failed")
        manifest_path = self.pack_dir / "manifest.json"
        summary_path = self.pack_dir / "summary.md"
        runbook_path = self.pack_dir / "runbook.md"
        archive_path = str(self.archive_path) if self.args.zip else ""
        result = json_safe(
            {
                "action": "operator-readiness-certification",
                "run_id": self.run_id,
                "context_id": self.context,
                "overall_status": overall_status,
                "operator_trustworthy": overall_status == "ready",
                "pack_dir": str(self.pack_dir),
                "manifest_path": str(manifest_path),
                "summary_path": str(summary_path),
                "runbook_path": str(runbook_path),
                "archive_path": archive_path,
                "failed_required": manifest["failed_required"],
                "required_ready": manifest["required_ready"],
                "required_total": manifest["required_total"],
            }
        )
        if not isinstance(result, dict):  # pragma: no cover - static shape
            raise RuntimeError("readiness result sanitization failed")
        result_path = self.pack_dir / "result.json"
        try:
            # The manifest is the cutover authority. Supporting artifacts and
            # the optional ZIP are made durable first. The ZIP receives the
            # staged in-memory manifest so no authoritative ready file exists
            # during archive creation. manifest.json is atomically published
            # last, after every guarded/temporary context has already exited.
            self._write_text(
                summary_path,
                render_summary_markdown(manifest, self.results),
            )
            self._write_text(runbook_path, render_runbook_markdown(manifest))
            self._write_json(result_path, result)
            if self.args.zip:
                write_private_evidence_zip(
                    self.archive_path,
                    pack_dir=self.pack_dir,
                    members=set(self._evidence_files),
                    opaque_members=set(self._opaque_evidence_files),
                    virtual_json_members={"manifest.json": manifest},
                )
            self._write_json(manifest_path, manifest)
        except BaseException:
            # A failed pre-manifest publication can leave only non-authoritative
            # artifacts. Remove the optional archive because its staged
            # manifest must never be mistaken for a completed evidence pack.
            if manifest_path.is_file() and not manifest_path.is_symlink():
                try:
                    manifest_path.unlink()
                    directory_fd = os.open(self.pack_dir, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError:
                    pass
            if (
                not manifest_path.exists()
                and self.args.zip
                and self.archive_path.is_file()
                and not self.archive_path.is_symlink()
            ):
                try:
                    self.archive_path.unlink()
                    directory_fd = os.open(self.archive_path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError:
                    pass
            raise
        return result

    def _proof_summary(self) -> dict[str, Any]:
        by_id = {result.check_id: result for result in self.results}
        proofs: dict[str, Any] = {}
        for proof in REQUIRED_PROOFS:
            result = by_id.get(proof)
            if result is None and proof == "mcp_connect":
                result = by_id.get("mcp_connect")
            proofs[proof] = result.to_manifest() if result else {"status": "missing"}
        return proofs

    def _write_json(self, path: Path, payload: Any) -> None:
        self._write_artifact(
            path,
            json.dumps(json_safe(payload), indent=2, sort_keys=True) + "\n",
        )

    def _write_signed_json_artifact(
        self,
        path: Path,
        *,
        source_bytes: bytes,
        expected_payload: dict[str, Any],
    ) -> None:
        """Publish one verified signed receipt without altering its bytes."""

        self._write_opaque_json_artifact(
            path,
            source_bytes=source_bytes,
            expected_payload=expected_payload,
        )

    def _write_opaque_json_artifact(
        self,
        path: Path,
        *,
        source_bytes: bytes,
        expected_payload: dict[str, Any],
    ) -> None:
        """Publish trusted private JSON without redacting binding fields."""

        candidate = Path(path)
        if (
            not candidate.is_absolute()
            or "\x00" in str(candidate)
            or ".." in candidate.parts
            or Path(os.path.normpath(str(candidate))) != candidate
        ):
            raise ValueError("signed evidence artifact path must be normal and absolute")
        try:
            relative = candidate.relative_to(self.pack_dir)
        except ValueError as exc:
            raise ValueError("signed evidence artifact escapes the run directory") from exc
        if not relative.parts:
            raise ValueError("signed evidence artifact path must name a file")
        loaded = json.loads(source_bytes.decode("utf-8"))
        if not isinstance(loaded, dict) or loaded != expected_payload:
            raise ValueError("signed evidence payload changed before publication")
        write_private_bytes(candidate, source_bytes)
        if (
            read_private_regular_bytes(candidate, max_bytes=1024 * 1024)
            != source_bytes
        ):
            raise ValueError("signed evidence artifact changed after publication")
        self._evidence_files.add(candidate)
        self._opaque_evidence_files.add(candidate)

    def _write_text(self, path: Path, text: str) -> None:
        self._write_artifact(path, sanitize_evidence_text(text))

    def _write_artifact(self, path: Path, text: str) -> None:
        candidate = path.resolve(strict=False)
        try:
            relative = candidate.relative_to(self.pack_dir)
        except ValueError as exc:
            raise ValueError("evidence artifact escapes the run directory") from exc
        if not relative.parts:
            raise ValueError("evidence artifact path must name a file")
        write_private_text(candidate, text)
        self._evidence_files.add(candidate)


def sanitize_context(value: str) -> str:
    raw = reject_sensitive_identifier(value, field="readiness context_id")
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw.strip()).strip("._-:")
    return (cleaned or "default")[:128]


def sanitize_agent(value: str) -> str:
    raw = reject_sensitive_identifier(value, field="readiness agent_id")
    cleaned = re.sub(r"[^A-Za-z0-9_.:@-]+", "_", raw.strip()).strip("._-:@")
    return (cleaned or "codex-desktop")[:128]


def render_summary_markdown(manifest: dict[str, Any], results: list[CheckResult]) -> str:
    lines = [
        "# SYNAPSE-S2 Operator Readiness Certification",
        "",
        f"- Run id: `{manifest['run_id']}`",
        f"- Context: `{manifest['context_id']}`",
        f"- Overall status: `{manifest['overall_status']}`",
        f"- Operator trustworthy: `{str(manifest['operator_trustworthy']).lower()}`",
        f"- Required checks: `{manifest['required_ready']} / {manifest['required_total']}`",
        f"- Git head: `{manifest.get('git', {}).get('head', '')}`",
        f"- Embedding provider requested: `{manifest.get('embedding_provider', '')}`",
        "",
        "## Required Proofs",
        "",
        "| Proof | Status | Evidence | Repair |",
        "| --- | --- | --- | --- |",
    ]
    for result in results:
        required = "required" if result.required else "optional"
        lines.append(
            "| "
            + " | ".join(
                [
                    f"{result.label} ({required})",
                    result.status,
                    compact_text(result.detail, limit=180).replace("|", "\\|"),
                    compact_text(result.repair or "", limit=180).replace("|", "\\|"),
                ]
            )
            + " |"
        )
    repairs = [
        result
        for result in results
        if result.status != "ready" and str(result.repair or "").strip()
    ]
    lines.extend(["", "## Repair Plan", ""])
    if repairs:
        for result in repairs:
            lines.append(f"- `{result.check_id}`: {result.repair}")
    else:
        lines.append("- No repair required.")
    lines.extend(
        [
            "",
            "## Artifact Index",
            "",
            f"- Manifest: `{manifest['run_id']}/manifest.json`",
            f"- Raw artifacts: `{manifest['run_id']}/artifacts/`",
            "- Each command check stores stdout, stderr, and parsed JSON when available.",
            "",
            "## Certification Meaning",
            "",
            "This pack is only ready when every required proof is `ready`. A `degraded` or `blocked` proof is not hidden: the pack remains useful as a repair report, but it should not be used to claim operator readiness until rerun cleanly.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_runbook_markdown(manifest: dict[str, Any]) -> str:
    command = [
        ".venv/bin/python",
        "scripts/operator_readiness_certify.py",
        "--context",
        str(manifest["context_id"]),
        "--agent-id",
        str(manifest["agent_id"]),
        # This is an acceptance expectation for the provider reported by the
        # core, not a client-side request to configure a neural backend.
        "--expect-embedding-provider",
        str(manifest.get("embedding_provider") or "mlx-neural"),
    ]
    lines = [
        "# Operator Readiness Runbook",
        "",
        "Run this before relying on SYNAPSE-S2 for live operator work:",
        "",
        "```bash",
        command_to_text(command),
        "```",
        "",
        "The certifier writes one evidence pack under `.synapse_s2/evidence_packs/` and creates a `.zip` archive beside it.",
        "",
        "Required proof gates:",
        "",
        "- Client configs dry-run without pending changes.",
        "- FastMCP connects to the installed local launcher and lists SYNAPSE-S2 tools.",
        "- The installed launcher returns the compact MCP contract within the separate 12,288-byte structured and 4,096-byte safety-channel ceilings.",
        "- The exact candidate core configuration is embedded in the manifest and its provider produces a non-empty local vector; `mlx-neural` must match every pinned model setting and report native MLX.",
        "- Doctor is clean or returns concrete repair steps.",
        "- Start Work generates an operator brief from real memory.",
        "- A unique readiness trace is written to the local SQLite memory DB.",
        "- Recall finds that same readiness trace.",
        "- App Connect attach and preview produce quality/capability badges without writing memory.",
        "- Wrap Session persists a factual handoff memory.",
        "- The bounded capture drain reaches zero debt, then exclusive core authority and the global capture lock remain held through final evidence publication.",
        "- Processed capture.v2 evidence passes a read-only audit against the authoritative SQLite capture ledger.",
        "- A signed paired database plus capture recovery point is created, reverified, and restored into an isolated staging directory.",
        "- The loopback dashboard page, assets, and snapshot API load without known warning text.",
        "",
        "If the overall status is not `ready`, open `summary.md`, complete the repair plan, and rerun this command. Do not treat a degraded pack as a success claim.",
    ]
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(
        description="Produce a single SYNAPSE-S2 operator readiness evidence pack."
    )
    parser.add_argument("--context", default="default")
    parser.add_argument("--agent-id", default="codex-desktop")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--output-dir", default=str(ROOT / ".synapse_s2" / "evidence_packs"))
    parser.add_argument("--launcher", default=str(DEFAULT_LAUNCHER))
    parser.add_argument(
        "--core-socket",
        default=os.getenv("SYNAPSE_S2_CORE_SOCKET", ""),
        help="Optional matching legacy socket assertion; a reviewed core binding remains authoritative.",
    )
    parser.add_argument(
        "--core-binding",
        default="",
        help="Owner-only core binding; defaults to SYNAPSE_S2_CORE_BINDING or ~/.config/synapse-s2/core-binding.json.",
    )
    parser.add_argument(
        "--core-label",
        default=os.getenv("SYNAPSE_S2_CORE_LABEL", DEFAULT_CORE_LABEL),
    )
    parser.add_argument(
        "--noncanonical-layout-manifest",
        default=os.getenv("SYNAPSE_S2_NONCANONICAL_LAYOUT_MANIFEST", ""),
        help="Private reviewed manifest authorizing the candidate noncanonical layout.",
    )
    parser.add_argument(
        "--expect-embedding-provider",
        "--embedding-provider",
        dest="expected_embedding_provider",
        default=None,
        help="Optional assertion; the candidate installer configuration remains authoritative.",
    )
    parser.add_argument(
        "--expect-dimension",
        "--dimension",
        dest="expected_dimension",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--expect-neurons",
        "--neurons",
        dest="expected_neurons",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--expect-top-k",
        "--top-k",
        dest="expected_top_k",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--expect-neural-model",
        "--neural-model",
        dest="expected_neural_model",
        default=None,
    )
    parser.add_argument("--expect-neural-revision", default=None)
    parser.add_argument("--expect-neural-pooling", default=None)
    parser.add_argument("--expect-neural-max-tokens", type=int, default=None)
    parser.add_argument(
        "--expect-neural-normalize",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--expect-neural-cache-dir",
        "--neural-cache-dir",
        dest="expected_neural_cache_dir",
        default=None,
    )
    parser.add_argument(
        "--expect-neural-local-files-only",
        "--neural-local-files-only",
        dest="expected_neural_local_files_only",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument("--app-name", default="")
    parser.add_argument("--no-zip", dest="zip", action="store_false", default=True)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    certifier = OperatorReadinessCertifier(args)
    result = certifier.run()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"SYNAPSE-S2 operator readiness: {result['overall_status']}")
        print(f"summary: {result['summary_path']}")
        if result.get("archive_path"):
            print(f"archive: {result['archive_path']}")
    return 0 if result["overall_status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())

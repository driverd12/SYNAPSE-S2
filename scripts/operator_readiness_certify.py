#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import math
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import time
import zipfile
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
    strip_untrusted_raw_digest_fields,
)


DEFAULT_LAUNCHER = Path.home() / ".local" / "bin" / "synapse-s2-mcp"
DEFAULT_NEURAL_MODEL = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
MCP_CONTRACT_SCHEMA = "synapse-s2.token-contract.v1"
MCP_SAFETY_SCHEMA = "synapse-s2.mcp-safety-summary.v1"
MCP_SAFETY_PREFIX = "SYNAPSE-S2 safety summary: "
MCP_COMPACT_BUDGET = 12_288
MCP_SAFETY_BUDGET = 4_096
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RAW_DIGEST_TEXT_RE = re.compile(
    r"(?i)(?:['\"]?)(?:input_sha256|raw_input_sha256|raw_sha256|"
    r"raw_text_sha256|payload_sha256|source_text_sha256|"
    r"raw_[A-Za-z0-9_-]*sha(?:256)?)(?:['\"]?)\s*[:=]\s*"
    r"(?:['\"](?:\\.|[^'\"\\])*['\"]|[^\s,;}\]]+)"
)
REQUIRED_PROOFS = [
    "client_config",
    "mcp_connect",
    "mcp_contract_probe",
    "neural_embedding",
    "doctor",
    "start_work",
    "memory_write",
    "recall",
    "app_preview",
    "wrap_session",
    "capture_ledger_audit",
    "recovery_backup",
    "recovery_verify",
    "recovery_restore",
    "dashboard",
]


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


def write_private_evidence_zip(
    archive_path: Path,
    *,
    pack_dir: Path,
    members: set[Path],
) -> None:
    """Atomically create a private ZIP from this run's explicit file set."""

    root = pack_dir.resolve()
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
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                source_text = resolved.read_text(encoding="utf-8")
                if resolved.suffix == ".json":
                    source_payload = json.loads(source_text)
                    archived_text = json.dumps(
                        json_safe(source_payload),
                        indent=2,
                        sort_keys=True,
                    ) + "\n"
                elif resolved.suffix in {".txt", ".md"}:
                    archived_text = sanitize_evidence_text(source_text)
                else:
                    raise ValueError(
                        "evidence ZIP members must use JSON, text, or Markdown"
                    )
                archive.writestr(info, archived_text.encode("utf-8"))
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
        or set(provenance) != {"source", "context_id", "recall_scope"}
        or provenance.get("source") != "sqlite-memory-store"
        or provenance.get("context_id") != data.get("context_id")
        or provenance.get("recall_scope") != data.get("recall_scope")
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
    if "pagination-unsupported" not in warning_codes:
        return blocked("MCP compact memory-list omitted its pagination warning.")
    if truncated != ("output-truncated" in warning_codes):
        return blocked("MCP compact truncation warning disagrees with its contract metadata.")
    pagination = structured.get("pagination")
    if not isinstance(pagination, dict) or set(pagination) != {
        "supported",
        "strategy",
        "requested_limit",
        "effective_limit",
        "returned",
        "has_more",
        "next_cursor",
    } or pagination.get("returned") != returned:
        return blocked("MCP compact pagination metadata is invalid.")
    if (
        pagination.get("supported") is not False
        or pagination.get("strategy") != "retrieval-v2-required"
        or type(pagination.get("requested_limit")) is not int
        or pagination.get("requested_limit") != 1
        or type(pagination.get("effective_limit")) is not int
        or pagination.get("effective_limit") != 1
        or pagination.get("has_more") is not None
        or pagination.get("next_cursor") is not None
    ):
        return blocked("MCP compact pagination values are invalid.")
    completeness = structured.get("completeness")
    if not isinstance(completeness, dict) or set(completeness) != {
        "complete",
        "source_limit_reduced",
        "reason",
    }:
        return blocked("MCP compact completeness metadata is invalid.")
    if (
        completeness.get("complete") is not None
        or completeness.get("source_limit_reduced") is not False
        or completeness.get("reason")
        != "authoritative-total-and-cursor-unavailable"
    ):
        return blocked("MCP compact completeness values are invalid.")
    continuation = structured.get("continuation")
    if not isinstance(continuation, dict) or set(continuation) != {
        "strategy",
        "cursor",
    }:
        return blocked("MCP compact continuation metadata is invalid.")
    if (
        continuation.get("strategy")
        != "request-full-or-wait-for-retrieval-v2"
        or continuation.get("cursor") is not None
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
        # Keep the venv shim path intact. Resolving it follows uv's interpreter
        # symlink and bypasses the virtualenv site-packages.
        self.python = str(ROOT / ".venv" / "bin" / "python")
        self.launcher = validate_evidence_path(
            args.launcher,
            field="readiness launcher path",
        ).resolve()
        self.args.embedding_provider = reject_sensitive_identifier(
            args.embedding_provider,
            field="readiness embedding provider",
        ).strip()
        if not self.args.embedding_provider:
            raise ValueError("readiness embedding provider must not be empty")
        self.args.neural_model = reject_sensitive_identifier(
            args.neural_model,
            field="readiness neural model",
        ).strip()
        if not self.args.neural_model:
            raise ValueError("readiness neural model must not be empty")
        self.args.neural_cache_dir = str(
            validate_evidence_path(
                args.neural_cache_dir,
                field="readiness neural cache path",
            )
        )
        self.args.app_name = reject_sensitive_identifier(
            args.app_name,
            field="readiness app name",
        ).strip()
        self.results: list[CheckResult] = []
        self.metadata: dict[str, Any] = {}

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
        self._check_recovery()
        self._check_dashboard()
        return self._finalize()

    def _run_metadata(self) -> dict[str, Any]:
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
            "embedding_provider": self.args.embedding_provider,
            "topology": {
                "dimension": int(self.args.dimension),
                "neurons": int(self.args.neurons),
                "top_k": int(self.args.top_k),
            },
            "neural_model": self.args.neural_model,
            "neural_local_files_only": bool(self.args.neural_local_files_only),
            "memory_db": str((ROOT / ".synapse_s2" / "memory.sqlite3").resolve()),
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
        env = dict(os.environ)
        env.setdefault("MLX_DEVICE", "gpu")
        env["SYNAPSE_S2_EMBEDDING_PROVIDER"] = str(self.args.embedding_provider)
        env["SYNAPSE_S2_DIMENSION"] = str(self.args.dimension)
        env["SYNAPSE_S2_NEURONS"] = str(self.args.neurons)
        env["SYNAPSE_S2_TOP_K"] = str(self.args.top_k)
        env.setdefault("SYNAPSE_S2_RECALL_COUNT", "10")
        env.setdefault("SYNAPSE_S2_STATE_PATH", str(ROOT / ".synapse_s2" / "runtime_state.json"))
        env.setdefault("SYNAPSE_S2_MEMORY_DB", str(ROOT / ".synapse_s2" / "memory.sqlite3"))
        env.setdefault("SYNAPSE_S2_EXPORT_DIR", str(ROOT / ".synapse_s2"))
        env.setdefault("SYNAPSE_S2_CAPTURE_ROOT", str(ROOT / ".synapse_s2"))
        if str(self.args.embedding_provider).startswith("mlx-neural"):
            env["SYNAPSE_S2_NEURAL_MODEL"] = str(self.args.neural_model)
            env["SYNAPSE_S2_NEURAL_CACHE_DIR"] = str(
                Path(self.args.neural_cache_dir).expanduser().resolve()
            )
            env["SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY"] = "1" if self.args.neural_local_files_only else "0"
        return env

    def _cli_command(self, *parts: str) -> list[str]:
        return [
            self.python,
            str(ROOT / "synapse_cli.py"),
            "--json",
            "--embedding-provider",
            str(self.args.embedding_provider),
            "--dimension",
            str(self.args.dimension),
            "--neurons",
            str(self.args.neurons),
            "--top-k",
            str(self.args.top_k),
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
                env=env or self._base_env(),
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

        self._run_command(
            "client_config",
            label="Client config dry-run",
            command=[self.python, str(ROOT / "scripts" / "install_client_configs.py"), "--dry-run"],
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
            expected = "query_spiking_attention_text"
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
            ready = "runtime" in stdout and "ready" in stdout.lower()
            return (
                "ready" if ready else "degraded",
                "FastMCP status call returned runtime payload." if ready else "FastMCP status call returned without a clear ready payload.",
                "Inspect FastMCP call stdout and resolve runtime status if not ready.",
                {"runtime_ready_text_seen": ready},
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
            nonzero = int(parsed.get("vector_nonzero_count") or 0)
            native = bool(provider.get("native_mlx"))
            expected_neural = str(self.args.embedding_provider).startswith("mlx-neural")
            ready = nonzero > 0 and (not expected_neural or (provider_type == "mlx-neural" and native))
            detail = (
                f"{provider_type or provider.get('provider', 'unknown')} produced {nonzero} nonzero dims "
                f"in {parsed.get('average_latency_ms')} ms; native_mlx={native}."
            )
            repair = ""
            if not ready:
                repair = "Run with --embedding-provider mlx-neural after the model is cached locally, or repair MLX neural dependencies."
            return (
                "ready" if ready else "blocked",
                detail,
                repair,
                {
                    "provider_type": provider_type,
                    "native_mlx": native,
                    "vector_nonzero_count": nonzero,
                    "average_latency_ms": parsed.get("average_latency_ms"),
                    "model_id": provider.get("model_id"),
                    "runtime_source": (provider.get("details") or {}).get("runtime_source"),
                },
            )

        self._run_command(
            "neural_embedding",
            label="Embedding provider proof",
            command=self._cli_command(
                "provider-benchmark",
                "--text",
                f"SYNAPSE-S2 readiness neural embedding proof {self.run_id}",
                "--runs",
                "1",
            ),
            required=True,
            timeout=120,
            evaluator=evaluate,
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

        self._run_command(
            "doctor",
            label="SYNAPSE Doctor",
            command=self._cli_command("doctor", "--context", self.context, "--include-apps", "--repair-plan"),
            required=True,
            timeout=60,
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
            result_text = str(parsed.get("result") or "")
            matched = [item for item in expected if item and item in result_text]
            if not matched:
                return (
                    "blocked",
                    "Recall returned but did not include the readiness memory id, tag, or run id.",
                    "Inspect query-text output and memory index consistency.",
                    {"expected": [item for item in expected if item]},
                )
            return (
                "ready",
                f"Recall returned the readiness write using {', '.join(matched[:2])}.",
                "",
                {"matched_evidence": matched, "result_chars": len(result_text)},
            )

        self._run_command(
            "recall",
            label="Recall proof",
            command=self._cli_command("query-text", "--context", self.context, "--text", query),
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
            required=True,
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
            required=True,
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

    def _check_recovery(self) -> None:
        def binding_proof(parsed: dict[str, Any]) -> dict[str, Any]:
            value = parsed.get("capture_ledger_binding")
            return dict(value) if isinstance(value, dict) else {}

        def binding_proof_ready(value: dict[str, Any]) -> bool:
            count = value.get("verified_capture_count")
            return (
                value.get("schema")
                == "synapse-s2.capture-ledger-binding-proof.v1"
                and value.get("verified") is True
                and type(count) is int
                and int(count) >= 0
                and re.fullmatch(r"[0-9a-f]{64}", str(value.get("revision") or ""))
                is not None
            )

        def ledger_audit_evaluate(
            returncode: int,
            parsed: Any,
            stdout: str,
            stderr: str,
        ):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(
                        stderr or stdout or "capture ledger integrity audit failed"
                    ),
                    "Run capture-ledger-integrity directly and resolve its read-only audit failure before creating a recovery point.",
                    {},
                )
            missing_count = int(
                parsed.get("missing_authoritative_ledger_count") or 0
            )
            mismatch_count = int(parsed.get("ledger_binding_mismatch_count") or 0)
            blocked_count = int(parsed.get("blocked_capture_count") or 0)
            audit_revision = str(parsed.get("audit_revision") or "")
            ready = (
                parsed.get("action") == "capture-ledger-audit"
                and parsed.get("status") == "ready"
                and bool(parsed.get("verification_passed"))
                and re.fullmatch(r"[0-9a-f]{64}", audit_revision) is not None
                and missing_count == 0
                and mismatch_count == 0
                and blocked_count == 0
            )
            if ready:
                return (
                    "ready",
                    "Processed capture.v2 evidence matches the authoritative SQLite capture ledger.",
                    "",
                    {
                        "status": "ready",
                        "audit_revision": audit_revision,
                        "processed_v2_capture_count": int(
                            parsed.get("processed_v2_capture_count") or 0
                        ),
                        "ledger_capture_count": int(
                            parsed.get("ledger_capture_count") or 0
                        ),
                        "missing_authoritative_ledger_count": 0,
                        "ledger_binding_mismatch_count": 0,
                        "blocked_capture_count": 0,
                    },
                )
            if bool(parsed.get("repairable")) and missing_count > 0:
                repair = (
                    "Review this check's finding samples and audit_revision, then run "
                    "capture-ledger-integrity --repair --confirm --expected-revision "
                    "'<audit_revision>'; rerun the read-only audit before certification."
                )
            else:
                repair = (
                    "Do not replay capture files or synthesize receipts. Resolve ambiguous "
                    "evidence or restore a verified paired recovery point, then rerun the audit."
                )
            return (
                "blocked",
                (
                    "Capture ledger is not authoritative: "
                    f"missing={missing_count}, mismatched={mismatch_count}, "
                    f"blocked={blocked_count}."
                ),
                repair,
                {
                    "status": parsed.get("status"),
                    "audit_revision": audit_revision,
                    "repairable": bool(parsed.get("repairable")),
                    "repairable_capture_count": int(
                        parsed.get("repairable_capture_count") or 0
                    ),
                    "missing_authoritative_ledger_count": missing_count,
                    "ledger_binding_mismatch_count": mismatch_count,
                    "blocked_capture_count": blocked_count,
                },
            )

        ledger_audit = self._run_command(
            "capture_ledger_audit",
            label="Capture ledger integrity audit",
            command=self._cli_command(
                "capture-ledger-integrity",
                "--capture-root",
                str(ROOT / ".synapse_s2"),
                "--sample-limit",
                "20",
            ),
            required=True,
            timeout=300,
            evaluator=ledger_audit_evaluate,
        )
        if ledger_audit.status != "ready":
            for check_id, label in (
                ("recovery_backup", "Paired recovery backup"),
                ("recovery_verify", "Recovery bundle verification"),
                ("recovery_restore", "Isolated recovery drill"),
            ):
                self._record_manual(
                    check_id,
                    label=label,
                    status="blocked",
                    required=True,
                    detail=(
                        "Skipped because capture-ledger integrity did not pass its "
                        "read-only authority gate."
                    ),
                    repair="Repair and re-audit the capture ledger before creating recovery artifacts.",
                )
            return

        recovery_root = ROOT / ".synapse_s2" / "backups" / "verified"
        ensure_private_directory(recovery_root)
        database_path = recovery_root / (
            f"readiness-{safe_filename(self.run_id)}.sqlite3"
        )

        def backup_evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "paired recovery backup failed"),
                    "Resolve backup integrity, capture transport, free-space, and signing-authority errors.",
                    {},
                )
            binding = binding_proof(parsed)
            if (
                not parsed.get("bundle_verified")
                or not parsed.get("cutover_ready")
                or not binding_proof_ready(binding)
            ):
                return (
                    "blocked",
                    "Recovery artifacts were created but are not verified and immediately cutover-ready.",
                    "Drain or reconcile replay-required capture files, then rerun certification.",
                    {
                        "bundle_verified": bool(parsed.get("bundle_verified")),
                        "cutover_ready": bool(parsed.get("cutover_ready")),
                        "capture_ledger_binding": binding,
                        "reconciliation": parsed.get("reconciliation", {}),
                    },
                )
            return (
                "ready",
                "Created a signed paired SQLite and exactly-once capture recovery point.",
                "",
                {
                    "bundle_verified": True,
                    "cutover_ready": True,
                    "capture_file_count": int(parsed.get("capture_file_count") or 0),
                    "capture_ledger_binding": binding,
                    "reconciliation": parsed.get("reconciliation", {}),
                },
            )

        backup_result = self._run_command(
            "recovery_backup",
            label="Paired recovery backup",
            command=self._cli_command(
                "backup-recovery",
                "--output",
                str(database_path),
                "--capture-root",
                str(ROOT / ".synapse_s2"),
                "--purpose",
                "operator-readiness",
                "--pinned",
            ),
            required=True,
            timeout=300,
            evaluator=backup_evaluate,
        )
        backup = backup_result.parsed if isinstance(backup_result.parsed, dict) else {}
        expected_binding_proof = binding_proof(backup)
        receipt_path = str(backup.get("bundle_receipt_path") or "")
        if backup_result.status != "ready" or not receipt_path:
            for check_id, label in (
                ("recovery_verify", "Recovery bundle verification"),
                ("recovery_restore", "Isolated recovery drill"),
            ):
                self._record_manual(
                    check_id,
                    label=label,
                    status="blocked",
                    required=True,
                    detail="Skipped because paired recovery backup did not produce a trusted receipt.",
                    repair="Repair the paired recovery backup gate first.",
                )
            return

        def verify_evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "recovery verification failed"),
                    "Inspect the signed bundle receipt and all four bound artifacts.",
                    {},
                )
            binding = binding_proof(parsed)
            ready = (
                bool(parsed.get("verified"))
                and bool(parsed.get("cutover_ready"))
                and binding_proof_ready(binding)
                and binding == expected_binding_proof
            )
            return (
                "ready" if ready else "blocked",
                (
                    "Reverified the signed database, capture archive, schema contract, and replay state."
                    if ready
                    else "Recovery bundle verification did not prove immediate cutover readiness."
                ),
                "" if ready else "Inspect signed reconciliation and replay-required files.",
                {
                    "verified": bool(parsed.get("verified")),
                    "cutover_ready": bool(parsed.get("cutover_ready")),
                    "reconciliation": parsed.get("reconciliation", {}),
                    "capture_ledger_binding": binding,
                },
            )

        verify_result = self._run_command(
            "recovery_verify",
            label="Recovery bundle verification",
            command=self._cli_command(
                "verify-recovery",
                "--receipt",
                receipt_path,
                "--capture-root",
                str(ROOT / ".synapse_s2"),
            ),
            required=True,
            timeout=300,
            evaluator=verify_evaluate,
        )
        if verify_result.status != "ready":
            self._record_manual(
                "recovery_restore",
                label="Isolated recovery drill",
                status="blocked",
                required=True,
                detail="Skipped because cryptographic recovery verification failed.",
                repair="Repair the recovery verification gate first.",
            )
            return

        staging_root = ROOT / ".synapse_s2" / "recovery-staging"
        ensure_private_directory(staging_root)

        def restore_evaluate(returncode: int, parsed: Any, stdout: str, stderr: str):
            if returncode != 0 or not isinstance(parsed, dict):
                return (
                    "blocked",
                    compact_text(stderr or stdout or "isolated recovery drill failed"),
                    "Inspect restore proof, capture ledger reconciliation, and available disk space.",
                    {},
                )
            binding = binding_proof(parsed)
            ready = (
                bool(parsed.get("verified"))
                and bool(parsed.get("cutover_ready"))
                and binding_proof_ready(binding)
                and binding == expected_binding_proof
            )
            return (
                "ready" if ready else "blocked",
                (
                    "Materialized and verified an isolated paired restore without touching live state."
                    if ready
                    else "Isolated restore completed but is not immediately cutover-ready."
                ),
                "" if ready else "Resolve replay-required capture debt before cutover.",
                {
                    "verified": bool(parsed.get("verified")),
                    "cutover_ready": bool(parsed.get("cutover_ready")),
                    "capture_file_count": int(parsed.get("capture_file_count") or 0),
                    "missing_transport_ledger_count": int(
                        parsed.get("missing_transport_ledger_count") or 0
                    ),
                    "reconciliation": parsed.get("reconciliation", {}),
                    "capture_ledger_binding": binding,
                },
            )

        with tempfile.TemporaryDirectory(
            prefix=f"readiness-{safe_filename(self.run_id)}-",
            dir=staging_root,
        ) as temporary:
            restore_root = Path(temporary) / "isolated-restore"
            restore_result = self._run_command(
                "recovery_restore",
                label="Isolated recovery drill",
                command=self._cli_command(
                    "restore-recovery-proof",
                    "--receipt",
                    receipt_path,
                    "--output-root",
                    str(restore_root),
                    "--capture-root",
                    str(ROOT / ".synapse_s2"),
                    "--confirm",
                ),
                required=True,
                timeout=300,
                evaluator=restore_evaluate,
            )
            if restore_result.status == "ready" and isinstance(
                restore_result.parsed, dict
            ):
                proof_path = Path(
                    str(restore_result.parsed.get("recovery_proof_path") or "")
                )
                if proof_path.is_file() and not proof_path.is_symlink():
                    proof = json.loads(proof_path.read_text(encoding="utf-8"))
                    durable_proof = self.artifact_dir / "recovery_restore_proof.receipt.json"
                    self._write_json(durable_proof, proof)
                    restore_result.artifact_paths["recovery_proof"] = str(durable_proof)

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
            timeout=90,
            evaluator=smoke_eval,
        )

    def _finalize(self) -> dict[str, Any]:
        overall_status = classify_overall(self.results)
        required = [result for result in self.results if result.required]
        failed_required = [result for result in required if result.status != "ready"]
        manifest = json_safe(
            {
                **self.metadata,
                "overall_status": overall_status,
                "operator_trustworthy": overall_status == "ready",
                "required_ready": len(required) - len(failed_required),
                "required_total": len(required),
                "failed_required": [
                    result.check_id for result in failed_required
                ],
                "checks": [result.to_manifest() for result in self.results],
                "proofs": self._proof_summary(),
            }
        )
        if not isinstance(manifest, dict):  # pragma: no cover - static shape
            raise RuntimeError("readiness manifest sanitization failed")
        manifest_path = self.pack_dir / "manifest.json"
        summary_path = self.pack_dir / "summary.md"
        runbook_path = self.pack_dir / "runbook.md"
        self._write_json(manifest_path, manifest)
        self._write_text(
            summary_path,
            render_summary_markdown(manifest, self.results),
        )
        self._write_text(runbook_path, render_runbook_markdown(manifest))
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
        self._write_json(self.pack_dir / "result.json", result)
        if self.args.zip:
            write_private_evidence_zip(
                self.archive_path,
                pack_dir=self.pack_dir,
                members=set(self._evidence_files),
            )
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
        "--embedding-provider",
        str(manifest["embedding_provider"]),
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
        "- The requested embedding provider produces a non-empty local vector; `mlx-neural` must report native MLX.",
        "- Doctor is clean or returns concrete repair steps.",
        "- Start Work generates an operator brief from real memory.",
        "- A unique readiness trace is written to the local SQLite memory DB.",
        "- Recall finds that same readiness trace.",
        "- App Connect attach and preview produce quality/capability badges without writing memory.",
        "- Wrap Session persists a factual handoff memory.",
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
    parser.add_argument("--embedding-provider", default="mlx-neural")
    parser.add_argument("--dimension", type=int, default=1024)
    parser.add_argument("--neurons", type=int, default=8192)
    parser.add_argument("--top-k", type=int, default=256)
    parser.add_argument("--neural-model", default=DEFAULT_NEURAL_MODEL)
    parser.add_argument("--neural-cache-dir", default=str(ROOT / ".synapse_s2" / "models"))
    parser.add_argument("--neural-local-files-only", action=argparse.BooleanOptionalAction, default=True)
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

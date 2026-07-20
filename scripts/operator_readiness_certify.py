#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
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
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    strip_untrusted_raw_digest_fields,
)


DEFAULT_LAUNCHER = Path.home() / ".local" / "bin" / "synapse-s2-mcp"
DEFAULT_NEURAL_MODEL = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
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
    "neural_embedding",
    "doctor",
    "start_work",
    "memory_write",
    "recall",
    "app_preview",
    "wrap_session",
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
        env.setdefault("SYNAPSE_S2_DIMENSION", "1024")
        env.setdefault("SYNAPSE_S2_NEURONS", "8192")
        env.setdefault("SYNAPSE_S2_TOP_K", "256")
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
                parsed = json_safe(parse_json_stdout(stdout))
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
            parsed,
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
                str(self.launcher),
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
                str(self.launcher),
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
        "- The requested embedding provider produces a non-empty local vector; `mlx-neural` must report native MLX.",
        "- Doctor is clean or returns concrete repair steps.",
        "- Start Work generates an operator brief from real memory.",
        "- A unique readiness trace is written to the local SQLite memory DB.",
        "- Recall finds that same readiness trace.",
        "- App Connect attach and preview produce quality/capability badges without writing memory.",
        "- Wrap Session persists a factual handoff memory.",
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

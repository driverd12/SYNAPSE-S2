from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from core_client_binding import (
    BINDING_ENV,
    CoreClientBinding,
    default_binding_path,
    load_bound_core_config,
    load_core_client_binding,
)

from redaction import (
    SecretSafeArgumentParser,
    redact_capture_text,
    reject_sensitive_identifier,
)


SERVER_NAME = "synapse-s2"
ROOT = Path(__file__).resolve().parent
DEFAULT_LAUNCHER = Path.home() / ".local" / "bin" / "synapse-s2-mcp"
DEFAULT_EMBEDDING_PROVIDER = "mlx-neural"
DEFAULT_NEURAL_MODEL = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
DEFAULT_DIMENSION = "1024"
DEFAULT_NEURONS = "8192"
DEFAULT_TOP_K = "256"
DEFAULT_RECALL_COUNT = "10"
DEFAULT_RESPONSE_MODE = "compact"
DEFAULT_MAX_RESPONSE_BYTES = "12288"
MAX_CLIENT_CONFIG_BYTES = 4 * 1024 * 1024
PUBLICATION_SCHEMA = "synapse-s2.client-config-publication.v1"


def _canonical_config_path(path: Path, *, field: str) -> Path:
    expanded = path.expanduser()
    reject_sensitive_identifier(str(expanded), field=field)
    if (
        not expanded.is_absolute()
        or ".." in expanded.parts
        or "\x00" in str(expanded)
    ):
        raise OSError(f"{field} must be a normal absolute path")
    _assert_no_symlink_components(expanded)
    canonical = expanded.resolve(strict=False)
    if canonical == Path(canonical.anchor):
        raise OSError(f"{field} is too broad")
    return canonical


def build_server_definition(
    *,
    repo_root: Path = ROOT,
    launcher_path: Path = DEFAULT_LAUNCHER,
    client_agent_id: str = "local-mcp-client",
    context_id: str = "default",
    startup_prompt: str | None = None,
    core_binding_path: Path | None = None,
    core_binding: CoreClientBinding | None = None,
) -> dict[str, Any]:
    repo = _canonical_config_path(repo_root, field="repo_root")
    launcher = _canonical_config_path(launcher_path, field="launcher_path")
    agent = _sanitize_agent_id(client_agent_id)
    context = _sanitize_context_id(context_id)
    raw_prompt = startup_prompt or (
        f"Hydrate SYNAPSE-S2 context for {agent} local MCP client startup."
    )
    prompt, _ = redact_capture_text(raw_prompt)
    binding = core_binding
    binding_path = None
    if core_binding_path is not None:
        binding_path = _canonical_config_path(
            core_binding_path,
            field="core_binding_path",
        )
        loaded = load_core_client_binding(binding_path)
        load_bound_core_config(loaded)
        if binding is not None and loaded != binding:
            raise OSError("core binding changed during client configuration")
        binding = loaded
    if (binding is None) != (binding_path is None):
        raise OSError("core binding and binding path must be supplied together")
    if binding is not None and binding.repo_root != repo:
        raise OSError("core binding belongs to a different repository")
    route_env = (
        {
            BINDING_ENV: str(binding_path),
        }
        if binding is not None and binding_path is not None
        else {
            # Before the reviewed binding is published, preserve the existing
            # v5 local lane.  A v6 database still routes to the core from its
            # durable marker; this fallback never overrides adopted authority.
            "MLX_DEVICE": "gpu",
            "SYNAPSE_S2_EMBEDDING_PROVIDER": DEFAULT_EMBEDDING_PROVIDER,
            "SYNAPSE_S2_NEURAL_MODEL": DEFAULT_NEURAL_MODEL,
            "SYNAPSE_S2_NEURAL_CACHE_DIR": str(repo / ".synapse_s2" / "models"),
            "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": "1",
            "SYNAPSE_S2_DIMENSION": DEFAULT_DIMENSION,
            "SYNAPSE_S2_NEURONS": DEFAULT_NEURONS,
            "SYNAPSE_S2_TOP_K": DEFAULT_TOP_K,
            "SYNAPSE_S2_RECALL_COUNT": DEFAULT_RECALL_COUNT,
            "SYNAPSE_S2_STATE_PATH": str(
                repo / ".synapse_s2" / "runtime_state.json"
            ),
            "SYNAPSE_S2_MEMORY_DB": str(repo / ".synapse_s2" / "memory.sqlite3"),
            "SYNAPSE_S2_EXPORT_DIR": str(repo / ".synapse_s2"),
            "SYNAPSE_S2_CAPTURE_ROOT": str(repo / ".synapse_s2"),
        }
    )
    return {
        "type": "stdio",
        "command": str(launcher),
        "args": [],
        "env": {
            "PYTHONPATH": str(repo),
            **route_env,
            "SYNAPSE_S2_DEFAULT_RESPONSE_MODE": DEFAULT_RESPONSE_MODE,
            "SYNAPSE_S2_MAX_RESPONSE_BYTES": DEFAULT_MAX_RESPONSE_BYTES,
            "SYNAPSE_S2_CONTEXT_ID": context,
            "SYNAPSE_S2_CLIENT_AGENT_ID": agent,
            "SYNAPSE_S2_CLIENT_SESSION_BRIDGE": "1",
            "SYNAPSE_S2_CLIENT_CORTEX": "1",
            "SYNAPSE_S2_CLIENT_CORTEX_MODE": "strict",
            "SYNAPSE_S2_CLIENT_STARTUP_RECALL_MODE": "surface",
            "SYNAPSE_S2_CLIENT_SESSION_SOURCE_TAG": "client-session-boundary",
            "SYNAPSE_S2_CLIENT_STARTUP_PROMPT": prompt,
        },
        "timeout": 30000,
    }


def install_client_configs(
    *,
    home: Path = Path.home(),
    repo_root: Path = ROOT,
    launcher_path: Path = DEFAULT_LAUNCHER,
    dry_run: bool = False,
    core_binding_path: Path | None = None,
) -> dict[str, Any]:
    repo = _canonical_config_path(repo_root, field="repo_root")
    home_path = _canonical_config_path(home, field="home")
    launcher = _canonical_config_path(launcher_path, field="launcher_path")
    requested_binding = core_binding_path
    if requested_binding is None:
        discovered = default_binding_path(home_path)
        if discovered.exists() or discovered.is_symlink():
            requested_binding = discovered
    binding_path = (
        _canonical_config_path(requested_binding, field="core_binding_path")
        if requested_binding is not None
        else None
    )
    binding = (
        load_core_client_binding(binding_path)
        if binding_path is not None
        else None
    )
    if binding is not None:
        load_bound_core_config(binding)
    if binding is not None and binding.repo_root != repo:
        raise OSError("core binding belongs to a different repository")
    result: dict[str, Any] = {
        "server_name": SERVER_NAME,
        "repo_root": str(repo),
        "launcher_path": str(launcher),
        "restart_required": False,
        "core_binding": (
            None
            if binding is None
            else {
                "path": str(binding_path),
                "digest": binding.digest,
                "authority_mode": binding.authority_mode,
                "config_path": str(binding.config_path),
                "config_digest": binding.config_digest,
                "config_fingerprint": binding.config_fingerprint,
                "embedding_space_identity": binding.embedding_space_identity,
            }
        ),
        "clients": {},
    }
    project_path = repo / ".mcp.json"
    desktop_path = (
        home_path
        / "Library"
        / "Application Support"
        / "Claude"
        / "claude_desktop_config.json"
    )
    claude_code_path = home_path / ".claude.json"
    codex_path = home_path / ".codex" / "config.toml"
    journal_path = repo / ".synapse_s2" / "client-config-publication.journal.json"
    allowed_targets = {project_path, desktop_path, claude_code_path, codex_path}
    if not dry_run:
        _recover_pending_publication(
            journal_path,
            allowed_targets=allowed_targets,
        )

    project_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher,
        client_agent_id="project-mcp",
        core_binding_path=binding_path,
        core_binding=binding,
    )
    project_payload = _read_json(project_path, fallback={})
    _merge_mcp_server(project_payload, project_server)

    desktop_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher,
        client_agent_id="claude-desktop",
        core_binding_path=binding_path,
        core_binding=binding,
    )
    desktop_payload = _read_json(desktop_path, fallback={})
    _merge_mcp_server(desktop_payload, desktop_server)

    claude_code_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher,
        client_agent_id="claude-code",
        core_binding_path=binding_path,
        core_binding=binding,
    )
    claude_code_payload = _read_json(claude_code_path, fallback={})
    _merge_mcp_server(claude_code_payload, claude_code_server)
    _merge_claude_code_project(claude_code_payload, repo)

    codex_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher,
        client_agent_id="codex-desktop",
        core_binding_path=binding_path,
        core_binding=binding,
    )
    next_codex = merge_codex_config_text(
        _read_text(codex_path),
        server=codex_server,
    )
    json_plans = (
        ("project_mcp", project_path, project_payload),
        ("claude_desktop", desktop_path, desktop_payload),
        ("claude_code", claude_code_path, claude_code_payload),
    )
    plans: list[dict[str, Any]] = []
    for client, path, payload in json_plans:
        status, next_text, original_text = _plan_json_update(
            path,
            payload,
            dry_run=dry_run,
        )
        result["clients"][client] = status
        if status["would_change"]:
            plans.append(
                {
                    "client": client,
                    "path": path,
                    "next_text": next_text,
                    "original_text": original_text,
                    "original_exists": path.exists(),
                }
            )
    codex_status, original_codex = _plan_text_update(
        codex_path,
        next_codex,
        dry_run=dry_run,
    )
    result["clients"]["codex"] = codex_status
    if codex_status["would_change"]:
        plans.append(
            {
                "client": "codex",
                "path": codex_path,
                "next_text": next_codex,
                "original_text": original_codex,
                "original_exists": codex_path.exists(),
            }
        )

    if plans and not dry_run:
        applied = _publish_config_transaction(
            plans,
            journal_path=journal_path,
            allowed_targets=allowed_targets,
        )
        for client, status in applied.items():
            result["clients"][client] = status

    result["restart_required"] = any(
        bool(client.get("changed") or client.get("would_change"))
        for client in result["clients"].values()
    )
    return result


def _plan_json_update(
    path: Path,
    payload: dict[str, Any],
    *,
    dry_run: bool,
) -> tuple[dict[str, Any], str, str]:
    current = _read_text(path)
    same = False
    if current:
        try:
            same = json.dumps(
                json.loads(current),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ) == json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            same = False
    next_text = json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n"
    return (
        {
            "path": str(path),
            "changed": False,
            "would_change": not same,
            "backup_path": None,
        },
        next_text,
        current,
    )


def _plan_text_update(
    path: Path,
    next_text: str,
    *,
    dry_run: bool,
) -> tuple[dict[str, Any], str]:
    del dry_run
    current = _read_text(path)
    changed = current != next_text
    return (
        {
            "path": str(path),
            "changed": False,
            "would_change": changed,
            "backup_path": None,
        },
        current,
    )


def merge_codex_config_text(text: str, *, server: dict[str, Any]) -> str:
    cleaned = _remove_toml_sections(
        text,
        {
            "mcp_servers.synapse-s2",
            "mcp_servers.synapse-s2.env",
        },
    ).rstrip()
    separator = "\n\n" if cleaned else ""
    return cleaned + separator + _codex_server_block(server)


def _codex_server_block(server: dict[str, Any]) -> str:
    lines = [
        "[mcp_servers.synapse-s2]",
        f"command = {_toml_string(server['command'])}",
        "args = []",
        "startup_timeout_sec = 15",
        "tool_timeout_sec = 30",
        "enabled = true",
        "",
        "[mcp_servers.synapse-s2.env]",
    ]
    for key, value in server["env"].items():
        lines.append(f"{key} = {_toml_string(str(value))}")
    return "\n".join(lines) + "\n"


def _merge_mcp_server(payload: dict[str, Any], server: dict[str, Any]) -> None:
    servers = payload.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        payload["mcpServers"] = {}
        servers = payload["mcpServers"]
    servers[SERVER_NAME] = dict(server)


def _merge_claude_code_project(payload: dict[str, Any], repo_root: Path) -> None:
    projects = payload.setdefault("projects", {})
    if not isinstance(projects, dict):
        payload["projects"] = {}
        projects = payload["projects"]
    project = projects.setdefault(str(repo_root), {})
    if not isinstance(project, dict):
        project = {}
        projects[str(repo_root)] = project
    project.setdefault("allowedTools", [])
    project.setdefault("mcpContextUris", [])
    enabled = project.setdefault("enabledMcpjsonServers", [])
    if not isinstance(enabled, list):
        enabled = []
        project["enabledMcpjsonServers"] = enabled
    if SERVER_NAME not in enabled:
        enabled.append(SERVER_NAME)
    disabled = project.setdefault("disabledMcpjsonServers", [])
    if isinstance(disabled, list) and SERVER_NAME in disabled:
        project["disabledMcpjsonServers"] = [
            item for item in disabled if item != SERVER_NAME
        ]
    project.setdefault("hasTrustDialogAccepted", True)
    project.setdefault("projectOnboardingSeenCount", 0)
    project.setdefault("hasClaudeMdExternalIncludesApproved", False)
    project.setdefault("hasClaudeMdExternalIncludesWarningShown", False)


def _read_json(path: Path, *, fallback: dict[str, Any]) -> dict[str, Any]:
    if not (path.exists() or path.is_symlink()):
        return dict(fallback)
    try:
        payload = json.loads(_read_text(path))
    except Exception as exc:
        raise ValueError(f"refusing to overwrite unreadable JSON client config: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"refusing to overwrite non-object JSON client config: {path}")
    return payload


def _read_text(path: Path) -> str:
    if not (path.exists() or path.is_symlink()):
        return ""
    try:
        payload, _identity = _read_private_regular(path)
        return payload.decode("utf-8")
    except OSError:
        raise
    except Exception as exc:
        raise ValueError(f"refusing to overwrite unreadable client config: {path}") from exc


def _read_private_regular(path: Path) -> tuple[bytes, tuple[int, int, int, int, int]]:
    _assert_no_symlink_components(path)
    observed = path.lstat()
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
        or observed.st_size > MAX_CLIENT_CONFIG_BYTES
    ):
        raise OSError("client config must be an owner-controlled regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, MAX_CLIENT_CONFIG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CLIENT_CONFIG_BYTES:
                raise OSError("client config exceeds its size limit")
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    visible = path.lstat()
    identities = {_file_identity(item) for item in (observed, opened, finished, visible)}
    if len(identities) != 1 or total != observed.st_size:
        raise OSError("client config changed while being read")
    return b"".join(chunks), _file_identity(observed)


def _write_json_if_changed(
    path: Path,
    payload: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    current = _read_text(path)
    if current:
        try:
            current_payload = json.loads(current)
            current_canonical = json.dumps(
                current_payload,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            next_canonical = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError):
            current_canonical = None
            next_canonical = None
        if current_canonical is not None and current_canonical == next_canonical:
            return {
                "path": str(path),
                "changed": False,
                "would_change": False,
                "backup_path": None,
            }
    next_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return _write_text_if_changed(path, next_text, dry_run=dry_run)


def _write_text_if_changed(path: Path, next_text: str, *, dry_run: bool) -> dict[str, Any]:
    original_exists = path.exists() or path.is_symlink()
    current = _read_text(path)
    changed = current != next_text
    status = {
        "path": str(path),
        "changed": False,
        "would_change": bool(changed and dry_run),
        "backup_path": None,
    }
    if not changed or dry_run:
        return status
    _ensure_private_directory(path.parent)
    with _exclusive_config_lock(path):
        locked_exists = path.exists() or path.is_symlink()
        if locked_exists != original_exists or _read_text(path) != current:
            raise RuntimeError(
                f"client config changed during update; refusing to overwrite: {path}"
            )
        expected_identity: tuple[int, int, int, int, int] | None = None
        if locked_exists:
            current_stat = path.lstat()
            if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISREG(current_stat.st_mode):
                raise OSError(f"refusing to replace non-regular client config: {path}")
            expected_identity = _file_identity(current_stat)
            backup_path = _create_exclusive_private_backup(path)
            status["backup_path"] = str(backup_path)
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
                handle.write(next_text)
                handle.flush()
                os.fsync(handle.fileno())
            current_exists = path.exists() or path.is_symlink()
            if current_exists != original_exists or _read_text(path) != current:
                raise RuntimeError(
                    f"client config changed during update; refusing to overwrite: {path}"
                )
            if current_exists:
                before_replace = path.lstat()
                if (
                    stat.S_ISLNK(before_replace.st_mode)
                    or not stat.S_ISREG(before_replace.st_mode)
                    or _file_identity(before_replace) != expected_identity
                ):
                    raise RuntimeError(
                        f"client config identity changed during update; refusing to overwrite: {path}"
                    )
            staged = temp_path.lstat()
            os.replace(temp_path, path)
            _assert_private_publication(path, staged=staged)
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
    status["changed"] = True
    return status


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid():
            raise OSError("client config directory is not owner-controlled")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_private_publication(path: Path, *, staged: os.stat_result) -> None:
    visible = path.lstat()
    if (
        stat.S_ISLNK(visible.st_mode)
        or not stat.S_ISREG(visible.st_mode)
        or visible.st_uid != os.getuid()
        or visible.st_nlink != 1
        or stat.S_IMODE(visible.st_mode) != 0o600
        or (
            visible.st_dev,
            visible.st_ino,
            visible.st_size,
            visible.st_mtime_ns,
        )
        != (
            staged.st_dev,
            staged.st_ino,
            staged.st_size,
            staged.st_mtime_ns,
        )
    ):
        raise RuntimeError("private publication identity changed during replacement")


def _atomic_private_payload(path: Path, payload: bytes) -> None:
    _ensure_private_directory(path.parent)
    existing = path.lstat() if path.exists() or path.is_symlink() else None
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.getuid()
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise OSError("private publication target is unsafe")
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("private publication write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        staged = temporary.lstat()
        visible = path.lstat() if path.exists() or path.is_symlink() else None
        if existing is None:
            if visible is not None:
                raise RuntimeError("private publication target appeared during update")
        elif visible is None or _file_identity(visible) != _file_identity(existing):
            raise RuntimeError("private publication target changed during update")
        os.replace(temporary, path)
        _assert_private_publication(path, staged=staged)
        _fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_publication_journal(path: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_CLIENT_CONFIG_BYTES:
        raise ValueError("client config publication journal is too large")
    _atomic_private_payload(path, encoded)


def _safe_unlink_private(path: Path, *, expected_sha256: str | None = None) -> None:
    payload, _identity = _read_private_regular(path)
    if stat.S_IMODE(path.lstat().st_mode) != 0o600:
        raise OSError("private publication artifact has an unsafe mode")
    if expected_sha256 is not None and _sha256(payload) != expected_sha256:
        raise RuntimeError("private publication artifact digest changed")
    path.unlink()
    _fsync_directory(path.parent)


def _validate_publication_entry(
    entry: Any,
    *,
    allowed_targets: set[Path],
) -> tuple[Path, Path | None, Path]:
    if not isinstance(entry, dict):
        raise ValueError("client config publication journal entry is invalid")
    target_raw = entry.get("target")
    temp_raw = entry.get("temp_path")
    backup_raw = entry.get("backup_path")
    if not isinstance(target_raw, str) or not isinstance(temp_raw, str):
        raise ValueError("client config publication journal paths are invalid")
    target = Path(target_raw)
    temporary = Path(temp_raw)
    backup = Path(backup_raw) if isinstance(backup_raw, str) else None
    if target not in allowed_targets or temporary.parent != target.parent:
        raise ValueError("client config publication journal escaped its target set")
    if not temporary.name.startswith(f".{target.name}.") or not temporary.name.endswith(".tmp"):
        raise ValueError("client config publication temporary path is invalid")
    if backup is not None and (
        backup.parent != target.parent
        or not backup.name.startswith(f"{target.name}.bak-")
    ):
        raise ValueError("client config publication backup path is invalid")
    for key in ("original_sha256", "desired_sha256"):
        value = entry.get(key)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("client config publication digest is invalid")
    if type(entry.get("original_exists")) is not bool:
        raise ValueError("client config publication existence state is invalid")
    return target, backup, temporary


def _recover_config_transaction(
    journal_path: Path,
    *,
    allowed_targets: set[Path],
) -> bool:
    if not (journal_path.exists() or journal_path.is_symlink()):
        return False
    journal_stat = journal_path.lstat()
    if stat.S_IMODE(journal_stat.st_mode) != 0o600:
        raise OSError("client config publication journal has an unsafe mode")
    raw, _identity = _read_private_regular(journal_path)
    try:
        journal = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("client config publication journal is invalid") from exc
    entries = journal.get("entries") if isinstance(journal, dict) else None
    state = journal.get("state") if isinstance(journal, dict) else None
    if (
        not isinstance(journal, dict)
        or journal.get("schema") != PUBLICATION_SCHEMA
        or state not in {"prepared", "committed"}
        or not isinstance(entries, list)
        or not entries
    ):
        raise ValueError("client config publication journal contract is invalid")
    validated = [
        (entry, *_validate_publication_entry(entry, allowed_targets=allowed_targets))
        for entry in entries
    ]
    if state == "committed":
        for entry, target, _backup, temporary in validated:
            current, _ = _read_private_regular(target)
            if _sha256(current) != entry["desired_sha256"]:
                raise RuntimeError("committed client config publication is incomplete")
            if temporary.exists() or temporary.is_symlink():
                _safe_unlink_private(
                    temporary,
                    expected_sha256=entry["desired_sha256"],
                )
    else:
        for entry, target, backup, temporary in reversed(validated):
            target_exists = target.exists() or target.is_symlink()
            if entry["original_exists"]:
                if backup is None:
                    raise ValueError("client config rollback backup is missing from journal")
                original, _ = _read_private_regular(backup)
                if _sha256(original) != entry["original_sha256"]:
                    raise RuntimeError("client config rollback backup digest changed")
                restore_required = True
                if target_exists:
                    current, _ = _read_private_regular(target)
                    current_digest = _sha256(current)
                    if current_digest not in {
                        entry["original_sha256"],
                        entry["desired_sha256"],
                    }:
                        raise RuntimeError(
                            "client config changed after interrupted publication; manual review required"
                        )
                    restore_required = current_digest != entry["original_sha256"]
                if restore_required:
                    _atomic_private_payload(target, original)
            elif target_exists:
                current, _ = _read_private_regular(target)
                if _sha256(current) != entry["desired_sha256"]:
                    raise RuntimeError(
                        "new client config changed after interrupted publication; manual review required"
                    )
                _safe_unlink_private(target, expected_sha256=entry["desired_sha256"])
            if temporary.exists() or temporary.is_symlink():
                _safe_unlink_private(
                    temporary,
                    expected_sha256=entry["desired_sha256"],
                )
    _safe_unlink_private(journal_path, expected_sha256=_sha256(raw))
    return True


def _stage_private_payload(path: Path, payload: bytes) -> Path:
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary = Path(temp_name)
    completed = False
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("client config staging write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        completed = True
    finally:
        os.close(descriptor)
        if not completed:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return temporary


def _publish_config_transaction(
    plans: list[dict[str, Any]],
    *,
    journal_path: Path,
    allowed_targets: set[Path],
) -> dict[str, dict[str, Any]]:
    if len({Path(plan["path"]) for plan in plans}) != len(plans):
        raise ValueError("client config publication contains duplicate targets")
    if any(Path(plan["path"]) not in allowed_targets for plan in plans):
        raise ValueError("client config publication escaped its target set")
    for target in allowed_targets:
        _assert_no_symlink_components(target)
    for plan in plans:
        _ensure_private_directory(Path(plan["path"]).parent)
    _ensure_private_directory(journal_path.parent)
    results: dict[str, dict[str, Any]] = {}
    with _exclusive_config_lock(journal_path):
        with ExitStack() as stack:
            for target in sorted(allowed_targets, key=lambda value: str(value)):
                stack.enter_context(_exclusive_config_lock(target))
            _recover_config_transaction(
                journal_path,
                allowed_targets=allowed_targets,
            )
            entries: list[dict[str, Any]] = []
            for plan in plans:
                target = Path(plan["path"])
                exists = target.exists() or target.is_symlink()
                current = _read_text(target)
                if exists != bool(plan["original_exists"]) or current != plan["original_text"]:
                    raise RuntimeError(
                        "client config changed before transaction lock; refusing publication"
                    )
                original = current.encode("utf-8")
                desired = str(plan["next_text"]).encode("utf-8")
                backup = _create_exclusive_private_backup(target) if exists else None
                temporary = _stage_private_payload(target, desired)
                entries.append(
                    {
                        "client": str(plan["client"]),
                        "target": str(target),
                        "original_exists": exists,
                        "original_sha256": _sha256(original),
                        "desired_sha256": _sha256(desired),
                        "backup_path": str(backup) if backup is not None else None,
                        "temp_path": str(temporary),
                    }
                )
                results[str(plan["client"])] = {
                    "path": str(target),
                    "changed": True,
                    "would_change": False,
                    "backup_path": str(backup) if backup is not None else None,
                }
            journal = {
                "schema": PUBLICATION_SCHEMA,
                "state": "prepared",
                "entries": entries,
            }
            _write_publication_journal(journal_path, journal)
            try:
                for entry in entries:
                    target = Path(entry["target"])
                    current_exists = target.exists() or target.is_symlink()
                    if current_exists != entry["original_exists"]:
                        raise RuntimeError("client config existence changed during publication")
                    if current_exists:
                        current, _ = _read_private_regular(target)
                        if _sha256(current) != entry["original_sha256"]:
                            raise RuntimeError("client config changed during publication")
                    temporary = Path(entry["temp_path"])
                    staged = temporary.lstat()
                    os.replace(temporary, target)
                    _assert_private_publication(target, staged=staged)
                    _fsync_directory(target.parent)
                journal["state"] = "committed"
                _write_publication_journal(journal_path, journal)
            except BaseException:
                _recover_config_transaction(
                    journal_path,
                    allowed_targets=allowed_targets,
                )
                raise
            _recover_config_transaction(
                journal_path,
                allowed_targets=allowed_targets,
            )
    return results


def _recover_pending_publication(
    journal_path: Path,
    *,
    allowed_targets: set[Path],
) -> bool:
    if not (journal_path.exists() or journal_path.is_symlink()):
        return False
    _ensure_private_directory(journal_path.parent)
    for target in allowed_targets:
        _ensure_private_directory(target.parent)
    with _exclusive_config_lock(journal_path):
        with ExitStack() as stack:
            for target in sorted(allowed_targets, key=lambda value: str(value)):
                stack.enter_context(_exclusive_config_lock(target))
            return _recover_config_transaction(
                journal_path,
                allowed_targets=allowed_targets,
            )


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


@contextmanager
def _exclusive_config_lock(path: Path):
    lock_path = path.with_name(f".{path.name}.synapse-config.lock")
    _assert_no_symlink_components(lock_path)
    existing = lock_path.lstat() if lock_path.exists() or lock_path.is_symlink() else None
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_uid != os.getuid()
        or existing.st_nlink != 1
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise ValueError("client config lock is unsafe")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        visible = lock_path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            raise ValueError("client config lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another client config publication is in progress") from exc
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _create_exclusive_private_backup(path: Path) -> Path:
    """Copy an existing regular config without ever replacing an older backup."""

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    source_fd = os.open(path, source_flags)
    try:
        source_stat = os.fstat(source_fd)
        visible_source = path.lstat()
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_uid != os.getuid()
            or source_stat.st_nlink != 1
            or _file_identity(source_stat) != _file_identity(visible_source)
        ):
            raise ValueError(f"refusing to back up non-regular client config: {path}")

        backup_path: Path | None = None
        backup_fd = -1
        for _attempt in range(64):
            candidate = path.with_name(
                f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(6)}"
            )
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                backup_fd = os.open(candidate, flags, 0o600)
            except FileExistsError:
                continue
            backup_path = candidate
            break
        if backup_path is None or backup_fd < 0:
            raise FileExistsError(f"could not reserve a unique backup path for {path}")

        completed = False
        try:
            os.fchmod(backup_fd, 0o600)
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(backup_fd, view)
                    if written <= 0:
                        raise OSError("client config backup write made no progress")
                    view = view[written:]
            os.fsync(backup_fd)
            finished_source = os.fstat(source_fd)
            completed = True
        finally:
            os.close(backup_fd)
            if not completed:
                try:
                    backup_path.unlink()
                except FileNotFoundError:
                    pass

        visible_source = path.lstat()
        source_identities = {
            _file_identity(item)
            for item in (source_stat, finished_source, visible_source)
        }
        backup_stat = backup_path.lstat()
        try:
            if (
                len(source_identities) != 1
                or stat.S_ISLNK(backup_stat.st_mode)
                or not stat.S_ISREG(backup_stat.st_mode)
                or backup_stat.st_uid != os.getuid()
                or backup_stat.st_nlink != 1
                or stat.S_IMODE(backup_stat.st_mode) != 0o600
                or backup_stat.st_size != source_stat.st_size
            ):
                raise RuntimeError("client config changed during backup")
        except BaseException:
            try:
                backup_path.unlink()
            except FileNotFoundError:
                pass
            _fsync_directory(path.parent)
            raise

        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return backup_path
    finally:
        os.close(source_fd)


def _ensure_private_directory(path: Path) -> None:
    """Create missing config directories at 0700; preserve existing modes."""

    _assert_no_symlink_components(path)
    missing: list[Path] = []
    cursor = path
    while not (cursor.exists() or cursor.is_symlink()):
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    parent_stat = cursor.lstat()
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o022
    ):
        raise OSError("client config directory parent is unsafe")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            observed = directory.lstat()
            if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                raise
        observed = directory.lstat()
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.getuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise OSError("created client config directory is unsafe")
    final = path.lstat()
    if (
        stat.S_ISLNK(final.st_mode)
        or not stat.S_ISDIR(final.st_mode)
        or final.st_uid != os.getuid()
        or stat.S_IMODE(final.st_mode) & 0o022
    ):
        raise OSError("client config directory is unsafe")


def _assert_no_symlink_components(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise OSError("client config path must be a normal absolute path")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            observed = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(observed.st_mode):
            # /var -> /private/var is a fixed macOS filesystem alias used by
            # TemporaryDirectory.  No application-controlled symlink is ever
            # accepted.
            if current == Path("/var") and os.readlink(current) == "private/var":
                continue
            raise OSError("client config path contains a symlink component")
        if current != path and not stat.S_ISDIR(observed.st_mode):
            raise OSError("client config path contains a non-directory component")


def _toml_string(value: str) -> str:
    return json.dumps(str(value))


def _remove_toml_sections(text: str, section_names: set[str]) -> str:
    lines: list[str] = []
    skip = False
    for line in str(text or "").splitlines():
        match = re.match(r"\s*\[([^\]]+)\]\s*$", line)
        if match:
            section = match.group(1).strip()
            skip = section in section_names
            if skip:
                continue
        if not skip:
            lines.append(line)
    return "\n".join(lines)


def _sanitize_agent_id(agent_id: str) -> str:
    raw = reject_sensitive_identifier(agent_id or "", field="client_agent_id")
    cleaned = re.sub(r"[^A-Za-z0-9_.:@-]+", "_", raw.strip()).strip("._-:@")
    return (cleaned or "local-mcp-client")[:128]


def _sanitize_context_id(context_id: str) -> str:
    raw = reject_sensitive_identifier(context_id or "", field="context_id")
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw.strip()).strip("._-:")
    return (cleaned or "default")[:128]


def build_parser() -> argparse.ArgumentParser:
    parser = SecretSafeArgumentParser(
        description="Install SYNAPSE-S2 MCP client configuration for Codex and Claude.",
    )
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--launcher", type=Path, default=DEFAULT_LAUNCHER)
    parser.add_argument(
        "--core-binding",
        type=Path,
        default=None,
        help="Owner-only core binding; auto-discovered from ~/.config/synapse-s2 when present.",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = install_client_configs(
        home=args.home,
        repo_root=args.repo_root,
        launcher_path=args.launcher,
        dry_run=args.dry_run,
        core_binding_path=args.core_binding,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

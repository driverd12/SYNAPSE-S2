from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import secrets
import stat
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

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


def build_server_definition(
    *,
    repo_root: Path = ROOT,
    launcher_path: Path = DEFAULT_LAUNCHER,
    client_agent_id: str = "local-mcp-client",
    context_id: str = "default",
    startup_prompt: str | None = None,
) -> dict[str, Any]:
    repo = repo_root.expanduser().resolve()
    launcher = launcher_path.expanduser()
    agent = _sanitize_agent_id(client_agent_id)
    context = _sanitize_context_id(context_id)
    raw_prompt = startup_prompt or (
        f"Hydrate SYNAPSE-S2 context for {agent} local MCP client startup."
    )
    prompt, _ = redact_capture_text(raw_prompt)
    return {
        "type": "stdio",
        "command": str(launcher),
        "args": [],
        "env": {
            "PYTHONPATH": str(repo),
            "MLX_DEVICE": "gpu",
            "SYNAPSE_S2_EMBEDDING_PROVIDER": DEFAULT_EMBEDDING_PROVIDER,
            "SYNAPSE_S2_NEURAL_MODEL": DEFAULT_NEURAL_MODEL,
            "SYNAPSE_S2_NEURAL_CACHE_DIR": str(repo / ".synapse_s2" / "models"),
            "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": "1",
            "SYNAPSE_S2_DIMENSION": DEFAULT_DIMENSION,
            "SYNAPSE_S2_NEURONS": DEFAULT_NEURONS,
            "SYNAPSE_S2_TOP_K": DEFAULT_TOP_K,
            "SYNAPSE_S2_RECALL_COUNT": DEFAULT_RECALL_COUNT,
            "SYNAPSE_S2_STATE_PATH": str(repo / ".synapse_s2" / "runtime_state.json"),
            "SYNAPSE_S2_MEMORY_DB": str(repo / ".synapse_s2" / "memory.sqlite3"),
            "SYNAPSE_S2_EXPORT_DIR": str(repo / ".synapse_s2"),
            "SYNAPSE_S2_CAPTURE_ROOT": str(repo / ".synapse_s2"),
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
) -> dict[str, Any]:
    repo = repo_root.expanduser().resolve()
    home_path = home.expanduser()
    result: dict[str, Any] = {
        "server_name": SERVER_NAME,
        "repo_root": str(repo),
        "launcher_path": str(launcher_path.expanduser()),
        "restart_required": False,
        "clients": {},
    }

    project_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher_path,
        client_agent_id="project-mcp",
    )
    project_path = repo / ".mcp.json"
    project_payload = _read_json(project_path, fallback={})
    _merge_mcp_server(project_payload, project_server)
    result["clients"]["project_mcp"] = _write_json_if_changed(
        project_path,
        project_payload,
        dry_run=dry_run,
    )

    desktop_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher_path,
        client_agent_id="claude-desktop",
    )
    desktop_path = home_path / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    desktop_payload = _read_json(desktop_path, fallback={})
    _merge_mcp_server(desktop_payload, desktop_server)
    result["clients"]["claude_desktop"] = _write_json_if_changed(
        desktop_path,
        desktop_payload,
        dry_run=dry_run,
    )

    claude_code_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher_path,
        client_agent_id="claude-code",
    )
    claude_code_path = home_path / ".claude.json"
    claude_code_payload = _read_json(claude_code_path, fallback={})
    _merge_mcp_server(claude_code_payload, claude_code_server)
    _merge_claude_code_project(claude_code_payload, repo)
    result["clients"]["claude_code"] = _write_json_if_changed(
        claude_code_path,
        claude_code_payload,
        dry_run=dry_run,
    )

    codex_server = build_server_definition(
        repo_root=repo,
        launcher_path=launcher_path,
        client_agent_id="codex-desktop",
    )
    codex_path = home_path / ".codex" / "config.toml"
    next_codex = merge_codex_config_text(
        _read_text(codex_path),
        server=codex_server,
    )
    result["clients"]["codex"] = _write_text_if_changed(
        codex_path,
        next_codex,
        dry_run=dry_run,
    )

    result["restart_required"] = any(
        bool(client.get("changed") or client.get("would_change"))
        for client in result["clients"].values()
    )
    return result


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
    if not path.exists():
        return dict(fallback)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"refusing to overwrite unreadable JSON client config: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"refusing to overwrite non-object JSON client config: {path}")
    return payload


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        raise ValueError(f"refusing to overwrite unreadable client config: {path}") from exc


def _write_json_if_changed(
    path: Path,
    payload: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
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
    status["changed"] = True
    return status


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
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"client config lock must be a regular file: {lock_path}")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
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
        if not stat.S_ISREG(source_stat.st_mode):
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
            completed = True
        finally:
            os.close(backup_fd)
            if not completed:
                try:
                    backup_path.unlink()
                except FileNotFoundError:
                    pass

        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0),
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
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload = install_client_configs(
        home=args.home,
        repo_root=args.repo_root,
        launcher_path=args.launcher,
        dry_run=args.dry_run,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

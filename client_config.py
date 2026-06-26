from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any


SERVER_NAME = "synapse-s2"
ROOT = Path(__file__).resolve().parent
DEFAULT_LAUNCHER = Path.home() / ".local" / "bin" / "synapse-s2-mcp"


def build_server_definition(
    *,
    repo_root: Path = ROOT,
    launcher_path: Path = DEFAULT_LAUNCHER,
) -> dict[str, Any]:
    repo = repo_root.expanduser().resolve()
    launcher = launcher_path.expanduser()
    return {
        "type": "stdio",
        "command": str(launcher),
        "args": [],
        "env": {
            "PYTHONPATH": str(repo),
            "MLX_DEVICE": "gpu",
            "SYNAPSE_S2_STATE_PATH": str(repo / ".synapse_s2" / "runtime_state.json"),
            "SYNAPSE_S2_MEMORY_DB": str(repo / ".synapse_s2" / "memory.sqlite3"),
            "SYNAPSE_S2_EXPORT_DIR": str(repo / ".synapse_s2"),
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
    server = build_server_definition(repo_root=repo, launcher_path=launcher_path)
    result: dict[str, Any] = {
        "server_name": SERVER_NAME,
        "repo_root": str(repo),
        "launcher_path": str(launcher_path.expanduser()),
        "restart_required": False,
        "clients": {},
    }

    project_path = repo / ".mcp.json"
    project_payload = _read_json(project_path, fallback={})
    _merge_mcp_server(project_payload, server)
    result["clients"]["project_mcp"] = _write_json_if_changed(
        project_path,
        project_payload,
        dry_run=dry_run,
    )

    desktop_path = home_path / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    desktop_payload = _read_json(desktop_path, fallback={})
    _merge_mcp_server(desktop_payload, server)
    result["clients"]["claude_desktop"] = _write_json_if_changed(
        desktop_path,
        desktop_payload,
        dry_run=dry_run,
    )

    claude_code_path = home_path / ".claude.json"
    claude_code_payload = _read_json(claude_code_path, fallback={})
    _merge_mcp_server(claude_code_payload, server)
    _merge_claude_code_project(claude_code_payload, repo)
    result["clients"]["claude_code"] = _write_json_if_changed(
        claude_code_path,
        claude_code_payload,
        dry_run=dry_run,
    )

    codex_path = home_path / ".codex" / "config.toml"
    next_codex = merge_codex_config_text(
        _read_text(codex_path),
        server=server,
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
    if "[mcp_servers.synapse-s2]" in text:
        return text
    separator = "\n" if text.endswith("\n") or not text else "\n\n"
    return text + separator + _codex_server_block(server)


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
    try:
        if not path.exists():
            return dict(fallback)
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else dict(fallback)
    except Exception:
        return dict(fallback)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8") if path.exists() else ""
    except Exception:
        return ""


def _write_json_if_changed(
    path: Path,
    payload: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    next_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return _write_text_if_changed(path, next_text, dry_run=dry_run)


def _write_text_if_changed(path: Path, next_text: str, *, dry_run: bool) -> dict[str, Any]:
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
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup_path = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup_path)
        status["backup_path"] = str(backup_path)
    path.write_text(next_text, encoding="utf-8")
    status["changed"] = True
    return status


def _toml_string(value: str) -> str:
    return json.dumps(str(value))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
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

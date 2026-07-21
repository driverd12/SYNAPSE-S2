#!/usr/bin/env python3
"""Open the local dashboard without exposing its bootstrap capability in argv."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


DASHBOARD_AUTH_SCHEMA = "synapse-s2.dashboard-auth.v1"
DASHBOARD_BOOTSTRAP_PATH = "/__dashboard_bootstrap"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{40,128}\Z")


class DashboardOpenError(RuntimeError):
    pass


def _read_owner_auth_file(path: Path) -> dict[str, Any]:
    path = path.expanduser()
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise DashboardOpenError("dashboard auth path is invalid")
    parent = path.parent
    try:
        parent_stat = parent.lstat()
        visible = path.lstat()
    except FileNotFoundError as exc:
        raise DashboardOpenError("dashboard auth file is unavailable") from exc
    if (
        stat.S_ISLNK(parent_stat.st_mode)
        or not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
        or parent.resolve() != parent
    ):
        raise DashboardOpenError("dashboard auth directory is unsafe")
    if (
        stat.S_ISLNK(visible.st_mode)
        or not stat.S_ISREG(visible.st_mode)
        or visible.st_uid != os.geteuid()
        or visible.st_nlink != 1
        or stat.S_IMODE(visible.st_mode) != 0o600
        or visible.st_size > 4096
    ):
        raise DashboardOpenError("dashboard auth file is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino):
            raise DashboardOpenError("dashboard auth file changed while opening")
        chunks: list[bytes] = []
        remaining = 4097
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or sum(len(chunk) for chunk in chunks) > 4096
    ):
        raise DashboardOpenError("dashboard auth file changed while reading")
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DashboardOpenError("dashboard auth file is invalid") from exc
    if not isinstance(payload, dict) or payload.get("schema") != DASHBOARD_AUTH_SCHEMA:
        raise DashboardOpenError("dashboard auth schema is invalid")
    return payload


def _validated_bootstrap_url(payload: dict[str, Any]) -> str:
    value = payload.get("bootstrap_url")
    session_header = payload.get("session_header")
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1024:
        raise DashboardOpenError("dashboard bootstrap URL is invalid")
    try:
        parsed = urlparse(value)
        port = int(parsed.port or 80)
    except (TypeError, ValueError) as exc:
        raise DashboardOpenError("dashboard bootstrap URL is invalid") from exc
    params = parse_qs(parsed.query, keep_blank_values=True)
    tokens = params.get("token", [])
    if (
        parsed.scheme != "http"
        or parsed.hostname not in LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != DASHBOARD_BOOTSTRAP_PATH
        or parsed.params
        or parsed.fragment
        or set(params) != {"token"}
        or len(tokens) != 1
        or TOKEN_PATTERN.fullmatch(tokens[0]) is None
        or not isinstance(session_header, str)
        or TOKEN_PATTERN.fullmatch(session_header) is None
        or payload.get("host") != parsed.hostname
        or type(payload.get("port")) is not int
        or payload.get("port") != port
        or not 1 <= port <= 65535
    ):
        raise DashboardOpenError("dashboard bootstrap URL is invalid")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Open the authenticated SYNAPSE-S2 dashboard.")
    parser.add_argument(
        "--auth-file",
        default=os.getenv(
            "SYNAPSE_S2_DASHBOARD_AUTH_FILE",
            str(Path(__file__).resolve().parent.parent / ".synapse_s2" / "dashboard-auth.json"),
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = _read_owner_auth_file(Path(args.auth_file))
        bootstrap_url = _validated_bootstrap_url(payload)
        escaped_url = bootstrap_url.replace("\\", "\\\\").replace('"', '\\"')
        script = f'open location "{escaped_url}"\n'
        subprocess.run(
            ["/usr/bin/osascript", "-"],
            input=script,
            text=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (DashboardOpenError, OSError, subprocess.CalledProcessError):
        print(
            "Authenticated dashboard launch failed; verify the dashboard service and private auth file.",
            file=sys.stderr,
        )
        return 2
    print("Opened authenticated SYNAPSE-S2 dashboard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

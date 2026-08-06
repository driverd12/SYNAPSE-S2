#!/usr/bin/env python3
"""Open the local dashboard without exposing its bootstrap capability in argv."""

from __future__ import annotations

import argparse
import http.server
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


DASHBOARD_AUTH_SCHEMA = "synapse-s2.dashboard-auth.v1"
DASHBOARD_BOOTSTRAP_PATH = "/__dashboard_bootstrap"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{40,128}\Z")
CHROME_BINARY = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
CHROME_APP_RELAY_TIMEOUT_SECONDS = 10.0


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


def _open_default_browser(bootstrap_url: str) -> None:
    escaped_url = bootstrap_url.replace("\\", "\\\\").replace('"', '\\"')
    subprocess.run(
        ["/usr/bin/osascript", "-"],
        input=f'open location "{escaped_url}"\n',
        text=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _open_chrome_app(bootstrap_url: str) -> None:
    """Open an app-framed Chrome window without placing the capability in argv."""
    if not CHROME_BINARY.is_file():
        raise DashboardOpenError("Google Chrome is unavailable")

    requested = threading.Event()
    nonce = secrets.token_urlsafe(24)
    expected_path = f"/{nonce}"

    class BootstrapRelay(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != expected_path:
                self.send_error(404)
                return
            self.send_response(302)
            self.send_header("Location", bootstrap_url)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            requested.set()

        def log_message(self, _format: str, *args: object) -> None:
            del args

    relay = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BootstrapRelay)
    relay.daemon_threads = True
    relay_thread = threading.Thread(target=relay.serve_forever, daemon=True)
    relay_thread.start()
    relay_url = f"http://127.0.0.1:{relay.server_port}{expected_path}"
    try:
        subprocess.Popen(
            [str(CHROME_BINARY), f"--app={relay_url}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if not requested.wait(CHROME_APP_RELAY_TIMEOUT_SECONDS):
            raise DashboardOpenError("Chrome did not request the secure dashboard relay")
    finally:
        relay.shutdown()
        relay.server_close()
        relay_thread.join(timeout=1.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Open the authenticated SYNAPSE-S2 dashboard.")
    parser.add_argument(
        "--auth-file",
        default=os.getenv(
            "SYNAPSE_S2_DASHBOARD_AUTH_FILE",
            str(Path(__file__).resolve().parent.parent / ".synapse_s2" / "dashboard-auth.json"),
        ),
    )
    launch_mode = parser.add_mutually_exclusive_group()
    launch_mode.add_argument(
        "--chrome-app",
        dest="chrome_app",
        action="store_true",
        default=True,
        help="Open an app-framed Google Chrome window through a one-shot loopback relay (default).",
    )
    launch_mode.add_argument(
        "--browser-tab",
        dest="chrome_app",
        action="store_false",
        help="Open an authenticated tab in the system browser instead.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = _read_owner_auth_file(Path(args.auth_file))
        bootstrap_url = _validated_bootstrap_url(payload)
        if args.chrome_app:
            _open_chrome_app(bootstrap_url)
        else:
            _open_default_browser(bootstrap_url)
    except (DashboardOpenError, OSError, subprocess.CalledProcessError):
        print(
            "Authenticated dashboard launch failed; verify the dashboard service and private auth file.",
            file=sys.stderr,
        )
        return 2
    mode = " in Chrome app mode" if args.chrome_app else ""
    print(f"Opened authenticated SYNAPSE-S2 dashboard{mode}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import json
import http.client
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard_server import (
    DASHBOARD_BOOTSTRAP_PATH,
    DASHBOARD_SESSION_FRAGMENT_KEY,
    DASHBOARD_SESSION_HEADER_NAME,
    DashboardRuntime,
    SynapseDashboardServer,
)


WARNING_TOKENS = (
    "KaTeX parse error",
    "Some tools have naming issues",
    "Traceback (most recent call last)",
    "ReferenceError:",
    "TypeError:",
)


# Static assets and the local bootstrap handshake should be immediate.  The
# first API request may initialize a cold, locally pinned neural backend, which
# has taken just over 30 seconds on production Apple Silicon.  Keep that path
# bounded while giving it enough headroom to avoid a timeout race at 30s.
STATIC_HTTP_TIMEOUT_SECONDS = 5.0
BOOTSTRAP_HTTP_TIMEOUT_SECONDS = 5.0
SNAPSHOT_HTTP_TIMEOUT_SECONDS = 60.0
GRAPH_HTTP_TIMEOUT_SECONDS = 20.0
NAMESPACE_MAP_HTTP_TIMEOUT_SECONDS = 20.0
SMOKE_REQUEST_BUDGET_SECONDS = 75.0
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{40,128}\Z")


def request_timeout(
    *,
    deadline: float,
    stage_timeout: float,
    stage: str,
) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise TimeoutError(
            f"dashboard smoke request budget exhausted before {stage}"
        )
    return min(stage_timeout, remaining)


def fetch_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float,
) -> dict:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_text(url: str, *, timeout: float) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8")


def bootstrap_session(
    server: SynapseDashboardServer,
    *,
    timeout: float,
) -> dict[str, str]:
    authority = f"127.0.0.1:{server.server_port}"
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_port,
        timeout=timeout,
    )
    try:
        connection.request(
            "GET",
            f"{DASHBOARD_BOOTSTRAP_PATH}?token={server._dashboard_bootstrap_capability}",
            headers={"Host": authority},
        )
        response = connection.getresponse()
        response.read()
        location = response.getheader("Location") or ""
        set_cookie = response.getheader("Set-Cookie") or ""
        if response.status != 303:
            raise RuntimeError("dashboard bootstrap did not redirect")
    finally:
        connection.close()
    fragment = parse_qs(urlparse(location).fragment, keep_blank_values=True)
    candidates = fragment.get(DASHBOARD_SESSION_FRAGMENT_KEY, [])
    cookie_pair = set_cookie.split(";", 1)[0]
    if (
        set(fragment) != {DASHBOARD_SESSION_FRAGMENT_KEY, "target"}
        or len(candidates) != 1
        or TOKEN_PATTERN.fullmatch(candidates[0]) is None
        or fragment.get("target") != ["namespaceGalaxy"]
        or not cookie_pair.startswith(f"{server._dashboard_cookie_name}=")
    ):
        raise RuntimeError("dashboard bootstrap credentials were invalid")
    return {
        "Cookie": cookie_pair,
        DASHBOARD_SESSION_HEADER_NAME: candidates[0],
    }


def main() -> int:
    context = sys.argv[1] if len(sys.argv) > 1 else "default"
    request_deadline = time.monotonic() + SMOKE_REQUEST_BUDGET_SECONDS
    runtime = DashboardRuntime()
    server = SynapseDashboardServer(("127.0.0.1", 0), runtime)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        index = fetch_text(
            f"{base_url}/",
            timeout=request_timeout(
                deadline=request_deadline,
                stage_timeout=STATIC_HTTP_TIMEOUT_SECONDS,
                stage="index",
            ),
        )
        app_js = fetch_text(
            f"{base_url}/app.js",
            timeout=request_timeout(
                deadline=request_deadline,
                stage_timeout=STATIC_HTTP_TIMEOUT_SECONDS,
                stage="app.js",
            ),
        )
        styles = fetch_text(
            f"{base_url}/styles.css",
            timeout=request_timeout(
                deadline=request_deadline,
                stage_timeout=STATIC_HTTP_TIMEOUT_SECONDS,
                stage="styles.css",
            ),
        )
        session_headers = bootstrap_session(
            server,
            timeout=request_timeout(
                deadline=request_deadline,
                stage_timeout=BOOTSTRAP_HTTP_TIMEOUT_SECONDS,
                stage="session bootstrap",
            ),
        )
        # The browser intentionally hydrates its shell without the graph first,
        # then loads graph/galaxy data through their bounded endpoints.  Mirror
        # that production contract here so a cold MLX process cannot make the
        # readiness probe look hung while still proving every visual data lane.
        snapshot = fetch_json(
            f"{base_url}/api/snapshot?context_id={context}&limit=8&include_graph=false",
            headers=session_headers,
            timeout=request_timeout(
                deadline=request_deadline,
                stage_timeout=SNAPSHOT_HTTP_TIMEOUT_SECONDS,
                stage="snapshot",
            ),
        )
        graph = fetch_json(
            f"{base_url}/api/graph?context_id={context}&limit=8",
            headers=session_headers,
            timeout=request_timeout(
                deadline=request_deadline,
                stage_timeout=GRAPH_HTTP_TIMEOUT_SECONDS,
                stage="graph",
            ),
        )
        namespace_map = fetch_json(
            f"{base_url}/api/namespace-map?context_id={context}"
            "&limit=50&suggestion_limit=0&include_suggestions=false",
            headers=session_headers,
            timeout=request_timeout(
                deadline=request_deadline,
                stage_timeout=NAMESPACE_MAP_HTTP_TIMEOUT_SECONDS,
                stage="namespace map",
            ),
        )
        warnings = []
        for token in WARNING_TOKENS:
            if token in index or token in app_js or token in styles:
                warnings.append(token)
        js_syntax_ok = None
        js_syntax_stderr = ""
        node = shutil.which("node")
        if node:
            check = subprocess.run(
                [node, "--check", str(ROOT / "web" / "app.js")],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            js_syntax_ok = check.returncode == 0
            js_syntax_stderr = check.stderr.strip()
            if not js_syntax_ok:
                warnings.append("web/app.js syntax check failed")
        result = {
            "url": base_url,
            "index_loaded": "SYNAPSE-S2 Control" in index,
            "app_js_loaded": "Start Wizard" in app_js or "startWizard" in app_js,
            "styles_loaded": ".app-shell" in styles,
            "ready": bool(snapshot["status"]["runtime"] == "ready"),
            "context_id": snapshot["context_id"],
            "memory_entries": snapshot["status"]["memory_context_entry_count"],
            "relationships": snapshot["status"]["memory_context_relationship_count"],
            "graph_loaded": isinstance(graph.get("entries"), list)
            and isinstance(graph.get("relationships"), list),
            "graph_entries": int(graph.get("entry_count", 0) or 0),
            "namespace_map_loaded": isinstance(namespace_map.get("nodes"), list)
            and isinstance(namespace_map.get("links"), list),
            "namespace_count": int(namespace_map.get("node_count", 0) or 0),
            "resource_mb": snapshot["profile"]["estimated_total_mb"],
            "warnings": warnings,
            "js_syntax_ok": js_syntax_ok,
            "js_syntax_stderr": js_syntax_stderr,
        }
        print(json.dumps(result, sort_keys=True))
        return (
            0
            if result["index_loaded"]
            and result["app_js_loaded"]
            and result["styles_loaded"]
            and result["ready"]
            and result["graph_loaded"]
            and result["namespace_map_loaded"]
            and not warnings
            else 1
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())

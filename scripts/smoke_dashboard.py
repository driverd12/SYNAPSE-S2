from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard_server import DashboardRuntime, SynapseDashboardServer


WARNING_TOKENS = (
    "KaTeX parse error",
    "Some tools have naming issues",
    "Traceback (most recent call last)",
    "ReferenceError:",
    "TypeError:",
)


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def main() -> int:
    context = sys.argv[1] if len(sys.argv) > 1 else "default"
    runtime = DashboardRuntime()
    server = SynapseDashboardServer(("127.0.0.1", 0), runtime)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        index = fetch_text(f"{base_url}/")
        app_js = fetch_text(f"{base_url}/app.js")
        styles = fetch_text(f"{base_url}/styles.css")
        snapshot = fetch_json(f"{base_url}/api/snapshot?context_id={context}&limit=8")
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
            and not warnings
            else 1
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())

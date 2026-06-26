from __future__ import annotations

import json
import sys
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard_server import DashboardRuntime, SynapseDashboardServer


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def main() -> int:
    context = sys.argv[1] if len(sys.argv) > 1 else "board-demo"
    runtime = DashboardRuntime()
    server = SynapseDashboardServer(("127.0.0.1", 0), runtime)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        index = fetch_text(f"{base_url}/")
        snapshot = fetch_json(f"{base_url}/api/snapshot?context_id={context}&limit=8")
        result = {
            "url": base_url,
            "index_loaded": "SYNAPSE-S2 Control" in index,
            "ready": bool(snapshot["status"]["runtime"] == "ready"),
            "context_id": snapshot["context_id"],
            "memory_entries": snapshot["status"]["memory_context_entry_count"],
            "relationships": snapshot["status"]["memory_context_relationship_count"],
            "resource_mb": snapshot["profile"]["estimated_total_mb"],
        }
        print(json.dumps(result, sort_keys=True))
        return 0 if result["index_loaded"] and result["ready"] else 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())

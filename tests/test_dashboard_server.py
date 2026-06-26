import json
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import urllib.error
import urllib.request

from dashboard_server import DashboardRuntime, SynapseDashboardServer
from mlx_backend import SpikingAttentionBackend


class DashboardRuntimeTests(unittest.TestCase):
    def make_runtime(self, tmp: str) -> DashboardRuntime:
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=3,
            compile_graph=False,
            state_path=Path(tmp) / "state.json",
            memory_path=Path(tmp) / "memory.sqlite3",
        )
        backend.register_trace(
            tag="dashboard-memory",
            embedding=backend.embed_text("SYNAPSE-S2 dashboard recalls local memory"),
            context_id="demo",
            source_text="SYNAPSE-S2 dashboard recalls local memory",
            metadata={"source": "unit-test"},
        )
        backend.ingest_text_events(
            text=(
                "Apple Silicon MLX compiles kernels into Metal. "
                "Sparse spiking recall reduces context pressure. "
                "Operators review graph relationships before approval."
            ),
            context_id="demo",
            source_tag="dashboard-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )
        return DashboardRuntime(backend)

    def decode(self, response):
        status, headers, body = response
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        return status, json.loads(body.decode("utf-8"))

    def test_snapshot_reports_status_profile_and_graph(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            status, payload = self.decode(
                runtime.handle("GET", "/api/snapshot?context_id=demo&limit=10")
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload["context_id"], "demo")
        self.assertEqual(payload["status"]["memory_context_entry_count"], 4)
        self.assertGreaterEqual(payload["graph"]["relationship_count"], 1)
        self.assertIn("estimated_total_mb", payload["profile"])

    def test_toggle_and_query_use_real_backend_state(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            toggle_status, toggle_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/toggle",
                    json.dumps({"context_id": "demo", "enabled": False}).encode(),
                )
            )
            query_status, query_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/query",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "prompt": "SYNAPSE-S2 dashboard recalls local memory",
                        }
                    ).encode(),
                )
            )

        self.assertEqual(toggle_status, 200)
        self.assertFalse(toggle_payload["effective_enabled"])
        self.assertEqual(query_status, 200)
        self.assertIn("disabled", query_payload["result"].lower())

    def test_profile_and_quick_prune_endpoints_report_budget(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            profile_status, profile_payload = self.decode(
                runtime.handle("GET", "/api/profile?benchmark_quick_prune=true")
            )
            prune_status, prune_payload = self.decode(
                runtime.handle("POST", "/api/quick-prune", b"{}")
            )

        self.assertEqual(profile_status, 200)
        self.assertTrue(profile_payload["quick_pruning"]["within_60ms_budget"])
        self.assertEqual(prune_status, 200)
        self.assertEqual(prune_payload["mode"], "quick-pruning")

    def test_static_paths_cannot_escape_web_root(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            status, payload = self.decode(runtime.handle("GET", "/../pyproject.toml"))

        self.assertEqual(status, 403)
        self.assertIn("escapes", payload["error"])

    def test_static_responses_include_browser_security_headers(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            status, headers, body = runtime.handle("GET", "/")

        self.assertEqual(status, 200)
        self.assertIn(b"SYNAPSE-S2 Control", body)
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_http_handler_rejects_cross_origin_mutations(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            server = SynapseDashboardServer(("127.0.0.1", 0), runtime)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/api/toggle"
                blocked_request = urllib.request.Request(
                    url,
                    data=json.dumps({"context_id": "demo", "enabled": False}).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": "https://example.invalid",
                    },
                    method="POST",
                )
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(blocked_request, timeout=10)
                allowed_request = urllib.request.Request(
                    url,
                    data=json.dumps({"context_id": "demo", "enabled": False}).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": f"http://127.0.0.1:{server.server_port}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(allowed_request, timeout=10) as response:
                    allowed_payload = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

        self.assertEqual(raised.exception.code, 403)
        self.assertFalse(allowed_payload["effective_enabled"])

    def test_remember_endpoint_persists_new_memory(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            remember_status, remember_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/remember",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "tag": "operator-note",
                            "text": "Tomorrow demo uses a live dashboard and MCP backend.",
                        }
                    ).encode(),
                )
            )
            recall = runtime.backend.query(
                runtime.backend.embed_text(
                    "Tomorrow demo uses a live dashboard and MCP backend."
                ),
                context_id="demo",
            )

        self.assertEqual(remember_status, 200)
        self.assertEqual(remember_payload["tag"], "operator-note")
        self.assertIn("operator-note", recall)


if __name__ == "__main__":
    unittest.main()

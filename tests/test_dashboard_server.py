import json
import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import urllib.error
import urllib.request

from dashboard_server import DEFAULT_CONTEXT, DashboardRuntime, SynapseDashboardServer
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
        self.assertEqual(payload["system"]["model_uri"], "s2://local/demo")
        self.assertEqual(payload["system"]["mode"], "LOCAL ONLY")
        self.assertIn("project_version", payload["system"])
        self.assertIn("uptime_seconds", payload["system"])
        self.assertIn("timings_ms", payload)
        self.assertGreaterEqual(payload["timings_ms"]["total"], 0)
        for stage in ("status", "profile", "graph", "system"):
            self.assertIn(stage, payload["timings_ms"])

    def test_snapshot_can_defer_graph_for_fast_hydration(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            status, payload = self.decode(
                runtime.handle("GET", "/api/snapshot?context_id=demo&limit=10&include_graph=false")
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload["context_id"], "demo")
        self.assertTrue(payload["graph"]["deferred"])
        self.assertEqual(payload["graph"]["entries"], [])
        self.assertEqual(payload["graph"]["relationships"], [])
        self.assertEqual(payload["graph"]["entry_count"], 4)
        self.assertGreaterEqual(payload["graph"]["relationship_count"], 1)
        self.assertEqual(payload["timings_ms"]["graph"], 0)
        self.assertIn("estimated_total_mb", payload["profile"])
        self.assertEqual(payload["system"]["model_uri"], "s2://local/demo")

    def test_snapshot_defaults_to_neutral_context(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            status, payload = self.decode(runtime.handle("GET", "/api/snapshot"))

        self.assertEqual(status, 200)
        self.assertEqual(DEFAULT_CONTEXT, "default")
        self.assertEqual(payload["context_id"], "default")

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
        self.assertIn("latency_ms", query_payload)
        self.assertIn("query_id", query_payload)
        self.assertEqual(query_payload["results"][0]["kind"], "status")

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

    def test_readiness_audit_endpoint_reports_actionable_checks(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            audit_status, audit_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/readiness-audit",
                    json.dumps({"context_id": "demo"}).encode(),
                )
            )

        self.assertEqual(audit_status, 200)
        self.assertEqual(audit_payload["context_id"], "demo")
        self.assertTrue(audit_payload["ready"])
        self.assertEqual(audit_payload["action"], "readiness-audit")
        self.assertIn("audit_id", audit_payload)
        self.assertGreaterEqual(audit_payload["elapsed_ms"], 0)
        self.assertTrue(audit_payload["checks"]["runtime_ready"])
        self.assertTrue(audit_payload["checks"]["mlx_ready"])
        self.assertTrue(audit_payload["checks"]["memory_ready"])
        self.assertTrue(audit_payload["checks"]["graph_ready"])
        self.assertIn("dashboard-memory", audit_payload["query_result"])

    def test_evidence_pack_endpoint_writes_local_report_and_backup(self):
        with TemporaryDirectory() as tmp:
            previous_export_dir = os.environ.get("SYNAPSE_S2_EXPORT_DIR")
            os.environ["SYNAPSE_S2_EXPORT_DIR"] = tmp
            try:
                runtime = self.make_runtime(tmp)

                pack_status, pack_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/evidence-pack",
                        json.dumps({"context_id": "demo"}).encode(),
                    )
                )
            finally:
                if previous_export_dir is None:
                    os.environ.pop("SYNAPSE_S2_EXPORT_DIR", None)
                else:
                    os.environ["SYNAPSE_S2_EXPORT_DIR"] = previous_export_dir

            report_path = Path(pack_payload["report_path"])
            backup_path = Path(pack_payload["backup"]["backup_path"])

            self.assertEqual(pack_status, 200)
            self.assertEqual(pack_payload["context_id"], "demo")
            self.assertEqual(pack_payload["action"], "evidence-pack")
            self.assertTrue(report_path.exists())
            self.assertTrue(backup_path.exists())
            self.assertEqual(report_path.parent, Path(tmp).resolve())
            self.assertIn("sha256", pack_payload)
            self.assertGreaterEqual(pack_payload["snapshot"]["graph"]["relationship_count"], 1)
            self.assertEqual(pack_payload["snapshot"]["status"]["runtime"], "ready")

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

    def test_dashboard_assets_do_not_seed_demo_or_auto_recall(self):
        root = Path(__file__).resolve().parents[1]
        index = (root / "web" / "index.html").read_text(encoding="utf-8")
        app = (root / "web" / "app.js").read_text(encoding="utf-8")
        styles = (root / "web" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("themeButton", index)
        self.assertIn("hydrateLabel", index)
        self.assertIn("runtimeHealthGrid", index)
        self.assertIn("operatorGuide", index)
        self.assertIn("recallGuide", index)
        self.assertIn("Local recall only", index)
        self.assertIn("query_spiking_attention_text", index)
        self.assertIn("readinessAuditButton", index)
        self.assertIn("evidencePackButton", index)
        self.assertIn("coreUnlockButton", index)
        self.assertIn("coreToggleGuardHint", index)
        self.assertIn("Locked. Press Unlock", index)
        self.assertIn("CORE_TOGGLE_UNLOCK_WINDOW_MS", app)
        self.assertIn("unlockCoreToggleGuard", app)
        self.assertIn("lockCoreToggleGuard", app)
        self.assertIn("data-section-target", index)
        self.assertIn("rememberForm", index)
        self.assertIn("ingestForm", index)
        self.assertIn("dataset.theme", app)
        self.assertIn("initializeSectionNavigation", app)
        self.assertIn("scrollSectionIntoView", app)
        self.assertIn("/api/readiness-audit", app)
        self.assertIn("/api/evidence-pack", app)
        self.assertIn('include_graph: "false"', app)
        self.assertIn('"/api/graph"', app)
        self.assertIn("graph.deferred", app)
        self.assertIn("data-theme", styles)
        self.assertIn("/api/remember", app)
        self.assertIn("/api/ingest", app)
        self.assertNotIn("board-demo", index)
        self.assertNotIn("board-demo", app)
        self.assertNotIn("durable real memory local SQLite substrate", index)
        self.assertNotIn('dispatchEvent(new Event("submit"', app)

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

    def test_ingest_endpoint_persists_events_and_relationships(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            ingest_status, ingest_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/ingest",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "tag": "ops-brief",
                            "text": (
                                "Battery telemetry exceeded limits during taxi. "
                                "Maintenance isolated the affected power channel. "
                                "The morning review needs traceable graph evidence."
                            ),
                            "surprise_threshold": 0.58,
                            "min_segment_sentences": 1,
                        }
                    ).encode(),
                )
            )
            snapshot_status, snapshot_payload = self.decode(
                runtime.handle("GET", "/api/snapshot?context_id=demo&limit=20")
            )

        self.assertEqual(ingest_status, 200)
        self.assertGreaterEqual(ingest_payload["event_count"], 2)
        self.assertGreaterEqual(ingest_payload["relationship_count"], 1)
        self.assertEqual(snapshot_status, 200)
        self.assertGreaterEqual(snapshot_payload["graph"]["relationship_count"], 1)
        self.assertEqual(
            snapshot_payload["graph"]["relationship_summary"]["total"],
            snapshot_payload["graph"]["relationship_count"],
        )
        self.assertGreaterEqual(
            snapshot_payload["graph"]["relationship_summary"]["temporal"],
            1,
        )
        self.assertTrue(
            any(
                entry["tag"].startswith("ops-brief-event")
                for entry in snapshot_payload["graph"]["entries"]
            )
        )


if __name__ == "__main__":
    unittest.main()

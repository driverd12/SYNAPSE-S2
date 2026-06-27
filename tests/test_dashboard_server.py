import json
import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import urllib.error
import urllib.request

from capture_daemon import write_capture_drop
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
                "Procurement reviews supplier contract exposure before approval. "
                "Operators prune sensitive graph relationships."
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
        self.assertEqual(payload["system"]["memory_uri"], "s2://local/demo")
        self.assertEqual(payload["system"]["model_uri"], "s2://local/demo")
        self.assertEqual(payload["system"]["substrate_label"], "SNN Memory Context")
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
        self.assertEqual(payload["system"]["memory_uri"], "s2://local/demo")

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

    def test_certify_runtime_endpoint_reports_native_evidence(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            certify_status, certify_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/certify-runtime",
                    json.dumps(
                        {
                            "strict_native": False,
                            "benchmark_quick_prune": True,
                        }
                    ).encode(),
                )
            )

        self.assertEqual(certify_status, 200)
        self.assertEqual(certify_payload["action"], "certify-runtime")
        self.assertIn("checks", certify_payload)
        self.assertIn("resource_profile", certify_payload)
        self.assertIn("quick_pruning", certify_payload["resource_profile"])

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

    def test_cortex_governor_endpoints_and_snapshot_state(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            enter_status, enter_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/enter",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-agent",
                            "task": "Govern dashboard operator work.",
                            "mode": "strict",
                        }
                    ).encode(),
                )
            )
            tick_status, tick_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/tick",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-agent",
                            "session_id": enter_payload["session_id"],
                            "observation": "Preparing a dashboard mutation.",
                            "proposed_action": "Edit UI and run tests.",
                            "intended_files": ["web/app.js", "dashboard_server.py"],
                            "intended_tools": ["node --check web/app.js"],
                            "mutation_intent": True,
                            "confidence": 0.39,
                        }
                    ).encode(),
                )
            )
            commit_status, commit_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/commit",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-agent",
                            "session_id": enter_payload["session_id"],
                            "trace_type": "decision",
                            "truth_posture": "operator-confirmed",
                            "text": "Dashboard exposes Cortex Governor state.",
                            "evidence": {"source": "unit-test"},
                        }
                    ).encode(),
                )
            )
            promote_status, promote_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/moderate",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "memory_id": commit_payload["memory_id"],
                            "action": "promote",
                            "reason": "dashboard operator verified",
                        }
                    ).encode(),
                )
            )
            state_status, state_payload = self.decode(
                runtime.handle("GET", "/api/cortex/state?context_id=demo&agent_id=dashboard-agent")
            )
            snapshot_status, snapshot_payload = self.decode(
                runtime.handle("GET", "/api/snapshot?context_id=demo&limit=10")
            )

        self.assertEqual(enter_status, 200)
        self.assertEqual(tick_status, 200)
        self.assertEqual(commit_status, 200)
        self.assertEqual(promote_status, 200)
        self.assertEqual(state_status, 200)
        self.assertEqual(snapshot_status, 200)
        self.assertEqual(enter_payload["action"], "enter-spiking-cortex")
        self.assertEqual(tick_payload["decision"], "verify-first")
        self.assertEqual(tick_payload["intended_files"], ["web/app.js", "dashboard_server.py"])
        self.assertEqual(tick_payload["intended_tools"], ["node --check web/app.js"])
        self.assertGreaterEqual(len(tick_payload["cortex_state"]["capture_queue"]), 1)
        self.assertEqual(commit_payload["trace_type"], "decision")
        self.assertEqual(promote_payload["moderation_action"], "promote")
        self.assertGreaterEqual(promote_payload["trace"]["confidence"], 0.9)
        self.assertGreaterEqual(state_payload["typed_memory_counts"]["decision"], 1)
        self.assertIn("suggested_next_move", state_payload)
        self.assertIn("capture_queue", state_payload)
        self.assertEqual(len(state_payload["capture_queue"]), 0)
        self.assertIn("cortex_state", snapshot_payload)
        self.assertGreaterEqual(
            snapshot_payload["cortex_state"]["typed_memory_counts"]["decision"],
            1,
        )

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
        self.assertIn("Memory URI", index)
        self.assertIn("Context bus", index)
        self.assertIn("Remember + publish", index)
        self.assertIn("Ingest + publish", index)
        self.assertIn("Capture conversation", index)
        self.assertIn("Magic Capture", index)
        self.assertIn("captureInboxButton", index)
        self.assertIn("captureInboxState", index)
        self.assertIn("App Connect", index)
        self.assertIn("appConnectButton", index)
        self.assertIn("appConnectForm", index)
        self.assertIn("appSnapshotButton", index)
        self.assertIn("Optimized operating range", index)
        self.assertIn("graph-prune-panel", index)
        self.assertIn("pruneForm", index)
        self.assertIn("relationshipLedger", index)
        self.assertIn("contextEventLedger", index)
        self.assertIn("neuralInspectorToggle", index)
        self.assertIn("neuralMathPanel", index)
        self.assertIn("cortexPanel", index)
        self.assertIn("Cortex Governor", index)
        self.assertIn("cortexIntendedFiles", index)
        self.assertIn("cortexIntendedTools", index)
        self.assertIn("cortexNextMove", index)
        self.assertIn("cortexCaptureQueue", index)
        self.assertIn("Sparse spike code", index)
        self.assertIn("Active neuron sample", index)
        self.assertIn("LIF update", index)
        self.assertIn("STDP update", index)
        self.assertIn("Locked. Press Unlock", index)
        self.assertIn("CORE_TOGGLE_UNLOCK_WINDOW_MS", app)
        self.assertIn("renderContextBus", app)
        self.assertIn("renderRelationshipLedger", app)
        self.assertIn("renderNeuralInspector", app)
        self.assertIn("renderCortexState", app)
        self.assertIn("splitIntentList", app)
        self.assertIn("renderCortexCaptureQueue", app)
        self.assertIn("/api/cortex/enter", app)
        self.assertIn("/api/cortex/tick", app)
        self.assertIn("/api/cortex/commit", app)
        self.assertIn("/api/cortex/moderate", app)
        self.assertIn("data-cortex-action", app)
        self.assertIn("moderateCortexTrace", app)
        self.assertIn("formatSpikeSubLabel", app)
        self.assertIn("contextMemoryType", app)
        self.assertIn("active coordinates", app)
        self.assertIn("projected neurons", app)
        self.assertIn("renderContextEventLedger", app)
        self.assertIn("pruneGraphItem", app)
        self.assertIn("captureForm", app)
        self.assertIn("renderCaptureInbox", app)
        self.assertIn("logSnapshotResponse", app)
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
        self.assertIn("namespace-node", styles)
        self.assertIn("objective-node", styles)
        self.assertIn('"/api/graph"', app)
        self.assertIn("graph.deferred", app)
        self.assertIn("data-theme", styles)
        self.assertIn("/api/remember", app)
        self.assertIn("/api/ingest", app)
        self.assertIn("/api/capture-conversation", app)
        self.assertIn("/api/prune-memory", app)
        self.assertIn("/api/capture-inbox", app)
        self.assertIn("/api/apps", app)
        self.assertIn("/api/app-connect", app)
        self.assertIn("/api/app-connections", app)
        self.assertIn("/api/app-snapshot", app)
        self.assertIn("renderAppConnect", app)
        self.assertIn("snapshotConnectedApp", app)
        self.assertIn("/api/context-events", app)
        self.assertIn("danger-button", styles)
        self.assertIn("app-connect-panel", styles)
        self.assertIn("neural-math-panel", styles)
        self.assertIn("neural-inspector-toggle", styles)
        self.assertIn("cortex-panel", styles)
        self.assertIn("cortex-memory-actions", styles)
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
        self.assertEqual(remember_payload["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertTrue(remember_payload["agent_deployment"]["published"])
        self.assertEqual(remember_payload["agent_deployment"]["event_type"], "remember-trace")
        self.assertEqual(remember_payload["agent_deployment"]["delivery_mode"], "durable-mcp-pull")
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
        self.assertTrue(ingest_payload["agent_deployment"]["published"])
        self.assertEqual(ingest_payload["agent_deployment"]["event_type"], "ingest-events")
        self.assertEqual(snapshot_status, 200)
        self.assertGreaterEqual(snapshot_payload["graph"]["relationship_count"], 1)
        self.assertGreaterEqual(
            snapshot_payload["status"]["context_bus_context_event_count"],
            1,
        )
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

    def test_capture_conversation_endpoint_publishes_visible_session_events(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            capture_status, capture_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/capture-conversation",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "source_tag": "codex-session",
                            "speaker": "codex",
                            "text": (
                                "User expects real conversation details in the graph. "
                                "Codex captures durable session events. "
                                "The memory graph should show these notes."
                            ),
                        }
                    ).encode(),
                )
            )
            graph_status, graph_payload = self.decode(
                runtime.handle("GET", "/api/graph?context_id=demo&limit=30")
            )

        self.assertEqual(capture_status, 200)
        self.assertGreaterEqual(capture_payload["event_count"], 2)
        self.assertIn("context_namespace", capture_payload)
        self.assertGreaterEqual(capture_payload["context_namespace"]["node_count"], 2)
        self.assertTrue(capture_payload["agent_deployment"]["published"])
        self.assertEqual(capture_payload["agent_deployment"]["event_type"], "conversation-capture")
        self.assertEqual(graph_status, 200)
        self.assertTrue(
            any(
                entry["metadata"].get("conversation_capture") is True
                for entry in graph_payload["entries"]
            )
        )
        self.assertTrue(
            any(
                entry["metadata"].get("context_automation") is True
                for entry in graph_payload["entries"]
            )
        )

    def test_prune_memory_endpoint_removes_single_nodes_edges_and_deployments(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            ingest_status, ingest_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/capture-conversation",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "source_tag": "bad-session",
                            "speaker": "user",
                            "text": (
                                "Sensitive event should be pruned. "
                                "Remaining event can stay available. "
                                "Shared terms create graph relationships."
                            ),
                        }
                    ).encode(),
                )
            )
            graph_status, graph_payload = self.decode(
                runtime.handle("GET", "/api/graph?context_id=demo&limit=30")
            )
            memory_id = next(
                entry["memory_id"]
                for entry in graph_payload["entries"]
                if entry["tag"].startswith("bad-session-event")
            )
            relationship_id = graph_payload["relationships"][0]["relationship_id"]
            deployment_id = ingest_payload["agent_deployment"]["event_id"]

            edge_status, edge_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/prune-memory",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "target_type": "relationship",
                            "relationship_id": relationship_id,
                            "confirm": True,
                            "reason": "bad edge",
                        }
                    ).encode(),
                )
            )
            node_status, node_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/prune-memory",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "target_type": "event",
                            "memory_id": memory_id,
                            "confirm": True,
                            "reason": "bad node",
                        }
                    ).encode(),
                )
            )
            deployment_status, deployment_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/prune-memory",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "target_type": "context_event",
                            "event_id": deployment_id,
                            "confirm": True,
                            "reason": "bad deployment",
                        }
                    ).encode(),
                )
            )
            final_graph_status, final_graph = self.decode(
                runtime.handle("GET", "/api/graph?context_id=demo&limit=30")
            )

        self.assertEqual(ingest_status, 200)
        self.assertEqual(graph_status, 200)
        self.assertEqual(edge_status, 200)
        self.assertEqual(edge_payload["target_type"], "relationship")
        self.assertTrue(edge_payload["result"]["deleted"])
        self.assertEqual(node_status, 200)
        self.assertTrue(node_payload["result"]["deleted"])
        self.assertEqual(deployment_status, 200)
        self.assertTrue(deployment_payload["result"]["deleted"])
        self.assertEqual(final_graph_status, 200)
        self.assertNotIn(memory_id, [entry["memory_id"] for entry in final_graph["entries"]])

    def test_prune_memory_endpoint_requires_explicit_confirmation(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            graph_status, graph_payload = self.decode(
                runtime.handle("GET", "/api/graph?context_id=demo&limit=30")
            )
            relationship_id = graph_payload["relationships"][0]["relationship_id"]

            prune_status, prune_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/prune-memory",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "target_type": "relationship",
                            "relationship_id": relationship_id,
                            "confirm": False,
                        }
                    ).encode(),
                )
            )

        self.assertEqual(graph_status, 200)
        self.assertEqual(prune_status, 400)
        self.assertIn("confirm", prune_payload["error"])

    def test_capture_inbox_status_and_process_endpoint_ingests_pending_payload(self):
        with TemporaryDirectory() as tmp:
            previous_root = os.environ.get("SYNAPSE_S2_CAPTURE_ROOT")
            os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = tmp
            try:
                runtime = self.make_runtime(tmp)
                write_capture_drop(
                    root=tmp,
                    context_id="demo",
                    source_tag="dashboard-magic",
                    speaker="codex",
                    text="Dashboard capture inbox should process this dropped payload.",
                )

                status_before, payload_before = self.decode(
                    runtime.handle("GET", "/api/capture-inbox")
                )
                process_status, process_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/capture-inbox/process",
                        json.dumps({"context_id": "demo"}).encode(),
                    )
                )
                graph_status, graph_payload = self.decode(
                    runtime.handle("GET", "/api/graph?context_id=demo&limit=30")
                )
            finally:
                if previous_root is None:
                    os.environ.pop("SYNAPSE_S2_CAPTURE_ROOT", None)
                else:
                    os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = previous_root

        self.assertEqual(status_before, 200)
        self.assertEqual(payload_before["pending_file_count"], 1)
        self.assertEqual(process_status, 200)
        self.assertEqual(process_payload["processed_file_count"], 1)
        self.assertEqual(graph_status, 200)
        self.assertTrue(
            any(
                entry["tag"].startswith("dashboard-magic-event")
                for entry in graph_payload["entries"]
            )
        )

    def test_app_connect_endpoint_registers_manual_local_app_connection(self):
        with TemporaryDirectory() as tmp:
            previous_root = os.environ.get("SYNAPSE_S2_CAPTURE_ROOT")
            os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = tmp
            try:
                runtime = self.make_runtime(tmp)
                connect_status, connect_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/app-connect",
                        json.dumps(
                            {
                                "context_id": "demo",
                                "app_name": "Codex IDE",
                                "bundle_id": "com.openai.codex",
                                "pid": 4242,
                                "source_tag": "codex-ide",
                                "speaker": "codex",
                                "confirm": True,
                                "allow_manual": True,
                            }
                        ).encode(),
                    )
                )
                list_status, list_payload = self.decode(
                    runtime.handle("GET", "/api/app-connections")
                )
            finally:
                if previous_root is None:
                    os.environ.pop("SYNAPSE_S2_CAPTURE_ROOT", None)
                else:
                    os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = previous_root

        self.assertEqual(connect_status, 200)
        self.assertEqual(connect_payload["app_name"], "Codex IDE")
        self.assertEqual(connect_payload["bundle_id"], "com.openai.codex")
        self.assertEqual(list_status, 200)
        self.assertEqual(list_payload["connection_count"], 1)
        self.assertEqual(list_payload["connections"][0]["source_tag"], "codex-ide")

    def test_context_events_endpoint_lists_published_agent_handoffs(self):
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
                            "text": "Publish this context for connected MCP clients.",
                        }
                    ).encode(),
                )
            )
            event_id = remember_payload["agent_deployment"]["event_id"]

            list_status, list_payload = self.decode(
                runtime.handle("GET", "/api/context-events?context_id=demo&limit=5")
            )
            since_status, since_payload = self.decode(
                runtime.handle(
                    f"GET",
                    f"/api/context-events?context_id=demo&since_event_id={event_id}&limit=5",
                )
            )
            ack_status, ack_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/context-ack",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-ui",
                            "last_event_id": event_id,
                        }
                    ).encode(),
                )
            )
            cursor_status, cursor_payload = self.decode(
                runtime.handle("GET", "/api/context-cursors?context_id=demo")
            )

        self.assertEqual(remember_status, 200)
        self.assertEqual(list_status, 200)
        self.assertEqual(list_payload["events"][-1]["event_id"], event_id)
        self.assertEqual(list_payload["events"][-1]["payload"]["tag"], "operator-note")
        self.assertEqual(since_status, 200)
        self.assertEqual(since_payload["events"], [])
        self.assertEqual(ack_status, 200)
        self.assertEqual(ack_payload["agent_id"], "dashboard-ui")
        self.assertEqual(ack_payload["pending_event_count"], 0)
        self.assertEqual(cursor_status, 200)
        self.assertEqual(cursor_payload["cursors"][0]["agent_id"], "dashboard-ui")


if __name__ == "__main__":
    unittest.main()

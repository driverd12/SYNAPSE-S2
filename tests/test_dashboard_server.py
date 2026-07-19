import hashlib
import json
import os
import threading
import unittest
from contextlib import closing
from http.server import HTTPServer, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
import urllib.error
import urllib.request
from unittest import mock

from capture_daemon import write_capture_drop
from dashboard_server import DEFAULT_CONTEXT, DashboardRuntime, SynapseDashboardServer, main
from mlx_backend import SpikingAttentionBackend
from transcript_capture import TranscriptCaptureManager


class DashboardRuntimeTests(unittest.TestCase):
    def test_dashboard_server_preserves_single_threaded_mlx_affinity(self):
        self.assertTrue(issubclass(SynapseDashboardServer, HTTPServer))
        self.assertFalse(issubclass(SynapseDashboardServer, ThreadingHTTPServer))

    def test_doctor_global_audit_detects_corruption_outside_active_namespace(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            other = runtime.backend.register_trace(
                tag="other-namespace-memory",
                embedding=runtime.backend.embed_text("Other namespace integrity"),
                context_id="other",
                source_text="Other namespace integrity",
                metadata={},
            )
            import sqlite3

            with closing(sqlite3.connect(Path(tmp) / "memory.sqlite3")) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ?",
                    (other["memory_id"],),
                )
                conn.commit()
            payload = runtime.doctor_report(
                context_id="demo",
                include_apps=False,
                wait_for_semantic_audit=True,
            )

        semantic = next(
            check for check in payload["checks"] if check["id"] == "semantic_indexes"
        )
        self.assertEqual(semantic["status"], "degraded")
        self.assertIn("all namespaces", semantic["detail"])
        self.assertIn("1 mismatched", semantic["detail"])

    def test_dashboard_doctor_returns_pending_while_global_audit_runs_in_background(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            started = threading.Event()
            release = threading.Event()
            finished = threading.Event()
            waiter_started = threading.Event()
            waiter_finished = threading.Event()
            waiter_payload: dict[str, object] = {}
            original = runtime.backend.memory_store.audit_semantic_indexes

            def delayed_audit(*args, **kwargs):
                started.set()
                release.wait(timeout=2.0)
                try:
                    return original(*args, **kwargs)
                finally:
                    finished.set()

            def wait_for_current_audit() -> None:
                waiter_started.set()
                waiter_payload.update(runtime._semantic_audit_health(wait=True))
                waiter_finished.set()

            with mock.patch.object(
                runtime.backend.memory_store,
                "audit_semantic_indexes",
                side_effect=delayed_audit,
            ) as audit_mock:
                first = runtime.doctor_report(
                    context_id="demo",
                    include_apps=False,
                )
                self.assertTrue(started.wait(timeout=1.0))
                first_semantic = next(
                    check
                    for check in first["checks"]
                    if check["id"] == "semantic_indexes"
                )
                self.assertEqual(first_semantic["status"], "degraded")
                self.assertIn("pending True", first_semantic["detail"])
                waiter = threading.Thread(
                    target=wait_for_current_audit,
                    daemon=True,
                )
                waiter.start()
                self.assertTrue(waiter_started.wait(timeout=1.0))
                self.assertFalse(waiter_finished.is_set())
                release.set()
                self.assertTrue(finished.wait(timeout=2.0))
                self.assertTrue(waiter_finished.wait(timeout=2.0))
                waiter.join(timeout=2.0)
                self.assertEqual(audit_mock.call_count, 1)
                self.assertEqual(waiter_payload.get("status"), "ready")
                second = runtime.doctor_report(
                    context_id="demo",
                    include_apps=False,
                )

            second_semantic = next(
                check
                for check in second["checks"]
                if check["id"] == "semantic_indexes"
            )
            self.assertEqual(second_semantic["status"], "ready")
            self.assertIn("pending False", second_semantic["detail"])

    def test_dashboard_doctor_surfaces_ack_tombstone_count(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            event = runtime.backend.publish_context_event(
                context_id="demo",
                source_surface="dashboard-test",
                event_type="tombstone-doctor",
                summary="doctor retains acknowledgement evidence after pruning",
                agent_targets=["dashboard-ui"],
            )
            delivery = runtime.backend.lease_context_events(
                context_id="demo",
                agent_id="dashboard-ui",
                consumer_instance_id="dashboard-doctor-test",
                limit=1,
            )["deliveries"][0]
            runtime.backend.ack_context_events(
                context_id="demo",
                agent_id="dashboard-ui",
                receipt_id=delivery["receipt_id"],
            )
            runtime.backend.memory_store.delete_context_event(
                context_id="demo",
                event_id=event["event_id"],
            )

            payload = runtime.doctor_report(
                context_id="demo",
                include_apps=False,
                wait_for_semantic_audit=True,
            )

        delivery_check = next(
            check for check in payload["checks"] if check["id"] == "context_delivery"
        )
        self.assertEqual(delivery_check["status"], "ready")
        self.assertIn("1 ACK tombstones", delivery_check["detail"])

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
        self.assertTrue(payload["system"]["model_uri"].startswith("embedding://"))
        self.assertIn("embedding_model_id", payload["system"])
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
        self.assertEqual(query_payload["diagnostics"]["runtime"], "disabled")
        self.assertIn("memory_entry_revision", query_payload["diagnostics"])
        self.assertEqual(query_payload["results"][0]["kind"], "status")

    def test_query_defaults_to_local_scope_and_rejects_unknown_scope(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            local_status, local_payload = self.decode(
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
            invalid_status, invalid_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/query",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "prompt": "SYNAPSE-S2 dashboard recalls local memory",
                            "recall_scope": "unbounded",
                        }
                    ).encode(),
                )
            )

        self.assertEqual(local_status, 200)
        self.assertEqual(local_payload["recall_scope"], "local")
        self.assertEqual(local_payload["diagnostics"]["recall_scope"], "local")
        self.assertEqual(invalid_status, 400)
        self.assertEqual(
            invalid_payload["error"],
            "recall_scope must be local, connected, or all",
        )

    def test_namespace_map_and_confirmed_link_api(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            runtime.backend.register_trace(
                tag="linked-memory",
                embedding=runtime.backend.embed_text(
                    "SYNAPSE-S2 dashboard recalls related camera work"
                ),
                context_id="camera-work",
                source_text="SYNAPSE-S2 dashboard recalls related camera work",
                metadata={"source": "unit-test"},
            )

            map_status, map_payload = self.decode(
                runtime.handle("GET", "/api/namespace-map?context_id=demo")
            )
            refused_status, refused_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/namespace-links",
                    json.dumps(
                        {
                            "source_context_id": "demo",
                            "target_context_id": "camera-work",
                            "relation_type": "related",
                            "confirm": False,
                        }
                    ).encode(),
                )
            )
            approved_status, approved_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/namespace-links",
                    json.dumps(
                        {
                            "source_context_id": "demo",
                            "target_context_id": "camera-work",
                            "relation_type": "related",
                            "weight": 0.8,
                            "evidence": {"source": "dashboard-unit-test"},
                            "confirm": True,
                        }
                    ).encode(),
                )
            )
            connected_status, connected_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/query",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "prompt": "related camera work",
                            "recall_scope": "connected",
                        }
                    ).encode(),
                )
            )
            linked_status, linked_payload = self.decode(
                runtime.handle("GET", "/api/namespace-map?context_id=demo")
            )

        self.assertEqual(map_status, 200)
        self.assertEqual(map_payload["scope"], "all")
        self.assertEqual(map_payload["selected_context_id"], "demo")
        self.assertEqual(
            {node["context_id"] for node in map_payload["nodes"]},
            {"camera-work", "demo"},
        )
        self.assertEqual(refused_status, 400)
        self.assertEqual(
            refused_payload["error"],
            "confirm=true is required to approve a namespace link",
        )
        self.assertEqual(approved_status, 200)
        self.assertTrue(approved_payload["approved"])
        self.assertFalse(approved_payload["automatic_cross_namespace_write"])
        self.assertEqual(approved_payload["link"]["recall_hops"], 1)
        self.assertEqual(connected_status, 200)
        self.assertEqual(
            set(connected_payload["diagnostics"]["effective_context_ids"]),
            {"camera-work", "demo", "global"},
        )
        self.assertEqual(
            set(
                connected_payload["diagnostics"]["memory_entry_revision"][
                    "context_ids"
                ]
            ),
            {"camera-work", "demo", "global"},
        )
        camera_result = next(
            result
            for result in connected_payload["results"]
            if result.get("context_id") == "camera-work"
        )
        self.assertEqual(camera_result["recall_scope"], "connected")
        self.assertEqual(camera_result["recall_provenance"], "connected")
        self.assertTrue(camera_result["via_context_link_id"])
        self.assertEqual(linked_status, 200)
        self.assertEqual(linked_payload["link_count"], 1)
        self.assertIn("camera-work", linked_payload["nodes"][0]["connected_context_ids"])
        linked_nodes = {
            node["context_id"]: node for node in linked_payload["nodes"]
        }
        self.assertEqual(linked_nodes["demo"]["entry_count"], 4)
        self.assertEqual(linked_nodes["demo"]["relationship_count"], 2)
        self.assertGreater(
            linked_nodes["demo"]["surface_term_count"],
            linked_nodes["demo"]["entry_count"],
        )
        self.assertEqual(linked_nodes["camera-work"]["entry_count"], 1)
        self.assertEqual(linked_nodes["camera-work"]["relationship_count"], 0)
        self.assertGreater(
            linked_nodes["camera-work"]["surface_term_count"],
            linked_nodes["camera-work"]["entry_count"],
        )
        linked_bridge = linked_payload["links"][0]
        self.assertEqual(
            {
                linked_bridge["source_context_id"],
                linked_bridge["target_context_id"],
            },
            {"demo", "camera-work"},
        )
        self.assertEqual(linked_bridge["weight"], 0.8)
        self.assertTrue(linked_bridge["approved"])
        self.assertTrue(linked_bridge["enabled"])
        self.assertEqual(linked_bridge["direction"], "bidirectional")

    def test_api_errors_hide_internal_details_by_default(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            def fail_query(*args, **kwargs):
                raise RuntimeError("internal path /tmp/secret should stay in logs only")

            runtime.backend.query_text = fail_query  # type: ignore[method-assign]
            status, payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/query",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "prompt": "trigger failure",
                        }
                    ).encode(),
                )
            )

        self.assertEqual(status, 500)
        self.assertEqual(payload["error"], "dashboard request failed")
        self.assertIn("error_id", payload)
        self.assertNotIn("detail", payload)

    def test_main_refuses_non_loopback_dashboard_bind_without_override(self):
        previous = os.environ.get("SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD")
        os.environ.pop("SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD", None)
        try:
            status = main(["--host", "0.0.0.0", "--port", "0"])
        finally:
            if previous is None:
                os.environ.pop("SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD", None)
            else:
                os.environ["SYNAPSE_S2_ALLOW_NON_LOOPBACK_DASHBOARD"] = previous

        self.assertEqual(status, 2)

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

    def test_namespace_detail_endpoint_validates_and_preserves_bounded_projection(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            runtime.backend.register_text_trace(
                tag="dashboard-detail-objective",
                text="Objective adds another visible ganglion.",
                context_id="demo",
                metadata={"context_memory_type": "objective"},
            )
            detail_status, detail_payload = self.decode(
                runtime.handle(
                    "GET",
                    "/api/namespace-detail?context_id=demo&level=neurons&limit=1",
                )
            )
            selected_cluster_id = detail_payload["clusters"][0]["cluster_id"]
            selected_status, selected_payload = self.decode(
                runtime.handle(
                    "GET",
                    (
                        "/api/namespace-detail?context_id=demo&level=neurons"
                        f"&cluster_id={selected_cluster_id}&limit=20"
                    ),
                )
            )
            invalid_status, invalid_payload = self.decode(
                runtime.handle(
                    "GET",
                    "/api/namespace-detail?context_id=demo&level=unbounded",
                )
            )
            oversized_status, oversized_payload = self.decode(
                runtime.handle(
                    "GET",
                    "/api/namespace-detail?context_id=demo&cluster_id=" + ("x" * 129),
                )
            )

        self.assertEqual(detail_status, 200)
        self.assertTrue(detail_payload["read_only"])
        self.assertFalse(detail_payload["automatic_cross_namespace_write"])
        self.assertEqual(detail_payload["level"], "neurons")
        self.assertEqual(detail_payload["counts"]["returned_nodes"], 1)
        self.assertGreaterEqual(detail_payload["counts"]["returned_clusters"], 2)
        self.assertTrue(detail_payload["truncation"]["nodes"]["truncated"])
        self.assertEqual(selected_status, 200)
        self.assertEqual(selected_payload["selected_cluster_id"], selected_cluster_id)
        self.assertEqual(selected_payload["counts"]["eligible_clusters"], 1)
        self.assertEqual(
            {node["cluster_id"] for node in selected_payload["nodes"]},
            {selected_cluster_id},
        )
        self.assertEqual(invalid_status, 400)
        self.assertEqual(invalid_payload["error"], "level must be cortex, ganglion, or neurons")
        self.assertEqual(oversized_status, 413)
        self.assertEqual(oversized_payload["error"], "cluster_id is too large")

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
            close_status, close_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/close",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-agent",
                            "session_id": enter_payload["session_id"],
                            "reason": "unit-test-complete",
                        }
                    ).encode(),
                )
            )
            closed_state_status, closed_state_payload = self.decode(
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
        self.assertEqual(close_status, 200)
        self.assertEqual(closed_state_status, 200)
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
        self.assertEqual(state_payload["active_session_count"], 1)
        self.assertIn("suggested_next_move", state_payload)
        self.assertIn("capture_queue", state_payload)
        self.assertEqual(len(state_payload["capture_queue"]), 0)
        self.assertEqual(close_payload["action"], "close-spiking-cortex")
        self.assertEqual(close_payload["status"], "closed")
        self.assertEqual(close_payload["cortex_state"]["active_session_count"], 0)
        self.assertEqual(closed_state_payload["active_session_count"], 0)
        self.assertIn("cortex_state", snapshot_payload)
        self.assertGreaterEqual(
            snapshot_payload["cortex_state"]["typed_memory_counts"]["decision"],
            1,
        )

    def test_cortex_prune_endpoint_requires_explicit_confirmation(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            commit_status, commit_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/commit",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-agent",
                            "session_id": "moderation-session",
                            "trace_type": "assumption",
                            "truth_posture": "inferred",
                            "text": "Dashboard Cortex prune should require explicit confirmation.",
                            "confidence": 0.42,
                        }
                    ).encode(),
                )
            )
            rejected_status, rejected_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/moderate",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "memory_id": commit_payload["memory_id"],
                            "action": "prune",
                            "reason": "missing confirmation",
                            "confirm": False,
                        }
                    ).encode(),
                )
            )
            accepted_status, accepted_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/cortex/moderate",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "memory_id": commit_payload["memory_id"],
                            "action": "prune",
                            "reason": "confirmed removal",
                            "confirm": True,
                        }
                    ).encode(),
                )
            )

        self.assertEqual(commit_status, 200)
        self.assertEqual(rejected_status, 400)
        self.assertIn("confirm", rejected_payload["error"])
        self.assertEqual(accepted_status, 200)
        self.assertTrue(accepted_payload["prune"]["result"]["deleted"])

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
        self.assertIn("brand-copy", index)
        self.assertIn("runtime-build-line", index)
        self.assertNotIn('<span>S2 Core</span>\n            <strong id="coreVersion">', index)
        self.assertIn("hydrateLabel", index)
        self.assertIn("runtimeHealthGrid", index)
        self.assertIn("operatorGuide", index)
        self.assertIn("recallGuide", index)
        self.assertIn("Local uses this namespace plus global memory", index)
        self.assertIn("Connected adds approved one-hop bridges", index)
        self.assertIn("query_spiking_attention_text", index)
        self.assertIn("readinessAuditButton", index)
        self.assertIn("mondayReadinessButton", index)
        self.assertIn("connectionStatusCard", index)
        self.assertIn("contextSelect", index)
        self.assertIn("contextMenuList", index)
        self.assertIn("Choose existing memory context", index)
        self.assertIn("Loading saved contexts", index)
        self.assertIn("Saved namespaces", index)
        self.assertIn("wizardToggleButton", index)
        self.assertIn("wizardLayer", index)
        self.assertIn("wizardSpotlight", index)
        self.assertIn("wizardArrow", index)
        self.assertIn("wizardPanel", index)
        self.assertIn("wizardEyebrow", index)
        self.assertIn("wizardFlowPicker", index)
        self.assertIn("wizardIntroFlowButton", index)
        self.assertIn("wizardOperatorFlowButton", index)
        self.assertIn("wizardChecklist", index)
        self.assertIn("First-time orientation", index)
        self.assertIn("Operator use", index)
        self.assertIn("Skip the tour and walk through the required fields", index)
        self.assertIn("operatorLoopPanel", index)
        self.assertIn("operatorActionBanner", index)
        self.assertIn("operatorActionStatus", index)
        self.assertIn("operatorActionTitle", index)
        self.assertIn("Start governed work before risky actions", index)
        self.assertIn("Tick Action", index)
        self.assertIn("Start Work", index)
        self.assertIn("Wrap Session", index)
        self.assertIn("Doctor / Repair", index)
        self.assertIn("Context Health", index)
        self.assertIn("Memory Hygiene", index)
        self.assertIn("Recipes", index)
        self.assertIn("recipesToggleButton", index)
        self.assertIn("recipeDrawer", index)
        self.assertIn("goalsPanel", index)
        self.assertIn("Goal Ledger", index)
        self.assertIn("Memory Quality", index)
        self.assertIn("startWorkButton", index)
        self.assertIn("wrapSessionButton", index)
        self.assertIn("doctorReportButton", index)
        self.assertIn("memoryHygieneButton", index)
        self.assertIn("contextHealthButton", index)
        self.assertIn("selfTestButton", index)
        self.assertIn("selfTestState", index)
        self.assertIn("selfTestGrid", index)
        self.assertIn("coreStateIndicator", index)
        self.assertIn("core-status-badge", index)
        self.assertIn("core-status-dot", index)
        self.assertNotIn("switch-track", index)
        self.assertNotIn('id="toggleButton"', index)
        self.assertIn("coreActionGroup", index)
        self.assertIn("reliabilityActionGroup", index)
        self.assertIn("intakeActionGroup", index)
        self.assertIn("memoryMaintenanceActionGroup", index)
        self.assertIn("Reliability checks", index)
        self.assertIn("Local intake", index)
        self.assertIn("Memory maintenance", index)
        self.assertIn("locally exposed Accessibility text", index)
        self.assertIn("selected-text capture remains the exact-content fallback", index)
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
        self.assertIn("appPreviewButton", index)
        self.assertIn("appPreviewReceipt", index)
        self.assertIn("appSnapshotButton", index)
        self.assertIn("appSelectionText", index)
        self.assertIn("appSelectionCaptureButton", index)
        self.assertIn("Optimized operating range", index)
        self.assertIn("graph-prune-panel", index)
        self.assertIn("pruneForm", index)
        self.assertIn("relationshipLedger", index)
        self.assertIn("contextEventLedger", index)
        self.assertIn("neuralInspectorToggle", index)
        self.assertIn("neuralMathPanel", index)
        self.assertIn("cortexPanel", index)
        self.assertIn("Cortex Governor", index)
        self.assertIn("cortexSessionCallout", index)
        self.assertIn("Cortex is idle, not broken", index)
        self.assertIn("Start Cortex Session", index)
        self.assertIn("cortexCloseButton", index)
        self.assertIn("cortexCloseText", index)
        self.assertIn("No Session", index)
        self.assertIn("Commit / Wrap / End", index)
        self.assertNotIn("no active session", index)
        self.assertNotIn("Enter + hydrate", index)
        self.assertIn("cortexIntendedFiles", index)
        self.assertIn("cortexIntendedTools", index)
        self.assertIn("cortexNextMove", index)
        self.assertIn("cortexCaptureQueue", index)
        self.assertIn('<option value="evidence">evidence</option>', index)
        self.assertIn('<option value="observed" selected>observed</option>', index)
        self.assertNotIn('<option value="test-validated" selected>', index)
        self.assertIn("Sparse spike code", index)
        self.assertIn("Active neuron sample", index)
        self.assertIn("LIF update", index)
        self.assertIn("STDP update", index)
        self.assertIn("Locked. Press Unlock", index)
        self.assertIn("CORE_TOGGLE_UNLOCK_WINDOW_MS", app)
        self.assertIn("renderContextBus", app)
        self.assertIn("renderRelationshipLedger", app)
        self.assertIn("renderNeuralInspector", app)
        self.assertIn("semantic_facets", app)
        self.assertIn("graphNodeTitle", app)
        self.assertIn("relationship.source_label", app)
        self.assertIn("renderCortexState", app)
        self.assertIn("renderOperatorActionBanner", app)
        self.assertIn("operatorActionBanner", app)
        self.assertIn("Cortex is idle, which is normal before work starts", app)
        self.assertIn("Start Cortex Session before risky work", app)
        self.assertIn("End Session", app)
        self.assertIn("splitIntentList", app)
        self.assertIn("renderCortexCaptureQueue", app)
        self.assertIn("closeCortexSession", app)
        self.assertIn("/api/cortex/enter", app)
        self.assertIn("/api/cortex/tick", app)
        self.assertIn("/api/cortex/close", app)
        self.assertIn("/api/cortex/commit", app)
        self.assertIn("/api/cortex/moderate", app)
        self.assertIn("data-cortex-action", app)
        self.assertIn("moderateCortexTrace", app)
        self.assertIn('confirm: action === "prune"', app)
        self.assertIn("formatSpikeSubLabel", app)
        self.assertIn("contextMemoryType", app)
        self.assertIn("active coordinates", app)
        self.assertIn("projected neurons", app)
        self.assertIn("renderContextEventLedger", app)
        self.assertIn("pinRecallMemory", app)
        self.assertIn("/api/pin-memory", app)
        self.assertIn("data-recall-action", app)
        self.assertIn("pruneGraphItem", app)
        self.assertIn("captureForm", app)
        self.assertIn("renderCaptureInbox", app)
        self.assertIn("logSnapshotResponse", app)
        self.assertIn("unlockCoreToggleGuard", app)
        self.assertIn("lockCoreToggleGuard", app)
        self.assertIn("elements.toggleActionState.textContent = nextAction", app)
        self.assertIn("/api/monday-readiness", app)
        self.assertIn("renderMondayReadiness", app)
        self.assertIn("WIZARD_FLOWS", app)
        self.assertIn("WIZARD_STEPS", app)
        self.assertIn("intro: {", app)
        self.assertIn("operator: {", app)
        self.assertIn("startWizardFlow", app)
        self.assertIn("renderWizardChoice", app)
        self.assertIn("currentWizardSteps", app)
        self.assertIn("Choose a flow", app)
        self.assertIn("Start orientation", app)
        self.assertIn('progressLabel: "Operator"', app)
        self.assertIn("Required field: current task", app)
        self.assertIn("Required tick field: observation", app)
        self.assertIn("Required tick field: proposed action", app)
        self.assertIn("runStartWork", app)
        self.assertIn("function renderStartWorkDurableEvents(agentBrief)", app)
        self.assertIn('eventRow.dataset.startWorkEventId = String(eventId || "unknown")', app)
        self.assertIn("event?.event_type", app)
        self.assertIn("event?.source_surface", app)
        self.assertIn("event?.summary", app)
        self.assertIn("deliveryReceiptId === eventReceiptId", app)
        self.assertIn(
            "const isMeaningful = Boolean(eventId > 0 && eventType && sourceSurface && summary)",
            app,
        )
        self.assertIn("More durable events remain", app)
        self.assertIn("const renderedReceiptIds = renderStartWork(payload)", app)
        self.assertIn("await waitForStartWorkPaint()", app)
        self.assertIn(
            "requestAnimationFrame(() => requestAnimationFrame(resolve))",
            app,
        )
        self.assertIn(
            '"dashboard-ui",\n        payload.context_id,',
            app,
        )
        self.assertIn("context_id: contextId", app)
        self.assertNotIn(
            "const receiptIds = (payload.agent_brief?.deliveries || [])",
            app,
        )
        self.assertIn("runWrapSession", app)
        self.assertIn("runDoctorReport", app)
        self.assertIn("runContextHealth", app)
        self.assertIn("runMemoryHygiene", app)
        self.assertIn("renderOperationReceipt", app)
        self.assertIn("renderGoalLedger", app)
        self.assertIn("renderRecipeDrawer", app)
        self.assertIn("Why this matched", app)
        self.assertIn("data-recall-action=\"promote\"", app)
        self.assertIn("data-recall-action=\"demote\"", app)
        self.assertIn("data-recall-action=\"prune\"", app)
        self.assertIn("Use this memory now", app)
        self.assertIn("previewConnectedAppSnapshot", app)
        self.assertIn("/api/start-work", app)
        self.assertIn("/api/wrap-session/preview", app)
        self.assertIn("/api/wrap-session", app)
        self.assertIn("/api/context-health", app)
        self.assertIn("/api/memory-hygiene", app)
        self.assertIn("/api/doctor", app)
        self.assertIn("/api/app-snapshot/preview", app)
        self.assertIn("startWizard", app)
        self.assertIn("stopWizard", app)
        self.assertIn("renderWizardStep", app)
        self.assertIn("positionWizardOverlay", app)
        self.assertIn("wizard-highlight-target", app)
        self.assertIn("real local state", app)
        for selector in (
            "#wizardToggleButton",
            "#modelUri",
            "#operatorActionBanner",
            "#operatorLoopPanel",
            "#mondayReadinessButton",
            "#contextSelect",
            "#startWorkButton",
            "#cortexAgentId",
            "#cortexTask",
            "#cortexEnterForm",
            "#cortexObservation",
            "#cortexProposedAction",
            "#cortexIntendedFiles",
            "#cortexConfidence",
            "#cortexTickForm",
            "#cortexTraceText",
            "#wrapSessionButton",
            "#coreActionGroup",
            "#rememberForm",
            "#queryForm",
            "#appConnect",
            "#cortexPanel",
            "#memory",
            ".graph-prune-panel",
            "#evidencePackButton",
            "#operationLog",
        ):
            self.assertIn(selector, app)
        self.assertNotIn("toggleButton.addEventListener", app)
        self.assertNotIn("elements.toggleButton.disabled", app)
        self.assertIn("elements.coreStateIndicator", app)
        self.assertIn("state.coreToggle.enabled", app)
        self.assertIn("locally exposed Accessibility text", app)
        self.assertIn("selected-text fallback for exact content", app)
        self.assertIn("data-section-target", index)
        self.assertIn("rememberForm", index)
        self.assertIn("ingestForm", index)
        self.assertIn("dataset.theme", app)
        self.assertIn("renderContextSelector", app)
        self.assertIn("applySelectedContext", app)
        self.assertIn("context-choice-button", app)
        self.assertIn("contextMenuList.addEventListener", app)
        self.assertIn("status.memory_contexts", app)
        self.assertIn('synapse-s2-control-theme-v4', app)
        self.assertIn('stored : "dark"', app)
        self.assertIn("initializeSectionNavigation", app)
        self.assertIn("scrollSectionIntoView", app)
        self.assertIn("/api/readiness-audit", app)
        self.assertIn("/api/self-test", app)
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
        self.assertIn("/api/capture-inbox/preflight", app)
        self.assertIn("/api/apps", app)
        self.assertIn("/api/app-connect", app)
        self.assertIn("/api/app-connect/preflight", app)
        self.assertIn("/api/app-connections", app)
        self.assertIn("/api/app-snapshot", app)
        self.assertIn("/api/app-snapshot/preflight", app)
        self.assertIn("/api/app-selection-capture", app)
        self.assertIn("confirmation_token", app)
        self.assertIn("confirmPreflight", app)
        self.assertIn("renderAppConnect", app)
        self.assertIn("snapshotConnectedApp", app)
        self.assertIn("captureSelectedAppText", app)
        self.assertIn("window.crypto.getRandomValues", app)
        self.assertIn("captureRetries: new Map()", app)
        self.assertIn("retryableCaptureRequest", app)
        self.assertIn("finishRetryableCapture", app)
        self.assertIn("const body = { ...retry.body, capture_id: retry.captureId }", app)
        self.assertIn("/api/context-events", app)
        self.assertIn("danger-button", styles)
        self.assertIn("app-connect-panel", styles)
        self.assertIn("core-status-badge", styles)
        self.assertIn("core-status-dot", styles)
        self.assertIn("wizard-layer", styles)
        self.assertIn("wizard-spotlight", styles)
        self.assertIn("wizard-panel", styles)
        self.assertIn("wizard-arrow", styles)
        self.assertIn("wizard-highlight-target", styles)
        self.assertIn("operator-loop-panel", styles)
        self.assertIn("operator-action-banner", styles)
        self.assertIn("operator-run-order", styles)
        self.assertIn("operator-action-shortcuts", styles)
        self.assertIn("receipt-card", styles)
        self.assertIn("quality-badge", styles)
        self.assertIn("--accent-gradient", styles)
        self.assertIn("--magenta", styles)
        self.assertIn("--terminal-font", styles)
        self.assertIn("runtime-build-line", styles)
        self.assertNotIn(".switch-track", styles)
        self.assertIn("neural-math-panel", styles)
        self.assertIn("neural-inspector-toggle", styles)
        self.assertIn("cortex-panel", styles)
        self.assertIn("cortex-header-actions", styles)
        self.assertIn("compact-action", styles)
        self.assertIn("cortex-session-callout", styles)
        self.assertIn("cortex-memory-actions", styles)
        self.assertNotIn("board-demo", index)
        self.assertNotIn("board-demo", app)
        self.assertNotIn("durable real memory local SQLite substrate", index)
        self.assertNotIn('dispatchEvent(new Event("submit"', app)

    def test_namespace_galaxy_assets_explain_weighted_visual_mass(self):
        root = Path(__file__).resolve().parents[1]
        index = (root / "web" / "index.html").read_text(encoding="utf-8")
        app = (root / "web" / "app.js").read_text(encoding="utf-8")
        styles = (root / "web" / "styles.css").read_text(encoding="utf-8")

        for token in (
            "surfaceTermCount",
            "applyNamespaceGalaxyMetrics",
            "enabledApprovedLinks",
            "relationshipDensity",
            "surfaceDensity",
            "bridgeCentrality",
            "visualMassScore",
            "boundedAreaRadius",
            "applyNamespaceDetailMetrics",
            'level: "ganglion"',
            "aggregateEdges",
            "averageWeight",
            "storedRelationshipCount",
            "weightedRelationshipDensity",
            "weightedDegree",
            "namespaceGalaxyNeighborhood",
            "namespaceDetailNeighborhood",
        ):
            self.assertIn(token, app)

        for weighted_part in (
            "[volumeScore, 0.58]",
            "[densityScore, 0.27]",
            "[bridgeScore, 0.15]",
            "[surfaceDensityScore, 0.55]",
            "[relationshipDensityScore, 0.45]",
            "[memoryScore, 0.68]",
            "[relationshipDensityScore, 0.32]",
        ):
            self.assertIn(weighted_part, app)
        self.assertIn(
            "links.filter((link) => link.enabled && link.approved)", app
        )
        self.assertIn(
            "applyNamespaceGalaxyMetrics([...nodeMap.values()], storedLinks)",
            app,
        )
        self.assertIn(
            "Math.sqrt(minimumArea + normalized * (maximumArea - minimumArea))",
            app,
        )
        self.assertIn(
            "const [payload, ganglionPayload] = await Promise.all([neuronRequest, ganglionRequest])",
            app,
        )
        self.assertIn("detail.aggregateAvailable = true", app)
        self.assertIn(
            "const clusterMetricEdges = detail.aggregateAvailable ? detail.aggregateEdges : detail.edges",
            app,
        )
        self.assertIn("0.85 + link.weight * 3.35", app)
        self.assertIn("0.3 + item.weight * 0.56", app)
        self.assertIn("0.12 + item.weight * 0.22", app)

        self.assertIn("Sphere area = weighted memory mass", index)
        self.assertIn("Bridge width = approved weight", index)
        self.assertIn("Higher approved weight", index)
        self.assertIn("Suggestions never affect size or recall", index)
        self.assertIn("58% relative log memory volume", index)
        self.assertIn("27% relative log indexed term/relationship density", index)
        self.assertIn("Indexed term density", app)
        self.assertIn("Incident enabled bridge weight", app)
        self.assertIn("Relative size score", app)
        self.assertIn("Aggregate edge weight", app)
        self.assertIn("Weighted relationship density", app)
        self.assertIn("Relationship metric scope", app)
        for metric_scope in (
            '"stored aggregate"',
            '"bounded stored aggregate"',
            '"visible sample"',
        ):
            self.assertIn(metric_scope, app)
        self.assertIn("Visible weighted degree", app)
        self.assertIn("@media (max-width: 720px)", styles)
        self.assertIn("@media (prefers-reduced-motion: reduce)", styles)

    def test_namespace_galaxy_review_regressions_stay_fixed(self):
        root = Path(__file__).resolve().parents[1]
        index = (root / "web" / "index.html").read_text(encoding="utf-8")
        app = (root / "web" / "app.js").read_text(encoding="utf-8")

        for truncation_signal in (
            "aggregateTruncation?.truncated",
            "aggregateTruncation?.edges?.truncated",
            "aggregateTruncation?.clusters?.truncated",
            "aggregateTruncation?.source_scan?.entries_truncated",
            "aggregateTruncation?.source_scan?.relationships_truncated",
        ):
            self.assertIn(truncation_signal, app)

        clear_focus_start = app.index("function clearNamespaceGanglionFocus")
        clear_focus_end = app.index("function exitNamespaceGalaxy", clear_focus_start)
        clear_focus = app[clear_focus_start:clear_focus_end]
        self.assertIn("combinedNamespaceDetail()", clear_focus)
        self.assertNotIn("galaxy.detail?.namespace", clear_focus)
        self.assertNotIn("galaxy.detail?.clusters", clear_focus)

        fallback_start = app.index("function projectAggregateNamespaceDetailEdges")
        fallback_end = app.index("function drawNamespaceDetailEdge", fallback_start)
        fallback = app[fallback_start:fallback_end]
        key_start = fallback.index("const key = ")
        key_end = fallback.index(";", key_start)
        key_expression = fallback[key_start:key_end]
        for key_part in (
            "sourceCluster",
            "targetCluster",
            "edge.edgeType",
            "edge.direction",
        ):
            self.assertIn(key_part, key_expression)
        self.assertNotIn(".sort(", key_expression)

        self.assertIn("indexed term/relationship density", index.lower())
        self.assertIn("relative log", index.lower())
        self.assertIn("Indexed term density", app)
        self.assertIn("Relative size score", app)
        self.assertIn("Relative log", app)
        self.assertNotIn('["Content density"', app)
        self.assertEqual(app.count('["Bounded size score"'), 1)
        detail_facts_start = app.index("function detailFactsFor")
        detail_facts_end = app.index(
            "function renderNamespaceDetailInspector", detail_facts_start
        )
        self.assertIn(
            '["Bounded size score"',
            app[detail_facts_start:detail_facts_end],
        )
        self.assertEqual(app.count("percent bounded size"), 1)
        self.assertGreaterEqual(app.count("percent relative size"), 3)
        detail_list_start = app.index("function renderNamespaceDetailList")
        detail_list_end = app.index(
            "function handleNamespaceGalaxyListAction", detail_list_start
        )
        detail_list = app[detail_list_start:detail_list_end]
        self.assertEqual(detail_list.count("percent bounded size"), 1)
        self.assertEqual(detail_list.count("percent relative size"), 2)

    def test_self_test_endpoint_reports_operator_readiness(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=runtime.backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
            )
            runtime.transcript_capture = lambda: manager  # type: ignore[method-assign]

            status, payload = self.decode(runtime.handle("GET", "/api/self-test?context_id=demo"))

        components = payload["components"]
        self.assertEqual(status, 200)
        self.assertEqual(payload["action"], "self-test")
        self.assertEqual(payload["context_id"], "demo")
        self.assertIn(payload["overall_status"], {"ready", "degraded", "blocked"})
        for component in (
            "runtime",
            "memory",
            "embedding",
            "context_bus",
            "capture_inbox",
            "app_connect",
        ):
            self.assertIn(component, components)
            self.assertIn(components[component]["status"], {"ready", "degraded", "blocked"})
            self.assertTrue(components[component]["label"])
            self.assertIn("detail", components[component])
        self.assertGreaterEqual(components["app_connect"]["app_count"], 1)
        self.assertIsInstance(payload["recommended_actions"], list)

    def test_monday_readiness_endpoint_reports_demo_scorecard(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

            status, payload = self.decode(
                runtime.handle("GET", "/api/monday-readiness?context_id=demo&include_apps=false")
            )

        self.assertEqual(status, 200)
        self.assertEqual(payload["action"], "monday-readiness")
        self.assertEqual(payload["context_id"], "demo")
        self.assertIn(payload["overall_status"], {"ready", "degraded", "blocked"})
        self.assertIsInstance(payload["demo_ready"], bool)
        self.assertGreaterEqual(payload["score"], 0)
        self.assertLessEqual(payload["score"], 100)
        self.assertGreater(payload["summary"]["required_total"], 0)
        self.assertIn("operator_steps", payload)
        self.assertGreaterEqual(len(payload["operator_steps"]), 3)
        checks_by_id = {check["id"]: check for check in payload["checks"]}
        for check_id in (
            "runtime",
            "memory",
            "embedding",
            "context_bus",
            "capture_inbox",
            "resource_envelope",
            "quick_prune",
            "embedding_latency",
            "recall_audit",
        ):
            self.assertIn(check_id, checks_by_id)
            self.assertIn(checks_by_id[check_id]["status"], {"ready", "degraded", "blocked"})
            self.assertIn("detail", checks_by_id[check_id])
            self.assertIn("required", checks_by_id[check_id])

    def test_operator_trust_loop_endpoints_report_actionable_workflow(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            runtime.backend.commit_cortical_trace(
                context_id="demo",
                agent_id="codex-desktop",
                session_id="unit-session",
                trace_type="assumption",
                truth_posture="inferred",
                text="Feature: App Connect snapshot quality needs operator review.",
                confidence=0.44,
            )
            runtime.backend.register_text_trace(
                tag="low-signal-app-capture",
                context_id="demo",
                text="Codex ended.",
                metadata={
                    "adapter_kind": "app-accessibility-snapshot",
                    "snapshot_quality": {
                        "quality": "low",
                        "low_signal": True,
                        "signal_chars": 12,
                    },
                },
            )

            health_status, health_payload = self.decode(
                runtime.handle("GET", "/api/context-health?context_id=demo")
            )
            hygiene_status, hygiene_payload = self.decode(
                runtime.handle("GET", "/api/memory-hygiene?context_id=demo")
            )
            doctor_status, doctor_payload = self.decode(
                runtime.handle("GET", "/api/doctor?context_id=demo")
            )
            start_status, start_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/start-work",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-ui",
                            "prompt": "Monday operator brief",
                        }
                    ).encode(),
                )
            )
            preview_status, preview_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/wrap-session/preview",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "codex-desktop",
                            "text": "Feature: Implemented Operator Trust Loop endpoint tests.",
                            "operation_log": [
                                {
                                    "action": "test",
                                    "summary": "Added failing workflow coverage.",
                                }
                            ],
                        }
                    ).encode(),
                )
            )
            wrap_status, wrap_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/wrap-session",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "codex-desktop",
                            "text": "Feature: Operator Trust Loop tests are now captured.",
                            "operation_log": [
                                {
                                    "action": "test",
                                    "summary": "Verified wrap session capture path.",
                                }
                            ],
                            "confirm": True,
                        }
                    ).encode(),
                )
            )

        self.assertEqual(health_status, 200)
        self.assertEqual(health_payload["action"], "context-health")
        self.assertEqual(health_payload["context_id"], "demo")
        self.assertIn(health_payload["status"], {"ready", "degraded", "blocked"})
        self.assertGreaterEqual(health_payload["score"], 0)
        self.assertLessEqual(health_payload["score"], 100)
        self.assertGreaterEqual(health_payload["memory_quality_score"], 0)
        self.assertIsInstance(health_payload["factors"], list)
        self.assertEqual(health_payload["receipt"]["action"], "context-health")

        self.assertEqual(hygiene_status, 200)
        self.assertEqual(hygiene_payload["action"], "memory-hygiene")
        self.assertGreaterEqual(hygiene_payload["backlog_count"], 1)
        self.assertTrue(hygiene_payload["review_items"])
        self.assertIn("low_signal_app_capture", hygiene_payload["queue_summary"])
        self.assertEqual(hygiene_payload["receipt"]["action"], "memory-hygiene")

        self.assertEqual(doctor_status, 200)
        self.assertEqual(doctor_payload["action"], "doctor-report")
        self.assertIn(doctor_payload["overall_status"], {"ready", "degraded", "blocked"})
        self.assertTrue(doctor_payload["checks"])
        self.assertIn("repair_plan", doctor_payload)
        self.assertEqual(doctor_payload["receipt"]["action"], "doctor-report")

        self.assertEqual(start_status, 200)
        self.assertEqual(start_payload["action"], "start-work")
        self.assertEqual(start_payload["context_id"], "demo")
        self.assertTrue(start_payload["brief_sections"])
        self.assertGreaterEqual(len(start_payload["recipes"]), 3)
        self.assertTrue(start_payload["next_actions"])
        self.assertIn("context_health", start_payload)
        self.assertIn("memory_hygiene", start_payload)
        self.assertEqual(start_payload["receipt"]["action"], "start-work")

        self.assertEqual(preview_status, 200)
        self.assertEqual(preview_payload["action"], "wrap-session-preview")
        self.assertIn("Feature:", preview_payload["preview_text"])
        self.assertTrue(preview_payload["proposed_capture"]["source_tag"])
        self.assertEqual(preview_payload["receipt"]["action"], "wrap-session-preview")

        self.assertEqual(wrap_status, 200)
        self.assertEqual(wrap_payload["action"], "wrap-session")
        self.assertGreaterEqual(wrap_payload["event_count"], 1)
        self.assertEqual(wrap_payload["receipt"]["action"], "wrap-session")
        self.assertEqual(wrap_payload["receipt"]["status"], "ready")

    def test_recall_result_can_be_pinned_to_working_memory(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)

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
            memory_id = next(
                item["memory_id"]
                for item in query_payload["results"]
                if item.get("memory_id")
            )
            pin_status, pin_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/pin-memory",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "memory_id": memory_id,
                            "agent_id": "dashboard-ui",
                            "note": "Use this recalled memory for the current operator task.",
                        }
                    ).encode(),
                )
            )

        self.assertEqual(query_status, 200)
        self.assertEqual(pin_status, 200)
        self.assertEqual(pin_payload["action"], "pin-memory")
        self.assertEqual(pin_payload["pinned_memory_id"], memory_id)
        self.assertEqual(pin_payload["trace_type"], "evidence")
        self.assertEqual(pin_payload["receipt"]["action"], "pin-memory")
        self.assertEqual(pin_payload["receipt"]["status"], "ready")

    def test_http_handler_rejects_cross_origin_mutations(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            server = SynapseDashboardServer(("127.0.0.1", 0), runtime)
            self.assertNotIsInstance(server, ThreadingHTTPServer)
            self.assertGreaterEqual(server.request_queue_size, 32)
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
                with closing(raised.exception) as blocked_response:
                    self.assertEqual(blocked_response.code, 403)
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
        self.assertEqual(remember_payload["agent_deployment"]["delivery_mode"], "leased-at-least-once")
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

    def test_capture_conversation_endpoint_replays_supplied_capture_id_once(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            capture_id = "s2cap_" + ("7" * 32)
            request = {
                "context_id": "demo",
                "source_tag": "dashboard-retry",
                "speaker": "codex",
                "text": "Thread: Dashboard retry. Event: one logical capture is committed once.",
                "capture_id": capture_id,
            }

            first_status, first = self.decode(
                runtime.handle(
                    "POST",
                    "/api/capture-conversation",
                    json.dumps(request).encode(),
                )
            )
            graph_after_first = runtime.backend.list_memory_graph(
                context_id="demo",
                limit=100,
            )
            counts_after_first = (
                graph_after_first["entry_count"],
                graph_after_first["relationship_count"],
                len(runtime.backend.list_context_events(context_id="demo")["events"]),
            )
            replay_status, replay = self.decode(
                runtime.handle(
                    "POST",
                    "/api/capture-conversation",
                    json.dumps(request).encode(),
                )
            )
            graph_after_replay = runtime.backend.list_memory_graph(
                context_id="demo",
                limit=100,
            )
            counts_after_replay = (
                graph_after_replay["entry_count"],
                graph_after_replay["relationship_count"],
                len(runtime.backend.list_context_events(context_id="demo")["events"]),
            )

        self.assertEqual(first_status, 200)
        self.assertEqual(replay_status, 200)
        self.assertEqual(first["capture_id"], capture_id)
        self.assertEqual(replay["capture_id"], capture_id)
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(
            first["agent_deployment"]["event_id"],
            replay["agent_deployment"]["event_id"],
        )
        self.assertEqual(counts_after_replay, counts_after_first)

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
                drop_path = write_capture_drop(
                    root=tmp,
                    context_id="demo",
                    source_tag="dashboard-magic",
                    speaker="codex",
                    text="Dashboard capture inbox should process this dropped payload.",
                )
                raw_file_sha256 = hashlib.sha256(drop_path.read_bytes()).hexdigest()

                status_before, payload_before = self.decode(
                    runtime.handle("GET", "/api/capture-inbox")
                )
                rejected_status, rejected_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/capture-inbox/process",
                        json.dumps({"context_id": "demo"}).encode(),
                    )
                )
                preflight_status, preflight_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/capture-inbox/preflight",
                        json.dumps({"context_id": "demo", "max_files": 50}).encode(),
                    )
                )
                process_status, process_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/capture-inbox/process",
                        json.dumps(
                            {
                                "context_id": "demo",
                                "max_files": 50,
                                "confirmation_token": preflight_payload["confirmation_token"],
                            }
                        ).encode(),
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
        self.assertEqual(rejected_status, 400)
        self.assertIn("confirmation_token", rejected_payload["error"])
        self.assertEqual(preflight_status, 200)
        self.assertEqual(preflight_payload["selected_file_count"], 1)
        self.assertTrue(preflight_payload["requires_confirmation_token"])
        selected = preflight_payload["selected_files"][0]
        self.assertNotIn("sha256", selected)
        self.assertRegex(selected["transport_token"], r"^[0-9a-f]{64}$")
        self.assertRegex(selected["request_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            selected["request_fingerprint"],
            raw_file_sha256,
        )
        self.assertNotIn(raw_file_sha256, json.dumps(preflight_payload, sort_keys=True))
        self.assertEqual(process_status, 200)
        self.assertEqual(process_payload["processed_file_count"], 1)
        self.assertEqual(graph_status, 200)
        self.assertTrue(
            any(
                entry["tag"].startswith("dashboard-magic-event")
                for entry in graph_payload["entries"]
            )
        )

    def test_capture_inbox_confirmation_rejects_changed_safe_transport_target(self):
        with TemporaryDirectory() as tmp:
            previous_root = os.environ.get("SYNAPSE_S2_CAPTURE_ROOT")
            os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = tmp
            try:
                runtime = self.make_runtime(tmp)
                drop_path = write_capture_drop(
                    root=tmp,
                    context_id="demo",
                    source_tag="dashboard-toctou",
                    speaker="codex",
                    text="Original confirmed capture request.",
                )
                preflight_status, preflight_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/capture-inbox/preflight",
                        json.dumps({"max_files": 50}).encode(),
                    )
                )
                changed = json.loads(drop_path.read_text(encoding="utf-8"))
                changed["text"] = "Changed after operator preflight."
                drop_path.write_text(
                    json.dumps(changed, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                process_status, process_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/capture-inbox/process",
                        json.dumps(
                            {
                                "max_files": 50,
                                "confirmation_token": preflight_payload[
                                    "confirmation_token"
                                ],
                            }
                        ).encode(),
                    )
                )
                status_after, payload_after = self.decode(
                    runtime.handle("GET", "/api/capture-inbox")
                )
            finally:
                if previous_root is None:
                    os.environ.pop("SYNAPSE_S2_CAPTURE_ROOT", None)
                else:
                    os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = previous_root

        self.assertEqual(preflight_status, 200)
        self.assertEqual(process_status, 409)
        self.assertIn("target changed", process_payload["error"])
        self.assertEqual(status_after, 200)
        self.assertEqual(payload_after["pending_file_count"], 1)
        self.assertEqual(payload_after["processed_file_count"], 0)

    def test_app_connect_endpoint_registers_manual_local_app_connection(self):
        with TemporaryDirectory() as tmp:
            previous_root = os.environ.get("SYNAPSE_S2_CAPTURE_ROOT")
            os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = tmp
            try:
                runtime = self.make_runtime(tmp)
                app_payload = {
                    "context_id": "demo",
                    "app_name": "Manual MCP Probe",
                    "bundle_id": "local.manual.probe",
                    "pid": 424242,
                    "source_tag": "manual-probe",
                    "speaker": "codex",
                    "allow_manual": True,
                }
                rejected_status, rejected_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/app-connect",
                        json.dumps({**app_payload, "confirm": True}).encode(),
                    )
                )
                preflight_status, preflight_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/app-connect/preflight",
                        json.dumps(app_payload).encode(),
                    )
                )
                connect_status, connect_payload = self.decode(
                    runtime.handle(
                        "POST",
                        "/api/app-connect",
                        json.dumps(
                            {
                                **app_payload,
                                "confirmation_token": preflight_payload["confirmation_token"],
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

        self.assertEqual(rejected_status, 400)
        self.assertIn("confirmation_token", rejected_payload["error"])
        self.assertEqual(preflight_status, 200)
        self.assertEqual(preflight_payload["app_name"], "Manual MCP Probe")
        self.assertTrue(preflight_payload["requires_confirmation_token"])
        self.assertEqual(connect_status, 200)
        self.assertEqual(connect_payload["app_name"], "Manual MCP Probe")
        self.assertEqual(connect_payload["bundle_id"], "local.manual.probe")
        self.assertEqual(list_status, 200)
        self.assertEqual(list_payload["connection_count"], 1)
        self.assertEqual(list_payload["connections"][0]["source_tag"], "manual-probe")

    def test_app_connect_endpoint_attaches_detected_app_and_snapshots_memory(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=runtime.backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
                app_snapshot_provider=lambda app: (
                    f"{app['app_name']} active session: SYNAPSE-S2 App Connect is reading UI state. "
                    "api_key=sk-app-secret123"
                ),
            )
            runtime.transcript_capture = lambda: manager  # type: ignore[method-assign]
            app_payload = {
                "context_id": "demo",
                "app_name": "Codex",
                "bundle_id": "com.openai.codex",
                "pid": 4242,
                "source_tag": "codex-app",
                "speaker": "operator",
                "allow_manual": False,
            }

            apps_status, apps_payload = self.decode(runtime.handle("GET", "/api/apps"))
            preflight_status, preflight_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/app-connect/preflight",
                    json.dumps(app_payload).encode(),
                )
            )
            connect_status, connect_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/app-connect",
                    json.dumps(
                        {
                            **app_payload,
                            "confirmation_token": preflight_payload["confirmation_token"],
                        }
                    ).encode(),
                )
            )
            list_status, list_payload = self.decode(runtime.handle("GET", "/api/app-connections"))
            memory_before_preview = runtime.backend.list_memory(context_id="demo", limit=20)[
                "entry_count"
            ]
            preview_status, preview_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/app-snapshot/preview",
                    json.dumps({"connection_id": connect_payload["connection_id"]}).encode(),
                )
            )
            memory_after_preview = runtime.backend.list_memory(context_id="demo", limit=20)[
                "entry_count"
            ]
            snapshot_preflight_status, snapshot_preflight_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/app-snapshot/preflight",
                    json.dumps({"connection_id": connect_payload["connection_id"]}).encode(),
                )
            )
            snapshot_status, snapshot_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/app-snapshot",
                    json.dumps(
                        {
                            "connection_id": connect_payload["connection_id"],
                            "confirmation_token": snapshot_preflight_payload["confirmation_token"],
                        }
                    ).encode(),
                )
            )
            memory = runtime.backend.list_memory(context_id="demo", limit=20)
            captured = [
                entry
                for entry in memory["entries"]
                if entry["metadata"].get("adapter_kind") == "app-accessibility-snapshot"
            ]

        self.assertEqual(apps_status, 200)
        self.assertEqual(apps_payload["app_count"], 1)
        self.assertEqual(apps_payload["apps"][0]["app_name"], "Codex")
        self.assertEqual(preflight_status, 200)
        self.assertEqual(connect_status, 200)
        self.assertEqual(connect_payload["app_name"], "Codex")
        self.assertEqual(connect_payload["bundle_id"], "com.openai.codex")
        self.assertEqual(list_status, 200)
        self.assertEqual(list_payload["connection_count"], 1)
        self.assertEqual(preview_status, 200)
        self.assertEqual(preview_payload["action"], "preview-app-snapshot")
        self.assertEqual(preview_payload["app_name"], "Codex")
        self.assertNotIn("sk-app-secret123", preview_payload["preview_text"])
        self.assertIn(preview_payload["quality_badge"]["status"], {"ready", "degraded", "blocked"})
        self.assertTrue(preview_payload["capture_guidance"])
        self.assertEqual(memory_after_preview, memory_before_preview)
        self.assertEqual(snapshot_preflight_status, 200)
        self.assertEqual(snapshot_preflight_payload["connection"]["app_name"], "Codex")
        self.assertEqual(snapshot_status, 200)
        self.assertEqual(snapshot_payload["adapter_kind"], "app-accessibility-snapshot")
        self.assertGreaterEqual(snapshot_payload["event_count"], 1)
        self.assertEqual(snapshot_payload["receipt"]["action"], "capture-app-snapshot")
        self.assertIn(snapshot_payload["receipt"]["status"], {"ready", "degraded", "blocked"})
        self.assertTrue(captured)
        self.assertTrue(all("sk-app-secret123" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))

    def test_app_selection_capture_endpoint_persists_selected_text(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=runtime.backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
            )
            runtime.transcript_capture = lambda: manager  # type: ignore[method-assign]
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )

            rejected_status, rejected_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/app-selection-capture",
                    json.dumps(
                        {
                            "connection_id": attached["connection_id"],
                            "text": "Selected Codex text should require confirmation.",
                        }
                    ).encode(),
                )
            )
            capture_status, capture_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/app-selection-capture",
                    json.dumps(
                        {
                            "connection_id": attached["connection_id"],
                            "text": "Selected Codex text has password=selected-secret.",
                            "confirm": True,
                            "metadata": {"source": "dashboard-unit-test"},
                        }
                    ).encode(),
                )
            )
            memory = runtime.backend.list_memory(context_id="demo", limit=20)
            captured = [
                entry
                for entry in memory["entries"]
                if entry["metadata"].get("adapter_kind") == "app-selected-text"
            ]

        self.assertEqual(rejected_status, 400)
        self.assertIn("confirm", rejected_payload["error"])
        self.assertEqual(capture_status, 200)
        self.assertEqual(capture_payload["adapter_kind"], "app-selected-text")
        self.assertEqual(capture_payload["app_name"], "Codex")
        self.assertEqual(capture_payload["connection_id"], attached["connection_id"])
        self.assertGreaterEqual(capture_payload["event_count"], 1)
        self.assertTrue(captured)
        self.assertTrue(all("selected-secret" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))

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
            delivery_status, delivery_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/context-deliveries",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-ui",
                            "consumer_instance_id": "dashboard-test",
                            "limit": 5,
                        }
                    ).encode(),
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
                            "receipt_id": delivery_payload["deliveries"][0]["receipt_id"],
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
        self.assertEqual(delivery_status, 200)
        self.assertEqual(ack_status, 200)
        self.assertEqual(ack_payload["agent_id"], "dashboard-ui")
        self.assertEqual(ack_payload["cursor"]["pending_event_count"], 0)
        self.assertEqual(cursor_status, 200)
        self.assertEqual(cursor_payload["cursors"][0]["agent_id"], "dashboard-ui")

    def test_start_work_identity_and_method_contract_fail_closed(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            get_status, get_payload = self.decode(
                runtime.handle("GET", "/api/start-work?context_id=demo")
            )
            forbidden_status, forbidden_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/start-work",
                    json.dumps(
                        {"context_id": "demo", "agent_id": "codex-desktop"}
                    ).encode(),
                )
            )
            default_status, default_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/start-work",
                    json.dumps({"context_id": "demo"}).encode(),
                )
            )

        self.assertEqual(get_status, 405)
        self.assertIn("requires POST", get_payload["error"])
        self.assertEqual(forbidden_status, 403)
        self.assertIn("dashboard-ui", forbidden_payload["error"])
        self.assertEqual(default_status, 200)
        self.assertEqual(default_payload["agent_id"], "dashboard-ui")

    def test_context_release_rejects_empty_and_unbounded_batches(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            base_payload = {
                "context_id": "demo",
                "agent_id": "dashboard-ui",
                "consumer_instance_id": "dashboard-release-test",
            }
            empty_status, empty_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/context-release",
                    json.dumps({**base_payload, "receipt_ids": []}).encode(),
                )
            )
            oversized_status, oversized_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/context-release",
                    json.dumps(
                        {
                            **base_payload,
                            "receipt_ids": [
                                f"receipt-{index}" for index in range(501)
                            ],
                        }
                    ).encode(),
                )
            )
            ack_oversized_status, ack_oversized_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/context-ack",
                    json.dumps(
                        {
                            "context_id": "demo",
                            "agent_id": "dashboard-ui",
                            "receipt_ids": [
                                f"receipt-{index}" for index in range(501)
                            ],
                        }
                    ).encode(),
                )
            )

        self.assertEqual(empty_status, 400)
        self.assertIn("receipt_ids", empty_payload["error"])
        self.assertEqual(oversized_status, 400)
        self.assertIn("between 1 and 500", oversized_payload["error"])
        self.assertEqual(ack_oversized_status, 400)
        self.assertIn("at most 500", ack_oversized_payload["error"])

    def test_context_delivery_rejects_non_finite_lease_seconds_at_transport(self):
        with TemporaryDirectory() as tmp:
            runtime = self.make_runtime(tmp)
            with mock.patch.object(
                runtime.backend,
                "lease_context_events",
                wraps=runtime.backend.lease_context_events,
            ) as lease_context_events:
                for lease_seconds in (
                    float("inf"),
                    float("-inf"),
                    float("nan"),
                ):
                    with self.subTest(lease_seconds=lease_seconds):
                        status, payload = self.decode(
                            runtime.handle(
                                "POST",
                                "/api/context-deliveries",
                                json.dumps(
                                    {
                                        "context_id": "demo",
                                        "agent_id": "dashboard-ui",
                                        "consumer_instance_id": "dashboard-non-finite-test",
                                        "limit": 1,
                                        "lease_seconds": lease_seconds,
                                    }
                                ).encode(),
                            )
                        )
                        self.assertEqual(status, 400)
                        self.assertEqual(
                            payload["error"],
                            "lease_seconds must be finite",
                        )

            lease_context_events.assert_not_called()

    def test_context_dead_letter_endpoint_is_confirmed_and_audited(self):
        with TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {"SYNAPSE_S2_CONTEXT_MAX_DELIVERY_ATTEMPTS": "2"},
        ):
            runtime = self.make_runtime(tmp)
            runtime.backend.publish_context_event(
                context_id="dead-letter-dashboard",
                source_surface="dashboard-test",
                event_type="poison",
                summary="dashboard retry exhaustion",
                agent_targets=["dashboard-ui"],
            )
            first = runtime.backend.memory_store.lease_context_events(
                context_id="dead-letter-dashboard",
                agent_id="dashboard-ui",
                consumer_instance_id="dashboard-attempt-one",
                limit=1,
                lease_seconds=1.0,
                now=100.0,
            )["deliveries"][0]
            runtime.backend.memory_store.lease_context_events(
                context_id="dead-letter-dashboard",
                agent_id="dashboard-ui",
                consumer_instance_id="dashboard-attempt-two",
                limit=1,
                lease_seconds=1.0,
                now=102.0,
            )
            base = {
                "context_id": "dead-letter-dashboard",
                "agent_id": "dashboard-ui",
                "delivery_id": first["delivery_id"],
                "reason": "dashboard test consumer cannot decode event",
            }
            rejected_status, rejected_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/context-dead-letter",
                    json.dumps(base).encode(),
                )
            )
            accepted_status, accepted_payload = self.decode(
                runtime.handle(
                    "POST",
                    "/api/context-dead-letter",
                    json.dumps({**base, "confirm": True}).encode(),
                )
            )

        self.assertEqual(rejected_status, 400)
        self.assertIn("confirm=true", rejected_payload["error"])
        self.assertEqual(accepted_status, 200)
        self.assertEqual(
            accepted_payload["action"],
            "context-delivery-dead-letter",
        )
        self.assertTrue(accepted_payload["operation_id"].startswith("s2maint_"))


if __name__ == "__main__":
    unittest.main()

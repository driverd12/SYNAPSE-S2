import contextlib
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import mlx_backend
import mcp_server


class McpServerTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        mlx_backend._ENGINE_INSTANCE = mlx_backend.SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=Path(self.tmpdir.name) / "state.json",
            memory_path=Path(self.tmpdir.name) / "memory.sqlite3",
        )
        self.addCleanup(lambda: setattr(mlx_backend, "_ENGINE_INSTANCE", None))
        self.previous_export_dir = os.environ.get("SYNAPSE_S2_EXPORT_DIR")
        self.previous_capture_root = os.environ.get("SYNAPSE_S2_CAPTURE_ROOT")
        os.environ["SYNAPSE_S2_EXPORT_DIR"] = self.tmpdir.name
        os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = str(Path(self.tmpdir.name) / "capture-root")
        self.addCleanup(self._restore_export_dir)
        self.addCleanup(self._restore_capture_root)

    def _restore_export_dir(self):
        if self.previous_export_dir is None:
            os.environ.pop("SYNAPSE_S2_EXPORT_DIR", None)
        else:
            os.environ["SYNAPSE_S2_EXPORT_DIR"] = self.previous_export_dir

    def _restore_capture_root(self):
        if self.previous_capture_root is None:
            os.environ.pop("SYNAPSE_S2_CAPTURE_ROOT", None)
        else:
            os.environ["SYNAPSE_S2_CAPTURE_ROOT"] = self.previous_capture_root

    def test_query_rejects_empty_embedding(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = mcp_server.query_spiking_attention([], context_id="demo")

        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("invalid prompt_embedding", result)

    def test_query_sanitizes_context_id(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="sanitized-memory",
                context_id="../demo with spaces",
                prompt_embedding=[0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
            )
        )
        result = mcp_server.query_spiking_attention(
            [0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
            context_id="../demo with spaces",
        )

        self.assertEqual(registration["context_id"], "demo_with_spaces")
        self.assertIn("sanitized-memory", result)
        self.assertIn("demo_with_spaces", result)
        self.assertNotIn("..", result)

    def test_sleep_consolidation_returns_status_string(self):
        result = mcp_server.trigger_sleep_consolidation()

        self.assertIn("deep-sleep", result)

    def test_resource_profile_tool_reports_memory_estimate(self):
        profile = json.loads(
            mcp_server.profile_spiking_resources(benchmark_quick_prune=True)
        )

        self.assertEqual(profile["dimension"], 6)
        self.assertEqual(profile["num_neurons"], 10)
        self.assertIn("estimated_total_mb", profile)
        self.assertTrue(profile["quick_pruning"]["within_60ms_budget"])

    def test_embedding_provider_benchmark_tool_reports_provenance(self):
        self.assertTrue(
            hasattr(mcp_server, "benchmark_spiking_embedding_provider"),
            "MCP server must expose benchmark_spiking_embedding_provider",
        )
        benchmark = json.loads(
            mcp_server.benchmark_spiking_embedding_provider(
                text="MCP provider benchmark",
                runs=2,
                dimensions=6,
            )
        )

        self.assertEqual(benchmark["action"], "provider-benchmark")
        self.assertEqual(benchmark["runs"], 2)
        self.assertEqual(benchmark["dimensions"], 6)
        self.assertEqual(len(benchmark["sample_latencies_ms"]), 2)
        self.assertEqual(benchmark["embedding_provider"]["provider"], "semantic-hash-v1")

    def test_native_certification_tool_reports_evidence_shape(self):
        certification = json.loads(
            mcp_server.certify_spiking_runtime(
                strict_native=False,
                benchmark_quick_prune=True,
            )
        )

        self.assertEqual(certification["action"], "certify-runtime")
        self.assertIn("checks", certification)
        self.assertIn("resource_profile", certification)
        self.assertIn("quick_pruning", certification["resource_profile"])
        self.assertIn("mlx_available", certification["checks"])

    def test_idle_maintenance_tool_can_force_deep_sleep(self):
        result = json.loads(mcp_server.trigger_idle_maintenance(force_deep_sleep=True))

        self.assertEqual(result["mode"], "deep-sleep")
        self.assertEqual(result["trigger"], "idle-force")
        self.assertTrue(result["maintenance_run"])
        self.assertEqual(result["phase_count"], 7)

    def test_toggle_tool_disables_query_and_status_reports_state(self):
        disabled = json.loads(mcp_server.set_spiking_attention_enabled(False))
        status = json.loads(mcp_server.get_spiking_attention_status(context_id="demo"))
        disabled_query = mcp_server.query_spiking_attention(
            [0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
            context_id="demo",
        )
        enabled = json.loads(mcp_server.set_spiking_attention_enabled(True))

        self.assertFalse(disabled["global_enabled"])
        self.assertFalse(status["effective_enabled"])
        self.assertIn("disabled", disabled_query.lower())
        self.assertTrue(enabled["global_enabled"])

    def test_remember_trace_tool_makes_query_return_named_context(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="exec-briefing-memory",
                context_id="demo",
                prompt_embedding=[0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
                text="Tomorrow's executive SYNAPSE-S2 briefing",
                metadata={"source": "unit-test"},
            )
        )
        result = mcp_server.query_spiking_attention(
            [0.0, 1.0, 9.1, 2.1, 7.2, -4.0],
            context_id="demo",
        )

        self.assertEqual(registration["tag"], "exec-briefing-memory")
        self.assertTrue(registration["agent_deployment"]["published"])
        self.assertEqual(registration["agent_deployment"]["event_type"], "remember-trace")
        self.assertIn("exec-briefing-memory", result)

    def test_text_remember_tool_records_embedding_provider_provenance(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="mcp-semantic-memory",
                context_id="demo",
                text="Apple Silicon Metal acceleration",
                metadata={"surface": "mcp"},
            )
        )
        listing = json.loads(mcp_server.list_spiking_memory(context_id="demo", limit=5))
        status = json.loads(mcp_server.get_spiking_attention_status(context_id="demo"))

        self.assertEqual(registration["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertEqual(
            listing["entries"][0]["metadata"]["embedding_provider"]["provider"],
            "semantic-hash-v1",
        )
        self.assertEqual(status["embedding_provider"]["provider"], "semantic-hash-v1")

    def test_text_query_tool_uses_local_deterministic_embedding(self):
        mcp_server.remember_spiking_context(
            tag="local-demo-memory",
            context_id="demo",
            text="SYNAPSE-S2 local spiking memory demo",
            metadata={},
        )

        result = mcp_server.query_spiking_attention_text(
            prompt="SYNAPSE-S2 local spiking memory demo",
            context_id="demo",
        )

        self.assertIn("local-demo-memory", result)

    def test_memory_list_export_and_backup_tools_are_json_safe(self):
        mcp_server.remember_spiking_context(
            tag="ops-handoff-memory",
            context_id="demo",
            text="Real memory is inspectable through MCP.",
            metadata={"surface": "mcp"},
        )

        listing = json.loads(mcp_server.list_spiking_memory(context_id="demo", limit=5))
        exported = json.loads(mcp_server.export_spiking_memory(context_id="demo"))
        backup = json.loads(
            mcp_server.backup_spiking_memory(
                output_path=str(Path(self.tmpdir.name) / "backup.sqlite3")
            )
        )

        self.assertEqual(listing["entry_count"], 1)
        self.assertEqual(listing["entries"][0]["tag"], "ops-handoff-memory")
        self.assertNotIn("spike_indices", listing["entries"][0])
        self.assertNotIn("neuron_indices", listing["entries"][0])
        self.assertEqual(exported["entries"][0]["source_text"], "Real memory is inspectable through MCP.")
        self.assertTrue(Path(backup["backup_path"]).exists())

    def test_memory_list_tool_can_include_vector_details_when_requested(self):
        mcp_server.remember_spiking_context(
            tag="mcp-vector-memory",
            context_id="demo",
            text="MCP can include vector details on request.",
            metadata={"surface": "mcp"},
        )

        listing = json.loads(
            mcp_server.list_spiking_memory(
                context_id="demo",
                limit=5,
                include_vectors=True,
            )
        )

        self.assertEqual(listing["entries"][0]["tag"], "mcp-vector-memory")
        self.assertIn("spike_indices", listing["entries"][0])
        self.assertIn("neuron_indices", listing["entries"][0])

    def test_mcp_ingests_text_events_and_lists_memory_graph(self):
        text = (
            "Apple Silicon MLX compiles spiking kernels into Metal. "
            "Sparse spike populations recall local context. "
            "Procurement reviews supplier budget exposure and contract risk. "
            "Finance tracks renewal owners and approval status."
        )

        ingestion = json.loads(
            mcp_server.ingest_spiking_memory_text(
                tag="mcp-brief",
                text=text,
                context_id="demo",
                surprise_threshold=0.58,
                min_segment_sentences=1,
            )
        )
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))

        self.assertGreaterEqual(ingestion["event_count"], 2)
        self.assertTrue(ingestion["agent_deployment"]["published"])
        self.assertGreaterEqual(graph["relationship_count"], 1)
        self.assertEqual(graph["relationships"][0]["relation_type"], "temporal_next")

    def test_mcp_captures_conversation_and_prunes_memory_graph_items(self):
        capture = json.loads(
            mcp_server.capture_spiking_conversation(
                text=(
                    "User wants conversation details visible in SYNAPSE-S2. "
                    "Codex captures a durable session event. "
                    "Sensitive partial truths can be pruned later."
                ),
                context_id="demo",
                source_tag="mcp-session",
                speaker="codex",
            )
        )
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))
        memory_id = next(
            entry["memory_id"]
            for entry in graph["entries"]
            if entry["tag"].startswith("mcp-session-event")
        )
        relationship_id = graph["relationships"][0]["relationship_id"]

        edge_prune = json.loads(
            mcp_server.prune_spiking_memory(
                target_type="relationship",
                context_id="demo",
                relationship_id=relationship_id,
                reason="bad edge",
            )
        )
        memory_prune = json.loads(
            mcp_server.prune_spiking_memory(
                target_type="event",
                context_id="demo",
                memory_id=memory_id,
                reason="bad event",
            )
        )

        self.assertGreaterEqual(capture["event_count"], 2)
        self.assertTrue(capture["agent_deployment"]["published"])
        self.assertTrue(edge_prune["result"]["deleted"])
        self.assertTrue(memory_prune["result"]["deleted"])

    def test_mcp_capture_inbox_tools_drop_process_and_redact(self):
        drop = json.loads(
            mcp_server.drop_spiking_capture_inbox(
                text=(
                    "MCP wrappers can drop session notes into the magic inbox. "
                    "The sidecar processes api_key=sk-test-secret123 safely."
                ),
                context_id="demo",
                source_tag="mcp-magic",
                speaker="codex",
            )
        )
        status_before = json.loads(mcp_server.get_spiking_capture_inbox_status())
        processed = json.loads(mcp_server.process_spiking_capture_inbox(max_files=10))
        graph = json.loads(mcp_server.list_spiking_memory_graph(context_id="demo"))

        self.assertFalse(Path(drop["drop_path"]).exists())
        self.assertEqual(status_before["pending_file_count"], 1)
        self.assertEqual(processed["processed_file_count"], 1)
        self.assertTrue(
            any(entry["tag"].startswith("mcp-magic-event") for entry in graph["entries"])
        )
        self.assertTrue(
            all("sk-test-secret123" not in entry["source_text"] for entry in graph["entries"])
        )

    def test_context_deployment_tool_lists_published_thoughts_for_connected_agents(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="agent-visible-memory",
                context_id="demo",
                text="Connected agents should pull this context update.",
                metadata={"surface": "mcp"},
            )
        )

        deployments = json.loads(
            mcp_server.pull_spiking_context_deployments(
                context_id="demo",
                since_event_id=0,
                limit=10,
            )
        )
        after_registration = json.loads(
            mcp_server.pull_spiking_context_deployments(
                context_id="demo",
                since_event_id=registration["agent_deployment"]["event_id"],
                limit=10,
            )
        )

        self.assertEqual(deployments["delivery_mode"], "durable-mcp-pull")
        self.assertEqual(deployments["events"][0]["payload"]["tag"], "agent-visible-memory")
        self.assertEqual(after_registration["events"], [])

    def test_context_deployment_ack_tool_records_agent_cursor(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="ack-visible-memory",
                context_id="demo",
                text="Connected agents should acknowledge this context update.",
                metadata={"surface": "mcp"},
            )
        )

        ack = json.loads(
            mcp_server.ack_spiking_context_deployments(
                agent_id="codex-desktop",
                context_id="demo",
                last_event_id=registration["agent_deployment"]["event_id"],
            )
        )
        cursors = json.loads(
            mcp_server.list_spiking_context_cursors(context_id="demo")
        )

        self.assertEqual(ack["agent_id"], "codex-desktop")
        self.assertEqual(ack["pending_event_count"], 0)
        self.assertEqual(cursors["cursors"][0]["agent_id"], "codex-desktop")

    def test_agent_context_hydration_tool_briefs_and_acknowledges(self):
        registration = json.loads(
            mcp_server.remember_spiking_context(
                tag="mcp-agent-brief-memory",
                context_id="demo",
                text="MCP agent hydration should recall deployment context.",
                metadata={"surface": "mcp"},
            )
        )

        first = json.loads(
            mcp_server.hydrate_spiking_agent_context(
                agent_id="mcp-agent",
                context_id="demo",
                prompt="deployment context",
            )
        )
        second = json.loads(
            mcp_server.hydrate_spiking_agent_context(
                agent_id="mcp-agent",
                context_id="demo",
                prompt="deployment context",
            )
        )

        self.assertEqual(first["action"], "agent-context-hydrate")
        self.assertEqual(
            first["latest_event_id"],
            registration["agent_deployment"]["event_id"],
        )
        self.assertEqual(first["new_event_count"], 1)
        self.assertEqual(first["ack"]["agent_id"], "mcp-agent")
        self.assertTrue(first["ack"]["caught_up"])
        self.assertIn("mcp-agent-brief-memory", first["briefing_markdown"])
        self.assertIn("mcp-agent-brief-memory", first["recall_result"])
        self.assertIn("payload_summary", first["events"][0])
        self.assertNotIn(
            "MCP agent hydration should recall deployment context.",
            json.dumps(first["events"]),
        )
        self.assertIn("source_text_bytes", first["events"][0]["payload_summary"])
        self.assertEqual(second["new_event_count"], 0)
        self.assertEqual(
            second["since_event_id"],
            registration["agent_deployment"]["event_id"],
        )

    def test_cortex_governor_tools_enter_tick_commit_and_state(self):
        self.assertTrue(hasattr(mcp_server, "enter_spiking_cortex"))
        self.assertTrue(hasattr(mcp_server, "tick_spiking_cortex"))
        self.assertTrue(hasattr(mcp_server, "commit_spiking_cortical_trace"))
        self.assertTrue(hasattr(mcp_server, "moderate_spiking_cortical_trace"))
        self.assertTrue(hasattr(mcp_server, "get_spiking_cortex_state"))

        entered = json.loads(
            mcp_server.enter_spiking_cortex(
                agent_id="mcp-agent",
                context_id="demo",
                task="Govern MCP agent work.",
                mode="strict",
            )
        )
        tick = json.loads(
            mcp_server.tick_spiking_cortex(
                agent_id="mcp-agent",
                context_id="demo",
                session_id=entered["session_id"],
                observation="Preparing a mutation.",
                proposed_action="Edit code and run tests.",
                mutation_intent=True,
                confidence=0.4,
            )
        )
        committed = json.loads(
            mcp_server.commit_spiking_cortical_trace(
                agent_id="mcp-agent",
                context_id="demo",
                session_id=entered["session_id"],
                trace_type="validation",
                truth_posture="test-validated",
                text="MCP cortex tools returned structured governance state.",
                evidence_json='{"tests":["tests.test_mcp_server"]}',
            )
        )
        moderated = json.loads(
            mcp_server.moderate_spiking_cortical_trace(
                context_id="demo",
                memory_id=committed["memory_id"],
                action="promote",
                reason="MCP operator verified",
            )
        )
        state = json.loads(
            mcp_server.get_spiking_cortex_state(
                agent_id="mcp-agent",
                context_id="demo",
            )
        )

        self.assertEqual(entered["action"], "enter-spiking-cortex")
        self.assertEqual(tick["decision"], "verify-first")
        self.assertEqual(committed["trace_type"], "validation")
        self.assertEqual(moderated["moderation_action"], "promote")
        self.assertGreaterEqual(state["typed_memory_counts"]["validation"], 1)
        self.assertIn("cognitive_governance", state["policy"])

    def test_memory_export_tool_rejects_paths_outside_export_root(self):
        result = json.loads(
            mcp_server.export_spiking_memory(
                context_id="demo",
                output_path="/tmp/synapse-s2-outside-export.json",
            )
        )

        self.assertIn("error", result)
        self.assertIn("export root", result["error"])


if __name__ == "__main__":
    unittest.main()

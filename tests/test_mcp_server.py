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
        os.environ["SYNAPSE_S2_EXPORT_DIR"] = self.tmpdir.name
        self.addCleanup(self._restore_export_dir)

    def _restore_export_dir(self):
        if self.previous_export_dir is None:
            os.environ.pop("SYNAPSE_S2_EXPORT_DIR", None)
        else:
            os.environ["SYNAPSE_S2_EXPORT_DIR"] = self.previous_export_dir

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

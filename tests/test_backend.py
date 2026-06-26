import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
import time

import mlx.core as mx

from mlx_backend import SpikingAttentionBackend


class SpikingAttentionBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.state_path = Path(self.tmpdir.name) / "state.json"

    def test_encode_to_spikes_top_k_selects_standardized_top_coordinates(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=8,
            default_top_k=2,
            compile_graph=False,
            state_path=self.state_path,
        )

        spikes = backend.encode_to_spikes_top_k(mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]))

        self.assertEqual(spikes.tolist(), [0.0, 0.0, 1.0, 0.0, 1.0, 0.0])

    def test_encode_to_spikes_top_k_keeps_tied_sparse_vectors_bounded(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=8,
            default_top_k=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        spikes = backend.encode_to_spikes_top_k(mx.array([0.0] * 8))

        self.assertEqual(sum(spikes.tolist()), 3.0)

    def test_query_returns_context_tags_and_tracks_state(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        result = backend.query(mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]), context_id="demo")

        self.assertIn("demo::neuron-", result)
        self.assertGreater(len(backend.memory_mapping), 0)

    def test_register_trace_returns_named_tag_from_query(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        registration = backend.register_trace(
            tag="wing-load-analysis",
            embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        result = backend.query(
            mx.array([0.0, 1.0, 8.9, 2.1, 6.8, -4.0]),
            context_id="demo",
        )

        self.assertEqual(registration["tag"], "wing-load-analysis")
        self.assertIn("wing-load-analysis", result)
        self.assertNotIn("demo::neuron-", result)

    def test_registered_trace_persists_to_state_file(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "synapse-state.json"
            memory_path = Path(tmp) / "synapse-memory.sqlite3"
            backend = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            backend.register_trace(
                tag="procurement-memory",
                embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
                context_id="ops",
                metadata={"ticket": "S2"},
                source_text="Procurement memory should survive backend restarts.",
            )

            restored = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            result = restored.query(
                mx.array([0.0, 1.0, 8.8, 2.0, 6.9, -4.1]),
                context_id="ops",
            )
            memory = restored.list_memory(context_id="ops")

        self.assertIn("procurement-memory", result)
        self.assertEqual(memory["entries"][0]["source_text"], "Procurement memory should survive backend restarts.")
        self.assertEqual(memory["entries"][0]["metadata"], {"ticket": "S2"})
        self.assertEqual(memory["memory_db_path"], str(memory_path))

    def test_ingest_text_events_segments_persists_and_links_memory_graph(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        text = (
            "Apple Silicon MLX compiles spiking neural kernels into Metal. "
            "The local SNN tracks sparse top-k spike populations for recall. "
            "Procurement then reviews supplier budget exposure and contract risk. "
            "Finance needs renewal timing, approval owners, and payment status."
        )

        ingestion = backend.ingest_text_events(
            text=text,
            context_id="board-demo",
            source_tag="morning-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )
        graph = backend.list_memory_graph(context_id="board-demo")
        recall = backend.query(
            backend.embed_text("supplier budget contract risk"),
            context_id="board-demo",
        )

        self.assertGreaterEqual(ingestion["event_count"], 2)
        self.assertGreaterEqual(ingestion["relationship_count"], 1)
        self.assertEqual(ingestion["events"][0]["tag"], "morning-brief-event-001")
        self.assertTrue(graph["relationships"])
        self.assertEqual(graph["relationships"][0]["relation_type"], "temporal_next")
        self.assertIn("morning-brief-event", recall)

    def test_memory_graph_summarizes_temporal_and_associative_relationship_modes(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        text = (
            "Supplier contract renewal risk needs local recall. "
            "Apple Silicon kernels compile spiking attention locally. "
            "Supplier contract payment ownership needs associative follow-up."
        )

        backend.ingest_text_events(
            text=text,
            context_id="board-demo",
            source_tag="mode-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )
        graph = backend.list_memory_graph(context_id="board-demo")

        self.assertEqual(
            graph["relationship_summary"]["total"],
            graph["relationship_count"],
        )
        self.assertGreaterEqual(graph["relationship_summary"]["temporal"], 2)
        self.assertGreaterEqual(graph["relationship_summary"]["associative"], 1)
        self.assertEqual(
            graph["relationship_summary"]["by_type"]["temporal_next"],
            graph["relationship_summary"]["temporal"],
        )
        self.assertEqual(
            graph["relationship_summary"]["by_type"]["semantic_overlap"],
            graph["relationship_summary"]["associative"],
        )

    def test_query_expands_recall_with_related_event_graph_neighbors(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=1,
            compile_graph=False,
            state_path=self.state_path,
        )
        text = (
            "Apple Silicon MLX compiles spiking neural kernels into Metal. "
            "The local SNN tracks sparse top-k spike populations for recall. "
            "Procurement reviews supplier budget exposure and contract risk."
        )
        backend.ingest_text_events(
            text=text,
            context_id="board-demo",
            source_tag="graph-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )

        recall = backend.query(
            backend.embed_text("Apple Silicon MLX compiles spiking neural kernels into Metal."),
            context_id="board-demo",
        )

        self.assertIn("graph-brief-event-001", recall)
        self.assertIn("graph-brief-event-002", recall)

    def test_text_embedding_is_deterministic_for_cli_and_mcp_demo_use(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=16,
            compile_graph=False,
            state_path=self.state_path,
        )

        first = backend.embed_text("offboarding risk review", dimensions=32)
        second = backend.embed_text("offboarding risk review", dimensions=32)
        third = backend.embed_text("wing load analysis", dimensions=32)

        self.assertEqual(first.tolist(), second.tolist())
        self.assertNotEqual(first.tolist(), third.tolist())

    def test_global_toggle_disables_and_reenables_queries(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        disabled = backend.set_enabled(False)
        disabled_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="demo",
        )
        enabled = backend.set_enabled(True)
        enabled_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="demo",
        )

        self.assertFalse(disabled["global_enabled"])
        self.assertIn("disabled", disabled_query.lower())
        self.assertTrue(enabled["global_enabled"])
        self.assertIn("demo::neuron-", enabled_query)

    def test_context_toggle_overrides_global_state(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        backend.set_enabled(True)
        backend.set_enabled(False, context_id="quiet-demo")

        quiet_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="quiet-demo",
        )
        active_query = backend.query(
            mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
            context_id="active-demo",
        )

        self.assertIn("disabled", quiet_query.lower())
        self.assertIn("active-demo::neuron-", active_query)

    def test_toggle_state_persists_to_state_file(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "synapse-state.json"
            backend = SpikingAttentionBackend(
                dimension=4,
                num_neurons=6,
                compile_graph=False,
                state_path=state_path,
            )

            backend.set_enabled(False, context_id="demo")
            restored = SpikingAttentionBackend(
                dimension=4,
                num_neurons=6,
                compile_graph=False,
                state_path=state_path,
            )

        status = restored.status(context_id="demo")

        self.assertTrue(status["global_enabled"])
        self.assertFalse(status["effective_enabled"])
        self.assertEqual(status["context_overrides"], {"demo": False})

    def test_status_reports_demo_readiness_fields(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        status = backend.status(context_id="demo")

        self.assertEqual(status["context_id"], "demo")
        self.assertTrue(status["effective_enabled"])
        self.assertEqual(status["dimension"], 4)
        self.assertEqual(status["num_neurons"], 6)
        self.assertIn("mlx_available", status)
        self.assertIn("mlxsnn_available", status)
        self.assertIn("memory_db_path", status)
        self.assertIn("memory_entry_count", status)
        self.assertIn("memory_event_count", status)
        self.assertEqual(status["quick_pruning_interval_seconds"], 300.0)
        self.assertEqual(status["idle_deep_sleep_seconds"], 1800.0)
        self.assertEqual(
            status["consolidation_phase_names"],
            [
                "connection-weight-decay",
                "synaptic-clustering",
                "semantic-merging",
                "threshold-rescoring",
                "trace-promotion",
                "relationship-extraction",
                "neurogenesis",
            ],
        )

    def test_resource_profile_reports_topology_memory_and_pruning_budget(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )

        profile = backend.resource_profile(benchmark_quick_prune=True)

        self.assertEqual(profile["dimension"], 8)
        self.assertEqual(profile["num_neurons"], 6)
        self.assertEqual(profile["arrays"]["W_syn"]["elements"], 48)
        self.assertEqual(profile["arrays"]["W_lateral"]["elements"], 36)
        self.assertGreater(profile["estimated_total_mb"], 0.0)
        self.assertIn("within_target_envelope", profile)
        self.assertTrue(profile["quick_pruning"]["within_60ms_budget"])

    def test_backend_exports_and_backs_up_real_memory_store(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            export_path = Path(tmp) / "memory-export.json"
            backup_path = Path(tmp) / "memory-backup.sqlite3"
            backend = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            backend.register_trace(
                tag="ops-memory",
                embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
                context_id="ops",
                metadata={"owner": "it"},
                source_text="Operators can inspect and export this memory.",
            )

            listing = backend.list_memory(context_id="ops")
            exported = backend.export_memory(path=export_path, context_id="ops")
            backup = backend.backup_memory(backup_path)
            export_exists = export_path.exists()
            backup_exists = backup_path.exists()

        self.assertEqual(listing["entry_count"], 1)
        self.assertEqual(exported["entries"][0]["tag"], "ops-memory")
        self.assertTrue(export_exists)
        self.assertEqual(backup["entry_count"], 1)
        self.assertTrue(backup_exists)

    def test_backend_publishes_context_events_for_connected_agents(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        event = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="remember-trace",
            summary="operator-note deployed",
            payload={"tag": "operator-note", "memory_id": "s2_demo"},
        )
        listing = backend.list_context_events(context_id="demo", limit=5)
        status = backend.status(context_id="demo")

        self.assertTrue(event["published"])
        self.assertEqual(event["delivery_mode"], "durable-mcp-pull")
        self.assertEqual(event["agent_targets"], ["mcp-clients", "codex-desktop", "local-ide-adapters"])
        self.assertEqual(listing["events"][0]["summary"], "operator-note deployed")
        self.assertEqual(status["context_bus_context_event_count"], 1)
        self.assertEqual(status["context_bus_latest_event_id"], event["event_id"])

    def test_quick_pruning_decays_weights_and_resets_membrane(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.state = {
            "mem": mx.ones((6,)),
            "spk": mx.ones((6,)),
        }
        before_weight = float(backend.W_syn[0, 0])

        status = backend.run_quick_pruning()

        self.assertEqual(status["mode"], "quick-pruning")
        self.assertEqual(status["trigger"], "manual")
        self.assertTrue(status["gpu_non_llm"])
        self.assertTrue(status["within_60ms_budget"])
        self.assertLessEqual(abs(float(backend.W_syn[0, 0])), abs(before_weight) + 1e-6)
        self.assertEqual(backend.state["mem"].tolist(), [0.0] * 6)

    def test_quick_pruning_uses_lazy_scalar_decay_for_large_substrates(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
            quick_pruning_eager_decay_elements=1,
        )
        before_weight = float(backend.W_syn[0, 0])

        status = backend.run_quick_pruning()

        self.assertEqual(status["decay_strategy"], "lazy-scalar")
        self.assertEqual(float(backend.W_syn[0, 0]), before_weight)
        self.assertLess(status["W_syn_decay_multiplier"], 1.0)
        self.assertLess(status["W_lateral_decay_multiplier"], 1.0)
        self.assertTrue(status["within_60ms_budget"])

    def test_query_auto_runs_quick_pruning_after_configured_interval(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            default_top_k=2,
            compile_graph=False,
            state_path=self.state_path,
            quick_pruning_interval_seconds=300.0,
        )
        backend.last_pruning_monotonic = time.monotonic() - 301.0

        result = backend.query(mx.array([0.0, 2.0, 7.0, -1.0]), context_id="demo")

        self.assertIn("demo::neuron-", result)
        self.assertEqual(backend.quick_pruning_count, 1)
        self.assertEqual(backend.last_maintenance["mode"], "quick-pruning")
        self.assertEqual(backend.last_maintenance["trigger"], "auto:query")

    def test_deep_sleep_consolidation_builds_semantic_hierarchy(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.memory_mapping = {
            1: "demo::neuron-000001",
            2: "demo::neuron-000002",
        }
        backend.active_traces = mx.array([0.0, 2.0, 1.5, 0.0, 0.0, 0.0])

        status = backend.run_deep_sleep_consolidation()

        self.assertEqual(status["mode"], "deep-sleep")
        self.assertIn("demo", backend.semantic_hierarchy)
        self.assertEqual(
            backend.semantic_hierarchy["demo"]["members"],
            ["demo::neuron-000001", "demo::neuron-000002"],
        )

    def test_deep_sleep_reports_all_proposal_consolidation_phases(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.register_trace(
            tag="proposal-memory",
            embedding=mx.array([0.0, 1.0, 9.0, 2.0]),
            context_id="proposal",
            metadata={"source": "unit-test"},
            source_text="Proposal lifecycle coverage.",
        )

        status = backend.run_deep_sleep_consolidation()
        phase_names = [phase["name"] for phase in status["phases"]]

        self.assertEqual(status["phase_count"], 7)
        self.assertEqual(
            phase_names,
            [
                "connection-weight-decay",
                "synaptic-clustering",
                "semantic-merging",
                "threshold-rescoring",
                "trace-promotion",
                "relationship-extraction",
                "neurogenesis",
            ],
        )
        self.assertEqual(status["phases"][4]["promoted_trace_count"], 1)
        self.assertEqual(status["phases"][5]["contexts"], ["proposal"])

    def test_deep_sleep_consolidation_includes_relationship_graph(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.ingest_text_events(
            text=(
                "Apple Silicon MLX compiles spiking kernels into Metal. "
                "Sparse spike populations recall local context. "
                "Procurement reviews supplier budget exposure and contract risk."
            ),
            context_id="board-demo",
            source_tag="sleep-brief",
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )

        status = backend.run_deep_sleep_consolidation()

        self.assertEqual(status["mode"], "deep-sleep")
        self.assertIn("relationships", backend.semantic_hierarchy["board-demo"])
        self.assertGreaterEqual(
            backend.semantic_hierarchy["board-demo"]["relationship_count"],
            1,
        )

    def test_idle_maintenance_runs_deep_sleep_after_idle_threshold(self):
        backend = SpikingAttentionBackend(
            dimension=4,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
            idle_deep_sleep_seconds=1.0,
        )
        backend.memory_mapping = {
            1: "idle::neuron-000001",
            2: "idle::neuron-000002",
        }
        backend.active_traces = mx.array([0.0, 2.0, 1.5, 0.0, 0.0, 0.0])
        backend.last_activity_monotonic = time.monotonic() - 2.0

        status = backend.run_idle_maintenance()

        self.assertEqual(status["mode"], "deep-sleep")
        self.assertEqual(status["trigger"], "idle-threshold")
        self.assertTrue(status["maintenance_run"])
        self.assertEqual(status["phase_count"], 7)
        self.assertEqual(backend.deep_sleep_count, 1)


if __name__ == "__main__":
    unittest.main()

import json
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
import time
import subprocess

import mlx.core as mx

import mlx_backend
from mlx_backend import BackendUnavailable
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

    def test_query_without_registered_memory_reports_raw_activation_not_fake_tags(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )

        result = backend.query(mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]), context_id="demo")

        self.assertIn("No registered historical context matched", result)
        self.assertIn("raw_activation_top_neurons=", result)
        self.assertNotIn("demo::neuron-", result)
        self.assertEqual(len(backend.memory_mapping), 0)

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
        self.assertTrue(ingestion["events"][0]["tag"].startswith("morning-brief-event-001-"))
        self.assertTrue(graph["relationships"])
        self.assertEqual(graph["relationships"][0]["relation_type"], "temporal_next")
        self.assertIn("morning-brief-event", recall)

    def test_ingest_text_events_records_embedding_surprise_metadata(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        ingestion = backend.ingest_text_events(
            text=(
                "Metal compiles local kernels for M-series acceleration. "
                "On-chip GPU execution keeps native compute efficient. "
                "Finance approval owners track contract renewal risk."
            ),
            context_id="default",
            source_tag="semantic-surprise",
            surprise_threshold=0.40,
            min_segment_sentences=1,
        )
        memory = backend.list_memory(context_id="default", limit=10)
        first_event = next(
            entry
            for entry in memory["entries"]
            if entry["tag"].startswith("semantic-surprise-event-001-")
        )

        self.assertEqual(
            ingestion["events"][0]["segment"]["surprise_mode"],
            "embedding",
        )
        self.assertEqual(first_event["metadata"]["surprise_mode"], "embedding")
        self.assertIn("semantic_surprise_score", first_event["metadata"])
        self.assertEqual(
            first_event["metadata"]["surprise_model"]["embedding_provider"],
            "semantic-hash-v1",
        )
        self.assertTrue(ingestion["surprise_model"]["semantic"])

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

    def test_memory_graph_prioritizes_relationship_endpoints_over_recent_noise(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=3,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        source = backend.register_trace(
            tag="old-critical-source",
            embedding=[0.1, 0.9, 0.2, 0.8, 0.0, -0.1, 0.4, 0.7],
            context_id="demo",
            metadata={"display_label": "old critical source"},
            source_text="Older critical source node.",
        )
        target = backend.register_trace(
            tag="old-critical-target",
            embedding=[0.0, 0.7, 0.3, 0.9, 0.1, -0.2, 0.5, 0.6],
            context_id="demo",
            metadata={"display_label": "old critical target"},
            source_text="Older critical target node.",
        )
        backend.memory_store.upsert_relationship(
            context_id="demo",
            source_memory_id=source["memory_id"],
            target_memory_id=target["memory_id"],
            relation_type="semantic_overlap",
            weight=0.93,
            evidence={"keywords": ["critical", "edge"]},
        )
        for index in range(6):
            backend.register_trace(
                tag=f"new-noise-{index}",
                embedding=[float(index), 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7],
                context_id="demo",
                source_text=f"New unrelated dashboard note {index}.",
            )

        graph = backend.list_memory_graph(context_id="demo", limit=3)
        graph_ids = {entry["memory_id"] for entry in graph["entries"]}

        self.assertEqual(graph["graph_entry_strategy"], "relationship_endpoints_first")
        self.assertEqual(graph["relationship_endpoint_count"], 2)
        self.assertIn(source["memory_id"], graph_ids)
        self.assertIn(target["memory_id"], graph_ids)
        self.assertEqual(graph["relationships"][0]["source_label"], "old critical source")
        self.assertEqual(graph["relationships"][0]["target_label"], "old critical target")

    def test_memory_graph_entries_include_bounded_neural_inspector_samples(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=16,
            default_top_k=3,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.register_trace(
            tag="inspector-memory",
            embedding=[0.0, 0.2, 0.9, -0.7, 0.4, 0.8, -0.1, 0.3],
            context_id="demo",
        )

        graph = backend.list_memory_graph(context_id="demo", limit=5)
        entry = graph["entries"][0]
        status = backend.status(context_id="demo")

        self.assertEqual(entry["tag"], "inspector-memory")
        self.assertEqual(entry["spike_count"], 3)
        self.assertEqual(entry["neuron_count"], 3)
        self.assertEqual(status["beta"], 0.95)
        self.assertEqual(status["threshold"], 1.0)
        self.assertIn("spike_coordinate_sample", entry)
        self.assertIn("neuron_index_sample", entry)
        self.assertLessEqual(len(entry["spike_coordinate_sample"]), 12)
        self.assertLessEqual(len(entry["neuron_index_sample"]), 12)
        self.assertTrue(
            all(isinstance(value, int) for value in entry["spike_coordinate_sample"])
        )
        self.assertTrue(
            all(isinstance(value, int) for value in entry["neuron_index_sample"])
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

    def test_text_embedding_provider_status_and_provenance_are_visible(self):
        backend = SpikingAttentionBackend(
            dimension=48,
            num_neurons=24,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        payload = backend.embed_text_payload("Apple Silicon Metal acceleration", dimensions=48)
        registration = backend.register_text_trace(
            tag="semantic-provider-memory",
            text="Apple Silicon Metal acceleration",
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        memory = backend.list_memory(context_id="demo")
        status = backend.status(context_id="demo")

        self.assertEqual(payload["provenance"]["provider"], "semantic-hash-v1")
        self.assertTrue(payload["provenance"]["semantic"])
        self.assertEqual(status["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertTrue(status["embedding_provider"]["semantic"])
        self.assertEqual(registration["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertEqual(
            memory["entries"][0]["metadata"]["embedding_provider"]["provider"],
            "semantic-hash-v1",
        )
        self.assertEqual(memory["entries"][0]["metadata"]["source"], "unit-test")

    def test_semantic_provider_improves_related_phrase_recall_without_exact_tokens(self):
        backend = SpikingAttentionBackend(
            dimension=96,
            num_neurons=48,
            default_top_k=8,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        backend.register_text_trace(
            tag="native-metal-memory",
            text="Apple Silicon Metal kernels accelerate the local spiking runtime.",
            context_id="demo",
        )

        result = backend.query(
            backend.embed_text("M-series MLX GPU compute path"),
            context_id="demo",
        )

        self.assertIn("native-metal-memory", result)

    def test_native_certification_reports_checks_and_writes_evidence(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            evidence_path = Path(tmp) / "certification.json"
            backend = SpikingAttentionBackend(
                dimension=8,
                num_neurons=6,
                compile_graph=False,
                state_path=state_path,
            )

            certification = backend.certify_runtime(
                strict_native=False,
                benchmark_quick_prune=True,
                output_path=evidence_path,
            )
            evidence_exists = evidence_path.exists()

        self.assertTrue(evidence_exists)
        self.assertEqual(certification["action"], "certify-runtime")
        self.assertIn("checks", certification)
        self.assertIn("resource_profile", certification)
        self.assertIn("quick_pruning", certification["resource_profile"])
        self.assertEqual(certification["evidence_path"], str(evidence_path.resolve()))
        self.assertEqual(certification["checks"]["mlx_available"]["passed"], True)
        self.assertIn("embedding_provider_native_mlx", certification["checks"])

    def test_native_certification_retries_cold_quick_prune_sample(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        samples = [
            {"elapsed_ms": 67.0, "within_60ms_budget": False},
            {"elapsed_ms": 11.5, "within_60ms_budget": True},
        ]

        def fake_quick_prune(*, trigger: str = "manual") -> dict:
            sample = dict(samples.pop(0))
            sample.update(
                {
                    "mode": "quick-pruning",
                    "trigger": trigger,
                    "gpu_non_llm": True,
                    "decay_strategy": "lazy-scalar",
                    "membrane_reset": True,
                }
            )
            return sample

        backend.run_quick_pruning = fake_quick_prune  # type: ignore[method-assign]

        certification = backend.certify_runtime(benchmark_quick_prune=True)
        quick_profile = certification["resource_profile"]["quick_pruning"]

        self.assertTrue(certification["checks"]["quick_pruning_budget"]["passed"])
        self.assertEqual(quick_profile["elapsed_ms"], 11.5)
        self.assertEqual(quick_profile["sample_count"], 2)
        self.assertTrue(quick_profile["cold_start_retry_used"])
        self.assertEqual(
            [sample["elapsed_ms"] for sample in quick_profile["samples"]],
            [67.0, 11.5],
        )

    def test_native_certification_strict_mode_fails_when_lif_downgrades(self):
        backend = SpikingAttentionBackend(
            dimension=8,
            num_neurons=6,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend._mlxsnn_lif_layer = None

        certification = backend.certify_runtime(strict_native=True)

        self.assertFalse(certification["ready"])
        self.assertTrue(certification["strict_native"])
        self.assertIn("mlxsnn_lif_execution_path", certification["failed_checks"])

    def test_require_native_constructor_raises_when_mlxsnn_is_unavailable(self):
        original_mlxsnn = mlx_backend.mlxsnn
        try:
            mlx_backend.mlxsnn = None
            with self.assertRaises(BackendUnavailable):
                SpikingAttentionBackend(
                    dimension=8,
                    num_neurons=6,
                    compile_graph=False,
                    state_path=self.state_path,
                    require_native=True,
                )
        finally:
            mlx_backend.mlxsnn = original_mlxsnn

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
        self.assertIn("No registered historical context matched", enabled_query)
        self.assertNotIn("demo::neuron-", enabled_query)

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
        self.assertIn("No registered historical context matched", active_query)
        self.assertNotIn("active-demo::neuron-", active_query)

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
        self.assertEqual(profile["target_envelope_mb"], {"min": 96.0, "max": 384.0})
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

    def test_backend_tracks_context_event_delivery_receipts_by_agent(self):
        backend = SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.state_path,
        )
        first = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="remember-trace",
            summary="first deployed",
            payload={"tag": "first"},
        )
        second = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="ingest-events",
            summary="second deployed",
            payload={"tag": "second"},
        )

        ack = backend.ack_context_events(
            context_id="demo",
            agent_id="codex-desktop",
            last_event_id=first["event_id"],
        )
        cursors = backend.list_context_cursors(context_id="demo")
        status = backend.status(context_id="demo")

        self.assertEqual(ack["agent_id"], "codex-desktop")
        self.assertEqual(ack["last_event_id"], first["event_id"])
        self.assertEqual(ack["latest_event_id"], second["event_id"])
        self.assertEqual(ack["pending_event_count"], 1)
        self.assertEqual(cursors["cursor_count"], 1)
        self.assertEqual(cursors["cursors"][0]["agent_id"], "codex-desktop")
        self.assertEqual(status["context_bus_ack_cursor_count"], 1)

    def test_agent_context_hydration_briefs_recalls_and_advances_cursor(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        registration = backend.register_trace(
            tag="agent-brief-memory",
            embedding=backend.embed_text("agent hydration should recall the sidecar context"),
            context_id="demo",
            source_text="agent hydration should recall the sidecar context",
            metadata={"source": "unit-test"},
        )
        event = backend.publish_context_event(
            context_id="demo",
            source_surface="unit-test",
            event_type="remember-trace",
            summary="agent-brief-memory captured and published",
            payload={"tag": registration["tag"], "memory_id": registration["memory_id"]},
        )

        first = backend.hydrate_agent_context(
            context_id="demo",
            agent_id="codex-hydrator",
            prompt="sidecar context recall",
        )
        second = backend.hydrate_agent_context(
            context_id="demo",
            agent_id="codex-hydrator",
            prompt="sidecar context recall",
        )

        self.assertEqual(first["action"], "agent-context-hydrate")
        self.assertEqual(first["context_id"], "demo")
        self.assertEqual(first["agent_id"], "codex-hydrator")
        self.assertEqual(first["new_event_count"], 1)
        self.assertEqual(first["latest_event_id"], event["event_id"])
        self.assertEqual(first["ack"]["last_event_id"], event["event_id"])
        self.assertTrue(first["ack"]["caught_up"])
        self.assertIn("agent-brief-memory captured and published", first["briefing_markdown"])
        self.assertIn("agent-brief-memory", first["recall_result"])
        self.assertEqual(first["graph_summary"]["entry_count"], 1)
        self.assertEqual(second["new_event_count"], 0)
        self.assertEqual(second["since_event_id"], event["event_id"])
        self.assertEqual(second["ack"]["last_event_id"], event["event_id"])

    def test_cortex_governor_enters_ticks_and_commits_typed_trace(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="operator",
            session_id="seed-session",
            trace_type="constraint",
            truth_posture="operator-confirmed",
            text="Operator requires tests before claiming Cortex Governor is complete.",
            evidence={"source": "unit-test"},
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="seed-session",
            trace_type="assumption",
            truth_posture="inferred",
            text="Maybe the dashboard already carries intended file scope.",
            evidence={"source": "unit-test"},
            confidence=0.42,
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="seed-session",
            trace_type="correction",
            truth_posture="operator-confirmed",
            text="Correction: Cortex ticks must declare intended files and tools before mutation.",
            evidence={"source": "unit-test"},
        )

        entry = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Implement the Cortex Governor release with tests.",
            mode="strict",
        )
        tick = backend.cortex_tick(
            context_id="demo",
            agent_id="codex",
            session_id=entry["session_id"],
            observation="About to edit backend and MCP files.",
            proposed_action="Modify mlx_backend.py and mcp_server.py, then run tests.",
            intended_files=["mlx_backend.py", "mcp_server.py"],
            intended_tools=["apply_patch", "python -m unittest tests.test_backend"],
            mutation_intent=True,
            confidence=0.42,
        )
        commit = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=entry["session_id"],
            trace_type="validation",
            truth_posture="test-validated",
            text="Cortex Governor tests passed for backend, CLI, MCP, and dashboard surfaces.",
            evidence={"tests": ["tests.test_backend"], "commit": "pending"},
        )
        state = backend.get_cortex_state(context_id="demo", agent_id="codex")
        close = backend.close_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            session_id=entry["session_id"],
            reason="unit-test-complete",
        )
        closed_state = backend.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(entry["action"], "enter-spiking-cortex")
        self.assertEqual(entry["mode"], "strict")
        self.assertIn("verify-before-mutation", entry["governance_contract"])
        self.assertEqual(entry["agent_deployment"]["event_type"], "cortex-entered")
        self.assertEqual(tick["action"], "cortex-tick")
        self.assertEqual(tick["session_id"], entry["session_id"])
        self.assertEqual(tick["decision"], "verify-first")
        self.assertEqual(tick["intended_files"], ["mlx_backend.py", "mcp_server.py"])
        self.assertEqual(
            tick["intended_tools"],
            ["apply_patch", "python -m unittest tests.test_backend"],
        )
        self.assertTrue(
            any(item["code"] == "mutation-verification-required" for item in tick["warnings"])
        )
        self.assertFalse(
            any(item["code"] == "missing-intent-scope" for item in tick["warnings"])
        )
        self.assertGreaterEqual(len(tick["recalled_constraints"]), 1)
        self.assertTrue(tick["capture_recommendation"]["recommended"])
        self.assertGreaterEqual(len(tick["cortex_state"]["capture_queue"]), 1)
        self.assertEqual(commit["action"], "commit-cortical-trace")
        self.assertEqual(commit["trace_type"], "validation")
        self.assertEqual(commit["truth_posture"], "test-validated")
        self.assertGreaterEqual(commit["confidence"], 0.85)
        self.assertEqual(commit["agent_deployment"]["event_type"], "cortex-trace-committed")
        self.assertEqual(state["action"], "cortex-state")
        self.assertEqual(state["active_goal"], "Implement the Cortex Governor release with tests.")
        self.assertEqual(state["active_sessions"][0]["session_id"], entry["session_id"])
        self.assertEqual(state["active_sessions"][0]["last_intended_files"], ["mlx_backend.py", "mcp_server.py"])
        self.assertIn("Resolve the surfaced correction", state["suggested_next_move"])
        self.assertEqual(len(state["capture_queue"]), 0)
        self.assertGreaterEqual(len(state["unverified_assumptions"]), 1)
        self.assertGreaterEqual(len(state["contradictions"]), 1)
        self.assertGreaterEqual(state["typed_memory_counts"]["validation"], 1)
        self.assertTrue(
            any(item["trace_type"] == "validation" for item in state["high_confidence_truths"])
        )
        self.assertEqual(close["action"], "close-spiking-cortex")
        self.assertEqual(close["status"], "closed")
        self.assertEqual(close["agent_deployment"]["event_type"], "cortex-closed")
        self.assertEqual(close["cortex_state"]["active_session_count"], 0)
        self.assertEqual(closed_state["active_session_count"], 0)

    def test_cortex_close_survives_stale_backend_runtime_persist(self):
        backend_a = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        first = backend_a.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Stale process first session.",
            mode="strict",
        )
        second = backend_a.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Stale process second session.",
            mode="strict",
        )

        backend_b = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend_b.close_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            session_id=first["session_id"],
            reason="closed-by-fresh-process",
        )
        backend_b.close_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            session_id=second["session_id"],
            reason="closed-by-fresh-process",
        )

        # Simulates a long-running dashboard/backend persisting an unrelated
        # setting after another process closed the sessions.
        backend_a.set_enabled(True, context_id="demo")

        backend_c = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        state = backend_c.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(state["active_session_count"], 0)
        self.assertEqual(backend_c.cortex_sessions[first["session_id"]]["status"], "closed")
        self.assertEqual(backend_c.cortex_sessions[second["session_id"]]["status"], "closed")

    def test_agent_context_hydration_includes_cortex_state(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Hydrate with governed memory.",
            mode="strict",
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=session["session_id"],
            trace_type="decision",
            truth_posture="operator-confirmed",
            text="Cortex hydration must expose active goals, decisions, and risks.",
            evidence={"source": "unit-test"},
        )

        hydrated = backend.hydrate_agent_context(
            context_id="demo",
            agent_id="codex",
            prompt="governed memory",
        )

        self.assertIn("cortex_state", hydrated)
        self.assertGreaterEqual(hydrated["cortex_state"]["typed_memory_counts"]["decision"], 1)
        self.assertIn("## Cortex Governor", hydrated["briefing_markdown"])
        self.assertIn("Active Sessions", hydrated["briefing_markdown"])

    def test_cortex_state_scans_beyond_visible_limit_for_typed_counts(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Keep governed memory visible with a small UI limit.",
            mode="strict",
        )
        backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=session["session_id"],
            trace_type="validation",
            truth_posture="test-validated",
            text="Cortex typed counts must survive newer non-cortex graph entries.",
            evidence={"source": "unit-test", "tests": ["tests.test_backend"]},
        )
        for index in range(8):
            backend.register_text_trace(
                tag=f"ordinary-memory-{index}",
                context_id="demo",
                text=f"Ordinary newer memory {index} should not hide cortical counts.",
                metadata={"source": "unit-test"},
            )

        state = backend.get_cortex_state(context_id="demo", agent_id="codex", limit=2)

        self.assertGreaterEqual(state["typed_memory_counts"]["validation"], 1)
        self.assertLessEqual(len(state["working_memory"]), 2)

    def test_cortex_state_reaps_dead_client_bridge_sessions(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Represent a wrapped MCP client process.",
            mode="strict",
        )
        child = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        child.wait(timeout=5)
        raw_session = dict(backend.cortex_sessions[session["session_id"]])
        raw_session.update(
            {
                "lease_kind": "mcp-client",
                "owner_pid": child.pid,
                "client_bridge_session_id": "unit-test-bridge",
            }
        )
        backend.cortex_sessions[session["session_id"]] = backend._normalize_cortex_session(
            raw_session
        )
        backend._persist_runtime_state()

        state = backend.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(state["active_session_count"], 0)
        self.assertEqual(
            backend.cortex_sessions[session["session_id"]]["status"],
            "orphaned",
        )

    def test_moderate_cortex_trace_promotes_demotes_and_prunes(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        session = backend.enter_spiking_cortex(
            context_id="demo",
            agent_id="codex",
            task="Moderate a cortical trace.",
            mode="strict",
        )
        committed = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id=session["session_id"],
            trace_type="assumption",
            truth_posture="inferred",
            text="This assumption needs operator moderation.",
            confidence=0.42,
        )

        promoted = backend.moderate_cortex_trace(
            context_id="demo",
            memory_id=committed["memory_id"],
            action="promote",
            reason="operator verified",
        )
        demoted = backend.moderate_cortex_trace(
            context_id="demo",
            memory_id=committed["memory_id"],
            action="demote",
            reason="operator marked stale",
        )
        pruned = backend.moderate_cortex_trace(
            context_id="demo",
            memory_id=committed["memory_id"],
            action="prune",
            reason="operator removed trace",
            confirm=True,
        )
        state = backend.get_cortex_state(context_id="demo", agent_id="codex")

        self.assertEqual(promoted["action"], "moderate-cortex-trace")
        self.assertEqual(promoted["moderation_action"], "promote")
        self.assertGreaterEqual(promoted["trace"]["confidence"], 0.9)
        self.assertEqual(promoted["trace"]["truth_posture"], "operator-confirmed")
        self.assertEqual(demoted["moderation_action"], "demote")
        self.assertLessEqual(demoted["trace"]["confidence"], 0.35)
        self.assertEqual(demoted["trace"]["truth_posture"], "stale")
        self.assertTrue(pruned["prune"]["result"]["deleted"])
        self.assertNotIn("assumption", state["typed_memory_counts"])

    def test_cortex_prune_requires_explicit_confirmation(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        committed = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="moderation-session",
            trace_type="assumption",
            truth_posture="inferred",
            text="This trace should require explicit confirmation before prune.",
            confidence=0.42,
        )

        with self.assertRaisesRegex(ValueError, "confirm"):
            backend.moderate_cortex_trace(
                context_id="demo",
                memory_id=committed["memory_id"],
                action="prune",
                reason="missing confirmation",
            )

        still_present = backend.memory_store.get_entry(committed["memory_id"])
        self.assertIsNotNone(still_present)

    def test_test_validated_cortex_commit_requires_concrete_evidence(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )

        with self.assertRaisesRegex(ValueError, "concrete validation evidence"):
            backend.commit_cortical_trace(
                context_id="demo",
                agent_id="codex",
                session_id="validation-session",
                trace_type="validation",
                truth_posture="test-validated",
                text="This claim lacks a concrete validation artifact.",
                evidence={"source": "unit-test"},
            )

        committed = backend.commit_cortical_trace(
            context_id="demo",
            agent_id="codex",
            session_id="validation-session",
            trace_type="validation",
            truth_posture="test-validated",
            text="This claim includes a concrete validation artifact.",
            evidence={"tests": ["tests.test_backend"], "command": "python -m unittest"},
        )

        self.assertEqual(committed["truth_posture"], "test-validated")
        self.assertGreaterEqual(committed["confidence"], 0.85)

    def test_capture_conversation_creates_event_graph_and_context_deployment(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )

        capture = backend.capture_conversation(
            text=(
                "User asked that future Codex conversations appear in the graph. "
                "Codex added a durable capture path for session notes. "
                "Operators can prune sensitive or partial information later."
            ),
            context_id="demo",
            source_tag="codex-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=20)
        deployments = backend.list_context_events(context_id="demo", limit=10)

        self.assertGreaterEqual(capture["event_count"], 2)
        self.assertTrue(capture["agent_deployment"]["published"])
        self.assertEqual(capture["agent_deployment"]["event_type"], "conversation-capture")
        self.assertGreaterEqual(graph["relationship_summary"]["temporal"], 1)
        self.assertTrue(
            all(
                entry["metadata"].get("conversation_capture") is True
                for entry in graph["entries"]
                if entry["tag"].startswith("codex-session-event")
            )
        )
        self.assertEqual(
            deployments["events"][-1]["payload"]["source_tag"],
            "codex-session",
        )

    def test_capture_conversation_automates_context_namespace_and_typed_nodes(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )

        capture = backend.capture_conversation(
            text=(
                "Thread: Namespace automation release. "
                "Goal: automatically create visible contextual memory namespaces. "
                "Objective: grow graph nodes for each new topic, feature, goal, and event. "
                "Event: user began the namespace automation feature and expects nodes to grow."
            ),
            context_id="demo",
            source_tag="namespace-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=40)
        deployments = backend.list_context_events(context_id="demo", limit=10)
        namespace = capture["context_namespace"]
        typed_entries = [
            entry
            for entry in graph["entries"]
            if entry["metadata"].get("context_automation") is True
        ]
        typed_memory_types = {
            entry["metadata"].get("context_memory_type")
            for entry in typed_entries
        }
        namespace_relationships = [
            relationship
            for relationship in graph["relationships"]
            if relationship["relation_type"] == "namespace_contains"
        ]

        self.assertEqual(namespace["namespace_id"], "namespace-automation-release")
        self.assertGreaterEqual(namespace["node_count"], 5)
        self.assertIn("namespace", typed_memory_types)
        self.assertIn("topic", typed_memory_types)
        self.assertIn("goal", typed_memory_types)
        self.assertIn("objective", typed_memory_types)
        self.assertIn("event", typed_memory_types)
        self.assertGreaterEqual(len(namespace_relationships), 4)
        self.assertTrue(
            any(
                entry["metadata"].get("context_namespace")
                == "namespace-automation-release"
                for entry in graph["entries"]
                if entry["tag"].startswith("namespace-session-event")
            )
        )
        self.assertEqual(
            deployments["events"][-1]["payload"]["context_namespace"]["namespace_id"],
            "namespace-automation-release",
        )

    def test_capture_conversation_adds_surface_node_details_and_relationship_labels(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        backend.capture_conversation(
            text=(
                "Thread: Surface detail release. "
                "Goal: add granular shorthand labels to graph memory nodes. "
                "Objective: related-topic searches should recall semantic facets, not only event tags. "
                "Event: user inspected spike nodes and asked for fine surface detail."
            ),
            context_id="demo",
            source_tag="surface-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=40)
        detailed_entries = [
            entry
            for entry in graph["entries"]
            if entry["metadata"].get("context_namespace") == "surface-detail-release"
        ]
        namespace_relationships = [
            relationship
            for relationship in graph["relationships"]
            if relationship["relation_type"] == "namespace_contains"
        ]
        recall = backend.query(
            backend.embed_text("fine grained related topic search facets"),
            context_id="demo",
        )

        self.assertTrue(detailed_entries)
        self.assertTrue(
            all(entry["metadata"].get("display_label") for entry in detailed_entries)
        )
        self.assertTrue(
            all(entry["metadata"].get("display_summary") for entry in detailed_entries)
        )
        self.assertTrue(
            all(entry["metadata"].get("semantic_facets") for entry in detailed_entries)
        )
        self.assertTrue(namespace_relationships)
        self.assertTrue(
            all(relationship.get("source_label") for relationship in namespace_relationships)
        )
        self.assertTrue(
            all(relationship.get("target_label") for relationship in namespace_relationships)
        )
        self.assertIn("label=", recall)
        self.assertIn("facets=", recall)
        self.assertIn("surface", recall.lower())

    def test_query_text_uses_surface_facets_for_related_topic_recall(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        backend.capture_conversation(
            text=(
                "Thread: Surface detail release. "
                "Goal: make graph nodes expose short semantic labels, summaries, and facets. "
                "Objective: related-topic recall should show why nodes matched instead of only raw event tags."
            ),
            context_id="demo",
            source_tag="surface-session",
            speaker="codex",
        )
        backend.capture_conversation(
            text=(
                "Thread: Startup boundary noise. "
                "Event: clients ended and reported generic recall statistics."
            ),
            context_id="demo",
            source_tag="client-session-boundary",
            speaker="codex",
        )

        recall = backend.query_text(
            "surface detail semantic facets related topic",
            context_id="demo",
        )

        self.assertIn("Surface detail release", recall)
        self.assertIn("facets=", recall)
        self.assertIn("semantic", recall.lower())

    def test_query_text_ranks_fresh_concrete_operational_trace_before_broad_summary(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        old_registration = backend.register_text_trace(
            tag="old-readiness-summary",
            text=(
                "SYNAPSE-S2 Monday readiness covers default topology, App Connect, "
                "Codex, Cursor, Claude installed state, W_lateral, W_syn, estimated "
                "neurons, and operator evidence."
            ),
            context_id="demo",
            metadata={
                "display_label": (
                    "SYNAPSE-S2 Monday readiness default topology App Connect "
                    "Codex Cursor Claude installed W_lateral W_syn estimated neurons"
                ),
                "semantic_facets": [
                    (
                        "default topology app connect codex cursor claude installed "
                        "w_lateral w_syn estimated neurons"
                    )
                ],
            },
        )
        backend.register_text_trace(
            tag="fresh-raised-topology-evidence",
            text=(
                "SYNAPSE-S2 default topology now uses 8192 neurons with an estimated "
                "288 MB substrate. W_lateral and W_syn sit inside the raised memory "
                "envelope. App Connect Codex and Cursor were tested; Claude is not installed."
            ),
            context_id="demo",
            metadata={"source": "unit-test"},
        )

        query_text = (
            "8192 neurons 288 MB W_lateral W_syn App Connect Codex Cursor "
            "Claude not installed default topology estimated"
        )
        recall = backend.query_text(query_text, context_id="demo")
        candidates = backend._surface_text_recall_candidates(
            context="demo",
            prompt_text=query_text,
        )
        scored_by_tag = {str(candidate["tag"]): candidate for candidate in candidates}
        fresh_candidate = scored_by_tag["fresh-raised-topology-evidence"]
        old_candidate = scored_by_tag["old-readiness-summary"]

        self.assertIn("fresh-raised-topology-evidence", recall)
        self.assertIn("old-readiness-summary", recall)
        self.assertIn("fresh-raised-topology-evidence", recall.split(" / ")[0])
        self.assertGreater(
            fresh_candidate["score"],
            old_candidate["score"],
        )
        self.assertIn(
            "8192",
            fresh_candidate["metadata"]["surface_text_overlap"],
        )
        self.assertIn(
            "288",
            fresh_candidate["metadata"]["surface_text_overlap"],
        )

        spike_heavy_old_candidate = backend.memory_store.get_entry(
            old_registration["memory_id"]
        )
        self.assertIsNotNone(spike_heavy_old_candidate)
        spike_heavy_old_candidate = dict(spike_heavy_old_candidate)
        spike_heavy_old_candidate["score"] = 0.96
        merged = backend._merge_surface_text_recall_candidates(
            context="demo",
            prompt_text=query_text,
            candidates=[spike_heavy_old_candidate],
        )
        self.assertEqual(merged[0]["tag"], "fresh-raised-topology-evidence")

    def test_surface_merge_does_not_bury_concrete_subfact_under_spike_only_summary(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        old_registration = backend.register_text_trace(
            tag="old-spike-heavy-summary",
            text=(
                "SYNAPSE-S2 Monday readiness covers default topology, App Connect, "
                "Codex, Cursor, Claude installed state, and estimated neurons."
            ),
            context_id="demo",
            metadata={
                "semantic_facets": [
                    "default topology app connect codex cursor claude installed estimated neurons"
                ],
            },
        )
        backend.register_text_trace(
            tag="fresh-topology-array-evidence",
            text=(
                "Default topology uses 8192 neurons and 288 MB. "
                "W_lateral and W_syn sit inside the raised envelope."
            ),
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        query_text = (
            "8192 neurons 288 MB W_lateral W_syn App Connect Codex Cursor "
            "Claude not installed default topology estimated"
        )
        spike_heavy_old_candidate = backend.memory_store.get_entry(
            old_registration["memory_id"]
        )
        self.assertIsNotNone(spike_heavy_old_candidate)
        spike_heavy_old_candidate = dict(spike_heavy_old_candidate)
        spike_heavy_old_candidate["score"] = 0.96

        merged = backend._merge_surface_text_recall_candidates(
            context="demo",
            prompt_text=query_text,
            candidates=[spike_heavy_old_candidate],
        )

        self.assertEqual(merged[0]["tag"], "fresh-topology-array-evidence")

    def test_repeated_conversation_captures_keep_distinct_event_nodes(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=8,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        first = backend.capture_conversation(
            text="Thread: Repeated captures. Event: first retained memory must remain.",
            context_id="demo",
            source_tag="codex-session",
            speaker="codex",
        )
        second = backend.capture_conversation(
            text="Thread: Repeated captures. Event: second retained memory must be additive.",
            context_id="demo",
            source_tag="codex-session",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=80)
        event_entries = [
            entry
            for entry in graph["entries"]
            if entry["tag"].startswith("codex-session-event")
        ]
        event_text = " ".join(entry["source_text"] for entry in event_entries)

        self.assertNotEqual(
            first["events"][0]["memory_id"],
            second["events"][0]["memory_id"],
        )
        self.assertGreaterEqual(len(event_entries), 2)
        self.assertIn("first retained memory", event_text)
        self.assertIn("second retained memory", event_text)

    def test_direct_capture_redacts_memory_and_context_bus_payloads(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )

        capture = backend.capture_conversation(
            text=(
                "Thread: Secret redaction. "
                "Event: direct capture includes api_key=sk-direct-secret123 and "
                '{"client_secret": "plain-direct-secret"}.'
            ),
            context_id="demo",
            source_tag="direct-secret",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=30)
        deployments = backend.list_context_events(context_id="demo", limit=10)
        combined_graph_text = json.dumps(graph, sort_keys=True, default=str)
        combined_deployment_text = json.dumps(deployments, sort_keys=True, default=str)
        combined_response_text = json.dumps(capture, sort_keys=True, default=str)

        self.assertNotIn("sk-direct-secret123", combined_graph_text)
        self.assertNotIn("plain-direct-secret", combined_graph_text)
        self.assertNotIn("sk-direct-secret123", combined_deployment_text)
        self.assertNotIn("plain-direct-secret", combined_deployment_text)
        self.assertNotIn("sk-direct-secret123", combined_response_text)
        self.assertNotIn("plain-direct-secret", combined_response_text)
        self.assertIn("[REDACTED_SECRET]", combined_graph_text)

    def test_surface_recall_cache_invalidates_when_memory_changes(self):
        backend = SpikingAttentionBackend(
            dimension=64,
            num_neurons=32,
            default_top_k=6,
            recall_count=6,
            compile_graph=False,
            state_path=self.state_path,
            embedding_provider_name="semantic-hash",
        )
        backend.capture_conversation(
            text=(
                "Thread: Surface recall cache. "
                "Goal: cache normalized graph surfaces without stale query results."
            ),
            context_id="demo",
            source_tag="surface-cache",
            speaker="codex",
        )

        first = backend.query_text("surface recall cache stale query", context_id="demo")
        self.assertIn("Surface recall cache", first)
        self.assertTrue(backend._surface_recall_cache)

        backend.register_text_trace(
            tag="cache-hardening-follow-up",
            text="Surface recall cache invalidation should expose new hardening follow-up nodes immediately.",
            context_id="demo",
            metadata={"source": "unit-test"},
        )
        second = backend.query_text("surface recall cache hardening follow-up", context_id="demo")

        self.assertIn("cache-hardening-follow-up", second)

    def test_prune_memory_removes_nodes_edges_modes_and_context_events(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        capture = backend.capture_conversation(
            text=(
                "First event must be removable. "
                "Second event remains available. "
                "Shared event terms create associative links."
            ),
            context_id="demo",
            source_tag="prune-session",
            speaker="user",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=20)
        first_entry = next(
            entry for entry in graph["entries"] if entry["tag"].startswith("prune-session-event")
        )
        first_relationship = graph["relationships"][0]

        edge_deletion = backend.prune_memory(
            context_id="demo",
            target_type="relationship",
            relationship_id=first_relationship["relationship_id"],
            reason="bad edge",
        )
        entry_deletion = backend.prune_memory(
            context_id="demo",
            target_type="event",
            memory_id=first_entry["memory_id"],
            reason="sensitive event",
        )
        mode_deletion = backend.prune_memory(
            context_id="demo",
            target_type="temporal",
            reason="drop temporal links",
        )
        event_deletion = backend.prune_memory(
            context_id="demo",
            target_type="context_event",
            event_id=capture["agent_deployment"]["event_id"],
            reason="remove deployment record",
        )
        remaining_graph = backend.list_memory_graph(context_id="demo", limit=20)
        remaining_deployments = backend.list_context_events(context_id="demo", limit=10)

        self.assertEqual(edge_deletion["action"], "prune-memory")
        self.assertTrue(edge_deletion["result"]["deleted"])
        self.assertTrue(entry_deletion["result"]["deleted"])
        self.assertGreaterEqual(mode_deletion["result"]["deleted_relationship_count"], 0)
        self.assertTrue(event_deletion["result"]["deleted"])
        self.assertNotIn(
            first_entry["memory_id"],
            [entry["memory_id"] for entry in remaining_graph["entries"]],
        )
        self.assertNotIn(
            capture["agent_deployment"]["event_id"],
            [event["event_id"] for event in remaining_deployments["events"]],
        )

    def test_temporal_prune_removes_typed_context_sequence_edges(self):
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=self.state_path,
        )
        backend.capture_conversation(
            text=(
                "Thread: Temporal cleanup. "
                "Goal: remove wrong order. "
                "Objective: typed sequence edges should prune with temporal links. "
                "Event: operator requested cleanup."
            ),
            context_id="demo",
            source_tag="temporal-cleanup",
            speaker="codex",
        )
        graph = backend.list_memory_graph(context_id="demo", limit=80)

        deletion = backend.prune_memory(
            context_id="demo",
            target_type="temporal",
            reason="drop all temporal ordering",
        )
        remaining_graph = backend.list_memory_graph(context_id="demo", limit=80)

        self.assertGreaterEqual(graph["relationship_summary"]["by_type"]["typed_context_sequence"], 1)
        self.assertGreaterEqual(graph["relationship_summary"]["temporal"], 1)
        self.assertTrue(deletion["result"]["deleted"])
        self.assertNotIn(
            "typed_context_sequence",
            remaining_graph["relationship_summary"]["by_type"],
        )

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

        self.assertIn("No registered historical context matched", result)
        self.assertNotIn("demo::neuron-", result)
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

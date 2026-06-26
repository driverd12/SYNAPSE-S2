import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

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
            backend = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
            )
            backend.register_trace(
                tag="procurement-memory",
                embedding=mx.array([0.0, 1.0, 9.0, 2.0, 7.0, -4.0]),
                context_id="ops",
                metadata={"ticket": "S2"},
            )

            restored = SpikingAttentionBackend(
                dimension=6,
                num_neurons=10,
                default_top_k=2,
                recall_count=3,
                compile_graph=False,
                state_path=state_path,
            )
            result = restored.query(
                mx.array([0.0, 1.0, 8.8, 2.0, 6.9, -4.1]),
                context_id="ops",
            )

        self.assertIn("procurement-memory", result)

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
        self.assertLessEqual(abs(float(backend.W_syn[0, 0])), abs(before_weight) + 1e-6)
        self.assertEqual(backend.state["mem"].tolist(), [0.0] * 6)

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


if __name__ == "__main__":
    unittest.main()

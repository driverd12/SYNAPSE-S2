import contextlib
import io
import json
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
        )
        self.addCleanup(lambda: setattr(mlx_backend, "_ENGINE_INSTANCE", None))

    def test_query_rejects_empty_embedding(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = mcp_server.query_spiking_attention([], context_id="demo")

        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("invalid prompt_embedding", result)

    def test_query_sanitizes_context_id(self):
        result = mcp_server.query_spiking_attention(
            [0.0, 1.0, 9.0, 2.0, 7.0, -4.0],
            context_id="../demo with spaces",
        )

        self.assertIn("demo_with_spaces", result)
        self.assertNotIn("..", result)

    def test_sleep_consolidation_returns_status_string(self):
        result = mcp_server.trigger_sleep_consolidation()

        self.assertIn("deep-sleep", result)

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


if __name__ == "__main__":
    unittest.main()

import contextlib
import io
import unittest

import mcp_server


class McpServerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

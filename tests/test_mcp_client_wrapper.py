import unittest
from unittest.mock import Mock, patch

import mcp_client_wrapper


class McpClientWrapperTests(unittest.TestCase):
    def test_main_starts_bridge_and_finishes_even_when_server_exits(self):
        bridge = Mock()
        run = Mock(side_effect=RuntimeError("server stopped"))

        with patch.object(
            mcp_client_wrapper.ClientSessionBridge,
            "from_environment",
            return_value=bridge,
        ), patch.object(mcp_client_wrapper.mcp_server.mcp, "run", run):
            with self.assertRaisesRegex(RuntimeError, "server stopped"):
                mcp_client_wrapper.main()

        bridge.start.assert_called_once_with()
        bridge.finish.assert_called_once_with(reason="mcp-server-exit")


if __name__ == "__main__":
    unittest.main()

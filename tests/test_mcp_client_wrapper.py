import unittest
import signal
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

    def test_main_finishes_bridge_when_sigterm_handler_runs(self):
        bridge = Mock()
        handlers = {}

        def capture_handler(signum, handler):
            handlers[signum] = handler
            return signal.SIG_DFL

        def run_until_sigterm():
            handlers[signal.SIGTERM](signal.SIGTERM, None)

        with patch.object(
            mcp_client_wrapper.ClientSessionBridge,
            "from_environment",
            return_value=bridge,
        ), patch.object(
            mcp_client_wrapper.mcp_server.mcp,
            "run",
            Mock(side_effect=run_until_sigterm),
        ), patch.object(mcp_client_wrapper.signal, "signal", side_effect=capture_handler):
            with self.assertRaises(SystemExit):
                mcp_client_wrapper.main()

        bridge.start.assert_called_once_with()
        bridge.finish.assert_called_once_with(reason="signal-sigterm")


if __name__ == "__main__":
    unittest.main()

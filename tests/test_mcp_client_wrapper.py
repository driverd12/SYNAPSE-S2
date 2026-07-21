import unittest
import signal
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

import mcp_client_wrapper


class McpClientWrapperTests(unittest.TestCase):
    @staticmethod
    def _lazy_modules(*, bridge, run):
        bridge_module = ModuleType("client_session_bridge")
        bridge_module.ClientSessionBridge = SimpleNamespace(
            from_environment=Mock(return_value=bridge)
        )
        server_module = ModuleType("mcp_server")
        server_module.mcp = SimpleNamespace(run=run)
        return bridge_module, server_module

    def test_main_starts_bridge_and_finishes_even_when_server_exits(self):
        bridge = Mock()
        run = Mock(side_effect=RuntimeError("server stopped"))
        bridge_module, server_module = self._lazy_modules(bridge=bridge, run=run)

        with patch.object(
            mcp_client_wrapper,
            "apply_binding_environment",
        ) as apply_binding, patch.dict(
            sys.modules,
            {
                "client_session_bridge": bridge_module,
                "mcp_server": server_module,
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "server stopped"):
                mcp_client_wrapper.main()

        apply_binding.assert_called_once_with()
        bridge_module.ClientSessionBridge.from_environment.assert_called_once_with()
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

        run = Mock(side_effect=run_until_sigterm)
        bridge_module, server_module = self._lazy_modules(bridge=bridge, run=run)
        with patch.object(
            mcp_client_wrapper,
            "apply_binding_environment",
        ) as apply_binding, patch.dict(
            sys.modules,
            {
                "client_session_bridge": bridge_module,
                "mcp_server": server_module,
            },
        ), patch.object(
            mcp_client_wrapper.signal,
            "signal",
            side_effect=capture_handler,
        ):
            with self.assertRaises(SystemExit):
                mcp_client_wrapper.main()

        apply_binding.assert_called_once_with()
        bridge_module.ClientSessionBridge.from_environment.assert_called_once_with()
        bridge.start.assert_called_once_with()
        bridge.finish.assert_called_once_with(reason="signal-sigterm")


if __name__ == "__main__":
    unittest.main()

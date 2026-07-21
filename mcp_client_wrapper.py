from __future__ import annotations

import signal
from typing import Any

from core_client_binding import apply_binding_environment


class _BridgeShutdown:
    def __init__(self, bridge: Any) -> None:
        self.bridge = bridge
        self.finished = False

    def finish_once(self, *, reason: str) -> None:
        if self.finished:
            return
        self.finished = True
        self.bridge.finish(reason=reason)


def _install_signal_handlers(shutdown: _BridgeShutdown) -> dict[int, signal.Handlers]:
    previous: dict[int, signal.Handlers] = {}

    def handle_signal(signum: int, _frame: object) -> None:
        try:
            signame = signal.Signals(signum).name.lower()
        except ValueError:
            signame = str(signum)
        shutdown.finish_once(reason=f"signal-{signame}")
        old_handler = previous.get(signum, signal.SIG_DFL)
        if callable(old_handler):
            old_handler(signum, _frame)
            return
        raise SystemExit(128 + int(signum))

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, handle_signal)
    return previous


def _restore_signal_handlers(previous: dict[int, signal.Handlers]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def main() -> None:
    # Resolve the owner-only layout binding before importing any adapter that
    # can construct a backend or choose a capture/export root.
    apply_binding_environment()
    from client_session_bridge import ClientSessionBridge
    import mcp_server

    bridge = ClientSessionBridge.from_environment()
    shutdown = _BridgeShutdown(bridge)
    previous_handlers = _install_signal_handlers(shutdown)
    bridge.start()
    try:
        mcp_server.mcp.run()
    finally:
        shutdown.finish_once(reason="mcp-server-exit")
        _restore_signal_handlers(previous_handlers)


if __name__ == "__main__":
    main()

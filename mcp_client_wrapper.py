from __future__ import annotations

from client_session_bridge import ClientSessionBridge
import mcp_server


def main() -> None:
    bridge = ClientSessionBridge.from_environment()
    bridge.start()
    try:
        mcp_server.mcp.run()
    finally:
        bridge.finish(reason="mcp-server-exit")


if __name__ == "__main__":
    main()

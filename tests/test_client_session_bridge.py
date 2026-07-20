import contextlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import mlx_backend
from client_session_bridge import ClientSessionBridge, ClientSessionBridgeConfig


class ClientSessionBridgeTests(unittest.TestCase):
    def test_start_hydrates_without_claiming_or_acknowledging_hidden_events(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            backend = mlx_backend.SpikingAttentionBackend(
                dimension=32,
                num_neurons=24,
                default_top_k=4,
                recall_count=4,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            registration = backend.register_trace(
                tag="bridge-startup-memory",
                embedding=backend.embed_text("bridge startup hydration memory"),
                context_id="demo",
                source_text="bridge startup hydration memory",
            )
            event = backend.publish_context_event(
                context_id="demo",
                source_surface="unit-test",
                event_type="remember-trace",
                summary="bridge-startup-memory captured and published",
                payload={
                    "tag": registration["tag"],
                    "memory_id": registration["memory_id"],
                    "source_text": "bridge startup hydration memory",
                },
            )
            bridge = ClientSessionBridge(
                ClientSessionBridgeConfig(
                    context_id="demo",
                    agent_id="codex-desktop",
                    startup_prompt="bridge startup hydration",
                    capture_root=Path(tmp),
                ),
                backend=backend,
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                hydration = bridge.start()

            cursors = backend.list_context_cursors(context_id="demo")["cursors"]
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(hydration["action"], "agent-context-hydrate")
            self.assertEqual(hydration["new_event_count"], 0)
            self.assertFalse(hydration["claim_events"])
            self.assertFalse(hydration["acknowledged"])
            self.assertFalse(hydration["ack_required"])
            self.assertEqual(cursors, [])
            self.assertEqual(
                backend.list_context_events(context_id="demo")["events"][0]["event_id"],
                event["event_id"],
            )

    def test_start_enters_cortex_and_finish_commits_cortical_boundary_trace(self):
        with TemporaryDirectory() as tmp:
            backend = mlx_backend.SpikingAttentionBackend(
                dimension=32,
                num_neurons=24,
                default_top_k=4,
                recall_count=4,
                compile_graph=False,
                state_path=Path(tmp) / "state.json",
                memory_path=Path(tmp) / "memory.sqlite3",
            )
            bridge = ClientSessionBridge(
                ClientSessionBridgeConfig(
                    context_id="demo",
                    agent_id="codex-desktop",
                    startup_prompt="Govern a Codex startup through Cortex.",
                    capture_root=Path(tmp),
                ),
                backend=backend,
            )

            hydration = bridge.start()
            started_state = backend.get_cortex_state(
                context_id="demo",
                agent_id="codex-desktop",
            )
            finished = bridge.finish(
                reason="unit-test",
                final_note="validated lifecycle trace",
            )
            finished_state = backend.get_cortex_state(
                context_id="demo",
                agent_id="codex-desktop",
            )

            self.assertIn("client_cortex_session_id", hydration)
            self.assertEqual(started_state["active_session_count"], 1)
            self.assertTrue(finished["cortex_committed"])
            self.assertEqual(finished_state["active_session_count"], 0)
            self.assertGreaterEqual(finished_state["typed_memory_counts"]["follow_up"], 1)
            self.assertTrue(
                any(
                    item["trace_type"] == "follow_up"
                    and item["session_id"] == hydration["client_cortex_session_id"]
                    for item in finished_state["working_memory"]
                )
            )

    def test_finish_drops_sanitized_session_boundary_capture(self):
        with TemporaryDirectory() as tmp:
            backend = mlx_backend.SpikingAttentionBackend(
                dimension=32,
                num_neurons=24,
                default_top_k=4,
                compile_graph=False,
                state_path=Path(tmp) / "state.json",
                memory_path=Path(tmp) / "memory.sqlite3",
            )
            bridge = ClientSessionBridge(
                ClientSessionBridgeConfig(
                    context_id="demo",
                    agent_id="claude-code",
                    startup_prompt="session bridge",
                    capture_root=Path(tmp),
                    source_tag="client-session-boundary",
                ),
                backend=backend,
            )
            bridge.start()

            result = bridge.finish(
                reason="unit-test",
                final_note="operator note carried api_key=sk-test-secret123",
            )
            second = bridge.finish(reason="duplicate")

            drop_path = Path(result["drop_path"])
            payload = json.loads(drop_path.read_text(encoding="utf-8"))
            self.assertTrue(result["dropped"])
            self.assertEqual(second["dropped"], False)
            self.assertEqual(payload["context_id"], "demo")
            self.assertEqual(payload["source_tag"], "client-session-boundary")
            self.assertEqual(payload["speaker"], "claude-code")
            self.assertEqual(payload["capture_id"], result["capture_id"])
            self.assertRegex(result["capture_id"], r"^s2cap_[0-9a-f]{32}$")
            self.assertIn("SYNAPSE-S2 MCP client session ended", payload["text"])
            self.assertIn("[REDACTED_SECRET]", payload["text"])
            self.assertNotIn("sk-test-secret123", payload["text"])
            self.assertEqual(payload["metadata"]["redaction_count"], 1)
            self.assertTrue(payload["metadata"]["client_session_bridge"])

    def test_from_environment_assigns_client_identity_and_defaults(self):
        env = {
            "SYNAPSE_S2_CLIENT_SESSION_BRIDGE": "1",
            "SYNAPSE_S2_CLIENT_AGENT_ID": "codex-desktop",
            "SYNAPSE_S2_CONTEXT_ID": "demo",
            "SYNAPSE_S2_CAPTURE_ROOT": "/tmp/synapse-capture",
        }

        bridge = ClientSessionBridge.from_environment(env=env, backend=None)

        self.assertRegex(bridge.session_id, r"^[0-9a-f]{32}$")
        self.assertTrue(bridge.config.enabled)
        self.assertTrue(bridge.config.cortex_enabled)
        self.assertEqual(bridge.config.cortex_mode, "strict")
        self.assertEqual(bridge.config.startup_recall_mode, "surface")
        self.assertEqual(bridge.config.agent_id, "codex-desktop")
        self.assertEqual(bridge.config.context_id, "demo")
        self.assertEqual(bridge.config.capture_root, Path("/tmp/synapse-capture"))
        self.assertIn("codex-desktop", bridge.config.startup_prompt)

    def test_from_environment_uses_safe_limits_when_env_is_malformed(self):
        env = {
            "SYNAPSE_S2_CLIENT_EVENT_LIMIT": "not-an-int",
            "SYNAPSE_S2_CLIENT_GRAPH_LIMIT": "-999",
        }

        bridge = ClientSessionBridge.from_environment(env=env, backend=None)

        self.assertEqual(bridge.config.event_limit, 20)
        self.assertEqual(bridge.config.graph_limit, 1)

    def test_default_bridge_uses_control_plane_surface_bootstrap(self):
        with TemporaryDirectory() as tmp:
            backend = mlx_backend.SpikingAttentionBackend(
                dimension=32,
                num_neurons=24,
                default_top_k=4,
                recall_count=4,
                compile_graph=False,
                state_path=Path(tmp) / "state.json",
                memory_path=Path(tmp) / "memory.sqlite3",
                control_plane_only=True,
            )
            bridge = ClientSessionBridge(
                ClientSessionBridgeConfig(
                    context_id="demo",
                    agent_id="codex-desktop",
                    startup_prompt="hydrate local client context",
                    capture_root=Path(tmp),
                ),
                backend=backend,
            )

            hydration = bridge.start()
            finished = bridge.finish(reason="unit-test")

            self.assertEqual(hydration["recall_mode"], "surface")
            self.assertEqual(
                hydration["recall_provenance"],
                "sqlite-surface-bootstrap",
            )
            self.assertTrue(backend.control_plane_only)
            self.assertTrue(finished["cortex_queued"])
            self.assertFalse(finished["cortex_committed"])
            payload = json.loads(Path(finished["drop_path"]).read_text(encoding="utf-8"))
            self.assertTrue(payload["metadata"]["cortex_governor"])
            self.assertEqual(payload["metadata"]["trace_type"], "follow_up")


if __name__ == "__main__":
    unittest.main()

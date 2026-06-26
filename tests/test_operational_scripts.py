import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OperationalScriptTests(unittest.TestCase):
    def test_prep_tomorrow_does_not_seed_demo_memory_by_default(self):
        script = (ROOT / "scripts" / "prep_tomorrow.sh").read_text(encoding="utf-8")

        self.assertNotIn("seed-demo", script)
        self.assertIn('CONTEXT="${SYNAPSE_S2_PREFLIGHT_CONTEXT:-default}"', script)
        self.assertIn("factual preflight evidence", script)
        self.assertIn("install_capture_daemon.sh", script)
        self.assertIn("capture-inbox-drop", script)
        self.assertIn("get_spiking_capture_inbox_status", script)
        self.assertIn("embedding_providers.py", script)
        self.assertIn("certify-runtime", script)
        self.assertIn("certify_spiking_runtime", script)

    def test_capture_daemon_installer_declares_launch_agent(self):
        script = (ROOT / "scripts" / "install_capture_daemon.sh").read_text(encoding="utf-8")

        self.assertIn("aero.boom.synapse-s2.capture-daemon", script)
        self.assertIn("capture_daemon.py", script)
        self.assertIn("SYNAPSE_S2_CAPTURE_ROOT", script)
        self.assertIn("launchctl bootstrap", script)

    def test_local_launcher_uses_client_session_wrapper(self):
        script = (ROOT / "scripts" / "install_local_launcher.sh").read_text(encoding="utf-8")

        self.assertIn("mcp_client_wrapper.py", script)
        self.assertIn("SYNAPSE_S2_CLIENT_SESSION_BRIDGE", script)
        self.assertIn("SYNAPSE_S2_EMBEDDING_PROVIDER:=mlx-neural", script)
        self.assertIn("SYNAPSE_S2_NEURAL_MODEL", script)
        self.assertIn("Qwen3-Embedding-0.6B-4bit-DWQ", script)
        self.assertIn("MLX_DEVICE:=gpu", script)
        self.assertIn("SYNAPSE_S2_MEMORY_DB", script)
        self.assertNotIn('"$REPO_ROOT/mcp_server.py"', script)

    def test_dashboard_agent_installer_runs_neural_dashboard_on_loopback(self):
        script_path = ROOT / "scripts" / "install_dashboard_agent.sh"

        self.assertTrue(script_path.exists(), "dashboard LaunchAgent installer must exist")
        script = script_path.read_text(encoding="utf-8")
        self.assertIn("aero.boom.synapse-s2.dashboard", script)
        self.assertIn("dashboard_server.py", script)
        self.assertIn("127.0.0.1", script)
        self.assertIn("SYNAPSE_S2_EMBEDDING_PROVIDER", script)
        self.assertIn("mlx-neural", script)
        self.assertIn("Qwen3-Embedding-0.6B-4bit-DWQ", script)


if __name__ == "__main__":
    unittest.main()

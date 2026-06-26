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
        self.assertNotIn('"$REPO_ROOT/mcp_server.py"', script)


if __name__ == "__main__":
    unittest.main()

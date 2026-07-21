from __future__ import annotations

import importlib.util
import json
import stat
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "open_dashboard.py"
SPEC = importlib.util.spec_from_file_location("synapse_open_dashboard", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
open_dashboard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = open_dashboard
SPEC.loader.exec_module(open_dashboard)


class DashboardOpenTests(unittest.TestCase):
    def write_auth(self, root: Path, *, url: str, session_header: str = "H" * 43) -> Path:
        root.mkdir(mode=0o700)
        path = root / "dashboard-auth.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "synapse-s2.dashboard-auth.v1",
                    "host": "127.0.0.1",
                    "port": 8765,
                    "bootstrap_url": url,
                    "session_header": session_header,
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def test_main_keeps_bootstrap_capability_out_of_process_arguments(self):
        token = "A" * 43
        session_header = "H" * 43
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "private"
            path = self.write_auth(
                root,
                url=f"http://127.0.0.1:8765/__dashboard_bootstrap?token={token}",
                session_header=session_header,
            )
            with mock.patch.object(open_dashboard.subprocess, "run") as run:
                status = open_dashboard.main(["--auth-file", str(path)])

        self.assertEqual(status, 0)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/osascript", "-"])
        self.assertNotIn(token, " ".join(run.call_args.args[0]))
        self.assertIn(token, run.call_args.kwargs["input"])
        self.assertNotIn(session_header, " ".join(run.call_args.args[0]))
        self.assertNotIn(session_header, run.call_args.kwargs["input"])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_main_rejects_world_readable_auth_file_before_opening(self):
        token = "B" * 43
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "private"
            path = self.write_auth(
                root,
                url=f"http://127.0.0.1:8765/__dashboard_bootstrap?token={token}",
            )
            path.chmod(0o644)
            with mock.patch.object(open_dashboard.subprocess, "run") as run:
                status = open_dashboard.main(["--auth-file", str(path)])
            observed_mode = stat.S_IMODE(path.stat().st_mode)

        self.assertEqual(observed_mode, 0o644)
        self.assertEqual(status, 2)
        run.assert_not_called()

    def test_main_rejects_nonloopback_bootstrap_url(self):
        token = "C" * 43
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "private"
            path = self.write_auth(
                root,
                url=f"http://attacker.example:8765/__dashboard_bootstrap?token={token}",
            )
            with mock.patch.object(open_dashboard.subprocess, "run") as run:
                status = open_dashboard.main(["--auth-file", str(path)])

        self.assertEqual(status, 2)
        run.assert_not_called()

    def test_main_rejects_auth_file_without_valid_session_header(self):
        token = "D" * 43
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "private"
            path = self.write_auth(
                root,
                url=f"http://127.0.0.1:8765/__dashboard_bootstrap?token={token}",
                session_header="invalid header",
            )
            with mock.patch.object(open_dashboard.subprocess, "run") as run:
                status = open_dashboard.main(["--auth-file", str(path)])

        self.assertEqual(status, 2)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

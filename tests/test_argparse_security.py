from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKER = "SYNTHETIC_ONLY_ARGPARSE_SECRET_42"


class SecretSafeArgparseEntrypointTests(unittest.TestCase):
    def test_secret_safe_parser_preserves_normal_help_contract(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "capture_daemon.py"), "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("usage:", result.stdout.lower())
        self.assertIn("SYNAPSE-S2 capture inbox daemon", result.stdout)

    def test_public_entrypoints_redact_invalid_values_and_unknown_arguments(self):
        cases = (
            (ROOT / "capture_daemon.py", ("--dimension", f"password={MARKER}")),
            (ROOT / "capture_daemon.py", (f"--unknown=/private/tmp/password={MARKER}",)),
            (ROOT / "dashboard_server.py", ("--port", f"api_key={MARKER}")),
            (ROOT / "dashboard_server.py", (f"--unknown=/private/tmp/token={MARKER}",)),
            (ROOT / "transcript_capture.py", ("--max-bytes", f"password={MARKER}")),
            (ROOT / "transcript_capture.py", (f"--unknown=/private/tmp/api_key={MARKER}",)),
            (ROOT / "client_config.py", (f"--unknown=/private/tmp/password={MARKER}",)),
            (
                ROOT / "scripts" / "operator_readiness_certify.py",
                (f"--unknown=/private/tmp/token={MARKER}",),
            ),
            (
                ROOT / "scripts" / "synapse_status_report.py",
                ("--hygiene-limit", f"password={MARKER}"),
            ),
            (
                ROOT / "scripts" / "synapse_status_report.py",
                (f"--unknown=/private/tmp/api_key={MARKER}",),
            ),
        )

        for entrypoint, arguments in cases:
            with self.subTest(entrypoint=entrypoint.name, arguments=arguments):
                result = subprocess.run(
                    [sys.executable, str(entrypoint), *arguments],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=30,
                )

                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn(MARKER, result.stderr)
                self.assertNotIn("/private/tmp/", result.stderr)
                self.assertIn("usage:", result.stderr.lower())
                self.assertIn("error:", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SynapseCliTests(unittest.TestCase):
    def run_cli(self, *args: str, state_path: Path):
        command = [
            sys.executable,
            str(ROOT / "synapse_cli.py"),
            "--state",
            str(state_path),
            "--dimension",
            "32",
            "--neurons",
            "24",
            "--top-k",
            "4",
            "--json",
            *args,
        ]
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_cli_remembers_queries_and_toggles_text_context(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"

            remember = self.run_cli(
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "cli-memory",
                "--text",
                "SYNAPSE-S2 remembers local MCP state",
                state_path=state_path,
            )
            query = self.run_cli(
                "query-text",
                "--context",
                "demo",
                "--text",
                "SYNAPSE-S2 remembers local MCP state",
                state_path=state_path,
            )
            disable = self.run_cli("disable", "--context", "demo", state_path=state_path)
            disabled_query = self.run_cli(
                "query-text",
                "--context",
                "demo",
                "--text",
                "SYNAPSE-S2 remembers local MCP state",
                state_path=state_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(query.returncode, 0, query.stderr)
        self.assertEqual(disable.returncode, 0, disable.stderr)
        self.assertEqual(disabled_query.returncode, 0, disabled_query.stderr)
        self.assertEqual(json.loads(remember.stdout)["tag"], "cli-memory")
        self.assertIn("cli-memory", json.loads(query.stdout)["result"])
        self.assertFalse(json.loads(disable.stdout)["effective_enabled"])
        self.assertIn("disabled", json.loads(disabled_query.stdout)["result"].lower())

    def test_cli_doctor_reports_runtime_fields(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"

            result = self.run_cli("doctor", "--context", "demo", state_path=state_path)

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"]["context_id"], "demo")
        self.assertIn("python", payload)
        self.assertIn("dependencies", payload)


if __name__ == "__main__":
    unittest.main()

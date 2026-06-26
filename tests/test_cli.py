import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SynapseCliTests(unittest.TestCase):
    def run_cli(self, *args: str, state_path: Path, memory_path: Path | None = None):
        command = [
            sys.executable,
            str(ROOT / "synapse_cli.py"),
            "--state",
            str(state_path),
            "--memory-db",
            str(memory_path or state_path.with_name("memory.sqlite3")),
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
        self.assertIn("memory_db_path", payload["status"])

    def test_cli_idle_maintenance_can_force_deep_sleep(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"

            result = self.run_cli(
                "idle-maintenance",
                "--force-deep-sleep",
                state_path=state_path,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["mode"], "deep-sleep")
        self.assertEqual(payload["trigger"], "idle-force")
        self.assertTrue(payload["maintenance_run"])
        self.assertEqual(payload["phase_count"], 7)

    def test_cli_lists_exports_and_backs_up_real_memory(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            export_path = Path(tmp) / "memory-export.json"
            backup_path = Path(tmp) / "memory-backup.sqlite3"

            remember = self.run_cli(
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "cli-real-memory",
                "--text",
                "SYNAPSE-S2 stores full local memory in SQLite.",
                state_path=state_path,
                memory_path=memory_path,
            )
            listing = self.run_cli(
                "list-memory",
                "--context",
                "demo",
                "--limit",
                "5",
                state_path=state_path,
                memory_path=memory_path,
            )
            exported = self.run_cli(
                "export-memory",
                "--context",
                "demo",
                "--output",
                str(export_path),
                state_path=state_path,
                memory_path=memory_path,
            )
            backup = self.run_cli(
                "backup-memory",
                "--output",
                str(backup_path),
                state_path=state_path,
                memory_path=memory_path,
            )
            export_exists = export_path.exists()
            backup_exists = backup_path.exists()

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertEqual(backup.returncode, 0, backup.stderr)
        listing_payload = json.loads(listing.stdout)
        self.assertEqual(listing_payload["entries"][0]["tag"], "cli-real-memory")
        self.assertNotIn("spike_indices", listing_payload["entries"][0])
        self.assertNotIn("neuron_indices", listing_payload["entries"][0])
        self.assertEqual(json.loads(exported.stdout)["entries"][0]["source_text"], "SYNAPSE-S2 stores full local memory in SQLite.")
        self.assertTrue(export_exists)
        self.assertTrue(backup_exists)

    def test_cli_list_memory_can_include_vector_details_when_requested(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "cli-vector-memory",
                "--text",
                "SYNAPSE-S2 can expose vector details explicitly.",
                state_path=state_path,
                memory_path=memory_path,
            )
            listing = self.run_cli(
                "list-memory",
                "--context",
                "demo",
                "--limit",
                "5",
                "--include-vectors",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        entry = json.loads(listing.stdout)["entries"][0]
        self.assertIn("spike_indices", entry)
        self.assertIn("neuron_indices", entry)

    def test_cli_preflight_reports_ready_when_runtime_memory_and_launcher_are_good(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "cli-preflight-memory",
                "--text",
                "SYNAPSE-S2 preflight verifies memory recall.",
                state_path=state_path,
                memory_path=memory_path,
            )
            preflight = self.run_cli(
                "preflight",
                "--context",
                "demo",
                "--query-text",
                "SYNAPSE-S2 preflight verifies memory recall.",
                "--minimum-memory",
                "1",
                "--launcher",
                sys.executable,
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        payload = json.loads(preflight.stdout)
        self.assertTrue(payload["ready"])
        self.assertEqual(payload["failed_checks"], [])
        self.assertTrue(payload["checks"]["launcher_executable"])
        self.assertTrue(payload["checks"]["memory_minimum_met"])
        self.assertIn("cli-preflight-memory", payload["query_result"])

    def test_cli_preflight_reports_failed_checks_without_crashing(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            preflight = self.run_cli(
                "preflight",
                "--context",
                "demo",
                "--minimum-memory",
                "1",
                "--launcher",
                str(Path(tmp) / "missing-launcher"),
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        payload = json.loads(preflight.stdout)
        self.assertFalse(payload["ready"])
        self.assertIn("launcher_executable", payload["failed_checks"])
        self.assertIn("memory_minimum_met", payload["failed_checks"])


if __name__ == "__main__":
    unittest.main()

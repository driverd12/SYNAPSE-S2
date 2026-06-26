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

    def test_cli_does_not_expose_seed_demo_command(self):
        help_result = subprocess.run(
            [sys.executable, str(ROOT / "synapse_cli.py"), "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        invalid_result = subprocess.run(
            [sys.executable, str(ROOT / "synapse_cli.py"), "seed-demo"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertNotIn("seed-demo", help_result.stdout)
        self.assertNotEqual(invalid_result.returncode, 0)
        self.assertIn("invalid choice", invalid_result.stderr)

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

    def test_cli_profile_reports_resource_envelope(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"

            result = self.run_cli(
                "profile",
                "--benchmark-quick-prune",
                state_path=state_path,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["dimension"], 32)
        self.assertEqual(payload["num_neurons"], 24)
        self.assertIn("estimated_total_mb", payload)
        self.assertTrue(payload["quick_pruning"]["within_60ms_budget"])

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

    def test_cli_ingests_text_events_and_lists_memory_graph(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            text = (
                "Apple Silicon MLX compiles spiking kernels into Metal. "
                "Sparse spike populations recall local context. "
                "Procurement reviews supplier budget exposure and contract risk. "
                "Finance tracks renewal owners and approval status."
            )

            ingestion = self.run_cli(
                "ingest-text",
                "--context",
                "demo",
                "--tag",
                "cli-brief",
                "--text",
                text,
                "--surprise-threshold",
                "0.58",
                "--min-segment-sentences",
                "1",
                state_path=state_path,
                memory_path=memory_path,
            )
            graph = self.run_cli(
                "graph",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(ingestion.returncode, 0, ingestion.stderr)
        self.assertEqual(graph.returncode, 0, graph.stderr)
        ingestion_payload = json.loads(ingestion.stdout)
        graph_payload = json.loads(graph.stdout)
        self.assertGreaterEqual(ingestion_payload["event_count"], 2)
        self.assertGreaterEqual(graph_payload["relationship_count"], 1)
        self.assertEqual(
            graph_payload["relationships"][0]["relation_type"],
            "temporal_next",
        )

    def test_cli_publishes_and_acknowledges_context_deployments(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"

            remember = self.run_cli(
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "cli-published-memory",
                "--text",
                "CLI writes should publish durable context deployments.",
                state_path=state_path,
            )
            event_id = json.loads(remember.stdout)["agent_deployment"]["event_id"]
            pull = self.run_cli(
                "pull-context",
                "--context",
                "demo",
                "--since-event-id",
                "0",
                state_path=state_path,
            )
            ack = self.run_cli(
                "ack-context",
                "--context",
                "demo",
                "--agent-id",
                "cli-test",
                "--last-event-id",
                str(event_id),
                state_path=state_path,
            )
            cursors = self.run_cli(
                "list-context-cursors",
                "--context",
                "demo",
                state_path=state_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(pull.returncode, 0, pull.stderr)
        self.assertEqual(ack.returncode, 0, ack.stderr)
        self.assertEqual(cursors.returncode, 0, cursors.stderr)
        self.assertEqual(
            json.loads(pull.stdout)["events"][0]["payload"]["tag"],
            "cli-published-memory",
        )
        self.assertEqual(json.loads(ack.stdout)["agent_id"], "cli-test")
        self.assertEqual(json.loads(cursors.stdout)["cursors"][0]["agent_id"], "cli-test")

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

    def test_cli_preflight_can_require_memory_graph_relationships(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            ingestion = self.run_cli(
                "ingest-text",
                "--context",
                "demo",
                "--tag",
                "preflight-graph",
                "--text",
                (
                    "Apple Silicon MLX compiles spiking kernels into Metal. "
                    "Sparse spike populations recall local context. "
                    "Procurement reviews supplier budget exposure and contract risk."
                ),
                "--surprise-threshold",
                "0.58",
                "--min-segment-sentences",
                "1",
                state_path=state_path,
                memory_path=memory_path,
            )
            preflight = self.run_cli(
                "preflight",
                "--context",
                "demo",
                "--minimum-memory",
                "2",
                "--minimum-relationships",
                "1",
                "--launcher",
                sys.executable,
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(ingestion.returncode, 0, ingestion.stderr)
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        payload = json.loads(preflight.stdout)
        self.assertTrue(payload["ready"])
        self.assertTrue(payload["checks"]["relationship_minimum_met"])

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

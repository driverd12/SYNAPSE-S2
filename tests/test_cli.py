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

    def test_cli_status_and_remember_text_report_embedding_provider(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "cli-semantic-memory",
                "--text",
                "Apple Silicon Metal acceleration",
                state_path=state_path,
                memory_path=memory_path,
            )
            status = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "status",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )
            listing = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "list-memory",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual(json.loads(remember.stdout)["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertEqual(json.loads(status.stdout)["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertEqual(
            json.loads(listing.stdout)["entries"][0]["metadata"]["embedding_provider"]["provider"],
            "semantic-hash-v1",
        )

    def test_cli_provider_benchmark_reports_latency_and_provenance(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"

            result = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "provider-benchmark",
                "--text",
                "SYNAPSE-S2 neural provider benchmark",
                "--runs",
                "2",
                state_path=state_path,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["action"], "provider-benchmark")
        self.assertEqual(payload["embedding_provider"]["provider"], "semantic-hash-v1")
        self.assertEqual(payload["dimensions"], 32)
        self.assertEqual(payload["runs"], 2)
        self.assertEqual(len(payload["sample_latencies_ms"]), 2)
        self.assertGreaterEqual(payload["elapsed_ms"], 0.0)
        self.assertGreaterEqual(payload["average_latency_ms"], 0.0)

    def test_cli_monday_readiness_reports_scorecard(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "monday-readiness-memory",
                "--text",
                "Monday readiness should prove recall, runtime health, and local memory.",
                state_path=state_path,
                memory_path=memory_path,
            )
            result = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "monday-readiness",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["action"], "monday-readiness")
        self.assertEqual(payload["context_id"], "demo")
        self.assertGreaterEqual(payload["score"], 0)
        self.assertLessEqual(payload["score"], 100)
        self.assertIsInstance(payload["demo_ready"], bool)
        self.assertGreater(payload["summary"]["required_total"], 0)
        self.assertIn("operator_steps", payload)
        self.assertGreaterEqual(len(payload["operator_steps"]), 3)
        self.assertIn(
            "embedding_latency",
            {check["id"] for check in payload["checks"]},
        )

    def test_operator_loop_cli_commands_report_receipts(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "operator-loop-memory",
                "--text",
                "Feature: Start Work should brief the operator before daily use.",
                state_path=state_path,
                memory_path=memory_path,
            )
            start = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "start-work",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--prompt",
                "Start Monday SYNAPSE-S2 workflow",
                state_path=state_path,
                memory_path=memory_path,
            )
            health = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "context-health",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )
            hygiene = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "memory-hygiene",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )
            doctor = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "doctor",
                "--context",
                "demo",
                "--repair-plan",
                state_path=state_path,
                memory_path=memory_path,
            )
            preview = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "wrap-session",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--text",
                "Feature: CLI preview should show wrap session content.",
                "--preview",
                state_path=state_path,
                memory_path=memory_path,
            )
            wrapped = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "wrap-session",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--text",
                "Feature: CLI confirmed wrap session captures reliable handoff evidence.",
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )

        for result in (remember, start, health, hygiene, doctor, preview, wrapped):
            self.assertEqual(result.returncode, 0, result.stderr)

        start_payload = json.loads(start.stdout)
        health_payload = json.loads(health.stdout)
        hygiene_payload = json.loads(hygiene.stdout)
        doctor_payload = json.loads(doctor.stdout)
        preview_payload = json.loads(preview.stdout)
        wrapped_payload = json.loads(wrapped.stdout)

        self.assertEqual(start_payload["action"], "start-work")
        self.assertIn(start_payload["status"], {"ready", "degraded", "blocked"})
        self.assertGreaterEqual(start_payload["score"], 0)
        self.assertLessEqual(start_payload["score"], 100)
        self.assertTrue(start_payload["brief_sections"])
        self.assertEqual(start_payload["receipt"]["action"], "start-work")
        self.assertEqual(health_payload["action"], "context-health")
        self.assertEqual(health_payload["receipt"]["action"], "context-health")
        self.assertEqual(hygiene_payload["action"], "memory-hygiene")
        self.assertIn("queue_summary", hygiene_payload)
        self.assertEqual(doctor_payload["action"], "doctor-report")
        self.assertIn("repair_plan", doctor_payload)
        self.assertEqual(preview_payload["action"], "wrap-session-preview")
        self.assertIn("Feature:", preview_payload["preview_text"])
        self.assertEqual(wrapped_payload["action"], "wrap-session")
        self.assertGreaterEqual(wrapped_payload["event_count"], 1)
        self.assertEqual(wrapped_payload["receipt"]["status"], "ready")

    def test_cli_goal_ledger_create_update_and_list(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            created = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "goal.create",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--title",
                "Prepare SYNAPSE-S2 Monday operator demo",
                "--owner",
                "operator",
                "--goal-state",
                "in_progress",
                "--next-action",
                "Run Start Work and verify receipts.",
                state_path=state_path,
                memory_path=memory_path,
            )
            created_payload = json.loads(created.stdout) if created.stdout else {}
            updated = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "goal.update",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--goal-id",
                created_payload.get("memory_id", ""),
                "--goal-state",
                "blocked",
                "--evidence",
                "Blocked until the GitHub mirror repository exists.",
                "--next-action",
                "Create private GitHub repo or sign in.",
                state_path=state_path,
                memory_path=memory_path,
            )
            listed = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "goal.list",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )

        for result in (created, updated, listed):
            self.assertEqual(result.returncode, 0, result.stderr)

        create_payload = json.loads(created.stdout)
        update_payload = json.loads(updated.stdout)
        list_payload = json.loads(listed.stdout)
        self.assertEqual(create_payload["action"], "goal-create")
        self.assertEqual(update_payload["action"], "goal-update")
        self.assertEqual(list_payload["action"], "goal-list")
        self.assertTrue(list_payload["goals"])
        self.assertEqual(list_payload["goals"][0]["state"], "blocked")
        self.assertIn("Monday operator demo", list_payload["goals"][0]["title"])

    def test_cli_certify_runtime_writes_evidence_pack(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            evidence_path = Path(tmp) / "native-certification.json"

            result = self.run_cli(
                "certify-runtime",
                "--benchmark-quick-prune",
                "--output",
                str(evidence_path),
                state_path=state_path,
            )
            evidence_exists = evidence_path.exists()

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["action"], "certify-runtime")
        self.assertEqual(payload["evidence_path"], str(evidence_path.resolve()))
        self.assertTrue(evidence_exists)
        self.assertIn("checks", payload)
        self.assertIn("resource_profile", payload)

    def test_cli_preflight_can_require_native_certification(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "native-preflight-memory",
                "--text",
                "SYNAPSE-S2 native certification should run during preflight.",
                state_path=state_path,
                memory_path=memory_path,
            )
            preflight = self.run_cli(
                "preflight",
                "--context",
                "demo",
                "--query-text",
                "native certification preflight",
                "--minimum-memory",
                "1",
                "--launcher",
                sys.executable,
                "--require-native",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        payload = json.loads(preflight.stdout)
        self.assertIn("native_certification", payload)
        self.assertTrue(payload["checks"]["native_certification_ready"])
        self.assertEqual(payload["native_certification"]["action"], "certify-runtime")

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

    def test_cli_captures_session_and_prunes_graph_items(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            text = (
                "Apple Silicon Metal kernels accelerate local MLX compute. "
                "Finance owners review supplier renewal approval risk. "
                "Operators can clear sensitive graph items."
            )

            capture = self.run_cli(
                "capture-session",
                "--context",
                "demo",
                "--tag",
                "cli-session",
                "--speaker",
                "codex",
                "--text",
                text,
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
            graph_payload = json.loads(graph.stdout)
            memory_id = next(
                entry["memory_id"]
                for entry in graph_payload["entries"]
                if entry["tag"].startswith("cli-session-event")
            )
            relationship_id = graph_payload["relationships"][0]["relationship_id"]
            edge_prune = self.run_cli(
                "prune-memory",
                "--context",
                "demo",
                "--target-type",
                "relationship",
                "--relationship-id",
                relationship_id,
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )
            memory_prune = self.run_cli(
                "prune-memory",
                "--context",
                "demo",
                "--target-type",
                "event",
                "--memory-id",
                memory_id,
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(capture.returncode, 0, capture.stderr)
        self.assertEqual(graph.returncode, 0, graph.stderr)
        self.assertEqual(edge_prune.returncode, 0, edge_prune.stderr)
        self.assertEqual(memory_prune.returncode, 0, memory_prune.stderr)
        self.assertGreaterEqual(json.loads(capture.stdout)["event_count"], 2)
        self.assertTrue(json.loads(edge_prune.stdout)["result"]["deleted"])
        self.assertTrue(json.loads(memory_prune.stdout)["result"]["deleted"])

    def test_cli_capture_inbox_drop_status_and_process(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            inbox_root = Path(tmp) / "capture-root"

            drop = self.run_cli(
                "capture-inbox-drop",
                "--context",
                "demo",
                "--tag",
                "cli-magic",
                "--speaker",
                "codex",
                "--text",
                "The passive capture inbox should ingest this payload. api_key=sk-test-secret123",
                "--capture-root",
                str(inbox_root),
                state_path=state_path,
                memory_path=memory_path,
            )
            status_before = self.run_cli(
                "capture-inbox-status",
                "--capture-root",
                str(inbox_root),
                state_path=state_path,
                memory_path=memory_path,
            )
            rejected = self.run_cli(
                "capture-inbox-process",
                "--capture-root",
                str(inbox_root),
                state_path=state_path,
                memory_path=memory_path,
            )
            processed = self.run_cli(
                "capture-inbox-process",
                "--capture-root",
                str(inbox_root),
                "--confirm",
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

        self.assertEqual(drop.returncode, 0, drop.stderr)
        self.assertEqual(status_before.returncode, 0, status_before.stderr)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("--confirm", rejected.stdout + rejected.stderr)
        self.assertEqual(processed.returncode, 0, processed.stderr)
        self.assertEqual(graph.returncode, 0, graph.stderr)
        self.assertFalse(Path(json.loads(drop.stdout)["drop_path"]).exists())
        self.assertEqual(json.loads(status_before.stdout)["pending_file_count"], 1)
        self.assertEqual(json.loads(processed.stdout)["processed_file_count"], 1)
        graph_payload = json.loads(graph.stdout)
        self.assertTrue(
            any(entry["tag"].startswith("cli-magic-event") for entry in graph_payload["entries"])
        )
        self.assertTrue(
            all("sk-test-secret123" not in entry["source_text"] for entry in graph_payload["entries"])
        )

    def test_cli_transcript_source_register_poll_and_clipboard_capture(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            capture_root = Path(tmp) / "capture-root"
            transcript = Path(tmp) / "codex-session.log"
            transcript.write_text("Historical transcript line.\n", encoding="utf-8")

            add_source = self.run_cli(
                "transcript-source-add",
                "--context",
                "demo",
                "--source-id",
                "codex-file",
                "--path",
                str(transcript),
                "--tag",
                "codex-file",
                "--speaker",
                "codex",
                "--capture-root",
                str(capture_root),
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )
            transcript.write_text(
                transcript.read_text(encoding="utf-8")
                + "New Codex transcript delta reaches SYNAPSE-S2. token=sk-cli-secret123\n",
                encoding="utf-8",
            )
            poll = self.run_cli(
                "transcript-source-poll",
                "--source-id",
                "codex-file",
                "--capture-root",
                str(capture_root),
                state_path=state_path,
                memory_path=memory_path,
            )
            clipboard = self.run_cli(
                "capture-clipboard",
                "--context",
                "demo",
                "--tag",
                "operator-selection",
                "--speaker",
                "operator",
                "--text",
                "Selected browser transcript. password=clip-secret",
                "--capture-root",
                str(capture_root),
                state_path=state_path,
                memory_path=memory_path,
            )
            listing = self.run_cli(
                "transcript-source-list",
                "--capture-root",
                str(capture_root),
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(add_source.returncode, 0, add_source.stderr)
        self.assertEqual(poll.returncode, 0, poll.stderr)
        self.assertEqual(clipboard.returncode, 0, clipboard.stderr)
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertEqual(json.loads(add_source.stdout)["source_id"], "codex-file")
        self.assertGreaterEqual(json.loads(poll.stdout)["captured_event_count"], 1)
        self.assertEqual(json.loads(clipboard.stdout)["adapter_kind"], "clipboard-once")
        self.assertEqual(json.loads(listing.stdout)["source_count"], 1)

    def test_cli_app_connect_can_register_manual_local_app(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            capture_root = Path(tmp) / "capture-root"

            connected = self.run_cli(
                "app-connect",
                "--context",
                "demo",
                "--app-name",
                "Manual MCP Probe",
                "--bundle-id",
                "local.manual.probe",
                "--pid",
                "424242",
                "--tag",
                "manual-probe",
                "--speaker",
                "codex",
                "--capture-root",
                str(capture_root),
                "--confirm",
                "--allow-manual",
                state_path=state_path,
                memory_path=memory_path,
            )
            connections = self.run_cli(
                "app-connections",
                "--capture-root",
                str(capture_root),
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(connected.returncode, 0, connected.stderr)
        self.assertEqual(connections.returncode, 0, connections.stderr)
        self.assertEqual(json.loads(connected.stdout)["app_name"], "Manual MCP Probe")
        self.assertEqual(json.loads(connections.stdout)["connection_count"], 1)

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

    def test_cli_agent_brief_hydrates_context_and_advances_cursor(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "cli-agent-brief-memory",
                "--text",
                "Agent brief hydration should recall CLI context deployments.",
                state_path=state_path,
                memory_path=memory_path,
            )
            event_id = json.loads(remember.stdout)["agent_deployment"]["event_id"]
            first = self.run_cli(
                "agent-brief",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                "--prompt",
                "CLI context deployments",
                state_path=state_path,
                memory_path=memory_path,
            )
            second = self.run_cli(
                "agent-brief",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                "--prompt",
                "CLI context deployments",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        first_payload = json.loads(first.stdout)
        second_payload = json.loads(second.stdout)
        self.assertEqual(first_payload["action"], "agent-context-hydrate")
        self.assertEqual(first_payload["new_event_count"], 1)
        self.assertEqual(first_payload["latest_event_id"], event_id)
        self.assertEqual(first_payload["ack"]["agent_id"], "cli-agent")
        self.assertIn("cli-agent-brief-memory", first_payload["briefing_markdown"])
        self.assertIn("cli-agent-brief-memory", first_payload["recall_result"])
        self.assertIn("payload_summary", first_payload["events"][0])
        self.assertNotIn(
            "Agent brief hydration should recall CLI context deployments.",
            json.dumps(first_payload["events"]),
        )
        self.assertIn("source_text_bytes", first_payload["events"][0]["payload_summary"])
        self.assertEqual(second_payload["new_event_count"], 0)
        self.assertEqual(second_payload["since_event_id"], event_id)

    def test_cli_agent_brief_morning_mode_returns_operator_start_work_sections(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            remember = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "remember-text",
                "--context",
                "demo",
                "--tag",
                "morning-brief-memory",
                "--text",
                "Decision: Morning Brief should tell the operator what to verify before touching code.",
                state_path=state_path,
                memory_path=memory_path,
            )
            brief = self.run_cli(
                "--embedding-provider",
                "semantic-hash",
                "agent-brief",
                "--mode",
                "morning",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                "--prompt",
                "Morning Brief operator workflow",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(brief.returncode, 0, brief.stderr)
        payload = json.loads(brief.stdout)
        self.assertEqual(payload["action"], "agent-brief-morning")
        self.assertEqual(payload["mode"], "morning")
        section_ids = [section["id"] for section in payload["brief_sections"]]
        self.assertEqual(
            section_ids[:5],
            [
                "current_objective",
                "relevant_memories",
                "open_risks",
                "recent_app_session_traces",
                "recommended_next_actions",
            ],
        )
        for section in payload["brief_sections"][:5]:
            self.assertIn("confidence", section)
            self.assertIn("source_memories", section)
        self.assertEqual(payload["receipt"]["action"], "agent-brief-morning")

    def test_cli_cortex_governor_enters_ticks_commits_and_reports_state(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"

            entered = self.run_cli(
                "enter-cortex",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                "--task",
                "Ship a governed cortex loop.",
                "--mode",
                "strict",
                state_path=state_path,
                memory_path=memory_path,
            )
            session_id = json.loads(entered.stdout)["session_id"]
            tick = self.run_cli(
                "cortex-tick",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                "--session-id",
                session_id,
                "--observation",
                "Preparing to mutate files.",
                "--proposed-action",
                "Edit backend and run tests.",
                "--intended-file",
                "mlx_backend.py",
                "--intended-tool",
                "python -m unittest tests.test_cli",
                "--mutation-intent",
                "--confidence",
                "0.41",
                state_path=state_path,
                memory_path=memory_path,
            )
            committed = self.run_cli(
                "commit-cortex",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                "--session-id",
                session_id,
                "--type",
                "decision",
                "--truth-posture",
                "operator-confirmed",
                "--text",
                "Cortex Governor exposes typed state through CLI.",
                "--evidence",
                '{"source":"unit-test"}',
                state_path=state_path,
                memory_path=memory_path,
            )
            memory_id = json.loads(committed.stdout)["memory_id"]
            moderated = self.run_cli(
                "moderate-cortex",
                "--context",
                "demo",
                "--memory-id",
                memory_id,
                "--action",
                "promote",
                "--reason",
                "CLI operator verified",
                state_path=state_path,
                memory_path=memory_path,
            )
            state = self.run_cli(
                "cortex-state",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(entered.returncode, 0, entered.stderr)
        self.assertEqual(tick.returncode, 0, tick.stderr)
        self.assertEqual(committed.returncode, 0, committed.stderr)
        self.assertEqual(moderated.returncode, 0, moderated.stderr)
        self.assertEqual(state.returncode, 0, state.stderr)
        self.assertEqual(json.loads(entered.stdout)["action"], "enter-spiking-cortex")
        self.assertEqual(json.loads(tick.stdout)["decision"], "verify-first")
        self.assertEqual(json.loads(tick.stdout)["intended_files"], ["mlx_backend.py"])
        self.assertEqual(
            json.loads(tick.stdout)["intended_tools"],
            ["python -m unittest tests.test_cli"],
        )
        self.assertEqual(json.loads(committed.stdout)["trace_type"], "decision")
        self.assertEqual(json.loads(moderated.stdout)["moderation_action"], "promote")
        self.assertGreaterEqual(json.loads(state.stdout)["typed_memory_counts"]["decision"], 1)

    def test_cli_moderate_cortex_prune_requires_confirm(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            committed = self.run_cli(
                "commit-cortex",
                "--context",
                "demo",
                "--agent-id",
                "cli-agent",
                "--session-id",
                "moderation-session",
                "--type",
                "assumption",
                "--truth-posture",
                "inferred",
                "--text",
                "CLI Cortex prune should require explicit confirmation.",
                "--confidence",
                "0.42",
                state_path=state_path,
                memory_path=memory_path,
            )
            memory_id = json.loads(committed.stdout)["memory_id"]
            rejected = self.run_cli(
                "moderate-cortex",
                "--context",
                "demo",
                "--memory-id",
                memory_id,
                "--action",
                "prune",
                "--reason",
                "missing confirmation",
                state_path=state_path,
                memory_path=memory_path,
            )
            accepted = self.run_cli(
                "moderate-cortex",
                "--context",
                "demo",
                "--memory-id",
                memory_id,
                "--action",
                "prune",
                "--reason",
                "confirmed removal",
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(committed.returncode, 0, committed.stderr)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("confirm", json.loads(rejected.stdout)["error"])
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertTrue(json.loads(accepted.stdout)["prune"]["result"]["deleted"])

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

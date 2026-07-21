import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from memory_store import DurableMemoryStore
from mlx_backend import SpikingAttentionBackend
from capture_daemon import CaptureInboxDaemon
from core_client import CoreClient, CoreOutcomeUnknown


ROOT = Path(__file__).resolve().parents[1]


class SynapseCliTests(unittest.TestCase):
    def test_replication_peer_add_uses_core_inbox_and_anti_tofu_digest(self):
        import synapse_cli

        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            core = CoreClient(
                socket_path=root / "core" / "service.sock",
                state_path=root / "runtime_state.json",
                replication_inbox_root=root / "replication" / "inbox",
            )
            core.replication_pair_peer = mock.Mock(return_value={"paired": True})
            arguments = mock.Mock(
                descriptor="peer.json",
                expected_descriptor_digest="a" * 64,
                lineage_id="s2lineage_" + ("b" * 32),
                direction="send",
                confirm=True,
            )
            with mock.patch("synapse_cli.build_backend", return_value=core):
                result = synapse_cli.command_replication_peer_add(arguments)

        self.assertTrue(result["paired"])
        core.replication_pair_peer.assert_called_once_with(
            str(root / "replication" / "inbox" / "peer.json"),
            "a" * 64,
            lineage_id="s2lineage_" + ("b" * 32),
            direction="send",
            confirm=True,
        )

    def test_replication_relative_input_requires_explicit_core_binding(self):
        import synapse_cli

        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            core = CoreClient(
                socket_path=root / "core" / "service.sock",
                state_path=root / "runtime_state.json",
            )
            arguments = mock.Mock(
                descriptor="peer.json",
                expected_descriptor_digest="a" * 64,
                lineage_id="s2lineage_" + ("b" * 32),
                direction="send",
                confirm=True,
            )
            with mock.patch("synapse_cli.build_backend", return_value=core):
                with self.assertRaisesRegex(RuntimeError, "binding"):
                    synapse_cli.command_replication_peer_add(arguments)

    def test_replication_mutation_cli_refuses_local_backend(self):
        import synapse_cli

        with mock.patch("synapse_cli.build_backend", return_value=mock.Mock()):
            with self.assertRaisesRegex(RuntimeError, "authoritative core"):
                synapse_cli.command_replication_checkpoint_create(
                    mock.Mock(peer_id="s2node_" + ("a" * 32))
                )

    def test_recovery_commands_forward_expected_journal_and_runtime_digests(self):
        import synapse_cli

        digest = "a" * 64
        runtime_digest = "c" * 64
        backend = mock.Mock()
        backend.verify_recovery_bundle.return_value = {"verified": True}
        backend.restore_recovery_bundle_isolated.return_value = {"verified": True}
        with TemporaryDirectory() as tmp, mock.patch(
            "synapse_cli.build_backend",
            return_value=backend,
        ):
            receipt = str(Path(tmp) / "bundle.receipt.json")
            output_root = str(Path(tmp) / "restore-proof")
            verify_args = mock.Mock(
                receipt=receipt,
                capture_root=None,
                expected_database_sha256=None,
                expected_capture_sha256=None,
                expected_request_journal_sha256=digest,
                expected_runtime_state_sha256=runtime_digest,
            )
            restore_args = mock.Mock(
                receipt=receipt,
                output_root=output_root,
                capture_root=None,
                expected_database_sha256=None,
                expected_capture_sha256=None,
                expected_request_journal_sha256=digest,
                expected_runtime_state_sha256=runtime_digest,
                confirm=True,
            )

            self.assertTrue(
                synapse_cli.command_verify_recovery_bundle(verify_args)["verified"]
            )
            self.assertTrue(
                synapse_cli.command_restore_recovery_bundle(restore_args)["verified"]
            )

        backend.verify_recovery_bundle.assert_called_once_with(
            receipt,
            capture_root=None,
            expected_database_sha256=None,
            expected_capture_sha256=None,
            expected_request_journal_sha256=digest,
            expected_runtime_state_sha256=runtime_digest,
        )
        backend.restore_recovery_bundle_isolated.assert_called_once_with(
            receipt,
            output_root,
            capture_root=None,
            expected_database_sha256=None,
            expected_capture_sha256=None,
            expected_request_journal_sha256=digest,
            expected_runtime_state_sha256=runtime_digest,
            confirm=True,
        )

    def run_cli(
        self,
        *args: str,
        state_path: Path,
        memory_path: Path | None = None,
        environment_overrides: dict[str, str] | None = None,
    ):
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
        environment = os.environ.copy()
        environment.pop("SYNAPSE_S2_DEFAULT_RESPONSE_MODE", None)
        environment.pop("SYNAPSE_S2_MAX_RESPONSE_BYTES", None)
        environment.update(environment_overrides or {})
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def assert_compact_contract(
        self,
        result: subprocess.CompletedProcess[str],
        *,
        operation: str,
        budget: int,
    ) -> dict:
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema"], "synapse-s2.token-contract.v1")
        self.assertEqual(payload["operation"], operation)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["response_contract"]["profile"], "compact")
        self.assertEqual(payload["response_contract"]["max_output_bytes"], budget)
        encoded = result.stdout.rstrip("\n").encode("utf-8")
        self.assertEqual(payload["response_contract"]["serialized_bytes"], len(encoded))
        self.assertLessEqual(len(encoded), budget)
        return payload

    def test_emit_exits_cleanly_when_stdout_pipe_closes(self):
        import synapse_cli

        class ClosedPipeStdout:
            def __init__(self):
                self.closed = False

            def write(self, _text: str) -> int:
                raise BrokenPipeError("pipe closed")

            def flush(self) -> None:
                return None

            def close(self) -> None:
                self.closed = True

        original_stdout = sys.stdout
        closed_stdout = ClosedPipeStdout()
        try:
            sys.stdout = closed_stdout
            with self.assertRaises(SystemExit) as raised:
                synapse_cli.emit({"ok": True}, as_json=True)
        finally:
            sys.stdout = original_stdout

        self.assertEqual(raised.exception.code, 0)
        self.assertTrue(closed_stdout.closed)

    def test_cli_public_error_redacts_secret_and_local_path(self):
        import synapse_cli

        secret = "sk-cli-error-secret-1234567890"
        local_path = "/Users/dan.driver/private/cli-token.json"
        parsed_args = mock.Mock(json=True)
        parsed_args.func = mock.Mock(
            side_effect=RuntimeError(f"token={secret} at {local_path}")
        )
        parser = mock.Mock()
        parser.parse_args.return_value = parsed_args
        with (
            mock.patch.object(synapse_cli, "build_parser", return_value=parser),
            mock.patch.object(synapse_cli, "emit") as emit_mock,
        ):
            return_code = synapse_cli.main(["--json"])

        self.assertEqual(return_code, 1)
        payload = emit_mock.call_args.args[0]
        self.assertIn("[REDACTED_SECRET]", payload["error"])
        self.assertIn("[LOCAL_PATH]", payload["error"])
        self.assertNotIn(secret, payload["error"])
        self.assertNotIn(local_path, payload["error"])
        self.assertTrue(emit_mock.call_args.kwargs["as_json"])

    def test_cli_outcome_unknown_emits_only_fixed_reconciliation_handle(self):
        import synapse_cli

        parsed_args = mock.Mock(json=True)
        parsed_args.func = mock.Mock(
            side_effect=CoreOutcomeUnknown(
                caller="cli-caller",
                request_id="req-cli-ambiguous",
                operation="set_enabled",
            )
        )
        parser = mock.Mock()
        parser.parse_args.return_value = parsed_args
        with (
            mock.patch.object(synapse_cli, "build_parser", return_value=parser),
            mock.patch.object(synapse_cli, "emit") as emit_mock,
        ):
            return_code = synapse_cli.main(["--json"])

        self.assertEqual(return_code, 1)
        payload = emit_mock.call_args.args[0]
        self.assertEqual(payload["error"], "outcome_unknown")
        self.assertEqual(
            payload["reconciliation"],
            {
                "code": "outcome_unknown",
                "caller": "cli-caller",
                "request_id": "req-cli-ambiguous",
                "operation": "set_enabled",
                "replay_safe": False,
            },
        )
        rendered = json.dumps(payload, sort_keys=True)
        for forbidden in ("arguments", "fingerprint", "response_sha256", "canary"):
            self.assertNotIn(forbidden, rendered)

    def test_request_status_command_uses_authoritative_backend_without_replay(self):
        import synapse_cli

        backend = mock.Mock()
        backend.request_status.return_value = {
            "caller": "cli-caller",
            "request_id": "req-cli-status",
            "state": "not_found",
            "replay_safe": False,
            "retention_expiry_possible": True,
        }
        args = mock.Mock(caller="cli-caller", request_id="req-cli-status")
        with mock.patch.object(synapse_cli, "build_backend", return_value=backend):
            payload = synapse_cli.command_request_status(args)

        self.assertEqual(payload["state"], "not_found")
        self.assertFalse(payload["replay_safe"])
        backend.request_status.assert_called_once_with(
            caller="cli-caller",
            request_id="req-cli-status",
        )

    def test_cli_startup_import_error_is_sanitized(self):
        import synapse_cli

        secret = "sk-cli-startup-secret-1234567890"
        local_path = "/Users/dan.driver/private/startup.py"
        with (
            mock.patch.object(
                synapse_cli,
                "_STARTUP_IMPORT_ERROR",
                RuntimeError(f"api_key={secret} from {local_path}"),
            ),
            mock.patch.object(synapse_cli, "emit") as emit_mock,
        ):
            return_code = synapse_cli.main(["--json"])

        self.assertEqual(return_code, 1)
        payload = emit_mock.call_args.args[0]
        self.assertIn("[REDACTED_SECRET]", payload["error"])
        self.assertIn("[LOCAL_PATH]", payload["error"])
        self.assertNotIn(secret, payload["error"])
        self.assertNotIn(local_path, payload["error"])
        self.assertTrue(emit_mock.call_args.kwargs["as_json"])

    def test_cli_rejects_secret_bearing_output_paths_before_backend_side_effects(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            secret = "sk-cli-output-secret-1234567890"
            unsafe_parent = Path(tmp) / f"api_key={secret}"
            commands = (
                ("certify-runtime", "--output", str(unsafe_parent / "certification.json")),
                (
                    "export-memory",
                    "--context",
                    "default",
                    "--output",
                    str(unsafe_parent / "memory.json"),
                ),
                ("backup-memory", "--output", str(unsafe_parent / "memory.sqlite3")),
            )

            for command in commands:
                with self.subTest(command=command[0]):
                    result = self.run_cli(
                        *command,
                        state_path=state_path,
                        memory_path=memory_path,
                    )
                    self.assertEqual(result.returncode, 1)
                    payload = json.loads(result.stdout)
                    self.assertIn("credential material", payload["error"])
                    self.assertNotIn(secret, result.stdout)
                    self.assertNotIn(secret, result.stderr)
                    self.assertFalse(unsafe_parent.exists())
                    self.assertFalse(state_path.exists())
                    self.assertFalse(memory_path.exists())

    def test_cli_argparse_json_errors_never_echo_secret_values(self):
        secret = "sk-cli-argparse-secret-1234567890"
        cases = (
            ["--json", f"password={secret}"],
            ["--json", "--dimension", f"password={secret}", "status"],
            ["--json", "status", "--unknown", f"password={secret}"],
        )

        for argv in cases:
            with self.subTest(argv=argv):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "synapse_cli.py"), *argv],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                combined = result.stdout + result.stderr
                self.assertEqual(result.returncode, 2, combined)
                self.assertEqual(result.stderr, "")
                payload = json.loads(result.stdout)
                self.assertIn("error", payload)
                self.assertIn("[REDACTED_SECRET]", payload["error"])
                self.assertNotIn(secret, combined)

    def test_cli_argparse_text_errors_preserve_safe_usage_without_secret(self):
        secret = "sk-cli-text-argparse-secret-1234567890"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "synapse_cli.py"),
                "--dimension",
                f"password={secret}",
                "status",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("usage: synapse_cli.py", result.stderr)
        self.assertIn("[REDACTED_SECRET]", result.stderr)
        self.assertNotIn(secret, result.stderr)

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

    def test_cli_memory_integrity_audits_and_requires_confirmed_repair(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            store = DurableMemoryStore(memory_path)
            entry = store.upsert_entry(
                tag="cli-index-repair",
                context_id="demo",
                source_text="Durable operator evidence.",
                metadata={"display_label": "Operator evidence"},
                embedding_dimensions=8,
                spike_indices=[1, 2, 3],
                neuron_indices=[1, 2],
            )
            with closing(sqlite3.connect(memory_path)) as conn:
                conn.execute(
                    "DELETE FROM memory_spikes WHERE memory_id = ? AND spike_index = ?",
                    (entry["memory_id"], 2),
                )
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = 'memory_spikes_v1'"
                )
                conn.commit()

            audit = self.run_cli(
                "memory-integrity",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )
            audit_payload = json.loads(audit.stdout)
            unconfirmed = self.run_cli(
                "memory-integrity",
                "--context",
                "demo",
                "--repair",
                state_path=state_path,
                memory_path=memory_path,
            )
            stale = self.run_cli(
                "memory-integrity",
                "--context",
                "demo",
                "--repair",
                "--confirm",
                "--expected-revision",
                "stale-revision",
                state_path=state_path,
                memory_path=memory_path,
            )
            with closing(sqlite3.connect(memory_path)) as conn:
                pre_repair_spikes = conn.execute(
                    "SELECT spike_index FROM memory_spikes WHERE memory_id = ? ORDER BY 1",
                    (entry["memory_id"],),
                ).fetchall()
                pre_repair_marker = conn.execute(
                    "SELECT 1 FROM store_migrations WHERE key = 'memory_spikes_v1'"
                ).fetchone()
            repaired = self.run_cli(
                "memory-integrity",
                "--context",
                "demo",
                "--repair",
                "--confirm",
                "--expected-revision",
                audit_payload["audit_revision"],
                state_path=state_path,
                memory_path=memory_path,
            )
            verified = self.run_cli(
                "memory-integrity",
                "--context",
                "demo",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(audit.returncode, 0, audit.stderr)
        self.assertEqual(audit_payload["status"], "degraded")
        self.assertNotEqual(unconfirmed.returncode, 0)
        self.assertIn("requires confirm=True", unconfirmed.stdout)
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("repair plan is stale", stale.stdout)
        self.assertEqual(pre_repair_spikes, [(1,), (3,)])
        self.assertIsNone(pre_repair_marker)
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        self.assertEqual(json.loads(repaired.stdout)["repaired_memory_count"], 1)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout)["status"], "ready")

    def test_cli_capture_ledger_integrity_requires_a_reviewed_repair(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            memory_path = root / "memory.sqlite3"
            DurableMemoryStore(memory_path)
            CaptureInboxDaemon(root=root).prepare_transport()

            audit = self.run_cli(
                "capture-ledger-integrity",
                "--capture-root",
                str(root),
                "--sample-limit",
                "7",
                state_path=state_path,
                memory_path=memory_path,
            )
            audit_payload = json.loads(audit.stdout)
            unconfirmed = self.run_cli(
                "capture-ledger-integrity",
                "--capture-root",
                str(root),
                "--repair",
                "--expected-revision",
                audit_payload["audit_revision"],
                state_path=state_path,
                memory_path=memory_path,
            )
            missing_revision = self.run_cli(
                "capture-ledger-integrity",
                "--capture-root",
                str(root),
                "--repair",
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )
            repaired = self.run_cli(
                "capture-ledger-integrity",
                "--capture-root",
                str(root),
                "--sample-limit",
                "7",
                "--repair",
                "--confirm",
                "--expected-revision",
                audit_payload["audit_revision"],
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(audit.returncode, 0, audit.stderr)
        self.assertEqual(audit_payload["action"], "capture-ledger-audit")
        self.assertEqual(audit_payload["status"], "ready")
        self.assertEqual(audit_payload["sample_limit"], 7)
        rendered_audit = json.dumps(audit_payload, sort_keys=True)
        for private_field in (
            '"_candidates"',
            '"file_sha256"',
            '"relative_path"',
            '"request_fingerprint"',
        ):
            self.assertNotIn(private_field, rendered_audit)

        self.assertEqual(unconfirmed.returncode, 1, unconfirmed.stderr)
        self.assertIn("requires confirm=True", unconfirmed.stdout)
        self.assertEqual(missing_revision.returncode, 1, missing_revision.stderr)
        self.assertIn("reviewed 64-character audit revision", missing_revision.stdout)
        self.assertEqual(repaired.returncode, 0, repaired.stderr)
        repaired_payload = json.loads(repaired.stdout)
        self.assertEqual(repaired_payload["action"], "capture-ledger-repair")
        self.assertEqual(repaired_payload["state"], "no-repair-needed")
        self.assertTrue(repaired_payload["repair_confirmed"])
        self.assertEqual(
            repaired_payload["expected_revision"],
            audit_payload["audit_revision"],
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
                "--scope",
                "local",
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
        self.assertEqual(json.loads(query.stdout)["recall_scope"], "local")
        self.assertFalse(json.loads(disable.stdout)["effective_enabled"])
        self.assertIn("disabled", json.loads(disabled_query.stdout)["result"].lower())

    def test_cli_lists_and_approves_namespace_links(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            for context, tag, text in (
                ("alpha", "alpha-memory", "shared camera control topic"),
                ("beta", "beta-memory", "shared control room topic"),
            ):
                remembered = self.run_cli(
                    "remember-text",
                    "--context",
                    context,
                    "--tag",
                    tag,
                    "--text",
                    text,
                    state_path=state_path,
                    memory_path=memory_path,
                )
                self.assertEqual(remembered.returncode, 0, remembered.stderr)

            refused = self.run_cli(
                "namespace-link",
                "--source-context",
                "alpha",
                "--target-context",
                "beta",
                state_path=state_path,
                memory_path=memory_path,
            )
            approved = self.run_cli(
                "namespace-link",
                "--source-context",
                "alpha",
                "--target-context",
                "beta",
                "--weight",
                "0.8",
                "--evidence",
                '{"source":"cli-unit-test"}',
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )
            namespace_map = self.run_cli(
                "namespace-map",
                "--context",
                "alpha",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("confirm=true is required", json.loads(refused.stdout)["error"])
        self.assertEqual(approved.returncode, 0, approved.stderr)
        approved_payload = json.loads(approved.stdout)
        self.assertTrue(approved_payload["approved"])
        self.assertFalse(approved_payload["automatic_cross_namespace_write"])
        self.assertEqual(namespace_map.returncode, 0, namespace_map.stderr)
        map_payload = json.loads(namespace_map.stdout)
        self.assertEqual(map_payload["node_count"], 2)
        self.assertEqual(map_payload["link_count"], 1)
        self.assertEqual(map_payload["default_recall_scope"], "local")

    def test_cli_governed_namespace_proposal_review_and_audit(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            for context in ("alpha", "beta"):
                remembered = self.run_cli(
                    "remember-text",
                    "--context",
                    context,
                    "--tag",
                    f"{context}-memory",
                    "--text",
                    f"{context} shared governed bridge evidence",
                    state_path=state_path,
                    memory_path=memory_path,
                )
                self.assertEqual(remembered.returncode, 0, remembered.stdout)

            proposed = self.run_cli(
                "namespace-link-propose",
                "--source-context",
                "alpha",
                "--target-context",
                "beta",
                "--reason",
                "Reviewed overlap requires an explicit decision.",
                "--governance-request-id",
                "cli-governance-proposal",
                state_path=state_path,
                memory_path=memory_path,
            )
            self.assertEqual(proposed.returncode, 0, proposed.stdout)
            proposal = json.loads(proposed.stdout)["proposal"]

            pending_map = self.run_cli(
                "namespace-map",
                "--context",
                "alpha",
                state_path=state_path,
                memory_path=memory_path,
            )
            self.assertEqual(json.loads(pending_map.stdout)["link_count"], 0)

            reviewed = self.run_cli(
                "namespace-link-review",
                "--proposal-id",
                proposal["proposal_id"],
                "--decision",
                "approve",
                "--expected-revision",
                proposal["revision"],
                "--reason",
                "The current evidence supports one-hop connected recall.",
                "--governance-request-id",
                "cli-governance-review",
                state_path=state_path,
                memory_path=memory_path,
            )
            audit = self.run_cli(
                "namespace-link-audit",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(reviewed.returncode, 0, reviewed.stdout)
        self.assertEqual(json.loads(reviewed.stdout)["state"], "approved")
        self.assertEqual(audit.returncode, 0, audit.stdout)
        self.assertEqual(json.loads(audit.stdout)["status"], "ready")

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
                "--response-mode",
                "legacy",
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

    def test_cli_contract_surfaces_default_compact_and_support_full_and_legacy(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            remember = self.run_cli(
                "remember-text",
                "--context",
                "contract-cli",
                "--tag",
                "contract-cli-memory",
                "--text",
                "Compact CLI contracts keep actionable provenance while omitting vectors.",
                state_path=state_path,
                memory_path=memory_path,
            )
            compact_results = {
                "memory-list": self.run_cli(
                    "list-memory",
                    "--context",
                    "contract-cli",
                    "--max-response-bytes",
                    "4096",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
                "memory-graph": self.run_cli(
                    "graph",
                    "--context",
                    "contract-cli",
                    "--max-response-bytes",
                    "4096",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
                "cortex-state": self.run_cli(
                    "cortex-state",
                    "--context",
                    "contract-cli",
                    "--max-response-bytes",
                    "4096",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
                "agent-hydration": self.run_cli(
                    "agent-brief",
                    "--context",
                    "contract-cli",
                    "--agent-id",
                    "codex-desktop",
                    "--consumer-instance-id",
                    "cli-contract-test",
                    "--max-response-bytes",
                    "4096",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
            }
            full = self.run_cli(
                "list-memory",
                "--context",
                "contract-cli",
                "--response-mode",
                "full",
                "--max-response-bytes",
                "131072",
                state_path=state_path,
                memory_path=memory_path,
            )
            legacy = self.run_cli(
                "list-memory",
                "--context",
                "contract-cli",
                "--response-mode",
                "legacy",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        compact_payloads = {
            operation: self.assert_compact_contract(
                result,
                operation=operation,
                budget=4096,
            )
            for operation, result in compact_results.items()
        }
        compact_rendered = json.dumps(compact_payloads, sort_keys=True)
        self.assertNotIn(str(Path(tmp)), compact_rendered)
        self.assertNotIn("memory_db_path", compact_rendered)
        self.assertNotIn("lease_token", compact_rendered)
        self.assertNotIn("spike_indices", compact_rendered)
        deployments = compact_payloads["agent-hydration"]["data"]["delivery"]["deployments"]
        self.assertEqual(len(deployments), 1)
        self.assertTrue(deployments[0]["receipt_id"].startswith("ctxrcpt_"))
        self.assertIsInstance(deployments[0]["event"], dict)

        self.assertEqual(full.returncode, 0, full.stderr)
        full_payload = json.loads(full.stdout)
        self.assertEqual(full_payload["response_contract"]["profile"], "full")
        self.assertEqual(
            full_payload["data"]["payload"]["entries"][0]["tag"],
            "contract-cli-memory",
        )
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        legacy_payload = json.loads(legacy.stdout)
        self.assertNotIn("schema", legacy_payload)
        self.assertEqual(legacy_payload["entries"][0]["tag"], "contract-cli-memory")

    def test_cli_contract_budget_vector_and_secret_errors_are_bounded(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            too_small = self.run_cli(
                "list-memory",
                "--max-response-bytes",
                "1024",
                state_path=state_path,
                memory_path=memory_path,
            )
            compact_vectors = self.run_cli(
                "list-memory",
                "--include-vectors",
                "--max-response-bytes",
                "4096",
                state_path=state_path,
                memory_path=memory_path,
            )
            secret = "sk-cli-contract-secret-1234567890"
            secret_mode = self.run_cli(
                "graph",
                "--response-mode",
                f"api_key={secret}",
                "--max-response-bytes",
                "4096",
                state_path=state_path,
                memory_path=memory_path,
            )
            secret_budget = self.run_cli(
                "cortex-state",
                "--max-response-bytes",
                f"password={secret}",
                state_path=state_path,
                memory_path=memory_path,
                environment_overrides={
                    "SYNAPSE_S2_MAX_RESPONSE_BYTES": "12288",
                },
            )
            self.assertFalse(state_path.exists())
            self.assertFalse(memory_path.exists())
            self.assertFalse(memory_path.with_suffix(".sqlite3.lock").exists())

        for result, expected_fragment in (
            (too_small, "at least 4096"),
            (compact_vectors, "do not support vectors"),
            (secret_mode, "compact or full"),
            (secret_budget, "must be an integer"),
        ):
            with self.subTest(expected_fragment=expected_fragment):
                self.assertEqual(result.returncode, 1)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["schema"], "synapse-s2.token-contract.v1")
                self.assertFalse(payload["ok"])
                self.assertIn(expected_fragment, payload["data"]["error"]["message"])
                self.assertLessEqual(
                    len(result.stdout.rstrip("\n").encode("utf-8")),
                    payload["response_contract"]["max_output_bytes"],
                )
                self.assertNotIn(secret, result.stdout)
                self.assertNotIn(secret, result.stderr)
        vector_payload = json.loads(compact_vectors.stdout)
        self.assertEqual(
            vector_payload["response_contract"]["max_output_bytes"],
            4096,
        )
        secret_mode_payload = json.loads(secret_mode.stdout)
        self.assertEqual(
            secret_mode_payload["response_contract"]["max_output_bytes"],
            4096,
        )
        secret_budget_payload = json.loads(secret_budget.stdout)
        self.assertEqual(
            secret_budget_payload["response_contract"]["max_output_bytes"],
            12288,
        )

    def test_cli_compact_limits_are_normalized_before_source_metadata(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            commands = {
                "memory-list": self.run_cli(
                    "list-memory",
                    "--limit",
                    "-9",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
                "memory-graph": self.run_cli(
                    "graph",
                    "--limit",
                    "-9",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
                "cortex-state": self.run_cli(
                    "cortex-state",
                    "--limit",
                    "-9",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
                "agent-hydration": self.run_cli(
                    "agent-brief",
                    "--context",
                    "negative-limit",
                    "--agent-id",
                    "codex-desktop",
                    "--consumer-instance-id",
                    "negative-limit-test",
                    "--limit",
                    "-9",
                    "--graph-limit",
                    "-7",
                    state_path=state_path,
                    memory_path=memory_path,
                ),
            }

        for operation, result in commands.items():
            with self.subTest(operation=operation):
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["operation"], operation)
                if operation == "agent-hydration":
                    self.assertEqual(payload["pagination"]["requested_limit"], 1)
                    self.assertEqual(payload["pagination"]["effective_limit"], 1)
                    self.assertFalse(
                        payload["completeness"]["graph_source_limit_reduced"]
                    )
                else:
                    self.assertEqual(payload["pagination"]["requested_limit"], 1)
                    self.assertEqual(payload["pagination"]["effective_limit"], 1)

    def test_cli_hydration_projection_failure_releases_receipts_after_source_cap(self):
        import synapse_cli

        backend = mock.Mock()
        backend.delivery_instance_id = "cli-contract-instance"
        backend.hydrate_agent_context.return_value = {
            "context_id": "demo",
            "agent_id": "codex-desktop",
            "deliveries": [
                {
                    "receipt_id": "ctxrcpt_test-projection-release",
                    "event_id": 1,
                }
            ],
        }
        args = mock.Mock(
            mode="hydrate",
            context="demo",
            agent_id="codex-desktop",
            prompt="",
            since_event_id=None,
            limit=500,
            graph_limit=500,
            observe_only=False,
            consumer_instance_id="",
            lease_seconds=60.0,
            response_mode="compact",
            max_response_bytes="4096",
        )
        with (
            mock.patch("synapse_cli.build_backend", return_value=backend),
            mock.patch(
                "synapse_cli.project_response",
                side_effect=RuntimeError("projection failed"),
            ),
            self.assertRaisesRegex(RuntimeError, "projection failed"),
        ):
            synapse_cli.command_agent_brief(args)

        effective_event_limit = backend.hydrate_agent_context.call_args.kwargs[
            "event_limit"
        ]
        self.assertGreaterEqual(effective_event_limit, 1)
        self.assertLessEqual(effective_event_limit, 8)
        self.assertEqual(
            backend.hydrate_agent_context.call_args.kwargs["graph_limit"],
            20,
        )
        backend.release_context_events.assert_called_once_with(
            context_id="demo",
            agent_id="codex-desktop",
            consumer_instance_id="cli-contract-instance",
            receipt_ids=["ctxrcpt_test-projection-release"],
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
        self.assertFalse(start_payload["agent_brief"]["claim_events"])
        self.assertEqual(start_payload["agent_brief"]["deliveries"], [])
        self.assertFalse(start_payload["agent_brief"]["ack_required"])
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

    def test_cli_output_paths_reject_secret_shapes_without_creating_files(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            marker = "SYNTHETIC_CLI_OUTPUT_SECRET_42"
            commands = (
                "certify-runtime",
                "export-memory",
                "backup-memory",
            )
            results = []
            outputs = []
            for command in commands:
                output = Path(tmp) / f"password={marker}-{command}.json"
                outputs.append(output)
                results.append(
                    self.run_cli(
                        command,
                        "--output",
                        str(output),
                        state_path=state_path,
                        memory_path=memory_path,
                    )
                )

        rendered = "\n".join(
            result.stdout + result.stderr for result in results
        )
        self.assertTrue(all(result.returncode == 1 for result in results))
        self.assertNotIn(marker, rendered)
        self.assertTrue(all(not output.exists() for output in outputs))

    def test_cli_database_only_backup_rejects_verified_bundle_lane(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            memory_path = root / "memory.sqlite3"
            verified_directory = root / "backups" / "verified"
            verified_directory.mkdir(mode=0o700, parents=True)
            output = verified_directory / "database-only.sqlite3"

            result = self.run_cli(
                "backup-memory",
                "--output",
                str(output),
                state_path=state_path,
                memory_path=memory_path,
            )

            self.assertEqual(result.returncode, 1, result.stdout)
            rendered = result.stdout + result.stderr
            self.assertRegex(
                rendered.lower(),
                r"verified|paired|reserved|database-only|recovery lane",
            )
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + ".receipt.json").exists())

    def test_cli_paired_recovery_and_retention_plan_are_operational(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            memory_path = root / "memory.sqlite3"
            CaptureInboxDaemon(root=root).prepare_transport()
            backup = self.run_cli(
                "backup-recovery",
                "--capture-root",
                str(root),
                "--purpose",
                "cli-test",
                "--pinned",
                state_path=state_path,
                memory_path=memory_path,
            )
            plan = self.run_cli(
                "recovery-retention-plan",
                "--keep-latest",
                "1",
                "--max-age-days",
                "0",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(backup.returncode, 0, backup.stderr)
        self.assertEqual(plan.returncode, 0, plan.stderr)
        backup_payload = json.loads(backup.stdout)
        plan_payload = json.loads(plan.stdout)
        self.assertTrue(backup_payload["bundle_verified"])
        self.assertTrue(backup_payload["cutover_ready"])
        self.assertTrue(
            backup_payload["capture_ledger_binding"]["verified"]
        )
        self.assertEqual(plan_payload["verified_bundle_count"], 1)
        self.assertEqual(plan_payload["retire_bundle_count"], 0)
        self.assertTrue(plan_payload["apply_permitted"])

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
                "--response-mode",
                "legacy",
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
                "--response-mode",
                "legacy",
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
                "--response-mode",
                "legacy",
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
                "--response-mode",
                "legacy",
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
            all(
                "sk-test-secret123" not in entry["source_text"]
                for entry in graph_payload["entries"]
            )
        )

    def test_cli_capture_error_resolution_archives_reviewed_history(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            capture_root = Path(tmp) / "capture-root"
            initial = self.run_cli(
                "capture-inbox-status",
                "--capture-root",
                str(capture_root),
                state_path=state_path,
                memory_path=memory_path,
            )
            self.assertEqual(initial.returncode, 0, initial.stderr)
            CaptureInboxDaemon(root=capture_root).prepare_transport()
            evidence = capture_root / "capture_errors" / "terminal.evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "artifact_type": "stale-capture-inbox-temp",
                        "raw_payload_retained": False,
                        "content_digest_recorded": False,
                        "disposition": "recovered-discard-complete",
                    }
                ),
                encoding="utf-8",
            )
            evidence.chmod(0o600)
            reason = "reviewed terminal capture evidence"
            preflight = self.run_cli(
                "capture-error-preflight",
                "--capture-root",
                str(capture_root),
                "--reason",
                reason,
                state_path=state_path,
                memory_path=memory_path,
            )
            token = json.loads(preflight.stdout)["preflight_token"]
            rejected = self.run_cli(
                "capture-error-resolve",
                "--capture-root",
                str(capture_root),
                "--preflight-token",
                token,
                "--reason",
                reason,
                state_path=state_path,
                memory_path=memory_path,
            )
            resolved = self.run_cli(
                "capture-error-resolve",
                "--capture-root",
                str(capture_root),
                "--preflight-token",
                token,
                "--reason",
                reason,
                "--confirm",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("confirm=true", rejected.stdout + rejected.stderr)
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        self.assertEqual(json.loads(resolved.stdout)["resolved_count"], 1)

    def test_cli_capture_session_replays_supplied_capture_id(self):
        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            capture_id = "s2cap_" + ("9" * 32)
            args = (
                "capture-session",
                "--context",
                "demo",
                "--tag",
                "cli-retry",
                "--speaker",
                "codex",
                "--text",
                "Thread: CLI retry. Event: one supplied operation ID commits once.",
                "--capture-id",
                capture_id,
            )

            first = self.run_cli(
                *args,
                state_path=state_path,
                memory_path=memory_path,
            )
            replay = self.run_cli(
                *args,
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        first_payload = json.loads(first.stdout)
        replay_payload = json.loads(replay.stdout)
        self.assertEqual(first_payload["capture_id"], capture_id)
        self.assertEqual(replay_payload["capture_id"], capture_id)
        self.assertFalse(first_payload["idempotent_replay"])
        self.assertTrue(replay_payload["idempotent_replay"])
        self.assertEqual(
            first_payload["agent_deployment"]["event_id"],
            replay_payload["agent_deployment"]["event_id"],
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
                "--agent-id",
                "codex-desktop",
                "--consumer-instance-id",
                "cli-test-instance",
                state_path=state_path,
            )
            receipt_id = json.loads(pull.stdout)["deliveries"][0]["receipt_id"]
            ack = self.run_cli(
                "ack-context",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--receipt-id",
                receipt_id,
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
        self.assertEqual(json.loads(ack.stdout)["agent_id"], "codex-desktop")
        self.assertEqual(
            json.loads(ack.stdout)["cursor"]["last_event_id"],
            event_id,
        )
        self.assertEqual(
            json.loads(cursors.stdout)["cursors"][0]["agent_id"],
            "codex-desktop",
        )

    def test_implicit_cli_consumers_are_nonce_fenced_per_backend_instance(self):
        import synapse_cli

        with TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            memory_path = Path(tmp) / "memory.sqlite3"
            first_backend = SpikingAttentionBackend(
                dimension=8,
                num_neurons=8,
                default_top_k=2,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            second_backend = SpikingAttentionBackend(
                dimension=8,
                num_neurons=8,
                default_top_k=2,
                compile_graph=False,
                state_path=state_path,
                memory_path=memory_path,
            )
            first_backend.publish_context_event(
                context_id="demo",
                source_surface="cli-test",
                event_type="nonce-fencing",
                summary="Do not share an active receipt across CLI instances.",
                agent_targets=["codex-desktop"],
            )
            args = mock.Mock(
                context="demo",
                agent_id="codex-desktop",
                consumer_instance_id="",
                limit=1,
                lease_seconds=60.0,
            )
            with mock.patch(
                "synapse_cli.build_backend",
                side_effect=[first_backend, second_backend],
            ):
                first = synapse_cli.command_pull_context(args)
                second = synapse_cli.command_pull_context(args)

        self.assertNotEqual(
            first["consumer_instance_id"],
            second["consumer_instance_id"],
        )
        self.assertRegex(
            first["consumer_instance_id"],
            r"^backend-\d+-[0-9a-f]{12}$",
        )
        self.assertEqual(first["delivery_count"], 1)
        self.assertEqual(second["delivery_count"], 0)
        self.assertIsNotNone(second["blocking_delivery"])

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
                "codex-desktop",
                "--consumer-instance-id",
                "cli-agent-instance",
                "--prompt",
                "CLI context deployments",
                "--response-mode",
                "legacy",
                state_path=state_path,
                memory_path=memory_path,
            )
            first_payload = json.loads(first.stdout)
            ack = self.run_cli(
                "ack-context",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--receipt-id",
                first_payload["deliveries"][0]["receipt_id"],
                state_path=state_path,
                memory_path=memory_path,
            )
            second = self.run_cli(
                "agent-brief",
                "--context",
                "demo",
                "--agent-id",
                "codex-desktop",
                "--consumer-instance-id",
                "cli-agent-instance",
                "--prompt",
                "CLI context deployments",
                "--response-mode",
                "legacy",
                state_path=state_path,
                memory_path=memory_path,
            )

        self.assertEqual(remember.returncode, 0, remember.stderr)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(ack.returncode, 0, ack.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        second_payload = json.loads(second.stdout)
        self.assertEqual(first_payload["action"], "agent-context-hydrate")
        self.assertEqual(first_payload["new_event_count"], 1)
        self.assertEqual(first_payload["latest_event_id"], event_id)
        self.assertIsNone(first_payload["ack"])
        self.assertTrue(first_payload["ack_required"])
        self.assertEqual(json.loads(ack.stdout)["acknowledged_count"], 1)
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
                "--response-mode",
                "legacy",
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
                "--response-mode",
                "legacy",
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
                "--retrieval-prompt",
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
        self.assertTrue(payload["checks"]["retrieval_v2_read_only_contract"])
        self.assertEqual(payload["query_result"]["schema"], "synapse-retrieval.v2")
        self.assertFalse(payload["query_result"]["raw_input_stored"])
        self.assertTrue(
            any(
                item.get("tag") == "cli-preflight-memory"
                for item in payload["query_result"]["items"]
            )
        )

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

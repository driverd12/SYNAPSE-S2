import os
import plistlib
import sqlite3
import stat
import subprocess
import sys
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts import operator_readiness_certify as readiness


ROOT = Path(__file__).resolve().parents[1]


class OperationalScriptTests(unittest.TestCase):
    @staticmethod
    def _capture_ledger_binding(*, revision: str = "a" * 64) -> dict:
        return {
            "schema": "synapse-s2.capture-ledger-binding-proof.v1",
            "verified": True,
            "verified_capture_count": 7,
            "revision": revision,
        }

    def _run_recovery_readiness_scenario(
        self,
        *,
        backup_binding: object,
        verify_binding: object,
        restore_binding: object,
    ) -> tuple[dict[str, readiness.CheckResult], list[str]]:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        temp_root = Path(temporary.name)
        certifier = object.__new__(readiness.OperatorReadinessCertifier)
        certifier.results = []
        certifier.run_id = "capture-ledger-binding-test"
        certifier.artifact_dir = temp_root / "artifacts"
        certifier.artifact_dir.mkdir(mode=0o700)
        certifier._cli_command = lambda *parts: list(parts)

        valid_audit = {
            "action": "capture-ledger-audit",
            "status": "ready",
            "verification_passed": True,
            "audit_revision": "f" * 64,
            "processed_v2_capture_count": 7,
            "ledger_capture_count": 7,
            "missing_authoritative_ledger_count": 0,
            "ledger_binding_mismatch_count": 0,
            "blocked_capture_count": 0,
        }
        payloads = {
            "capture_ledger_audit": valid_audit,
            "recovery_backup": {
                "bundle_verified": True,
                "cutover_ready": True,
                "bundle_receipt_path": str(temp_root / "bundle.receipt.json"),
                "capture_ledger_binding": backup_binding,
            },
            "recovery_verify": {
                "verified": True,
                "cutover_ready": True,
                "capture_ledger_binding": verify_binding,
            },
            "recovery_restore": {
                "verified": True,
                "cutover_ready": True,
                "capture_ledger_binding": restore_binding,
                "recovery_proof_path": str(temp_root / "missing-proof.json"),
            },
        }
        executed: list[str] = []

        def run_command(
            check_id: str,
            *,
            label: str,
            command: list[str],
            required: bool,
            timeout: float,
            evaluator,
            env=None,
        ) -> readiness.CheckResult:
            del timeout, env
            executed.append(check_id)
            parsed = payloads[check_id]
            status, detail, repair, metrics = evaluator(0, parsed, "", "")
            result = readiness.CheckResult(
                check_id=check_id,
                label=label,
                status=status,
                required=required,
                detail=detail,
                repair=repair,
                command=command,
                returncode=0,
                parsed=parsed,
                metrics=metrics,
            )
            certifier.results.append(result)
            return result

        certifier._run_command = run_command
        with patch.object(readiness, "ROOT", temp_root):
            certifier._check_recovery()
        return {result.check_id: result for result in certifier.results}, executed

    def _run_launch_agent_installer(
        self,
        script_name: str,
        *,
        label: str,
        extra_environment: dict[str, str],
    ) -> tuple[subprocess.CompletedProcess[str], dict, Path]:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        temp_root = Path(temporary.name)
        fake_bin = temp_root / "bin"
        fake_bin.mkdir()
        fake_launchctl = fake_bin / "launchctl"
        fake_launchctl.write_text(
            """#!/bin/sh
set -eu
state_path="$(dirname "$0")/launchctl-running"
case "$1" in
  print)
    test -f "$state_path"
    printf 'state = running\npid = 222\n'
    ;;
  bootout)
    rm -f -- "$state_path"
    ;;
  bootstrap)
    : > "$state_path"
    ;;
  enable|kickstart)
    ;;
  *)
    exit 64
    ;;
esac
""",
            encoding="utf-8",
        )
        fake_launchctl.chmod(0o755)
        fake_lsof = fake_bin / "lsof"
        fake_lsof.write_text(
            """#!/bin/sh
set -eu
printf 'p222\nn127.0.0.1:%s\n' "${SYNAPSE_S2_DASHBOARD_PORT:-8765}"
""",
            encoding="utf-8",
        )
        fake_lsof.chmod(0o755)
        fake_curl = fake_bin / "curl"
        fake_curl.write_text(
            """#!/bin/sh
set -eu
printf '{"runtime":"ready","effective_enabled":true,"memory_db_path":"%s","memory_context_entry_count":1}\n' "$SYNAPSE_S2_MEMORY_DB"
""",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)

        environment = os.environ.copy()
        environment.update(extra_environment)
        environment.update(
            {
                "HOME": str(temp_root / "home"),
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "SYNAPSE_S2_PYTHON": sys.executable,
                "SYNAPSE_S2_INSTALL_HEALTH_ATTEMPTS": "2",
                "SYNAPSE_S2_INSTALL_HEALTH_DELAY": "0.1",
                "SYNAPSE_S2_INSTALL_STABLE_CHECKS": "2",
                "SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS": "0.1",
            }
        )
        Path(environment["HOME"]).mkdir(mode=0o700)
        if script_name == "install_capture_daemon.sh":
            memory_db = Path(
                environment.get(
                    "SYNAPSE_S2_MEMORY_DB",
                    str(temp_root / "memory.sqlite3"),
                )
            )
            memory_db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with closing(sqlite3.connect(memory_db)) as connection:
                with connection:
                    connection.executescript(
                        """
                        CREATE TABLE memory_entries(memory_id TEXT PRIMARY KEY);
                        CREATE TABLE capture_operations(capture_id TEXT PRIMARY KEY);
                        CREATE TABLE store_migrations(key TEXT PRIMARY KEY);
                        """
                    )
            environment["SYNAPSE_S2_MEMORY_DB"] = str(memory_db)
        result = subprocess.run(
            ["bash", str(ROOT / "scripts" / script_name)],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        plist_path = (
            Path(environment["HOME"])
            / "Library"
            / "LaunchAgents"
            / f"{label}.plist"
        )
        payload: dict = {}
        if plist_path.exists():
            with plist_path.open("rb") as stream:
                payload = plistlib.load(stream)
        return result, payload, plist_path

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
        self.assertIn("--verify-only", script)
        self.assertIn("SYNAPSE_S2_PREFLIGHT_VERIFY_ONLY", script)
        self.assertIn("Skipping launcher/client/LaunchAgent installs", script)

    def test_capture_daemon_installer_declares_launch_agent(self):
        script = (ROOT / "scripts" / "install_capture_daemon.sh").read_text(encoding="utf-8")

        self.assertIn("aero.boom.synapse-s2.capture-daemon", script)
        self.assertIn("capture_daemon.py", script)
        self.assertIn("SYNAPSE_S2_CAPTURE_ROOT", script)
        self.assertIn("SYNAPSE_S2_TRANSCRIPT_POLL", script)
        self.assertIn("--poll-transcript-sources", script)
        self.assertIn("launchctl bootstrap", script)
        self.assertIn("umask 077", script)
        self.assertIn('plutil -insert Umask -integer 63 "$PLIST_TEMP"', script)
        self.assertIn('plutil -insert ProgramArguments -xml \'<array/>\'', script)
        self.assertIn('plutil -insert EnvironmentVariables -xml \'<dict/>\'', script)
        self.assertIn('chmod 600 "$PLIST_TEMP"', script)
        self.assertIn("prepare_private_log", script)
        self.assertIn("os.fchmod(descriptor, 0o600)", script)
        self.assertIn('plutil -lint "$PLIST_TEMP"', script)
        self.assertIn('mv -f -- "$PLIST_TEMP" "$PLIST"', script)
        self.assertIn("fsync_file_and_parent", script)
        self.assertIn("SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS", script)
        self.assertIn("capture_functional_probe", script)
        self.assertIn('launchctl bootout "gui/$UID_VALUE/$LABEL"', script)
        self.assertLess(
            script.index('plutil -lint "$PLIST_TEMP"'),
            script.rindex("if ! bootout_service; then"),
        )
        self.assertLess(
            script.index('mv -f -- "$PLIST_TEMP" "$PLIST"'),
            script.rindex("if ! bootout_service; then"),
        )
        self.assertNotIn('chmod 700 "$CAPTURE_ROOT"', script)
        self.assertNotIn("COMMAND=", script)
        self.assertNotIn("/bin/zsh", script)
        self.assertNotIn('"-lc"', script)

    def test_capture_installer_preserves_hostile_values_as_literal_plist_data(self):
        label = "aero.boom.synapse-s2.capture-test"
        data_temporary = TemporaryDirectory()
        self.addCleanup(data_temporary.cleanup)
        data_root = Path(data_temporary.name)
        sentinel = data_root / "shell-injection-ran"
        hostile_poll = f"2; touch {sentinel}"
        hostile_provider = f"mlx'\"&<$(touch {sentinel})"
        hostile_max_bytes = f"256000; touch {sentinel}"
        result, payload, plist_path = self._run_launch_agent_installer(
            "install_capture_daemon.sh",
            label=label,
            extra_environment={
                "SYNAPSE_S2_CAPTURE_LABEL": label,
                "SYNAPSE_S2_CAPTURE_ROOT": str(data_root / "capture"),
                "SYNAPSE_S2_STATE_PATH": str(data_root / "state.json"),
                "SYNAPSE_S2_MEMORY_DB": str(data_root / "memory.sqlite3"),
                "SYNAPSE_S2_CAPTURE_LOG": str(data_root / "capture.log"),
                "SYNAPSE_S2_CAPTURE_POLL_INTERVAL": hostile_poll,
                "SYNAPSE_S2_MAX_TRANSCRIPT_BYTES": hostile_max_bytes,
                "SYNAPSE_S2_EMBEDDING_PROVIDER": hostile_provider,
                "SYNAPSE_S2_TRANSCRIPT_POLL": "true",
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertEqual(payload["Label"], label)
        self.assertEqual(payload["Umask"], 63)
        self.assertEqual(payload["WorkingDirectory"], str(ROOT))
        self.assertEqual(payload["ProgramArguments"][0], sys.executable)
        self.assertEqual(
            payload["ProgramArguments"][1],
            str(ROOT / "capture_daemon.py"),
        )
        self.assertNotIn("/bin/zsh", payload["ProgramArguments"])
        self.assertNotIn("-lc", payload["ProgramArguments"])
        poll_index = payload["ProgramArguments"].index("--poll-interval")
        self.assertEqual(payload["ProgramArguments"][poll_index + 1], hostile_poll)
        max_index = payload["ProgramArguments"].index("--max-transcript-bytes")
        self.assertEqual(
            payload["ProgramArguments"][max_index + 1],
            hostile_max_bytes,
        )
        self.assertEqual(
            payload["EnvironmentVariables"]["SYNAPSE_S2_EMBEDDING_PROVIDER"],
            hostile_provider,
        )
        self.assertEqual(stat.S_IMODE(plist_path.stat().st_mode), 0o600)

    def test_frontmost_selection_helper_is_one_shot_and_restores_clipboard(self):
        script = (ROOT / "scripts" / "capture_frontmost_selection.sh").read_text(encoding="utf-8")

        self.assertIn("osascript", script)
        self.assertIn("pbcopy < \"$CLIPBOARD_BACKUP\"", script)
        self.assertIn("capture-clipboard", script)
        self.assertNotIn("while true", script)

    def test_local_launcher_uses_client_session_wrapper(self):
        script = (ROOT / "scripts" / "install_local_launcher.sh").read_text(encoding="utf-8")

        self.assertIn("mcp_client_wrapper.py", script)
        self.assertIn("SYNAPSE_S2_CLIENT_SESSION_BRIDGE", script)
        self.assertIn("SYNAPSE_S2_EMBEDDING_PROVIDER:=mlx-neural", script)
        self.assertIn("SYNAPSE_S2_NEURAL_MODEL", script)
        self.assertIn("Qwen3-Embedding-0.6B-4bit-DWQ", script)
        self.assertIn("umask 077", script)
        self.assertIn("MLX_DEVICE:=gpu", script)
        self.assertIn("SYNAPSE_S2_MEMORY_DB", script)
        self.assertIn("SYNAPSE_S2_DEFAULT_RESPONSE_MODE:=compact", script)
        self.assertIn("SYNAPSE_S2_MAX_RESPONSE_BYTES:=12288", script)
        self.assertNotIn('"$REPO_ROOT/mcp_server.py"', script)
        self.assertIn('mktemp "${LAUNCHER_DIR}/.synapse-s2-mcp.XXXXXX"', script)
        self.assertIn('/bin/sh -n "$LAUNCHER_TEMP"', script)
        self.assertIn('mv -f -- "$LAUNCHER_TEMP" "$LAUNCHER"', script)
        self.assertIn('fsync_file_and_parent "$LAUNCHER_TEMP"', script)
        self.assertIn('fsync_file_and_parent "$LAUNCHER"', script)
        self.assertIn("trap cleanup EXIT", script)

    def test_local_launcher_installs_atomically_and_syntax_checks_result(self):
        with TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            launcher_dir = home / ".local" / "bin"
            launcher_dir.mkdir(parents=True, mode=0o755)
            launcher_dir.chmod(0o755)
            environment = os.environ.copy()
            environment["HOME"] = str(home)

            result = subprocess.run(
                ["/bin/sh", str(ROOT / "scripts" / "install_local_launcher.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            launcher = launcher_dir / "synapse-s2-mcp"
            syntax = subprocess.run(
                ["/bin/sh", "-n", str(launcher)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            self.assertEqual(stat.S_IMODE(launcher_dir.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o755)
            self.assertEqual(list(launcher_dir.glob(".synapse-s2-mcp.*")), [])
            launcher_text = launcher.read_text(encoding="utf-8")
            self.assertIn("SYNAPSE_S2_DEFAULT_RESPONSE_MODE:=compact", launcher_text)
            self.assertIn("SYNAPSE_S2_MAX_RESPONSE_BYTES:=12288", launcher_text)

    def test_local_launcher_replace_failure_preserves_prior_launcher(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            launcher_dir = home / ".local" / "bin"
            launcher_dir.mkdir(parents=True)
            launcher = launcher_dir / "synapse-s2-mcp"
            launcher.write_text("prior-launcher\n", encoding="utf-8")
            launcher.chmod(0o755)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            fake_mv = fake_bin / "mv"
            fake_mv.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
            fake_mv.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                }
            )

            result = subprocess.run(
                ["/bin/sh", str(ROOT / "scripts" / "install_local_launcher.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                launcher.read_text(encoding="utf-8"),
                "prior-launcher\n",
            )
            self.assertEqual(list(launcher_dir.glob(".synapse-s2-mcp.*")), [])

    def test_local_launcher_refuses_symlink_target_without_following(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            launcher_dir = home / ".local" / "bin"
            launcher_dir.mkdir(parents=True)
            outside = root / "outside-launcher"
            outside.write_text("unchanged\n", encoding="utf-8")
            launcher = launcher_dir / "synapse-s2-mcp"
            launcher.symlink_to(outside)
            environment = os.environ.copy()
            environment["HOME"] = str(home)

            result = subprocess.run(
                ["/bin/sh", str(ROOT / "scripts" / "install_local_launcher.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("regular non-symlink", result.stderr)
            self.assertTrue(launcher.is_symlink())
            self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged\n")

    def test_local_launcher_does_not_remove_another_installers_lock(self):
        with TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            launcher_dir = home / ".local" / "bin"
            launcher_dir.mkdir(parents=True)
            lock = launcher_dir / ".synapse-s2-mcp.install.lock"
            lock.mkdir(mode=0o700)
            environment = os.environ.copy()
            environment["HOME"] = str(home)

            result = subprocess.run(
                ["/bin/sh", str(ROOT / "scripts" / "install_local_launcher.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already in progress", result.stderr)
            self.assertTrue(lock.is_dir())

    def test_local_launcher_rejects_secret_shaped_path_without_reflection(self):
        with TemporaryDirectory() as tmp:
            secret_component = "sk-abcdefghijklmnop"
            home = Path(tmp) / secret_component / "home"
            home.mkdir(parents=True)
            environment = os.environ.copy()
            environment["HOME"] = str(home)

            result = subprocess.run(
                ["/bin/sh", str(ROOT / "scripts" / "install_local_launcher.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("credential-shaped", result.stderr)
            self.assertNotIn(secret_component, result.stdout + result.stderr)
            self.assertFalse((home / ".local").exists())

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
        self.assertIn("umask 077", script)
        self.assertIn("Dashboard host must be loopback-only", script)
        self.assertIn('plutil -insert Umask -integer 63 "$PLIST_TEMP"', script)
        self.assertIn('plutil -insert ProgramArguments -xml \'<array/>\'', script)
        self.assertIn('plutil -insert EnvironmentVariables -xml \'<dict/>\'', script)
        self.assertIn('chmod 600 "$PLIST_TEMP"', script)
        self.assertIn("prepare_private_log", script)
        self.assertIn("os.fchmod(descriptor, 0o600)", script)
        self.assertIn('plutil -lint "$PLIST_TEMP"', script)
        self.assertIn('mv -f -- "$PLIST_TEMP" "$PLIST"', script)
        self.assertIn("fsync_file_and_parent", script)
        self.assertIn("/api/status", script)
        self.assertIn("SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS", script)
        self.assertIn('launchctl bootout "gui/$UID_VALUE/$LABEL"', script)
        self.assertLess(
            script.index('plutil -lint "$PLIST_TEMP"'),
            script.rindex("if ! bootout_service; then"),
        )
        self.assertLess(
            script.index('mv -f -- "$PLIST_TEMP" "$PLIST"'),
            script.rindex("if ! bootout_service; then"),
        )
        self.assertNotIn('chmod 700 "$EXPORT_DIR"', script)
        self.assertNotIn("COMMAND=", script)
        self.assertNotIn("/bin/zsh", script)
        self.assertNotIn('"-lc"', script)

    def test_dashboard_installer_preserves_hostile_values_as_literal_plist_data(self):
        label = "aero.boom.synapse-s2.dashboard-test"
        data_temporary = TemporaryDirectory()
        self.addCleanup(data_temporary.cleanup)
        data_root = Path(data_temporary.name)
        sentinel = data_root / "shell-injection-ran"
        dashboard_port = "18765"
        hostile_context = f"default'\"&<$(touch {sentinel})"
        hostile_provider = f"mlx'\"&<$(touch {sentinel})"
        result, payload, plist_path = self._run_launch_agent_installer(
            "install_dashboard_agent.sh",
            label=label,
            extra_environment={
                "SYNAPSE_S2_DASHBOARD_LABEL": label,
                "SYNAPSE_S2_DASHBOARD_HOST": "127.0.0.1",
                "SYNAPSE_S2_DASHBOARD_PORT": dashboard_port,
                "SYNAPSE_S2_DASHBOARD_CONTEXT": hostile_context,
                "SYNAPSE_S2_DASHBOARD_LOG": str(data_root / "dashboard.log"),
                "SYNAPSE_S2_STATE_PATH": str(data_root / "state.json"),
                "SYNAPSE_S2_MEMORY_DB": str(data_root / "memory.sqlite3"),
                "SYNAPSE_S2_EXPORT_DIR": str(data_root / "exports"),
                "SYNAPSE_S2_CAPTURE_ROOT": str(data_root / "capture"),
                "SYNAPSE_S2_EMBEDDING_PROVIDER": hostile_provider,
            },
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertEqual(payload["Label"], label)
        self.assertEqual(payload["Umask"], 63)
        self.assertEqual(payload["WorkingDirectory"], str(ROOT))
        self.assertEqual(payload["ProgramArguments"][0], sys.executable)
        self.assertEqual(
            payload["ProgramArguments"][1],
            str(ROOT / "dashboard_server.py"),
        )
        self.assertNotIn("/bin/zsh", payload["ProgramArguments"])
        self.assertNotIn("-lc", payload["ProgramArguments"])
        port_index = payload["ProgramArguments"].index("--port")
        self.assertEqual(payload["ProgramArguments"][port_index + 1], dashboard_port)
        context_index = payload["ProgramArguments"].index("--context")
        self.assertEqual(
            payload["ProgramArguments"][context_index + 1],
            hostile_context,
        )
        self.assertEqual(
            payload["EnvironmentVariables"]["SYNAPSE_S2_EMBEDDING_PROVIDER"],
            hostile_provider,
        )
        self.assertEqual(stat.S_IMODE(plist_path.stat().st_mode), 0o600)

    def test_dashboard_installer_rejects_hostile_port_before_writing(self):
        label = "aero.boom.synapse-s2.dashboard-test"
        data_temporary = TemporaryDirectory()
        self.addCleanup(data_temporary.cleanup)
        data_root = Path(data_temporary.name)
        sentinel = data_root / "shell-injection-ran"
        result, payload, plist_path = self._run_launch_agent_installer(
            "install_dashboard_agent.sh",
            label=label,
            extra_environment={
                "SYNAPSE_S2_DASHBOARD_LABEL": label,
                "SYNAPSE_S2_DASHBOARD_PORT": f"8765; touch {sentinel}",
            },
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Dashboard port must be an integer", result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertEqual(payload, {})
        self.assertFalse(plist_path.exists())

    def test_operator_readiness_certifier_covers_required_trust_gates(self):
        script_path = ROOT / "scripts" / "operator_readiness_certify.py"

        self.assertTrue(script_path.exists(), "operator readiness certifier must exist")
        script = script_path.read_text(encoding="utf-8")
        for token in (
            "client_config",
            "mcp_connect",
            "neural_embedding",
            "doctor",
            "start_work",
            "memory_write",
            "recall",
            "app_preview",
            "wrap_session",
            "dashboard",
            "recovery_backup",
            "recovery_verify",
            "recovery_restore",
            "evidence_packs",
        ):
            self.assertIn(token, script)
        self.assertIn("mlx-neural", script)
        self.assertIn("writes_memory=false", script)

    def test_readiness_recovery_rejects_missing_or_malformed_binding_at_every_stage(self):
        valid = self._capture_ledger_binding()
        invalid_proofs = {
            "missing": None,
            "malformed": {
                **valid,
                "revision": "not-a-canonical-revision",
            },
        }

        for stage in ("backup", "verify", "restore"):
            for proof_name, invalid in invalid_proofs.items():
                with self.subTest(stage=stage, proof=proof_name):
                    bindings = {
                        "backup": valid,
                        "verify": valid,
                        "restore": valid,
                    }
                    bindings[stage] = invalid
                    results, executed = self._run_recovery_readiness_scenario(
                        backup_binding=bindings["backup"],
                        verify_binding=bindings["verify"],
                        restore_binding=bindings["restore"],
                    )

                    self.assertEqual(results[f"recovery_{stage}"].status, "blocked")
                    self.assertNotEqual(
                        results[f"recovery_{stage}"].metrics.get(
                            "capture_ledger_binding"
                        ),
                        valid,
                    )
                    if stage == "backup":
                        self.assertEqual(
                            executed,
                            ["capture_ledger_audit", "recovery_backup"],
                        )
                        self.assertEqual(results["recovery_verify"].status, "blocked")
                        self.assertEqual(results["recovery_restore"].status, "blocked")
                    elif stage == "verify":
                        self.assertEqual(
                            executed,
                            [
                                "capture_ledger_audit",
                                "recovery_backup",
                                "recovery_verify",
                            ],
                        )
                        self.assertEqual(results["recovery_restore"].status, "blocked")
                    else:
                        self.assertEqual(
                            executed,
                            [
                                "capture_ledger_audit",
                                "recovery_backup",
                                "recovery_verify",
                                "recovery_restore",
                            ],
                        )

    def test_readiness_recovery_rejects_binding_drift_between_stages(self):
        original = self._capture_ledger_binding(revision="a" * 64)
        changed = self._capture_ledger_binding(revision="b" * 64)

        for changed_stage in ("verify", "restore"):
            with self.subTest(changed_stage=changed_stage):
                results, executed = self._run_recovery_readiness_scenario(
                    backup_binding=original,
                    verify_binding=(changed if changed_stage == "verify" else original),
                    restore_binding=(changed if changed_stage == "restore" else original),
                )

                self.assertEqual(
                    results[f"recovery_{changed_stage}"].status,
                    "blocked",
                )
                self.assertEqual(
                    results[f"recovery_{changed_stage}"].metrics[
                        "capture_ledger_binding"
                    ],
                    changed,
                )
                if changed_stage == "verify":
                    self.assertNotIn("recovery_restore", executed)
                    self.assertEqual(results["recovery_restore"].status, "blocked")
                else:
                    self.assertEqual(results["recovery_verify"].status, "ready")
                    self.assertIn("recovery_restore", executed)

    def test_readiness_recovery_accepts_stable_valid_binding_across_stages(self):
        binding = self._capture_ledger_binding()

        results, executed = self._run_recovery_readiness_scenario(
            backup_binding=binding,
            verify_binding=dict(binding),
            restore_binding=dict(binding),
        )

        self.assertEqual(
            executed,
            [
                "capture_ledger_audit",
                "recovery_backup",
                "recovery_verify",
                "recovery_restore",
            ],
        )
        for check_id in (
            "capture_ledger_audit",
            "recovery_backup",
            "recovery_verify",
            "recovery_restore",
        ):
            self.assertEqual(results[check_id].status, "ready", check_id)
        for check_id in ("recovery_backup", "recovery_verify", "recovery_restore"):
            self.assertEqual(
                results[check_id].metrics["capture_ledger_binding"],
                binding,
            )


if __name__ == "__main__":
    unittest.main()

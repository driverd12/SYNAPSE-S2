import json
import os
import plistlib
import shutil
import sqlite3
import stat
import subprocess
import sys
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from capture_daemon import CaptureInboxDaemon
from core_client_binding import (
    BINDING_ENV,
    binding_for_config,
    default_binding_path,
    write_core_client_binding,
)
from core_runtime_paths import canonical_core_socket_path
from core_service import CoreConfig, write_core_config
from scripts import operator_readiness_certify as readiness


ROOT = Path(__file__).resolve().parents[1]


def _write_test_core_config(data_root: Path) -> CoreConfig:
    data_root = data_root.resolve()
    core = data_root / "core"
    core.mkdir(parents=True, mode=0o700, exist_ok=True)
    data_root.chmod(0o700)
    core.chmod(0o700)
    config = CoreConfig(
        socket_path=canonical_core_socket_path(data_root),
        state_path=data_root / "runtime_state.json",
        memory_path=data_root / "memory.sqlite3",
        capture_root=data_root,
        dimension=8,
        num_neurons=16,
        default_top_k=4,
    )
    write_core_config(core / "service.json", config)
    return config


class OperationalScriptTests(unittest.TestCase):
    @staticmethod
    def _memora_audit() -> dict:
        return {
            "schema": "synapse-s2.memora-recovery-audit.v1",
            "audit_revision": "9" * 64,
            "catalog_count": 0,
            "binding_projection_count": 0,
            "governance_event_receipt_count": 0,
            "source_witness_count": 0,
            "cue_count": 0,
            "promoted_binding_count": 0,
            "effective_binding_count": 0,
            "ineffective_promoted_binding_count": 0,
            "provider_drift_binding_count": 0,
            "source_drift_binding_count": 0,
            "active_provider_revision": "absent",
            "integrity_valid": True,
            "effective_bindings_valid": True,
            "raw_cue_terms_included": False,
            "raw_source_text_included": False,
            "vectors_included": False,
        }

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
        temp_root = Path(temporary.name).resolve()
        certifier = object.__new__(readiness.OperatorReadinessCertifier)
        certifier.results = []
        certifier.run_id = "capture-ledger-binding-test"
        certifier.pack_dir = temp_root
        certifier.artifact_dir = temp_root / "artifacts"
        certifier.artifact_dir.mkdir(mode=0o700)
        certifier._evidence_files = set()
        certifier._opaque_evidence_files = set()

        reconciliation = {
            "missing_authoritative_ledger_count": 0,
            "replay_required_capture_count": 0,
            "replay_required_file_count": 0,
            "identifierless_replay_file_count": 0,
            "unclassified_file_count": 0,
        }
        audit = {
            "action": "capture-ledger-audit",
            "status": "ready",
            "verification_passed": True,
            "audit_revision": "f" * 64,
            "processed_file_count": 7,
            "processed_total_bytes": 700,
            "processed_v2_capture_count": 7,
            "ledger_capture_count": 7,
            "missing_authoritative_ledger_count": 0,
            "ledger_binding_mismatch_count": 0,
            "repairable_capture_count": 0,
            "blocked_capture_count": 0,
        }
        memora = self._memora_audit()
        proof_path = temp_root / "isolated-proof.json"
        proof_path.write_text(
            json.dumps(
                {
                    "schema": "synapse-s2.recovery-bundle-restore.v3",
                    "mode": "isolated-recovery-proof",
                    "verified": True,
                    "cutover_ready": True,
                    "auth_algorithm": "ed25519",
                    "auth_key_id": "unit-test-public-key-id",
                    "signing_public_key": "unit-test-public-key-material",
                    "receipt_digest": "c" * 64,
                    "receipt_signature": "unit-test-signature",
                    "missing_transport_ledger_count": 0,
                    "capture_ledger_binding": restore_binding,
                    "reconciliation": reconciliation,
                    "media_included": False,
                    "media_recovery_complete": True,
                    "media_reference_count": 0,
                    "media_sha256": None,
                    "media_manifest_sha256": None,
                    "media_object_count": 0,
                    "memora_integrity": memora,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        proof_path.chmod(0o600)
        evidence = {
            "verified": True,
            "bundle": {
                "bundle_schema": "synapse-s2.recovery-bundle.v3",
                "bundle_verified": True,
                "cutover_ready": True,
                "capture_file_count": 7,
                "capture_ledger_binding": backup_binding,
                "reconciliation": reconciliation,
                "media_included": False,
                "media_archive_sha256": None,
                "media_manifest_sha256": None,
                "media_object_count": 0,
                "media_reconciliation": {"referenced_count": 0},
                "memora_integrity": memora,
            },
            "verification": {
                "verified": True,
                "cutover_ready": True,
                "receipt_identity_trusted": True,
                "capture_database_binding": {
                    "auth_key_id": "unit-test-public-key-id",
                },
                "capture_ledger_binding": verify_binding,
                "reconciliation": reconciliation,
                "media_included": False,
                "media_recovery_complete": True,
                "media_reference_count": 0,
                "media": None,
                "memora_integrity": memora,
            },
            "restore": {
                "verified": True,
                "cutover_ready": True,
                "capture_file_count": 7,
                "missing_transport_ledger_count": 0,
                "capture_ledger_binding": restore_binding,
                "reconciliation": reconciliation,
                "media_included": False,
                "media_recovery_complete": True,
                "media_reference_count": 0,
                "media_object_count": 0,
                "memora_integrity": memora,
                "recovery_proof_path": str(proof_path),
            },
            "capture_ledger_before": dict(audit),
            "capture_ledger_after": dict(audit),
            "capture_transport_at_publication": {
                "ledger_audit_revision": "f" * 64,
                "ledger_verification_passed": True,
            },
        }

        certifier._record_guarded_recovery_evidence(
            evidence,
            duration_ms=1.0,
        )
        executed = [result.check_id for result in certifier.results]
        return {result.check_id: result for result in certifier.results}, executed

    def _run_launch_agent_installer(
        self,
        script_name: str,
        *,
        label: str,
        extra_environment: dict[str, str],
        install_dashboard_binding: bool = True,
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
    case "${2:-}" in
      gui/*/*)
        test -f "$state_path"
        printf 'state = running\npid = 222\n'
        ;;
      gui/*)
        printf 'services = {\n'
        if test -f "$state_path"; then
          printf '  222 - %s\n' "${SYNAPSE_S2_DASHBOARD_LABEL:-${SYNAPSE_S2_CAPTURE_LABEL:-test.service}}"
        fi
        printf '}\n'
        ;;
      *) exit 64 ;;
    esac
    ;;
  bootout)
    rm -f -- "$state_path"
    ;;
  bootstrap)
    : > "$state_path"
    if [ -n "${SYNAPSE_S2_DASHBOARD_AUTH_FILE:-}" ]; then
      mkdir -p "$(dirname "$SYNAPSE_S2_DASHBOARD_AUTH_FILE")"
      chmod 700 "$(dirname "$SYNAPSE_S2_DASHBOARD_AUTH_FILE")"
      printf '{"schema":"synapse-s2.dashboard-auth.v1","host":"127.0.0.1","port":%s,"bootstrap_url":"http://127.0.0.1:%s/__dashboard_bootstrap?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","session_header":"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"}\n' \
        "${SYNAPSE_S2_DASHBOARD_PORT:-8765}" \
        "${SYNAPSE_S2_DASHBOARD_PORT:-8765}" > "$SYNAPSE_S2_DASHBOARD_AUTH_FILE"
      chmod 600 "$SYNAPSE_S2_DASHBOARD_AUTH_FILE"
    fi
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
cat >/dev/null
if printf '%s\n' "$*" | grep -q -- '--write-out'; then
  printf '303'
  exit 0
fi
printf '{"runtime":"ready","effective_enabled":true,"memory_db_path":"%s","memory_context_entry_count":1}\n' "$SYNAPSE_S2_MEMORY_DB"
""",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)

        environment = os.environ.copy()
        if BINDING_ENV not in extra_environment:
            environment.pop(BINDING_ENV, None)
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
        if script_name == "install_dashboard_agent.sh":
            environment["SYNAPSE_S2_DASHBOARD_AUTH_FILE"] = str(
                temp_root / "dashboard-auth" / "dashboard-auth.json"
            )
        if script_name == "install_dashboard_agent.sh" and install_dashboard_binding:
            data_root = (temp_root / "reviewed-dashboard-data").resolve()
            config = _write_test_core_config(data_root)
            binding = binding_for_config(
                repo_root=ROOT,
                data_root=data_root,
                config=config,
                core_label="aero.boom.synapse-s2.core",
                authority_mode="authoritative-core-v6",
            )
            write_core_client_binding(
                default_binding_path(Path(environment["HOME"])),
                binding,
            )
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
            memory_db.chmod(0o600)
            environment["SYNAPSE_S2_MEMORY_DB"] = str(memory_db)
            daemon = CaptureInboxDaemon(
                root=environment["SYNAPSE_S2_CAPTURE_ROOT"]
            )
            daemon._ensure_transport_dirs(daemon.paths())
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

    def test_prep_tomorrow_unit_tests_do_not_inherit_production_paths(self):
        script = (ROOT / "scripts" / "prep_tomorrow.sh").read_text(encoding="utf-8")
        unit_test_section = script.split('echo "=== unit tests ==="', 1)[1].split(
            'echo "=== compile check ==="',
            1,
        )[0]

        self.assertIn("unset SYNAPSE_S2_STATE_PATH SYNAPSE_S2_MEMORY_DB", unit_test_section)
        self.assertIn("unset SYNAPSE_S2_EXPORT_DIR SYNAPSE_S2_CAPTURE_ROOT", unit_test_section)
        self.assertIn("unset SYNAPSE_S2_CORE_BINDING SYNAPSE_S2_CORE_SOCKET", unit_test_section)
        self.assertIn("unset SYNAPSE_S2_EMBEDDING_PROVIDER", unit_test_section)
        self.assertNotIn("SYNAPSE_S2_EMBEDDING_PROVIDER=semantic-hash", unit_test_section)
        self.assertIn(
            "xcrun --sdk macosx swiftc -parse native/apple_vision_enrich.swift",
            script,
        )

    def test_prep_tomorrow_compiles_both_longmem_lanes(self):
        script = (ROOT / "scripts" / "prep_tomorrow.sh").read_text(encoding="utf-8")

        for path in (
            "longmem_eval.py",
            "official_longmem/__init__.py",
            "official_longmem/bootstrap.py",
            "official_longmem/synapse_s2_memory.py",
            "scripts/measure_longmem_v2.py",
            "scripts/run_longmem_v2_official.py",
        ):
            with self.subTest(path=path):
                self.assertIn(path, script)

    def test_prep_tomorrow_certifies_immutably_before_explicit_apply(self):
        script = (ROOT / "scripts" / "prep_tomorrow.sh").read_text(encoding="utf-8")
        apply_marker = 'echo "=== apply stage (all immutable gates passed) ==="'
        self.assertIn("--apply", script)
        self.assertIn(apply_marker, script)
        pre_apply, apply_stage = script.split(apply_marker, 1)
        self.assertIn('git status --porcelain --untracked-files=all', pre_apply)
        self.assertIn('echo "=== unit tests ==="', pre_apply)
        self.assertIn('echo "=== compile check ==="', pre_apply)
        self.assertIn('echo "=== build identity ==="', pre_apply)
        self.assertIn("validate_evidence_contract", pre_apply)
        self.assertIn("Apply requires a reviewed candidate or authoritative core binding", pre_apply)
        self.assertNotIn('mkdir -p "$SYNAPSE_S2_EXPORT_DIR"', pre_apply)
        self.assertNotIn("\n    uv sync\n", pre_apply)
        self.assertNotIn("scripts/install_local_launcher.sh\n", pre_apply)
        self.assertNotIn("scripts/install_client_configs.py\n", pre_apply)
        self.assertIn('mkdir -p "$SYNAPSE_S2_EXPORT_DIR"', apply_stage)
        self.assertIn("scripts/install_core_agent.sh install", apply_stage)
        self.assertIn('echo "=== authoritative core status ==="', apply_stage)
        self.assertIn('"runtime_healthy"', apply_stage)
        self.assertIn('"production_ready"', apply_stage)
        self.assertIn("scripts/install_dashboard_agent.sh", apply_stage)
        self.assertLess(
            apply_stage.index("scripts/install_core_agent.sh install"),
            apply_stage.index('echo "=== authoritative core status ==="'),
        )
        self.assertLess(
            apply_stage.index('echo "=== authoritative core status ==="'),
            apply_stage.index("scripts/install_local_launcher.sh"),
        )
        self.assertLess(
            apply_stage.index("scripts/install_local_launcher.sh"),
            apply_stage.index("scripts/install_client_configs.py"),
        )
        self.assertLess(
            apply_stage.index("scripts/install_client_configs.py"),
            apply_stage.index("scripts/install_dashboard_agent.sh"),
        )
        self.assertIn('binding.get("ready") is not True', apply_stage)
        capture_process = apply_stage.split(
            "synapse_cli.py --json capture-inbox-process",
            1,
        )[1].split("synapse_cli.py --json capture-inbox-status", 1)[0]
        self.assertIn("--confirm", capture_process)
        cortex_commit = apply_stage.split(
            "synapse_cli.py --json commit-cortex",
            1,
        )[1].split("synapse_cli.py --json cortex-state", 1)[0]
        self.assertEqual(cortex_commit.count("--evidence"), 1)

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
        self.assertIn("secure_installer_support.py", script)
        self.assertIn("replace-regular", script)
        self.assertIn("run-locked", script)
        self.assertNotIn('mkdir -m 700 "$INSTALL_LOCK_CANDIDATE"', script)
        self.assertIn("fsync_file_and_parent", script)
        self.assertIn("SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS", script)
        self.assertIn("capture_functional_probe", script)
        self.assertIn("env -u PYTHONPATH -u PYTHONHOME -u PYTHONSAFEPATH", script)
        self.assertIn("sys.path.insert(0, str(repo_root))", script)
        self.assertNotIn('PYTHONPATH="$ROOT', script)
        self.assertIn('launchctl bootout "gui/$UID_VALUE/$LABEL"', script)
        self.assertLess(
            script.index('plutil -lint "$PLIST_TEMP"'),
            script.rindex("if ! bootout_service; then"),
        )
        self.assertLess(
            script.rindex("replace-regular"),
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
        self.assertIn("umask 077", script)
        self.assertIn('CLIPBOARD_BACKED_UP=1', script)
        self.assertIn("capture-clipboard", script)
        self.assertNotIn("while true", script)

    def test_frontmost_selection_prefers_reviewed_binding_without_direct_routes(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            data_root = (root / "reviewed-selection-data").resolve()
            config = _write_test_core_config(data_root)
            binding = binding_for_config(
                repo_root=ROOT,
                data_root=data_root,
                config=config,
                core_label="aero.boom.synapse-s2.core",
                authority_mode="candidate-local-v5",
            )
            binding_path = default_binding_path(home)
            write_core_client_binding(binding_path, binding)

            fake_bin = root / "bin"
            fake_bin.mkdir(mode=0o700)
            for name, body in {
                "pbpaste": "#!/bin/sh\nprintf 'selected text\\n'\n",
                "pbcopy": "#!/bin/sh\ncat > \"$PBCOPY_RECORD\"\n",
                "osascript": "#!/bin/sh\ncat >/dev/null\n",
            }.items():
                path = fake_bin / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)
            python_shim = fake_bin / "python-shim"
            python_shim.write_text(
                """#!/bin/bash
set -eu
printf '%s\n' "-- invocation --" "$@" >> "$PYTHON_SHIM_RECORD"
if [ "${1:-}" = - ]; then
  exec "$REAL_PYTHON" "$@"
fi
env | LC_ALL=C sort > "$SELECTION_ENV_RECORD"
printf '%s\n' "$@" > "$SELECTION_ARGS_RECORD"
""",
                encoding="utf-8",
            )
            python_shim.chmod(0o755)
            env_record = root / "selection.env"
            args_record = root / "selection.args"
            shim_record = root / "python-shim.log"
            pbcopy_record = root / "clipboard-restored.txt"
            environment = os.environ.copy()
            environment.pop(BINDING_ENV, None)
            environment.update(
                {
                    "HOME": str(home),
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "REAL_PYTHON": sys.executable,
                    "SELECTION_ENV_RECORD": str(env_record),
                    "SELECTION_ARGS_RECORD": str(args_record),
                    "PYTHON_SHIM_RECORD": str(shim_record),
                    "PBCOPY_RECORD": str(pbcopy_record),
                    "SYNAPSE_S2_PYTHON": str(python_shim),
                    "SYNAPSE_S2_SELECTION_COPY_DELAY": "0",
                    # Stale direct routes must be scrubbed, not allowed to
                    # override the reviewed owner-only binding.
                    "SYNAPSE_S2_CORE_SOCKET": str(root / "wrong" / "service.sock"),
                    "SYNAPSE_S2_CAPTURE_ROOT": str(root / "wrong-capture"),
                    "SYNAPSE_S2_MEMORY_DB": str(root / "wrong.sqlite3"),
                    "SYNAPSE_S2_STATE_PATH": str(root / "wrong.json"),
                }
            )

            completed = subprocess.run(
                ["bash", str(ROOT / "scripts" / "capture_frontmost_selection.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(
                env_record.exists(),
                completed.stderr + "\n" + shim_record.read_text(encoding="utf-8"),
            )
            forwarded_environment = env_record.read_text(encoding="utf-8")
            forwarded_arguments = args_record.read_text(encoding="utf-8").splitlines()
            selection_path = Path(
                forwarded_arguments[forwarded_arguments.index("--text-file") + 1]
            )
            self.assertFalse(selection_path.exists())
            self.assertEqual(
                pbcopy_record.read_text(encoding="utf-8"),
                "selected text\n",
            )

        self.assertIn(f"{BINDING_ENV}={binding_path}", forwarded_environment)
        for key in (
            "SYNAPSE_S2_CORE_SOCKET",
            "SYNAPSE_S2_CAPTURE_ROOT",
            "SYNAPSE_S2_EXPORT_DIR",
            "SYNAPSE_S2_MEMORY_DB",
            "SYNAPSE_S2_STATE_PATH",
            "SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT",
        ):
            self.assertNotIn(f"{key}=", forwarded_environment)
        self.assertIn("capture-clipboard", forwarded_arguments)
        self.assertNotIn("--capture-root", forwarded_arguments)

    def test_frontmost_selection_aborts_before_copy_when_clipboard_backup_fails(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            fake_bin = root / "bin"
            fake_bin.mkdir(mode=0o700)
            osascript_record = root / "osascript-ran"
            pbcopy_record = root / "pbcopy-ran"
            scripts = {
                "pbpaste": "#!/bin/sh\nexit 9\n",
                "pbcopy": f"#!/bin/sh\nprintf ran > {pbcopy_record!s}\n",
                "osascript": f"#!/bin/sh\nprintf ran > {osascript_record!s}\n",
            }
            for name, body in scripts.items():
                path = fake_bin / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)
            environment = os.environ.copy()
            environment.pop(BINDING_ENV, None)
            environment.update(
                {
                    "HOME": str(home),
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "SYNAPSE_S2_PYTHON": sys.executable,
                }
            )

            completed = subprocess.run(
                ["bash", str(ROOT / "scripts" / "capture_frontmost_selection.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 4)
            self.assertIn("Could not preserve the current clipboard", completed.stderr)
            self.assertFalse(osascript_record.exists())
            self.assertFalse(pbcopy_record.exists())

    def test_frontmost_selection_without_binding_uses_canonical_v5_routes(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            fake_bin = root / "bin"
            fake_bin.mkdir(mode=0o700)
            for name, body in {
                "pbpaste": "#!/bin/sh\nprintf 'selected text\\n'\n",
                "pbcopy": "#!/bin/sh\ncat >/dev/null\n",
                "osascript": "#!/bin/sh\ncat >/dev/null\n",
            }.items():
                path = fake_bin / name
                path.write_text(body, encoding="utf-8")
                path.chmod(0o755)
            python_shim = fake_bin / "python-shim"
            python_shim.write_text(
                """#!/bin/bash
set -eu
if [ "${1:-}" = - ]; then
  exec "$REAL_PYTHON" "$@"
fi
env | LC_ALL=C sort > "$SELECTION_ENV_RECORD"
printf '%s\n' "$@" > "$SELECTION_ARGS_RECORD"
""",
                encoding="utf-8",
            )
            python_shim.chmod(0o755)
            env_record = root / "selection.env"
            args_record = root / "selection.args"
            environment = os.environ.copy()
            for key in (
                BINDING_ENV,
                "SYNAPSE_S2_CORE_SOCKET",
                "SYNAPSE_S2_CAPTURE_ROOT",
                "SYNAPSE_S2_EXPORT_DIR",
            ):
                environment.pop(key, None)
            environment.update(
                {
                    "HOME": str(home),
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "REAL_PYTHON": sys.executable,
                    "SELECTION_ENV_RECORD": str(env_record),
                    "SELECTION_ARGS_RECORD": str(args_record),
                    "SYNAPSE_S2_PYTHON": str(python_shim),
                    "SYNAPSE_S2_SELECTION_COPY_DELAY": "0",
                    # Stale local-v5 database and state variables are ignored;
                    # the no-binding compatibility lane is canonical only.
                    "SYNAPSE_S2_MEMORY_DB": str(root / "wrong.sqlite3"),
                    "SYNAPSE_S2_STATE_PATH": str(root / "wrong.json"),
                }
            )

            completed = subprocess.run(
                ["bash", str(ROOT / "scripts" / "capture_frontmost_selection.sh")],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            forwarded_environment = env_record.read_text(encoding="utf-8")
            forwarded_arguments = args_record.read_text(encoding="utf-8").splitlines()

        self.assertNotIn(f"{BINDING_ENV}=", forwarded_environment)
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET=", forwarded_environment)
        self.assertEqual(
            forwarded_arguments,
            [
                "synapse_cli.py",
                "--json",
                "--state",
                str(ROOT / ".synapse_s2" / "runtime_state.json"),
                "--memory-db",
                str(ROOT / ".synapse_s2" / "memory.sqlite3"),
                "capture-clipboard",
                "--context",
                "default",
                "--tag",
                "frontmost-selection",
                "--speaker",
                "operator",
                "--text-file",
                forwarded_arguments[-3],
                "--capture-root",
                str(ROOT / ".synapse_s2"),
            ],
        )

    def test_local_launcher_uses_client_session_wrapper(self):
        script = (ROOT / "scripts" / "install_local_launcher.sh").read_text(encoding="utf-8")

        self.assertIn("mcp_client_wrapper.py", script)
        self.assertIn("SYNAPSE_S2_CLIENT_SESSION_BRIDGE", script)
        self.assertIn("SYNAPSE_S2_CORE_SOCKET", script)
        self.assertIn("umask 077", script)
        self.assertNotIn("MLX_DEVICE:=gpu", script)
        self.assertNotIn(': "\\${SYNAPSE_S2_MEMORY_DB:=', script)
        self.assertIn(
            'SYNAPSE_S2_MEMORY_DB="\\$REPO_ROOT/.synapse_s2/memory.sqlite3"',
            script,
        )
        self.assertIn("export SYNAPSE_S2_MEMORY_DB", script)
        self.assertIn("database_requires_core", script)
        self.assertIn("unset PYTHONPATH", script)
        self.assertNotIn("export PYTHONPATH", script)
        self.assertIn("unset MLX_DEVICE SYNAPSE_S2_DIMENSION", script)
        self.assertIn("unset SYNAPSE_S2_NEURAL_MODEL", script)
        self.assertIn("SYNAPSE_S2_STATE_PATH SYNAPSE_S2_TOP_K", script)
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
            root = Path(tmp)
            repo = root / "repo"
            scripts = repo / "scripts"
            runtime_bin = repo / ".venv" / "bin"
            scripts.mkdir(parents=True)
            runtime_bin.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts" / "install_local_launcher.sh", scripts)
            (runtime_bin / "python").symlink_to(Path(sys.executable).resolve())
            home = root / "home"
            launcher_dir = home / ".local" / "bin"
            launcher_dir.mkdir(parents=True, mode=0o755)
            launcher_dir.chmod(0o755)
            environment = os.environ.copy()
            environment["HOME"] = str(home)

            result = subprocess.run(
                ["/bin/sh", str(scripts / "install_local_launcher.sh")],
                cwd=repo,
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
            self.assertIn("unset PYTHONPATH", launcher_text)
            self.assertNotIn("export PYTHONPATH", launcher_text)

    def test_local_launcher_supports_colon_repo_and_drops_ambient_python_paths(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo:with-colon"
            scripts = repo / "scripts"
            runtime_bin = repo / ".venv" / "bin"
            scripts.mkdir(parents=True)
            runtime_bin.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts" / "install_local_launcher.sh", scripts)
            (runtime_bin / "python").symlink_to(Path(sys.executable).resolve())
            (repo / "sibling_module.py").write_text("VALUE = 'reviewed-repo'\n")
            (repo / "mcp_client_wrapper.py").write_text(
                "import json, os\n"
                "from pathlib import Path\n"
                "from sibling_module import VALUE\n"
                "Path(os.environ['LAUNCHER_PROBE_OUTPUT']).write_text(json.dumps({\n"
                "    'value': VALUE,\n"
                "    'pythonpath': os.environ.get('PYTHONPATH'),\n"
                "    'pythonhome': os.environ.get('PYTHONHOME'),\n"
                "    'nousersite': os.environ.get('PYTHONNOUSERSITE'),\n"
                "}))\n",
                encoding="utf-8",
            )
            hostile = root / "hostile"
            hostile.mkdir()
            (hostile / "sibling_module.py").write_text("VALUE = 'hostile'\n")
            home = root / "home"
            home.mkdir(mode=0o700)
            install_environment = os.environ.copy()
            install_environment["HOME"] = str(home)
            installed = subprocess.run(
                ["/bin/sh", str(scripts / "install_local_launcher.sh")],
                cwd=root,
                env=install_environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)
            output = root / "launcher-probe.json"
            launch_environment = install_environment | {
                BINDING_ENV: str(root / "synthetic-binding.json"),
                "LAUNCHER_PROBE_OUTPUT": str(output),
                "PYTHONPATH": str(hostile),
                "PYTHONHOME": str(root / "hostile-python-home"),
                "PYTHONSAFEPATH": "1",
            }
            launched = subprocess.run(
                [str(home / ".local" / "bin" / "synapse-s2-mcp")],
                cwd=root,
                env=launch_environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {
                    "value": "reviewed-repo",
                    "pythonpath": None,
                    "pythonhome": None,
                    "nousersite": "1",
                },
            )

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
            repo = root / "repo"
            scripts = repo / "scripts"
            runtime_bin = repo / ".venv" / "bin"
            scripts.mkdir(parents=True)
            runtime_bin.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts" / "install_local_launcher.sh", scripts)
            (runtime_bin / "python").symlink_to(Path(sys.executable).resolve())
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
                ["/bin/sh", str(scripts / "install_local_launcher.sh")],
                cwd=repo,
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
            root = Path(tmp)
            repo = root / "repo"
            scripts = repo / "scripts"
            runtime_bin = repo / ".venv" / "bin"
            scripts.mkdir(parents=True)
            runtime_bin.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts" / "install_local_launcher.sh", scripts)
            (runtime_bin / "python").symlink_to(Path(sys.executable).resolve())
            home = root / "home"
            launcher_dir = home / ".local" / "bin"
            launcher_dir.mkdir(parents=True)
            lock = launcher_dir / ".synapse-s2-mcp.install.lock"
            lock.mkdir(mode=0o700)
            environment = os.environ.copy()
            environment["HOME"] = str(home)

            result = subprocess.run(
                ["/bin/sh", str(scripts / "install_local_launcher.sh")],
                cwd=repo,
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

    def test_shared_launchagent_lock_is_reusable_and_rejects_hardlinks(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            lock = root / "agent.install.lock"
            helper = ROOT / "scripts" / "secure_installer_support.py"
            command = [
                sys.executable,
                str(helper),
                "run-locked",
                "--lock",
                str(lock),
                "--marker",
                "test-lock",
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(0)",
            ]
            first = subprocess.run(command, check=False, capture_output=True, text=True)
            second = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertTrue(lock.is_file())
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

            alias = root / "lock-alias"
            os.link(lock, alias)
            rejected = subprocess.run(command, check=False, capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("unsafe", rejected.stderr)

    def test_secure_installer_helper_does_not_reflect_secret_cli_values(self):
        secret = "github_pat_secretparser123456789012345"
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "secure_installer_support.py"),
                "validate-regular",
                "--path",
                str(ROOT / "missing"),
                "--unknown",
                secret,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret, result.stderr)

    def test_dashboard_agent_installer_runs_lightweight_core_adapter_on_loopback(self):
        script_path = ROOT / "scripts" / "install_dashboard_agent.sh"

        self.assertTrue(script_path.exists(), "dashboard LaunchAgent installer must exist")
        script = script_path.read_text(encoding="utf-8")
        self.assertIn("aero.boom.synapse-s2.dashboard", script)
        self.assertIn("dashboard_server.py", script)
        self.assertIn("127.0.0.1", script)
        self.assertIn("SYNAPSE_S2_CORE_BINDING", script)
        self.assertIn(
            '$HOME/Library/Logs/SYNAPSE-S2/dashboard.log',
            script,
        )
        self.assertIn("SYNAPSE_S2_EMBEDDING_PROVIDER", script)
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
        self.assertIn("secure_installer_support.py", script)
        self.assertIn("replace-regular", script)
        self.assertIn("run-locked", script)
        self.assertNotIn('mkdir -m 700 "$INSTALL_LOCK_CANDIDATE"', script)
        self.assertIn("fsync_file_and_parent", script)
        self.assertIn("/api/status", script)
        self.assertIn("SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS", script)
        self.assertIn('launchctl bootout "gui/$UID_VALUE/$LABEL"', script)
        self.assertLess(
            script.index('plutil -lint "$PLIST_TEMP"'),
            script.rindex("if ! bootout_service; then"),
        )
        self.assertLess(
            script.rindex("replace-regular"),
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
        hostile_socket = str(
            data_root / f"core'\"&<$(touch {sentinel})" / "service.sock"
        )
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
                "SYNAPSE_S2_CORE_SOCKET": hostile_socket,
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
        self.assertIn(BINDING_ENV, payload["EnvironmentVariables"])
        self.assertEqual(
            payload["EnvironmentVariables"][BINDING_ENV],
            str(plist_path.parents[2] / ".config" / "synapse-s2" / "core-binding.json"),
        )
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", payload["EnvironmentVariables"])
        self.assertNotIn("SYNAPSE_S2_CAPTURE_ROOT", payload["EnvironmentVariables"])
        self.assertNotIn("SYNAPSE_S2_EXPORT_DIR", payload["EnvironmentVariables"])
        self.assertNotIn(
            "SYNAPSE_S2_EMBEDDING_PROVIDER",
            payload["EnvironmentVariables"],
        )
        self.assertEqual(stat.S_IMODE(plist_path.stat().st_mode), 0o600)

    def test_dashboard_installer_rejects_unreviewed_noncanonical_direct_paths(self):
        label = "aero.boom.synapse-s2.dashboard-test"
        with TemporaryDirectory() as temporary:
            data_root = Path(temporary)
            result, payload, plist_path = self._run_launch_agent_installer(
                "install_dashboard_agent.sh",
                label=label,
                install_dashboard_binding=False,
                extra_environment={
                    "SYNAPSE_S2_DASHBOARD_LABEL": label,
                    "SYNAPSE_S2_MEMORY_DB": str(data_root / "memory.sqlite3"),
                    "SYNAPSE_S2_STATE_PATH": str(data_root / "runtime_state.json"),
                    "SYNAPSE_S2_CAPTURE_ROOT": str(data_root),
                    "SYNAPSE_S2_EXPORT_DIR": str(data_root),
                },
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("require a reviewed core binding", result.stderr)
        self.assertEqual(payload, {})
        self.assertFalse(plist_path.exists())

    def test_dashboard_installer_prefers_explicit_reviewed_binding(self):
        label = "aero.boom.synapse-s2.dashboard-test"
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_root = (root / "explicit-reviewed-data").resolve()
            config = _write_test_core_config(data_root)
            binding = binding_for_config(
                repo_root=ROOT,
                data_root=data_root,
                config=config,
                core_label="aero.boom.synapse-s2.core",
                authority_mode="candidate-local-v5",
            )
            binding_path = root / "explicit" / "binding.json"
            write_core_client_binding(binding_path, binding)
            result, payload, _plist_path = self._run_launch_agent_installer(
                "install_dashboard_agent.sh",
                label=label,
                extra_environment={
                    "SYNAPSE_S2_DASHBOARD_LABEL": label,
                    "SYNAPSE_S2_DASHBOARD_LOG": str(root / "dashboard.log"),
                    BINDING_ENV: str(binding_path),
                    # Used only by the test curl stub, never published.
                    "SYNAPSE_S2_MEMORY_DB": str(config.memory_path),
                },
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            payload["EnvironmentVariables"],
            {
                BINDING_ENV: str(binding_path),
                "SYNAPSE_S2_DEFAULT_RESPONSE_MODE": "compact",
                "SYNAPSE_S2_MAX_RESPONSE_BYTES": "12288",
            },
        )

    def test_dashboard_installer_rejects_nonprivate_explicit_binding(self):
        label = "aero.boom.synapse-s2.dashboard-test"
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            data_root = (root / "explicit-reviewed-data").resolve()
            config = _write_test_core_config(data_root)
            binding = binding_for_config(
                repo_root=ROOT,
                data_root=data_root,
                config=config,
                core_label="aero.boom.synapse-s2.core",
                authority_mode="authoritative-core-v6",
            )
            binding_path = root / "explicit" / "binding.json"
            write_core_client_binding(binding_path, binding)
            binding_path.chmod(0o644)
            result, payload, plist_path = self._run_launch_agent_installer(
                "install_dashboard_agent.sh",
                label=label,
                extra_environment={
                    "SYNAPSE_S2_DASHBOARD_LABEL": label,
                    BINDING_ENV: str(binding_path),
                },
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("core binding is invalid", result.stderr)
        self.assertEqual(payload, {})
        self.assertFalse(plist_path.exists())

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
                    self.assertEqual(
                        executed,
                        [
                            "capture_ledger_audit",
                            "recovery_backup",
                            "recovery_verify",
                            "recovery_restore",
                        ],
                    )
                    if stage == "backup":
                        self.assertEqual(results["recovery_verify"].status, "blocked")
                        self.assertEqual(results["recovery_restore"].status, "blocked")
                    elif stage == "verify":
                        self.assertEqual(results["recovery_backup"].status, "ready")
                        self.assertEqual(results["recovery_restore"].status, "blocked")
                    else:
                        # All three current recovery checks are bound to the
                        # same isolated proof. A missing restore binding makes
                        # that shared proof incomplete and must revoke earlier
                        # backup/verify readiness too; a present but malformed
                        # binding remains attributable to the restore stage.
                        expected_prior = (
                            "blocked" if proof_name == "missing" else "ready"
                        )
                        self.assertEqual(
                            results["recovery_backup"].status, expected_prior
                        )
                        self.assertEqual(
                            results["recovery_verify"].status, expected_prior
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
                    self.assertIn("recovery_restore", executed)
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

    def test_cutover_docs_quiesce_persistent_wrappers_before_final_certifier(self):
        operations = (
            ROOT / "docs" / "AUTHORITATIVE_CORE_OPERATIONS.md"
        ).read_text(encoding="utf-8")
        cutover = operations.split("## First cutover or replacement", 1)[1].split(
            "The installer unloads", 1
        )[0]
        ordered_markers = (
            "scripts/install_core_agent.sh publish-binding",
            "capture-inbox-process --confirm",
            "mcp_client_wrapper.py",
            "--inventory-only --require-quiescent",
            "scripts/operator_readiness_certify.py",
            "--evidence-manifest /absolute/path/to/evidence-pack/manifest.json",
            "scripts/install_core_agent.sh install",
        )
        positions = [cutover.index(marker) for marker in ordered_markers]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("process_findings_truncated: false", cutover)
        self.assertIn("--json", cutover)
        self.assertIn("A momentarily empty process list is not durable quiescence", cutover)
        self.assertIn("post-backup quiescence proof", cutover)


if __name__ == "__main__":
    unittest.main()

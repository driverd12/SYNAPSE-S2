import fcntl
import os
import sqlite3
import stat
import subprocess
import sys
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from core_client_binding import (
    binding_for_config,
    default_binding_path,
    write_core_client_binding,
)
from core_runtime_paths import canonical_core_socket_path
from core_service import CoreConfig, write_core_config

ROOT = Path(__file__).resolve().parents[1]
PRIOR_PLIST = b"PRIOR-PLIST-BYTES\n"


class LaunchAgentInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        self.state = self.root / "stub-state"
        self.state.mkdir(mode=0o700)
        self._write_stubs()

    def _write_executable(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def _write_dashboard_binding(self) -> Path:
        data_root = self.root / "reviewed-dashboard-data"
        core = data_root / "core"
        core.mkdir(parents=True, mode=0o700)
        data_root.chmod(0o700)
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
        binding = binding_for_config(
            repo_root=ROOT,
            data_root=data_root,
            config=config,
            core_label="aero.boom.synapse-s2.core",
            authority_mode="authoritative-core-v6",
        )
        path = default_binding_path(self.home)
        write_core_client_binding(path, binding)
        return path

    def _write_stubs(self) -> None:
        self._write_executable(
            "plutil",
            """#!/bin/bash
set -eu
target="${!#}"
case "$1" in
  -create) : > "$target" ;;
  -insert) printf '%s\n' "$2" >> "$target" ;;
  -lint) test -f "$target" ;;
  *) exit 64 ;;
esac
""",
        )
        self._write_executable(
            "launchctl",
            """#!/bin/bash
set -eu
state_dir="$STUB_STATE_DIR"
printf '%s' "$1" >> "$state_dir/launchctl.log"
printf ' %q' "${@:2}" >> "$state_dir/launchctl.log"
printf '\n' >> "$state_dir/launchctl.log"
command="$1"
shift
case "$command" in
  print)
    target="${1:-}"
    case "$target" in
      gui/*/*) ;;
      gui/*) printf '{}\n'; exit 0 ;;
      *) exit 64 ;;
    esac
    phase="$(cat "$state_dir/phase" 2>/dev/null || true)"
    case "$phase" in
      prior) pid=111 ;;
      prior-waiting) pid=111 ;;
      new) pid=222 ;;
      rollback) pid=333 ;;
      rollback-waiting) pid=333 ;;
      *) exit 113 ;;
    esac
    if { [ "$phase" = new ] && [ "${STUB_SERVICE_HEALTH_FAIL:-0}" = 1 ]; } \
      || { [ "$phase" = prior-waiting ] || [ "$phase" = rollback-waiting ]; }; then
      state=waiting
    else
      state=running
    fi
    printf 'state = %s\npid = %s\n' "$state" "$pid"
    ;;
  print-disabled)
    if [ -f "$state_dir/disabled" ]; then
      printf '{\n  "test.synapse.capture" => true\n  "test.synapse.dashboard" => true\n}\n'
    else
      printf '{}\n'
    fi
    ;;
  bootout)
    printf 'absent\n' > "$state_dir/phase"
    ;;
  bootstrap)
    count="$(cat "$state_dir/bootstrap-count" 2>/dev/null || printf 0)"
    count=$((count + 1))
    printf '%s\n' "$count" > "$state_dir/bootstrap-count"
    if [ -f "$state_dir/disabled" ]; then
      exit 78
    fi
    if [ "${STUB_FAIL_FIRST_BOOTSTRAP:-0}" = 1 ] && [ "$count" -eq 1 ]; then
      exit 42
    fi
    case "$2" in
      *test.synapse.capture.plist)
        mkdir -p \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_inbox" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_processing" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_processed" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_errors" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_receipts"
        chmod 700 \
          "$SYNAPSE_S2_CAPTURE_ROOT" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_inbox" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_processing" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_processed" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_errors" \
          "$SYNAPSE_S2_CAPTURE_ROOT/capture_receipts"
        ;;
      *test.synapse.dashboard.plist)
        mkdir -p "$(dirname "$SYNAPSE_S2_DASHBOARD_AUTH_FILE")"
        chmod 700 "$(dirname "$SYNAPSE_S2_DASHBOARD_AUTH_FILE")"
        printf '{"schema":"synapse-s2.dashboard-auth.v1","host":"127.0.0.1","port":%s,"bootstrap_url":"http://127.0.0.1:%s/__dashboard_bootstrap?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","session_header":"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"}\n' \
          "$STUB_PORT" "$STUB_PORT" > "$SYNAPSE_S2_DASHBOARD_AUTH_FILE"
        chmod 600 "$SYNAPSE_S2_DASHBOARD_AUTH_FILE"
        ;;
    esac
    if grep -q PRIOR-PLIST-BYTES "$2"; then
      printf 'rollback\n' > "$state_dir/phase"
    else
      printf 'new\n' > "$state_dir/phase"
    fi
    ;;
  disable)
    : > "$state_dir/disabled"
    ;;
  enable)
    rm -f -- "$state_dir/disabled"
    ;;
  kickstart)
    if [ "$(cat "$state_dir/phase" 2>/dev/null || true)" = rollback-waiting ]; then
      printf 'rollback\n' > "$state_dir/phase"
    fi
    ;;
  kill)
    case "$(cat "$state_dir/phase" 2>/dev/null || true)" in
      rollback) printf 'rollback-waiting\n' > "$state_dir/phase" ;;
      new) printf 'new-waiting\n' > "$state_dir/phase" ;;
    esac
    ;;
  *) exit 64 ;;
esac
""",
        )
        self._write_executable(
            "lsof",
            """#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$STUB_STATE_DIR/lsof.log"
[ "${STUB_LSOF_FAIL:-0}" != 1 ]
printf 'p222\nn127.0.0.1:%s\n' "$STUB_PORT"
""",
        )
        self._write_executable(
            "curl",
            """#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$STUB_STATE_DIR/curl.log"
[ "${STUB_CURL_FAIL:-0}" != 1 ]
cat >/dev/null
if printf '%s\n' "$*" | grep -q -- '--write-out'; then
  printf '303'
  exit 0
fi
if [ "${STUB_API_DEGRADED:-0}" = 1 ]; then
  printf '{"runtime":"disabled","effective_enabled":false,"memory_db_path":"%s","memory_context_entry_count":0}\n' "$SYNAPSE_S2_MEMORY_DB"
else
  printf '{"runtime":"ready","effective_enabled":true,"memory_db_path":"%s","memory_context_entry_count":1}\n' "$SYNAPSE_S2_MEMORY_DB"
fi
""",
        )

    def _environment(self, *, dashboard: bool) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("SYNAPSE_S2_CORE_BINDING", None)
        env.update(
            {
                "HOME": str(self.home),
                "PATH": f"{self.bin}:{env['PATH']}",
                "STUB_STATE_DIR": str(self.state),
                "STUB_PORT": "18765",
                "SYNAPSE_S2_PYTHON": sys.executable,
                "SYNAPSE_S2_INSTALL_HEALTH_ATTEMPTS": "2",
                "SYNAPSE_S2_INSTALL_HEALTH_DELAY": "0.1",
                "SYNAPSE_S2_INSTALL_STABLE_CHECKS": "2",
                "SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS": "0.1",
                "SYNAPSE_S2_STATE_PATH": str(self.root / "data" / "state.json"),
                "SYNAPSE_S2_MEMORY_DB": str(self.root / "data" / "memory.sqlite3"),
                "SYNAPSE_S2_CAPTURE_ROOT": str(self.root / "capture"),
            }
        )
        memory_db = self.root / "data" / "memory.sqlite3"
        memory_db.parent.mkdir(parents=True, mode=0o700)
        with closing(sqlite3.connect(memory_db)) as connection:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE memory_entries(memory_id TEXT PRIMARY KEY);
                    CREATE TABLE capture_operations(capture_id TEXT PRIMARY KEY);
                    CREATE TABLE store_migrations(key TEXT PRIMARY KEY);
                    INSERT INTO memory_entries(memory_id) VALUES ('sentinel');
                    """
                )
        memory_db.chmod(0o600)
        if dashboard:
            self._write_dashboard_binding()
            env.update(
                {
                    "SYNAPSE_S2_DASHBOARD_LABEL": "test.synapse.dashboard",
                    "SYNAPSE_S2_DASHBOARD_HOST": "127.0.0.1",
                    "SYNAPSE_S2_DASHBOARD_PORT": "18765",
                    "SYNAPSE_S2_DASHBOARD_LOG": str(self.root / "logs" / "dashboard.log"),
                    "SYNAPSE_S2_DASHBOARD_AUTH_FILE": str(
                        self.root / "dashboard-auth" / "dashboard-auth.json"
                    ),
                    "SYNAPSE_S2_EXPORT_DIR": str(self.root / "exports"),
                }
            )
        else:
            env.update(
                {
                    "SYNAPSE_S2_CAPTURE_LABEL": "test.synapse.capture",
                    "SYNAPSE_S2_CAPTURE_LOG": str(self.root / "logs" / "capture.log"),
                }
            )
        return env

    def _plist(self, *, dashboard: bool) -> Path:
        label = "test.synapse.dashboard" if dashboard else "test.synapse.capture"
        return self.home / "Library" / "LaunchAgents" / f"{label}.plist"

    def _install(
        self,
        *,
        dashboard: bool,
        prior: bool = False,
        prior_loaded: bool = True,
        prior_disabled: bool = False,
        prior_running: bool = True,
        extra: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        plist = self._plist(dashboard=dashboard)
        if prior:
            plist.parent.mkdir(parents=True, mode=0o700)
            plist.write_bytes(PRIOR_PLIST)
            plist.chmod(0o600)
            if prior_loaded:
                phase = "prior" if prior_running else "prior-waiting"
                (self.state / "phase").write_text(f"{phase}\n", encoding="utf-8")
        if prior_disabled:
            (self.state / "disabled").touch()
        env = self._environment(dashboard=dashboard)
        if extra:
            env.update(extra)
        script = "install_dashboard_agent.sh" if dashboard else "install_capture_daemon.sh"
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / script)],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_capture_success_installs_private_plist_after_stable_new_pid(self) -> None:
        result = self._install(dashboard=False, prior=True)
        plist = self._plist(dashboard=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(plist.read_bytes(), PRIOR_PLIST)
        self.assertEqual(stat.S_IMODE(plist.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(plist.parent.stat().st_mode), 0o700)
        self.assertEqual(list(plist.parent.glob(".test.synapse.capture.rollback.*")), [])
        install_lock = plist.parent / ".test.synapse.capture.install.lock"
        self.assertTrue(install_lock.is_file())
        self.assertEqual(stat.S_IMODE(install_lock.stat().st_mode), 0o600)
        with closing(
            sqlite3.connect(self.root / "data" / "memory.sqlite3")
        ) as connection:
            self.assertEqual(
                connection.execute("SELECT memory_id FROM memory_entries").fetchall(),
                [("sentinel",)],
            )
        self.assertFalse((self.root / "data" / "memory.sqlite3-journal").exists())

    def test_capture_bootstrap_failure_restores_exact_prior_plist(self) -> None:
        result = self._install(
            dashboard=False, prior=True, extra={"STUB_FAIL_FIRST_BOOTSTRAP": "1"}
        )
        plist = self._plist(dashboard=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(plist.read_bytes(), PRIOR_PLIST)
        self.assertEqual(stat.S_IMODE(plist.stat().st_mode), 0o600)
        self.assertEqual((self.state / "phase").read_text().strip(), "rollback")
        self.assertEqual((self.state / "bootstrap-count").read_text().strip(), "2")

    def test_dashboard_http_health_failure_restores_prior_definition(self) -> None:
        result = self._install(
            dashboard=True, prior=True, extra={"STUB_CURL_FAIL": "1"}
        )
        plist = self._plist(dashboard=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(plist.read_bytes(), PRIOR_PLIST)
        self.assertEqual((self.state / "phase").read_text().strip(), "rollback")
        self.assertTrue((self.state / "lsof.log").exists())
        self.assertTrue((self.state / "curl.log").exists())

    def test_dashboard_first_install_failure_removes_attempted_definition(self) -> None:
        result = self._install(
            dashboard=True, extra={"STUB_FAIL_FIRST_BOOTSTRAP": "1"}
        )
        plist = self._plist(dashboard=True)

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(plist.exists())
        self.assertEqual(list(plist.parent.glob(".test.synapse.dashboard.rollback.*")), [])

    def test_dashboard_success_requires_loopback_listener_and_http_health(self) -> None:
        result = self._install(dashboard=True, prior=True)
        plist = self._plist(dashboard=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(plist.stat().st_mode), 0o600)
        self.assertIn("-iTCP:18765", (self.state / "lsof.log").read_text())
        curl_argv = (self.state / "curl.log").read_text(encoding="utf-8")
        config_call_count = curl_argv.count("--config -")
        self.assertGreaterEqual(config_call_count, 4)
        self.assertEqual(config_call_count % 2, 0)
        self.assertEqual(
            curl_argv.count("--write-out %{http_code}"),
            config_call_count // 2,
        )
        self.assertNotIn("A" * 43, curl_argv)
        self.assertNotIn("H" * 43, curl_argv)

    def test_capture_success_from_disabled_enables_before_bootstrap(self) -> None:
        result = self._install(
            dashboard=False,
            prior=True,
            prior_disabled=True,
            prior_running=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "disabled").exists())
        self.assertEqual((self.state / "phase").read_text().strip(), "new")
        operations = [
            line.split()[0]
            for line in (self.state / "launchctl.log").read_text().splitlines()
            if line.strip()
        ]
        bootstrap_index = operations.index("bootstrap")
        self.assertIn("enable", operations[:bootstrap_index])

    def test_dashboard_success_from_disabled_enables_before_bootstrap(self) -> None:
        result = self._install(
            dashboard=True,
            prior=True,
            prior_disabled=True,
            prior_running=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.state / "disabled").exists())
        self.assertEqual((self.state / "phase").read_text().strip(), "new")
        operations = [
            line.split()[0]
            for line in (self.state / "launchctl.log").read_text().splitlines()
            if line.strip()
        ]
        bootstrap_index = operations.index("bootstrap")
        self.assertIn("enable", operations[:bootstrap_index])

    def test_health_delay_is_validated_before_any_filesystem_mutation(self) -> None:
        result = self._install(
            dashboard=False,
            extra={"SYNAPSE_S2_INSTALL_HEALTH_DELAY": "-0.1"},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("health delay", result.stderr)
        self.assertFalse(self._plist(dashboard=False).exists())
        self.assertFalse((self.root / "capture").exists())
        self.assertFalse((self.state / "launchctl.log").exists())

    def test_stabilization_window_must_fit_bounded_attempts_before_mutation(self) -> None:
        result = self._install(
            dashboard=True,
            extra={
                "SYNAPSE_S2_INSTALL_HEALTH_ATTEMPTS": "2",
                "SYNAPSE_S2_INSTALL_HEALTH_DELAY": "0.1",
                "SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS": "0.2",
            },
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot satisfy", result.stderr)
        self.assertFalse(self._plist(dashboard=True).exists())
        self.assertFalse((self.state / "launchctl.log").exists())

    def test_capture_rollback_does_not_load_previously_unloaded_job(self) -> None:
        result = self._install(
            dashboard=False,
            prior=True,
            prior_loaded=False,
            extra={"STUB_FAIL_FIRST_BOOTSTRAP": "1"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._plist(dashboard=False).read_bytes(), PRIOR_PLIST)
        self.assertEqual((self.state / "bootstrap-count").read_text().strip(), "1")
        self.assertFalse((self.state / "phase").exists())

    def test_dashboard_rollback_preserves_disabled_nonrunning_policy(self) -> None:
        result = self._install(
            dashboard=True,
            prior=True,
            prior_disabled=True,
            prior_running=False,
            extra={"STUB_FAIL_FIRST_BOOTSTRAP": "1"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._plist(dashboard=True).read_bytes(), PRIOR_PLIST)
        self.assertTrue((self.state / "disabled").exists())
        log = (self.state / "launchctl.log").read_text()
        self.assertIn("disable", log)
        self.assertIn("kill SIGTERM", log)
        self.assertNotIn("kickstart", log)
        self.assertEqual((self.state / "phase").read_text().strip(), "rollback-waiting")

    def test_capture_rollback_preserves_loaded_enabled_nonrunning_policy(self) -> None:
        result = self._install(
            dashboard=False,
            prior=True,
            prior_running=False,
            extra={"STUB_FAIL_FIRST_BOOTSTRAP": "1"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._plist(dashboard=False).read_bytes(), PRIOR_PLIST)
        self.assertFalse((self.state / "disabled").exists())
        self.assertEqual((self.state / "phase").read_text().strip(), "rollback-waiting")
        log = (self.state / "launchctl.log").read_text()
        self.assertIn("kill SIGTERM", log)
        self.assertNotIn("kickstart", log)

    def test_dashboard_rollback_preserves_disabled_running_policy(self) -> None:
        result = self._install(
            dashboard=True,
            prior=True,
            prior_disabled=True,
            prior_running=True,
            extra={"STUB_FAIL_FIRST_BOOTSTRAP": "1"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._plist(dashboard=True).read_bytes(), PRIOR_PLIST)
        self.assertTrue((self.state / "disabled").exists())
        self.assertEqual((self.state / "phase").read_text().strip(), "rollback")
        log = (self.state / "launchctl.log").read_text()
        self.assertNotIn("kickstart", log)
        self.assertNotIn("kill SIGTERM", log)

    def test_first_install_failure_restores_preexisting_disabled_policy(self) -> None:
        result = self._install(
            dashboard=False,
            prior_disabled=True,
            extra={"STUB_FAIL_FIRST_BOOTSTRAP": "1"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self._plist(dashboard=False).exists())
        self.assertTrue((self.state / "disabled").exists())
        self.assertIn("disable", (self.state / "launchctl.log").read_text())

    def test_dashboard_rejects_degraded_api_even_when_root_page_would_answer(self) -> None:
        result = self._install(
            dashboard=True,
            prior=True,
            extra={"STUB_API_DEGRADED": "1"},
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self._plist(dashboard=True).read_bytes(), PRIOR_PLIST)
        self.assertEqual((self.state / "phase").read_text().strip(), "rollback")

    def test_secret_shaped_label_is_rejected_without_reflection(self) -> None:
        secret_label = "sk-abcdefghijklmnop"
        result = self._install(
            dashboard=False,
            extra={"SYNAPSE_S2_CAPTURE_LABEL": secret_label},
        )

        self.assertEqual(result.returncode, 2)
        self.assertNotIn(secret_label, result.stdout + result.stderr)
        self.assertIn("credential-shaped", result.stderr)
        secret_plist = self.home / "Library" / "LaunchAgents" / f"{secret_label}.plist"
        self.assertFalse(secret_plist.exists())

    def test_symlinked_log_target_is_rejected_without_following(self) -> None:
        outside = self.root / "outside.log"
        outside.write_text("unchanged\n", encoding="utf-8")
        logs = self.root / "logs"
        logs.mkdir(mode=0o700)
        link = logs / "capture-link.log"
        link.symlink_to(outside)

        result = self._install(
            dashboard=False,
            extra={"SYNAPSE_S2_CAPTURE_LOG": str(link)},
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("regular non-symlink", result.stderr)
        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged\n")
        self.assertTrue(link.is_symlink())

    def test_per_label_lock_refuses_concurrent_install(self) -> None:
        plist = self._plist(dashboard=True)
        plist.parent.mkdir(parents=True, mode=0o700)
        lock = plist.parent / ".test.synapse.dashboard.install.lock"
        lock.touch(mode=0o600)
        descriptor = os.open(lock, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self._install(dashboard=True)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already in progress", result.stderr)
        self.assertFalse(plist.exists())
        self.assertTrue(lock.is_file())


if __name__ == "__main__":
    unittest.main()

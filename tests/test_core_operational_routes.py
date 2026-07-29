from __future__ import annotations

import argparse
import fcntl
import json
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

from core_client_binding import (
    BINDING_ENV,
    binding_for_config,
    default_binding_path,
    write_core_client_binding,
)
from core_runtime_paths import canonical_core_socket_path
from core_service import CoreConfig, write_core_config
from scripts.core_agent_installer import build_config, resolve_paths
from scripts.operator_readiness_certify import OperatorReadinessCertifier
from scripts import synapse_status_report


ROOT = Path(__file__).resolve().parents[1]
LEGACY_RUNTIME_ENV = {
    "MLX_DEVICE",
    "SYNAPSE_S2_DIMENSION",
    "SYNAPSE_S2_EMBEDDING_PROVIDER",
    "SYNAPSE_S2_MEMORY_DB",
    "SYNAPSE_S2_NEURAL_MODEL",
    "SYNAPSE_S2_NEURONS",
    "SYNAPSE_S2_STATE_PATH",
    "SYNAPSE_S2_TOP_K",
}


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _write_reviewed_binding(
    *,
    home: Path,
    data_root: Path,
    authority_mode: str = "authoritative-core-v6",
) -> Path:
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
    binding = binding_for_config(
        repo_root=ROOT,
        data_root=data_root,
        config=config,
        core_label="aero.boom.synapse-s2.core",
        authority_mode=authority_mode,
    )
    path = default_binding_path(home)
    write_core_client_binding(path, binding)
    return path


class CoreOperationalRouteTests(unittest.TestCase):
    def _fake_dashboard_environment(self, root: Path) -> dict[str, str]:
        fake_bin = root / "bin"
        fake_bin.mkdir()
        _write_executable(
            fake_bin / "launchctl",
            """#!/bin/sh
set -eu
state_path="$(dirname "$0")/running"
case "$1" in
  print)
    case "$2" in
      gui/*/*) test -f "$state_path"; printf 'state = running\npid = 222\n' ;;
      gui/*) exit 0 ;;
      *) exit 64 ;;
    esac
    ;;
  print-disabled) exit 0 ;;
  bootout) rm -f -- "$state_path" ;;
  bootstrap|kickstart)
    : > "$state_path"
    mkdir -p "$(dirname "$SYNAPSE_S2_DASHBOARD_AUTH_FILE")"
    chmod 700 "$(dirname "$SYNAPSE_S2_DASHBOARD_AUTH_FILE")"
    printf '{"schema":"synapse-s2.dashboard-auth.v1","host":"127.0.0.1","port":18765,"bootstrap_url":"http://127.0.0.1:18765/__dashboard_bootstrap?token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","session_header":"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"}\n' > "$SYNAPSE_S2_DASHBOARD_AUTH_FILE"
    chmod 600 "$SYNAPSE_S2_DASHBOARD_AUTH_FILE"
    ;;
  enable|disable|kill) exit 0 ;;
  *) exit 64 ;;
esac
""",
        )
        _write_executable(
            fake_bin / "lsof",
            """#!/bin/sh
set -eu
printf 'p222\nn127.0.0.1:%s\n' "${SYNAPSE_S2_DASHBOARD_PORT:-8765}"
""",
        )
        _write_executable(
            fake_bin / "curl",
            """#!/bin/sh
set -eu
cat >/dev/null
if printf '%s\n' "$*" | grep -q -- '--write-out'; then
  printf '303'
  exit 0
fi
printf '%s\n' '{"runtime":"ready","effective_enabled":true,"memory_db_path":"/authority/memory.sqlite3","memory_context_entry_count":1}'
""",
        )
        home = root / "home"
        home.mkdir(mode=0o700)
        _write_reviewed_binding(home=home, data_root=root / "reviewed-core-data")
        environment = os.environ.copy()
        environment.pop(BINDING_ENV, None)
        environment.update(
            {
                "HOME": str(home),
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "SYNAPSE_S2_PYTHON": sys.executable,
                "SYNAPSE_S2_DASHBOARD_LABEL": "aero.boom.synapse-s2.dashboard-route-test",
                "SYNAPSE_S2_DASHBOARD_PORT": "18765",
                "SYNAPSE_S2_DASHBOARD_LOG": str(root / "data" / "dashboard.log"),
                "SYNAPSE_S2_DASHBOARD_AUTH_FILE": str(
                    root / "dashboard-auth" / "dashboard-auth.json"
                ),
                "SYNAPSE_S2_CORE_SOCKET": str(root / "data" / "core" / "service.sock"),
                "SYNAPSE_S2_EXPORT_DIR": str(root / "data"),
                "SYNAPSE_S2_CAPTURE_ROOT": str(root / "data"),
                "SYNAPSE_S2_DEFAULT_RESPONSE_MODE": "compact",
                "SYNAPSE_S2_MAX_RESPONSE_BYTES": "12288",
                "SYNAPSE_S2_INSTALL_HEALTH_ATTEMPTS": "2",
                "SYNAPSE_S2_INSTALL_HEALTH_DELAY": "0.1",
                "SYNAPSE_S2_INSTALL_STABLE_CHECKS": "2",
                "SYNAPSE_S2_INSTALL_STABILIZATION_SECONDS": "0.1",
                # These hostile inherited values must never reach the plist.
                "MLX_DEVICE": "hostile-device",
                "SYNAPSE_S2_MEMORY_DB": str(root / "wrong.sqlite3"),
                "SYNAPSE_S2_STATE_PATH": str(root / "wrong.json"),
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "hostile-provider",
                "SYNAPSE_S2_NEURONS": "999",
            }
        )
        return environment

    def test_dashboard_launch_agent_is_a_lightweight_core_adapter(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            environment = self._fake_dashboard_environment(root)
            completed = subprocess.run(
                ["bash", str(ROOT / "scripts" / "install_dashboard_agent.sh")],
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
                / f"{environment['SYNAPSE_S2_DASHBOARD_LABEL']}.plist"
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            with plist_path.open("rb") as stream:
                payload = plistlib.load(stream)
            plist_mode = stat.S_IMODE(plist_path.stat().st_mode)

        self.assertEqual(
            payload["EnvironmentVariables"],
            {
                BINDING_ENV: str(default_binding_path(Path(environment["HOME"]))),
                "SYNAPSE_S2_DEFAULT_RESPONSE_MODE": "compact",
                "SYNAPSE_S2_MAX_RESPONSE_BYTES": "12288",
            },
        )
        self.assertNotIn("SYNAPSE_S2_CORE_SOCKET", payload["EnvironmentVariables"])
        self.assertNotIn("SYNAPSE_S2_CAPTURE_ROOT", payload["EnvironmentVariables"])
        self.assertNotIn("SYNAPSE_S2_EXPORT_DIR", payload["EnvironmentVariables"])
        self.assertTrue(LEGACY_RUNTIME_ENV.isdisjoint(payload["EnvironmentVariables"]))
        self.assertEqual(plist_mode, 0o600)

    def _run_legacy_capture(self, root: Path, memory_db: Path) -> subprocess.CompletedProcess[str]:
        home = root / "home"
        home.mkdir(mode=0o700, exist_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "SYNAPSE_S2_PYTHON": sys.executable,
                "SYNAPSE_S2_MEMORY_DB": str(memory_db),
                "SYNAPSE_S2_STATE_PATH": str(root / "data" / "runtime_state.json"),
                "SYNAPSE_S2_CAPTURE_ROOT": str(root / "data"),
                "SYNAPSE_S2_CAPTURE_LOG": str(root / "data" / "capture.log"),
            }
        )
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / "install_capture_daemon.sh")],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_legacy_capture_refuses_v6_before_any_install_mutation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            memory_db = root / "memory.sqlite3"
            with closing(sqlite3.connect(memory_db)) as connection:
                connection.execute("CREATE TABLE store_metadata(key TEXT PRIMARY KEY, value_json TEXT)")
                connection.execute(
                    "INSERT INTO store_metadata VALUES(?, ?)",
                    (
                        "core_authority",
                        json.dumps({"service_required": True}, separators=(",", ":")),
                    ),
                )
                connection.execute("PRAGMA user_version = 6")
                connection.commit()
            memory_db.chmod(0o600)
            completed = self._run_legacy_capture(root, memory_db)

            self.assertEqual(completed.returncode, 4)
            self.assertIn("superseded-by-authoritative-core", completed.stderr)
            self.assertFalse((root / "data").exists())
            self.assertFalse((root / "home" / "Library").exists())

    def test_legacy_capture_refuses_an_installed_core_even_for_v5(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            memory_db = root / "memory.sqlite3"
            with closing(sqlite3.connect(memory_db)) as connection:
                connection.execute("PRAGMA user_version = 5")
                connection.commit()
            memory_db.chmod(0o600)
            core_plist = (
                root
                / "home"
                / "Library"
                / "LaunchAgents"
                / "aero.boom.synapse-s2.core.plist"
            )
            core_plist.parent.mkdir(parents=True, mode=0o700)
            core_plist.write_text("installed", encoding="utf-8")
            core_plist.chmod(0o600)
            completed = self._run_legacy_capture(root, memory_db)

        self.assertEqual(completed.returncode, 4)
        self.assertIn("superseded-by-authoritative-core", completed.stderr)

    def test_legacy_capture_refuses_an_active_core_lock_before_mutation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            memory_db = root / "memory.sqlite3"
            with closing(sqlite3.connect(memory_db)) as connection:
                connection.execute("PRAGMA user_version = 5")
                connection.commit()
            memory_db.chmod(0o600)
            core_root = root / "core"
            core_root.mkdir(mode=0o700)
            lock_path = core_root / "authority.lock"
            lock_path.write_bytes(b"")
            lock_path.chmod(0o600)
            descriptor = os.open(lock_path, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                completed = self._run_legacy_capture(root, memory_db)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

            self.assertEqual(completed.returncode, 4)
            self.assertIn("superseded-by-authoritative-core", completed.stderr)
            self.assertFalse((root / "data").exists())
            self.assertFalse((root / "home" / "Library").exists())

    def test_selected_text_preserves_v5_fallback_and_prep_routes_binding(self) -> None:
        selected = (ROOT / "scripts" / "capture_frontmost_selection.sh").read_text()
        prep = (ROOT / "scripts" / "prep_tomorrow.sh").read_text()

        self.assertIn("SYNAPSE_S2_CORE_SOCKET", selected)
        self.assertIn('    --state "$CANONICAL_STATE_PATH"', selected)
        self.assertIn('    --memory-db "$CANONICAL_MEMORY_DB"', selected)
        self.assertIn('    --capture-root "$CANONICAL_CAPTURE_ROOT"', selected)
        self.assertIn("unset SYNAPSE_S2_STATE_PATH SYNAPSE_S2_MEMORY_DB", selected)
        binding_branch = selected.split('if [ -n "$CORE_BINDING" ]; then', 1)[1].split(
            "else", 1
        )[0]
        self.assertNotIn("--state", binding_branch)
        self.assertNotIn("--memory-db", binding_branch)
        self.assertNotIn("--capture-root", binding_branch)
        self.assertIn("--install-core", prep)
        self.assertIn("--evidence-manifest", prep)
        self.assertIn("scripts/install_dashboard_agent.sh", prep)
        self.assertNotIn("\n  scripts/install_capture_daemon.sh\n", prep)
        unit_section = prep.split('echo "=== unit tests ==="', 1)[1].split(
            'echo "=== compile check ==="', 1
        )[0]
        self.assertIn("SYNAPSE_S2_CORE_BINDING SYNAPSE_S2_CORE_SOCKET", unit_section)
        self.assertIn("unset SYNAPSE_S2_STATE_PATH SYNAPSE_S2_MEMORY_DB", unit_section)
        self.assertNotIn("SYNAPSE_S2_EMBEDDING_PROVIDER=", unit_section)

    def test_readiness_commands_use_socket_or_marker_without_local_tuning(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            candidate_environment = {
                "HOME": str(home),
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "semantic-hash",
            }
            with patch.dict(os.environ, candidate_environment, clear=True):
                candidate_paths = resolve_paths(
                    label="aero.boom.synapse-s2.core"
                )
                candidate_config = build_config(candidate_paths)
                args = argparse.Namespace(
                    context="default",
                    agent_id="codex-desktop",
                    run_id="core-route-test",
                    output_dir=str(root / "evidence"),
                    launcher=str(root / "launcher"),
                    core_socket=str(candidate_config.socket_path),
                    embedding_provider="semantic-hash",
                    dimension=candidate_config.dimension,
                    neurons=candidate_config.num_neurons,
                    top_k=candidate_config.default_top_k,
                    neural_model=None,
                    neural_cache_dir=None,
                    neural_local_files_only=None,
                    app_name="",
                    zip=False,
                    json=True,
                )
                certifier = OperatorReadinessCertifier(args)
            with patch.dict(
                os.environ,
                {
                    "MLX_DEVICE": "gpu",
                    "SYNAPSE_S2_MEMORY_DB": str(root / "wrong.sqlite3"),
                    "SYNAPSE_S2_STATE_PATH": str(root / "wrong.json"),
                    "SYNAPSE_S2_EMBEDDING_PROVIDER": "wrong",
                    "SYNAPSE_S2_NEURONS": "1",
                },
                clear=False,
            ):
                environment = certifier._base_env()
                command = certifier._cli_command("status", "--context", "default")

        self.assertEqual(
            environment["SYNAPSE_S2_CORE_SOCKET"],
            str(candidate_config.socket_path),
        )
        self.assertTrue(LEGACY_RUNTIME_ENV.isdisjoint(environment))
        for option in ("--memory-db", "--state", "--embedding-provider", "--dimension", "--neurons", "--top-k"):
            self.assertNotIn(option, command)

    def test_status_report_subprocesses_scrub_local_backend_configuration(self) -> None:
        calls: list[tuple[list[str], dict[str, str]]] = []

        def fake_run(command: list[str], *, env: dict[str, str]) -> dict:
            calls.append((command, env))
            return {}

        args = argparse.Namespace(
            context="default",
            agent_id="codex-desktop",
            embedding_provider="mlx-neural",
            hygiene_limit=10,
            core_socket="/tmp/synapse-test/core/service.sock",
        )
        with patch.dict(
            os.environ,
            {
                "MLX_DEVICE": "gpu",
                "SYNAPSE_S2_MEMORY_DB": "/tmp/wrong.sqlite3",
                "SYNAPSE_S2_STATE_PATH": "/tmp/wrong.json",
                "SYNAPSE_S2_NEURONS": "1",
            },
            clear=False,
        ), patch.object(synapse_status_report, "run_json", side_effect=fake_run), patch.object(
            synapse_status_report, "git_snapshot", return_value={}
        ):
            synapse_status_report.collect_live_report(args)

        self.assertEqual(len(calls), 6)
        for command, environment in calls:
            self.assertEqual(
                environment["SYNAPSE_S2_CORE_SOCKET"],
                "/tmp/synapse-test/core/service.sock",
            )
            self.assertTrue(LEGACY_RUNTIME_ENV.isdisjoint(environment))
            self.assertNotIn("--embedding-provider", command)


if __name__ == "__main__":
    unittest.main()

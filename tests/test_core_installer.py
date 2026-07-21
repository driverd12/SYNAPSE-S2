from __future__ import annotations

import json
import io
import hashlib
import os
import plistlib
import sqlite3
import stat
import sys
import tempfile
import time
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import core_agent_installer as installer
from scripts import core_cutover_preflight as preflight
from memory_store import DurableMemoryStore
from recovery_manager import VerifiedRecoveryManager
from capture_daemon import CaptureInboxDaemon, write_capture_drop
from core_authority import CoreAuthorityLease
from core_request_journal import CoreRequestJournal
from core_service import AuthoritativeCoreService


class CoreAgentInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="synapse-core-installer-")
        # macOS exposes /var as a symlink to /private/var.  Production path
        # validation is deliberately no-follow, so fixtures use the canonical
        # physical TemporaryDirectory path.
        self.base = Path(self.temporary.name).resolve()
        self.home = self.base / "home"
        self.data = self.base / "data"
        self.core = self.data / "core"
        self.capture = self.data
        self.memory_db = self.data / "memory.sqlite3"
        self.plist = self.home / "Library" / "LaunchAgents" / "aero.boom.synapse-s2.core.test.plist"
        self.paths = installer.InstallPaths(
            home=self.home,
            root=ROOT,
            data_root=self.data,
            core_root=self.core,
            config=self.core / "service.json",
            socket=self.core / "service.sock",
            state=self.data / "runtime_state.json",
            memory_db=self.memory_db,
            capture_root=self.capture,
            log=self.core / "service.log",
            plist=self.plist,
            python=Path(sys.executable),
            service_program=ROOT / "core_service.py",
        )
        self.data.mkdir(mode=0o700)
        self.memory_db.write_bytes(b"temporary test database")
        self.memory_db.chmod(0o600)
        self.launchctl_path = self._write_fake_launchctl()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_fake_launchctl(self) -> Path:
        executable = self.base / "fake-launchctl"
        state = self.base / "launchctl-loaded"
        disabled = self.base / "launchctl-disabled"
        log = self.base / "launchctl.log"
        executable.write_text(
            f"""#!{sys.executable}
import pathlib
import sys
state = pathlib.Path({str(state)!r})
disabled = pathlib.Path({str(disabled)!r})
log = pathlib.Path({str(log)!r})
with log.open('a', encoding='utf-8') as handle:
    handle.write(' '.join(sys.argv[1:]) + '\\n')
command = sys.argv[1] if len(sys.argv) > 1 else ''
if command == 'print':
    target = sys.argv[2]
    if target.count('/') == 1:
        print('services = {{')
        if state.exists():
            print('  4242 - aero.boom.synapse-s2.core.test')
        print('}}')
    elif not state.exists():
        raise SystemExit(3)
    else:
        print('state = running')
        print('pid = 4242')
elif command == 'bootstrap':
    state.write_text('loaded', encoding='utf-8')
elif command == 'bootout':
    state.unlink(missing_ok=True)
elif command == 'enable':
    disabled.unlink(missing_ok=True)
elif command == 'disable':
    disabled.write_text('disabled', encoding='utf-8')
elif command == 'kickstart':
    if not state.exists():
        raise SystemExit(4)
else:
    raise SystemExit(5)
""",
            encoding="utf-8",
        )
        executable.chmod(0o700)
        return executable

    def _launchctl(self) -> installer.LaunchCtl:
        return installer.LaunchCtl(
            self.launchctl_path,
            uid=os.getuid(),
            label="aero.boom.synapse-s2.core.test",
        )

    @staticmethod
    def _health() -> dict[str, object]:
        return {
            "ready": True,
            "capture_ready": True,
            "authority_id": "core-test",
            "neural_epoch": "epoch-test",
            "config_fingerprint": "f" * 64,
            "build_id": "b" * 64,
            "store_identity": "s" * 64,
            "schema_identity": "sqlite-test-v6",
        }

    def _install(self, *, force_restart: bool = False) -> dict[str, object]:
        return installer.install(
            paths=self.paths,
            label="aero.boom.synapse-s2.core.test",
            launchctl=self._launchctl(),
            launchctl_bin=str(self.launchctl_path),
            ps_bin="/bin/false",
            evidence_manifest=self.base / "evidence" / "manifest.json",
            maximum_evidence_age_seconds=7200,
            wait_seconds=2,
            force_restart=force_restart,
        )

    def test_install_writes_private_config_and_secret_free_minimal_plist(self) -> None:
        canary = "sk-do-not-copy-this-secret-canary-12345678"
        with mock.patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": canary,
                "SYNAPSE_S2_BUILD_ID": canary,
                "SYNAPSE_S2_DIMENSION": "8",
                "SYNAPSE_S2_NEURONS": "16",
                "SYNAPSE_S2_TOP_K": "4",
                "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "0",
            },
            clear=False,
        ), mock.patch.object(
            installer, "_preflight", return_value={"ready": True}
        ), mock.patch.object(
            installer,
            "wait_for_health",
            return_value={**self._health(), "pid": 4242},
        ):
            result = self._install()

        self.assertEqual(result["status"], "healthy")
        self.assertEqual(stat.S_IMODE(self.core.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.paths.config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.paths.log.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.paths.plist.stat().st_mode), 0o600)
        config = json.loads(self.paths.config.read_text(encoding="utf-8"))
        self.assertEqual(config["socket_path"], str(self.paths.socket))
        self.assertEqual(config["memory_path"], str(self.paths.memory_db))
        self.assertEqual(config["capture_root"], str(self.paths.capture_root))
        plist = plistlib.loads(self.paths.plist.read_bytes())
        self.assertEqual(
            plist["ProgramArguments"],
            [
                str(self.paths.python),
                str(ROOT / "core_service.py"),
                "serve",
                "--config",
                str(self.paths.config),
            ],
        )
        self.assertEqual(
            plist["EnvironmentVariables"],
            {
                "SYNAPSE_S2_BUILD_ID": installer._manifest_build_id(ROOT),
                "MLX_DEVICE": "default",
            },
        )
        self.assertNotIn(canary, self.paths.plist.read_text(encoding="utf-8"))
        self.assertNotIn(canary, self.paths.config.read_text(encoding="utf-8"))
        log = (self.base / "launchctl.log").read_text(encoding="utf-8")
        self.assertIn("bootstrap", log)
        self.assertIn("kickstart", log)
        self.assertNotIn(canary, log)

    def test_build_config_closes_nondefault_topology_and_canonical_neural_model(self) -> None:
        environment = {
            "SYNAPSE_S2_DIMENSION": "12",
            "SYNAPSE_S2_NEURONS": "24",
            "SYNAPSE_S2_TOP_K": "6",
            "SYNAPSE_S2_RECALL_COUNT": "5",
            "SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS": "17",
            "SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS": "29",
            "SYNAPSE_S2_EMBEDDING_PROVIDER": "mlx-neural",
            "SYNAPSE_S2_NEURAL_MODEL": "mlx-community/test-model",
            "SYNAPSE_S2_NEURAL_REVISION": "a" * 40,
            "SYNAPSE_S2_NEURAL_CACHE_DIR": str(self.data / "models"),
            "SYNAPSE_S2_NEURAL_POOLING": "last",
            "SYNAPSE_S2_NEURAL_MAX_TOKENS": "96",
            "SYNAPSE_S2_NEURAL_NORMALIZE": "true",
            "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": "true",
            "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "true",
            "SYNAPSE_S2_TRANSCRIPT_POLL": "false",
            "SYNAPSE_S2_CAPTURE_POLL_INTERVAL": "3.5",
            "SYNAPSE_S2_CAPTURE_MAX_FILES": "41",
            "SYNAPSE_S2_MAX_TRANSCRIPT_BYTES": "4096",
            "MLX_DEVICE": "gpu",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            config = installer.build_config(self.paths)

        self.assertEqual(config.dimension, 12)
        self.assertEqual(config.num_neurons, 24)
        self.assertEqual(config.default_top_k, 6)
        self.assertEqual(config.recall_count, 5)
        self.assertEqual(config.quick_pruning_interval_seconds, 17.0)
        self.assertEqual(config.idle_deep_sleep_seconds, 29.0)
        self.assertEqual(config.embedding_neural_model_id, "mlx-community/test-model")
        self.assertEqual(config.embedding_neural_revision, "a" * 40)
        self.assertEqual(config.embedding_neural_pooling, "last")
        self.assertEqual(config.embedding_neural_max_tokens, 96)
        self.assertTrue(config.embedding_neural_normalize)
        self.assertTrue(config.embedding_neural_local_files_only)
        self.assertEqual(config.mlx_device, "gpu")
        self.assertTrue(config.require_native)
        self.assertFalse(config.poll_transcript_sources)
        self.assertEqual(config.capture_poll_seconds, 3.5)
        self.assertEqual(config.capture_max_files, 41)
        self.assertEqual(config.max_transcript_bytes, 4096)

        plist = plistlib.loads(
            installer.plist_payload(
                label="aero.boom.synapse-s2.core.test",
                paths=self.paths,
                config=config,
            )
        )
        self.assertEqual(
            plist["EnvironmentVariables"],
            {
                "SYNAPSE_S2_BUILD_ID": installer._manifest_build_id(ROOT),
                "MLX_DEVICE": "gpu",
            },
        )

        with mock.patch.dict(
            os.environ,
            {
                **environment,
                "SYNAPSE_S2_NEURAL_MODEL_ID": "different/model",
            },
            clear=True,
        ), self.assertRaises(installer.CoreInstallerError):
            installer.build_config(self.paths)

    def test_nondefault_mlx_device_launch_environment_matches_closed_config(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "MLX_DEVICE": "gpu",
                "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "false",
            },
            clear=True,
        ):
            config = installer.build_config(self.paths)
        plist = plistlib.loads(
            installer.plist_payload(
                label="aero.boom.synapse-s2.core.test",
                paths=self.paths,
                config=config,
            )
        )
        launch_environment = dict(plist["EnvironmentVariables"])
        self.assertEqual(launch_environment["MLX_DEVICE"], "gpu")

        backend = mock.sentinel.backend
        service = AuthoritativeCoreService(config)
        with mock.patch.dict(
            os.environ,
            launch_environment,
            clear=True,
        ), mock.patch(
            "mlx_backend.SpikingAttentionBackend",
            return_value=backend,
        ) as backend_factory:
            created = service._default_backend_factory(mock.sentinel.authority)
        self.assertIs(created, backend)
        backend_factory.assert_called_once()

    def test_publish_binding_writes_and_verifies_config_before_binding(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_DIMENSION": "8",
                "SYNAPSE_S2_NEURONS": "16",
                "SYNAPSE_S2_TOP_K": "4",
                "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "false",
                "SYNAPSE_S2_TRANSCRIPT_POLL": "false",
            },
            clear=True,
        ):
            config = installer.build_config(self.paths)
        result = installer.publish_client_binding(
            paths=self.paths,
            label="aero.boom.synapse-s2.core.test",
            config=config,
            authority_mode="candidate-local-v5",
        )

        binding = installer.load_core_client_binding(Path(result["path"]))
        loaded = installer.load_bound_core_config(binding)
        self.assertEqual(loaded, config)
        self.assertEqual(result["config_path"], str(self.paths.config))
        self.assertEqual(result["config_digest"], config.fingerprint)
        self.assertEqual(result["config_fingerprint"], config.fingerprint)
        self.assertEqual(
            result["embedding_space_identity"],
            config.embedding_space_identity,
        )
        self.assertEqual(stat.S_IMODE(self.paths.config.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(Path(result["path"]).stat().st_mode), 0o600)

    def test_second_current_install_is_idempotent(self) -> None:
        environment = {
            "SYNAPSE_S2_DIMENSION": "8",
            "SYNAPSE_S2_NEURONS": "16",
            "SYNAPSE_S2_TOP_K": "4",
            "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "0",
        }
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            installer, "_preflight", return_value={"ready": True}
        ), mock.patch.object(
            installer,
            "wait_for_health",
            return_value={**self._health(), "pid": 4242},
        ):
            self._install()
        before = (self.base / "launchctl.log").read_text(encoding="utf-8")
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            installer,
            "probe_health",
            return_value=self._health(),
        ), mock.patch.object(installer, "_preflight") as preflight_mock:
            result = self._install()
        after = (self.base / "launchctl.log").read_text(encoding="utf-8")
        self.assertEqual(result["status"], "already-healthy")
        self.assertEqual(after.count("bootstrap"), before.count("bootstrap"))
        preflight_mock.assert_not_called()

    def test_failed_activation_boots_out_and_preserves_all_state(self) -> None:
        token = self.core / "service.sock.token"
        self.core.mkdir(mode=0o700)
        token.write_text("test-token-placeholder", encoding="utf-8")
        token.chmod(0o600)
        capture_marker = self.data / "capture_inbox" / "pending.json"
        capture_marker.parent.mkdir(mode=0o700)
        capture_marker.write_text("{}", encoding="utf-8")
        capture_marker.chmod(0o600)
        with mock.patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_DIMENSION": "8",
                "SYNAPSE_S2_NEURONS": "16",
                "SYNAPSE_S2_TOP_K": "4",
                "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "0",
            },
            clear=False,
        ), mock.patch.object(
            installer, "_preflight", return_value={"ready": True}
        ), mock.patch.object(
            installer,
            "wait_for_health",
            side_effect=installer.CoreInstallerError("health failed"),
        ):
            with self.assertRaisesRegex(installer.CoreInstallerError, "fail-closed"):
                self._install()
        self.assertFalse((self.base / "launchctl-loaded").exists())
        self.assertTrue((self.base / "launchctl-disabled").exists())
        self.assertTrue(self.paths.plist.is_file())
        self.assertTrue(self.paths.config.is_file())
        self.assertTrue(self.paths.log.is_file())
        self.assertEqual(self.memory_db.read_bytes(), b"temporary test database")
        self.assertTrue(capture_marker.is_file())
        self.assertEqual(token.read_text(encoding="utf-8"), "test-token-placeholder")
        calls = (self.base / "launchctl.log").read_text(encoding="utf-8")
        self.assertIn("bootout gui/", calls)
        self.assertIn("disable gui/", calls)

    def test_uninstall_is_idempotent_and_preserves_data_config_token_and_logs(self) -> None:
        self.core.mkdir(mode=0o700)
        self.plist.parent.mkdir(mode=0o700, parents=True)
        self.plist.write_bytes(b"plist")
        self.plist.chmod(0o600)
        for path, content in (
            (self.paths.config, "config"),
            (self.paths.log, "log"),
            (self.core / "service.sock.token", "token"),
        ):
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
        (self.base / "launchctl-loaded").write_text("loaded", encoding="utf-8")
        first = installer.uninstall(paths=self.paths, launchctl=self._launchctl(), wait_seconds=2)
        second = installer.uninstall(paths=self.paths, launchctl=self._launchctl(), wait_seconds=2)
        self.assertTrue(first["plist_removed"])
        self.assertFalse(second["plist_removed"])
        self.assertFalse(self.plist.exists())
        self.assertTrue(self.memory_db.exists())
        self.assertEqual(self.paths.config.read_text(encoding="utf-8"), "config")
        self.assertEqual(self.paths.log.read_text(encoding="utf-8"), "log")
        self.assertEqual((self.core / "service.sock.token").read_text(), "token")

    def test_status_does_not_create_install_paths(self) -> None:
        result = installer.status(paths=self.paths, launchctl=self._launchctl())
        self.assertFalse(result["loaded"])
        self.assertFalse(self.home.exists())
        self.assertFalse(self.core.exists())

    def test_symlinked_plist_is_refused(self) -> None:
        self.plist.parent.mkdir(mode=0o700, parents=True)
        target = self.base / "outside"
        target.write_text("outside", encoding="utf-8")
        self.plist.symlink_to(target)
        with self.assertRaisesRegex(installer.CoreInstallerError, "unsafe"):
            installer._atomic_private_bytes(self.plist, b"replacement")
        self.assertEqual(target.read_text(encoding="utf-8"), "outside")

    def test_shell_entrypoints_have_no_broad_process_or_delete_commands(self) -> None:
        combined = "\n".join(
            (ROOT / "scripts" / name).read_text(encoding="utf-8")
            for name in ("install_core_agent.sh", "core_cutover_preflight.sh")
        )
        for unsafe in ("pkill", "killall", "rm -rf", "find -delete", "eval "):
            self.assertNotIn(unsafe, combined)
        self.assertIn("set -euo pipefail", combined)
        self.assertIn("umask 077", combined)

    def test_resolved_paths_share_router_socket_and_existing_runtime_state_layout(self) -> None:
        layout = installer._canonical_layout(self.data)
        manifest = self.base / "layout.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": installer.LAYOUT_MANIFEST_SCHEMA,
                    "reviewed": True,
                    "reviewed_by": "installer-test",
                    "paths": {key: str(value) for key, value in layout.items()},
                }
            ),
            encoding="utf-8",
        )
        manifest.chmod(0o600)
        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "SYNAPSE_S2_CORE_DATA_ROOT": str(self.data),
            },
            clear=True,
        ):
            paths = installer.resolve_paths(
                label="aero.boom.synapse-s2.core.test",
                noncanonical_layout_manifest=manifest,
            )
        self.assertEqual(paths.socket, self.data / "core" / "service.sock")
        self.assertEqual(paths.socket.parent.parent, paths.data_root)
        self.assertEqual(paths.state, self.data / "runtime_state.json")
        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "SYNAPSE_S2_CORE_DATA_ROOT": str(self.data),
                "SYNAPSE_S2_CORE_SOCKET": str(self.base / "wrong" / "service.sock"),
            },
            clear=True,
        ):
            with self.assertRaisesRegex(installer.CoreInstallerError, "canonical layout"):
                installer.resolve_paths(
                    label="aero.boom.synapse-s2.core.test",
                    noncanonical_layout_manifest=manifest,
                )

    def test_noncanonical_layout_requires_exact_reviewed_private_manifest(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HOME": str(self.home), "SYNAPSE_S2_CORE_DATA_ROOT": str(self.data)},
            clear=True,
        ):
            with self.assertRaisesRegex(installer.CoreInstallerError, "reviewed manifest"):
                installer.resolve_paths(label="aero.boom.synapse-s2.core.test")

    def test_existing_managed_directories_are_never_repermissioned(self) -> None:
        unsafe = self.base / "caller-owned"
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        with self.assertRaisesRegex(installer.CoreInstallerError, "permission"):
            installer.ensure_private_directory(unsafe)
        self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o755)
        installer.ensure_private_directory(unsafe, require_private=False)
        self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o755)

    def test_layout_rejects_symlinked_component_and_broad_root(self) -> None:
        outside = self.base / "outside-data"
        outside.mkdir(mode=0o700)
        linked = self.base / "linked-data"
        linked.symlink_to(outside, target_is_directory=True)
        linked_paths = installer.InstallPaths(
            **{
                **self.paths.__dict__,
                "data_root": linked,
                "core_root": linked / "core",
                "config": linked / "core" / "service.json",
                "socket": linked / "core" / "service.sock",
                "state": linked / "runtime_state.json",
                "memory_db": linked / "memory.sqlite3",
                "capture_root": linked,
                "log": linked / "core" / "service.log",
            }
        )
        with self.assertRaisesRegex(installer.CoreInstallerError, "symlink"):
            installer._assert_layout(linked_paths)

    def test_health_requires_exact_v6_application_id_and_numeric_epoch(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_DIMENSION": "8",
                "SYNAPSE_S2_NEURONS": "16",
                "SYNAPSE_S2_TOP_K": "4",
                "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "0",
            },
            clear=False,
        ):
            config = installer.build_config(self.paths)
        identity = {
            "authority_id": "core-test",
            "neural_epoch": "epoch-1",
            "config_fingerprint": config.fingerprint,
            "build_id": installer._manifest_build_id(ROOT),
            "store_identity": installer._store_identity(config.memory_path),
            "schema_identity": installer.EXPECTED_SCHEMA_IDENTITY,
        }
        client = mock.Mock()
        client.health.return_value = {
            "ready": True,
            "protocol_version": installer.PROTOCOL_VERSION,
            "capture": {"enabled": True, "ready": True, "iteration_count": 1},
        }
        type(client).authority_identity = mock.PropertyMock(return_value=identity)
        with mock.patch("core_client.CoreClient", return_value=client), mock.patch.object(
            installer,
            "_private_socket",
        ), mock.patch.object(installer, "_private_token"):
            self.assertTrue(installer.probe_health(config)["ready"])
            identity["schema_identity"] = "sqlite-test-v6"
            with self.assertRaisesRegex(installer.CoreInstallerError, "exact v6"):
                installer.probe_health(config)
            identity["schema_identity"] = installer.EXPECTED_SCHEMA_IDENTITY
            identity["neural_epoch"] = "epoch-test"
            with self.assertRaisesRegex(installer.CoreInstallerError, "epoch"):
                installer.probe_health(config)

    def test_restored_health_uses_verified_persisted_store_identity(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_DIMENSION": "8",
                "SYNAPSE_S2_NEURONS": "16",
                "SYNAPSE_S2_TOP_K": "4",
                "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "0",
            },
            clear=False,
        ):
            config = installer.build_config(self.paths)
        candidate_a = "store-" + ("a" * 24)
        restored_identity = (
            candidate_a
            if candidate_a != installer._store_identity(config.memory_path)
            else "store-" + ("b" * 24)
        )
        identity = {
            "authority_id": "core-restored-test",
            "neural_epoch": "epoch-7",
            "config_fingerprint": config.fingerprint,
            "build_id": installer._manifest_build_id(ROOT),
            "store_identity": restored_identity,
            "schema_identity": installer.EXPECTED_SCHEMA_IDENTITY,
        }
        client = mock.Mock()
        client.health.return_value = {
            "ready": True,
            "protocol_version": installer.PROTOCOL_VERSION,
            "capture": {"enabled": True, "ready": True, "iteration_count": 2},
        }
        type(client).authority_identity = mock.PropertyMock(return_value=identity)
        verified = {
            "verified": True,
            "store_identity": restored_identity,
            "authority_epoch_number": 7,
        }
        with mock.patch("core_client.CoreClient", return_value=client), mock.patch.object(
            installer,
            "_private_socket",
        ), mock.patch.object(installer, "_private_token"), mock.patch.object(
            installer,
            "_verify_restored_health_identity",
            return_value=verified,
        ) as lineage:
            self.assertTrue(
                installer.probe_health(config, restored_target=True)["ready"]
            )
            lineage.assert_called_once_with(
                config,
                store_identity=restored_identity,
                authority_epoch_number=7,
            )
            lineage.return_value = {
                **verified,
                "store_identity": (
                    "store-" + ("c" * 24)
                    if restored_identity != "store-" + ("c" * 24)
                    else "store-" + ("d" * 24)
                ),
            }
            with self.assertRaisesRegex(
                installer.CoreInstallerError,
                "restored identity",
            ):
                installer.probe_health(config, restored_target=True)

    def test_installer_parser_does_not_reflect_secret_shaped_errors(self) -> None:
        secret = "sk-secret-parser-value-123456789"
        error = io.StringIO()
        with redirect_stderr(error), self.assertRaises(SystemExit):
            installer.build_parser().parse_args(["--wait-seconds", secret])
        self.assertNotIn(secret, error.getvalue())

    def test_preflight_repairs_empty_journal_only_after_exact_v5_inspection(
        self,
    ) -> None:
        self.memory_db.unlink()
        bootstrap = DurableMemoryStore(self.memory_db)
        bootstrap.close()
        store_identity = installer._store_identity(self.memory_db)
        journal = CoreRequestJournal(
            self.core / "requests.sqlite3",
            authority_epoch="epoch-1",
            prune_on_open=False,
            store_identity=store_identity,
        )
        journal.close()
        config = installer.CoreConfig(
            socket_path=self.paths.socket,
            state_path=self.paths.state,
            memory_path=self.paths.memory_db,
            capture_root=self.paths.capture_root,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )

        def verify_repair_precedes_full_preflight(**_kwargs):
            self.assertFalse((self.core / "requests.sqlite3").exists())
            self.assertEqual(
                len(
                    tuple(
                        self.core.glob(
                            "requests.sqlite3.preclaim-repair-*.json"
                        )
                    )
                ),
                1,
            )
            return {"ready": True}

        with mock.patch.object(
            installer,
            "run_preflight",
            side_effect=verify_repair_precedes_full_preflight,
        ) as delegated:
            result = installer._preflight(
                paths=self.paths,
                evidence_manifest=self.base / "unused-evidence.json",
                maximum_evidence_age_seconds=60.0,
                launchctl_bin=str(self.launchctl_path),
                ps_bin="/bin/ps",
                label="aero.boom.synapse-s2.core.test",
                config=config,
            )

        self.assertEqual(result, {"ready": True})
        delegated.assert_called_once()
        self.assertFalse((self.core / "requests.sqlite3").exists())
        receipts = tuple(
            self.core.glob("requests.sqlite3.preclaim-repair-*.json")
        )
        self.assertEqual(len(receipts), 1)
        self.assertEqual(
            json.loads(receipts[0].read_text(encoding="utf-8"))["status"],
            "complete",
        )

    def test_preflight_malformed_memory_schema_never_archives_journal(self) -> None:
        self.memory_db.unlink()
        bootstrap = DurableMemoryStore(self.memory_db)
        bootstrap.close()
        store_identity = installer._store_identity(self.memory_db)
        journal_path = self.core / "requests.sqlite3"
        journal = CoreRequestJournal(
            journal_path,
            authority_epoch="epoch-1",
            prune_on_open=False,
            store_identity=store_identity,
        )
        journal.close()
        with closing(sqlite3.connect(self.memory_db)) as connection:
            connection.execute(
                "ALTER TABLE memory_entries ADD COLUMN hidden_preflight_x "
                "TEXT GENERATED ALWAYS AS ('x') VIRTUAL"
            )
            connection.commit()
        journal_before = journal_path.read_bytes()
        journal_identity = journal_path.stat()
        config = installer.CoreConfig(
            socket_path=self.paths.socket,
            state_path=self.paths.state,
            memory_path=self.paths.memory_db,
            capture_root=self.paths.capture_root,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )

        with mock.patch.object(installer, "run_preflight") as delegated:
            with self.assertRaises(installer.CoreInstallerError):
                installer._preflight(
                    paths=self.paths,
                    evidence_manifest=self.base / "unused-evidence.json",
                    maximum_evidence_age_seconds=60.0,
                    launchctl_bin=str(self.launchctl_path),
                    ps_bin="/bin/ps",
                    label="aero.boom.synapse-s2.core.test",
                    config=config,
                )

        delegated.assert_not_called()
        self.assertEqual(journal_path.read_bytes(), journal_before)
        journal_after = journal_path.stat()
        self.assertEqual(
            (journal_after.st_dev, journal_after.st_ino, journal_after.st_size),
            (
                journal_identity.st_dev,
                journal_identity.st_ino,
                journal_identity.st_size,
            ),
        )
        self.assertFalse(
            tuple(self.core.glob("requests.sqlite3.preclaim-repair-*.json"))
        )
        self.assertFalse(tuple(self.core.glob(".*.preclaim-*.archive")))

    def test_preflight_active_core_contention_preserves_empty_residue(self) -> None:
        self.memory_db.unlink()
        bootstrap = DurableMemoryStore(self.memory_db)
        bootstrap.close()
        store_identity = installer._store_identity(self.memory_db)
        journal_path = self.core / "requests.sqlite3"
        journal = CoreRequestJournal(
            journal_path,
            authority_epoch="epoch-1",
            prune_on_open=False,
            store_identity=store_identity,
        )
        journal.close()
        before = journal_path.read_bytes()
        config = installer.CoreConfig(
            socket_path=self.paths.socket,
            state_path=self.paths.state,
            memory_path=self.paths.memory_db,
            capture_root=self.paths.capture_root,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )
        active = CoreAuthorityLease.acquire_core(
            self.memory_db,
            timeout_seconds=0.0,
            instance_id="active-core-contention-test",
        )
        try:
            with mock.patch.object(installer, "run_preflight") as delegated:
                with self.assertRaises(installer.CoreInstallerError):
                    installer._preflight(
                        paths=self.paths,
                        evidence_manifest=self.base / "unused-evidence.json",
                        maximum_evidence_age_seconds=60.0,
                        launchctl_bin=str(self.launchctl_path),
                        ps_bin="/bin/ps",
                        label="aero.boom.synapse-s2.core.test",
                        config=config,
                    )
            delegated.assert_not_called()
        finally:
            active.close()
        self.assertEqual(journal_path.read_bytes(), before)
        self.assertFalse(
            tuple(self.core.glob("requests.sqlite3.preclaim-repair-*.json"))
        )
        self.assertFalse(tuple(self.core.glob(".*.preclaim-*.archive")))

    def test_preflight_journal_recovery_never_bootstraps_missing_memory(self) -> None:
        self.memory_db.unlink()
        self.core.mkdir(parents=True, mode=0o700)
        journal_path = self.core / "requests.sqlite3"
        lock_path = self.core / "requests.sqlite3.lock"
        journal_path.write_bytes(b"preserve-journal-residue")
        lock_path.write_bytes(b"")
        journal_path.chmod(0o600)
        lock_path.chmod(0o600)
        config = installer.CoreConfig(
            socket_path=self.paths.socket,
            state_path=self.paths.state,
            memory_path=self.paths.memory_db,
            capture_root=self.paths.capture_root,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )

        with mock.patch.object(installer, "run_preflight") as delegated:
            with self.assertRaises(installer.CoreInstallerError):
                installer._preflight(
                    paths=self.paths,
                    evidence_manifest=self.base / "unused-evidence.json",
                    maximum_evidence_age_seconds=60.0,
                    launchctl_bin=str(self.launchctl_path),
                    ps_bin="/bin/ps",
                    label="aero.boom.synapse-s2.core.test",
                    config=config,
                )

        delegated.assert_not_called()
        self.assertFalse(self.memory_db.exists())
        self.assertEqual(journal_path.read_bytes(), b"preserve-journal-residue")
        self.assertEqual(lock_path.read_bytes(), b"")
        self.assertFalse(
            tuple(self.core.glob("requests.sqlite3.preclaim-repair-*.json"))
        )

    def test_preflight_normalizes_filesystem_repair_failure(self) -> None:
        self.memory_db.unlink()
        bootstrap = DurableMemoryStore(self.memory_db)
        bootstrap.close()
        store_identity = installer._store_identity(self.memory_db)
        journal_path = self.core / "requests.sqlite3"
        journal = CoreRequestJournal(
            journal_path,
            authority_epoch="epoch-1",
            prune_on_open=False,
            store_identity=store_identity,
        )
        journal.close()
        config = installer.CoreConfig(
            socket_path=self.paths.socket,
            state_path=self.paths.state,
            memory_path=self.paths.memory_db,
            capture_root=self.paths.capture_root,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )
        secret_path = "sk-filesystem-path-canary-1234567890"

        with mock.patch.object(
            installer,
            "repair_empty_preclaim_journal_residue",
            side_effect=OSError(secret_path),
        ), mock.patch.object(installer, "run_preflight") as delegated:
            with self.assertRaises(installer.CoreInstallerError) as raised:
                installer._preflight(
                    paths=self.paths,
                    evidence_manifest=self.base / "unused-evidence.json",
                    maximum_evidence_age_seconds=60.0,
                    launchctl_bin=str(self.launchctl_path),
                    ps_bin="/bin/ps",
                    label="aero.boom.synapse-s2.core.test",
                    config=config,
                )

        self.assertEqual(
            str(raised.exception),
            "authoritative core preflight failed",
        )
        self.assertNotIn(secret_path, str(raised.exception))
        delegated.assert_not_called()
        self.assertTrue(journal_path.exists())

    def test_preflight_validates_completed_repair_without_canonical_journal(
        self,
    ) -> None:
        self.memory_db.unlink()
        bootstrap = DurableMemoryStore(self.memory_db)
        bootstrap.close()
        store_identity = installer._store_identity(self.memory_db)
        journal = CoreRequestJournal(
            self.core / "requests.sqlite3",
            authority_epoch="epoch-1",
            prune_on_open=False,
            store_identity=store_identity,
        )
        journal.close()
        config = installer.CoreConfig(
            socket_path=self.paths.socket,
            state_path=self.paths.state,
            memory_path=self.paths.memory_db,
            capture_root=self.paths.capture_root,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )
        arguments = {
            "paths": self.paths,
            "evidence_manifest": self.base / "unused-evidence.json",
            "maximum_evidence_age_seconds": 60.0,
            "launchctl_bin": str(self.launchctl_path),
            "ps_bin": "/bin/ps",
            "label": "aero.boom.synapse-s2.core.test",
            "config": config,
        }
        with mock.patch.object(
            installer,
            "run_preflight",
            return_value={"ready": True},
        ):
            self.assertEqual(installer._preflight(**arguments), {"ready": True})
        receipt_path = next(
            self.core.glob("requests.sqlite3.preclaim-repair-*.json")
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        main = next(
            artifact
            for artifact in receipt["artifacts"]
            if artifact["source_name"] == "requests.sqlite3"
        )
        archive = self.core / main["archive_name"]
        archive.write_bytes(b"tampered-completed-archive")
        archive.chmod(0o600)
        self.assertFalse((self.core / "requests.sqlite3").exists())

        with mock.patch.object(installer, "run_preflight") as delegated:
            with self.assertRaises(installer.CoreInstallerError):
                installer._preflight(**arguments)

        delegated.assert_not_called()
        self.assertEqual(archive.read_bytes(), b"tampered-completed-archive")
        self.assertFalse((self.core / "requests.sqlite3").exists())


class CoreCutoverPreflightTests(unittest.TestCase):
    @staticmethod
    def _core_config(root: Path, *, memory_path: Path | None = None) -> installer.CoreConfig:
        return installer.CoreConfig(
            socket_path=root / "core" / "service.sock",
            state_path=root / "runtime_state.json",
            memory_path=memory_path or (root / "memory.sqlite3"),
            capture_root=root,
            dimension=8,
            num_neurons=16,
            default_top_k=4,
            authority_timeout_seconds=0.0,
        )

    @staticmethod
    def _write_cutover_evidence_pack(
        *,
        root: Path,
        verified: dict,
        proof: dict,
        git_head: str,
        config: installer.CoreConfig,
    ) -> tuple[Path, Path]:
        pack = root / "evidence-pack"
        artifacts = pack / "artifacts"
        artifacts.mkdir(parents=True, mode=0o700)
        parsed_path = artifacts / "recovery-verify.json"
        parsed_path.write_text(
            json.dumps(verified, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        parsed_path.chmod(0o600)
        proof_path = artifacts / "recovery-proof.receipt.json"
        proof_path.write_text(
            json.dumps(proof, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        proof_path.chmod(0o600)
        metrics = {
            "verified": True,
            "cutover_ready": True,
            "capture_ledger_binding": dict(verified["capture_ledger_binding"]),
            "reconciliation": dict(verified["reconciliation"]),
        }
        checks = [
            {
                "check_id": "recovery_backup",
                "required": True,
                "status": "ready",
                "metrics": dict(metrics),
                "artifact_paths": {},
            },
            {
                "check_id": "recovery_verify",
                "required": True,
                "status": "ready",
                "metrics": dict(metrics),
                "artifact_paths": {"parsed": str(parsed_path)},
            },
            {
                "check_id": "recovery_restore",
                "required": True,
                "status": "ready",
                "metrics": dict(metrics),
                "artifact_paths": {"recovery_proof": str(proof_path)},
            },
        ]
        manifest = pack / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "overall_status": "ready",
                    "operator_trustworthy": True,
                    "created_at": time.time(),
                    "git": {"head": git_head, "status_short": ""},
                    "core_config_contract": (
                        preflight.core_config_evidence_contract(config)
                    ),
                    "checks": checks,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest.chmod(0o600)
        return manifest, proof_path

    def test_cutover_attestation_contract_uses_real_build_id_and_wall_clock(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="synapse-cutover-attestation-contract-"
        ) as temporary:
            root = Path(temporary).resolve()
            store = DurableMemoryStore(root / "memory.sqlite3")
            now = int(time.time() * 1000)
            content = {
                "schema": preflight.CUTOVER_ATTESTATION_SCHEMA,
                "created_at_unix_ms": now,
                "expires_at_unix_ms": now + 300_000,
                "evidence_manifest_path": str(root / "evidence.json"),
                "evidence_manifest_sha256": "a" * 64,
                "git_head": "b" * 40,
                "build_id": installer._manifest_build_id(ROOT),
                "config_fingerprint": "c" * 64,
                "governance_mode": "pre-governed-v5",
                "store_identity": "store-" + "d" * 24,
                "store_generation": "legacy-v5",
                "authority_epoch_number": None,
                "database_schema_identity": "sqlite-53324442-v5",
                "database_logical_snapshot_schema": (
                    preflight.LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                ),
                "database_logical_snapshot_sha256": "e" * 64,
                "capture_manifest_sha256": "f" * 64,
                "runtime_state_required": False,
                "runtime_state_present": False,
                "runtime_state_canonical_sha256": None,
                "request_journal_id": None,
                "request_journal_schema_identity": None,
                "request_journal_logical_snapshot_schema": None,
                "request_journal_logical_snapshot_sha256": None,
                "request_journal_binding_receipt_digest": None,
                "restored_target": False,
                "restored_target_binding_receipt_digest": None,
                "recovery_bundle_receipt_digest": "1" * 64,
                "recovery_restore_proof_receipt_digest": "2" * 64,
            }

            def signed(**overrides):
                payload = {**content, **overrides}
                store._authenticate_receipt(payload)
                return payload

            try:
                valid = signed()
                self.assertEqual(
                    preflight._validate_cutover_attestation(
                        valid,
                        store=store,
                        expected_content=content,
                        now_unix_ms=now,
                        minimum_remaining_seconds=120,
                    ),
                    valid["receipt_digest"],
                )
                for overrides, message in (
                    ({"build_id": "3" * 64}, "values"),
                    (
                        {
                            "created_at_unix_ms": now - 300_000,
                            "expires_at_unix_ms": now - 1,
                        },
                        "values",
                    ),
                    (
                        {
                            "created_at_unix_ms": now + 61_000,
                            "expires_at_unix_ms": now + 300_000,
                        },
                        "values",
                    ),
                ):
                    with self.subTest(overrides=overrides):
                        with self.assertRaisesRegex(
                            preflight.CutoverPreflightError,
                            message,
                        ):
                            preflight._validate_cutover_attestation(
                                signed(**overrides),
                                store=store,
                                now_unix_ms=now,
                            )
                with self.assertRaisesRegex(
                    preflight.CutoverPreflightError,
                    "values",
                ):
                    preflight._validate_cutover_attestation(
                        signed(expires_at_unix_ms=now + 30_000),
                        store=store,
                        now_unix_ms=now,
                        minimum_remaining_seconds=120,
                    )
                authoritative = signed(
                    governance_mode="authoritative-v6",
                    store_generation="epoch-9",
                    authority_epoch_number=9,
                    database_schema_identity="sqlite-53324442-v6",
                    runtime_state_required=True,
                    runtime_state_present=True,
                    runtime_state_canonical_sha256="4" * 64,
                    request_journal_id="journal-" + "7" * 24,
                    request_journal_schema_identity=(
                        preflight.JOURNAL_SCHEMA_IDENTITY
                    ),
                    request_journal_logical_snapshot_schema=(
                        preflight.LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                    ),
                    request_journal_logical_snapshot_sha256="5" * 64,
                    request_journal_binding_receipt_digest="6" * 64,
                )
                self.assertEqual(
                    preflight._validate_cutover_attestation(
                        authoritative,
                        store=store,
                        now_unix_ms=now,
                    ),
                    authoritative["receipt_digest"],
                )
            finally:
                store.close()

    def test_cutover_attestation_is_signed_and_atomically_published(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="synapse-cutover-attestation-publish-"
        ) as temporary:
            root = Path(temporary).resolve()
            db = root / "memory.sqlite3"
            store = DurableMemoryStore(db)
            seed = {"schema": "test-recovery-key.v1"}
            store._authenticate_receipt(seed)
            auth_key_id = str(seed["auth_key_id"])
            store.close()
            core = root / "core"
            core.mkdir(mode=0o700, exist_ok=True)
            core.chmod(0o700)
            evidence = root / "evidence.json"
            evidence.write_text(
                json.dumps({"created_at": time.time()}),
                encoding="utf-8",
            )
            evidence.chmod(0o600)
            recovery = {
                "governance_mode": "pre-governed-v5",
                "store_identity": "store-" + "a" * 24,
                "store_generation": "legacy-v5",
                "authority_epoch_number": None,
                "database_schema_identity": "sqlite-53324442-v5",
                "database_logical_snapshot_schema": (
                    preflight.LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                ),
                "database_logical_snapshot_sha256": "b" * 64,
                "capture_manifest_sha256": "c" * 64,
                "runtime_state_required": False,
                "runtime_state_present": False,
                "runtime_state_canonical_sha256": None,
                "request_journal_id": None,
                "request_journal_schema_identity": None,
                "request_journal_logical_snapshot_schema": None,
                "request_journal_logical_snapshot_sha256": None,
                "request_journal_binding_receipt_digest": None,
                "restored_target": False,
                "restored_target_binding_receipt_digest": None,
                "recovery_bundle_receipt_digest": "d" * 64,
                "recovery_restore_proof_receipt_digest": "e" * 64,
                "recovery_auth_key_id": auth_key_id,
            }
            path = core / preflight.CUTOVER_ATTESTATION_NAME
            request = preflight.CutoverAttestationRequest(
                path=path,
                build_id=installer._manifest_build_id(ROOT),
                config_fingerprint="f" * 64,
            )
            with mock.patch.object(
                preflight,
                "_git_snapshot",
                return_value=("1" * 40, ""),
            ):
                result = preflight.publish_cutover_attestation(
                    request=request,
                    root=ROOT,
                    memory_db=db,
                    evidence_manifest=evidence,
                    maximum_evidence_age_seconds=7200,
                    recovery=recovery,
                )
            self.assertTrue(result["verified"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(result["path"], str(path))
            self.assertRegex(result["receipt_digest"], r"^[0-9a-f]{64}$")
            self.assertRegex(result["artifact_sha256"], r"^[0-9a-f]{64}$")

    def test_core_startup_verifier_refuses_stale_and_v5_state_drift(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="synapse-core-startup-attestation-"
        ) as temporary:
            root = Path(temporary).resolve()
            db = root / "memory.sqlite3"
            store = DurableMemoryStore(db)
            try:
                store.upsert_entry(
                    tag="startup-attestation",
                    context_id="installer-tests",
                    source_text="Synthetic core startup attestation fixture.",
                    metadata={"fixture": True},
                    embedding_dimensions=8,
                    spike_indices=[1],
                    neuron_indices=[2],
                    registered_at=100.0,
                )
                runtime_path = root / "runtime_state.json"
                runtime_payload = {
                    "version": 2,
                    "global_enabled": True,
                    "context_overrides": {},
                    "cortex_sessions": {},
                    "runtime_state_repair": {},
                    "memory_db_path": str(db),
                    "updated_at": 100.0,
                }
                runtime_bytes = (
                    json.dumps(runtime_payload, indent=2, sort_keys=True) + "\n"
                ).encode("utf-8")
                runtime_path.write_bytes(runtime_bytes)
                runtime_path.chmod(0o600)
                daemon = CaptureInboxDaemon(root=root)
                daemon._ensure_transport_dirs(daemon.paths())
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "startup.sqlite3",
                    purpose="core-startup-test",
                    pinned=False,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])
                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "startup-restore",
                    confirm=True,
                )
            finally:
                store.close()
            original_proof_path = Path(restored["recovery_proof_path"])
            proof = json.loads(original_proof_path.read_text(encoding="utf-8"))
            git_head = "7" * 40
            candidate_config = self._core_config(root, memory_path=db)
            manifest, proof_path = self._write_cutover_evidence_pack(
                root=root,
                verified=verified,
                proof=proof,
                git_head=git_head,
                config=candidate_config,
            )
            core = root / "core"
            core.mkdir(mode=0o700, exist_ok=True)
            core.chmod(0o700)
            recovery = preflight.verify_recovery_binding(
                parsed=verified,
                receipt_path=Path(bundle["bundle_receipt_path"]),
                restore_proof=proof,
                restore_proof_path=proof_path,
                memory_db=db,
                capture_root=root,
            )
            expected_build_id = installer._manifest_build_id(ROOT)
            config_fingerprint = candidate_config.fingerprint
            attestation_path = core / preflight.CUTOVER_ATTESTATION_NAME
            with mock.patch.object(
                preflight,
                "_git_snapshot",
                return_value=(git_head, ""),
            ):
                published = preflight.publish_cutover_attestation(
                    request=preflight.CutoverAttestationRequest(
                        path=attestation_path,
                        build_id=expected_build_id,
                        config_fingerprint=config_fingerprint,
                    ),
                    root=ROOT,
                    memory_db=db,
                    evidence_manifest=manifest,
                    maximum_evidence_age_seconds=7200,
                    recovery=recovery,
                )
            evidence_sha256 = hashlib.sha256(manifest.read_bytes()).hexdigest()

            def verify_startup() -> dict:
                with mock.patch.object(
                    preflight,
                    "_git_snapshot",
                    return_value=(git_head, ""),
                ):
                    return preflight.verify_cutover_attestation_for_core(
                        root=ROOT,
                        memory_db=db,
                        capture_root=root,
                        attestation_path=attestation_path,
                        evidence_manifest=manifest,
                        expected_build_id=expected_build_id,
                        expected_config_fingerprint=config_fingerprint,
                        expected_git_head=git_head,
                        expected_evidence_manifest_sha256=evidence_sha256,
                    )

            admission = verify_startup()
            self.assertTrue(admission["verified"])
            self.assertEqual(
                admission["receipt_digest"],
                published["receipt_digest"],
            )

            expires = int(published["expires_at_unix_ms"])
            with mock.patch.object(
                preflight.time,
                "time",
                return_value=(expires + 1) / 1000.0,
            ), self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "values",
            ):
                verify_startup()

            runtime_payload["updated_at"] = 101.0
            runtime_path.write_text(
                json.dumps(runtime_payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            runtime_path.chmod(0o600)
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "runtime state",
            ):
                verify_startup()
            runtime_path.write_bytes(runtime_bytes)
            runtime_path.chmod(0o600)

            capture_drift = write_capture_drop(
                root=root,
                context_id="installer-tests",
                source_tag="startup-capture-drift",
                speaker="codex",
                text="Synthetic startup capture drift.",
                metadata={"fixture": True},
            )
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "capture",
            ):
                verify_startup()
            capture_drift.unlink()

            changed_store = DurableMemoryStore(db)
            try:
                changed_store.upsert_entry(
                    tag="startup-database-drift",
                    context_id="installer-tests",
                    source_text="Synthetic startup database drift.",
                    metadata={"fixture": True},
                    embedding_dimensions=8,
                    spike_indices=[3],
                    neuron_indices=[4],
                    registered_at=102.0,
                )
            finally:
                changed_store.close()
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "live database",
            ):
                verify_startup()

    def test_preflight_parser_does_not_reflect_secret_shaped_errors(self) -> None:
        secret = "ghp_secretparser123456789012345"
        error = io.StringIO()
        with redirect_stderr(error), self.assertRaises(SystemExit):
            preflight.build_parser().parse_args(
                ["--maximum-evidence-age-seconds", secret]
            )
        self.assertNotIn(secret, error.getvalue())

    def test_process_inventory_is_bounded_and_never_returns_commands(self) -> None:
        canary = "sk-secret-process-command-123456789"
        lines = [
            f"{1000 + index} /tmp/mcp_client_wrapper.py --token {canary}-{index}"
            for index in range(30)
        ]
        findings = preflight.collect_process_inventory(lines=lines)
        self.assertEqual(len(findings), preflight.MAX_PROCESS_FINDINGS)
        payload = json.dumps([item.to_wire() for item in findings])
        self.assertNotIn(canary, payload)
        self.assertTrue(all(set(item.to_wire()) == {"pid", "category"} for item in findings))

    def test_fake_launchctl_inventory_reports_only_exact_labels_and_pid_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-launchctl-") as temporary:
            root = Path(temporary)
            log = root / "calls.log"
            fake = root / "launchctl"
            fake.write_text(
                f"""#!{sys.executable}
import pathlib
import sys
pathlib.Path({str(log)!r}).open('a').write(' '.join(sys.argv[1:]) + '\\n')
if sys.argv[-1].endswith('.capture'):
    print('state = running')
    print('pid = 321')
    raise SystemExit(0)
if len(sys.argv) == 3 and sys.argv[2].count('/') == 1:
    print('services = {{')
    print('  321 - test.capture')
    print('}}')
    raise SystemExit(0)
raise SystemExit(3)
""",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            result = preflight.collect_launchagent_inventory(
                launchctl_bin=fake,
                labels={
                    "capture": "test.capture",
                    "dashboard": "test.dashboard",
                    "core": "test.core",
                },
            )
            self.assertEqual(result["capture"]["pid"], 321)
            self.assertTrue(result["capture"]["loaded"])
            self.assertFalse(result["dashboard"]["loaded"])
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(calls), 5)
            self.assertTrue(all(line.startswith("print gui/") for line in calls))

    def test_launchctl_inventory_fails_closed_when_domain_query_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-launchctl-error-") as temporary:
            fake = Path(temporary) / "launchctl"
            fake.write_text(f"#!{sys.executable}\nraise SystemExit(70)\n", encoding="utf-8")
            fake.chmod(0o700)
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "could not be proven",
            ):
                preflight.collect_launchagent_inventory(
                    launchctl_bin=fake,
                    labels={"core": "test.core"},
                )

    def test_process_inventory_includes_exact_authoritative_core(self) -> None:
        finding = preflight.collect_process_inventory(
            lines=["7654 /usr/bin/python3 /repo/core_service.py serve --config /private"]
        )
        self.assertEqual([item.category for item in finding], ["authoritative-core"])

    def test_authority_lock_is_required_private_and_exclusive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-lock-") as temporary:
            db = Path(temporary) / "memory.sqlite3"
            db.write_bytes(b"db")
            db.chmod(0o600)
            core = db.parent / "core"
            core.mkdir(mode=0o700)
            lock = core / "authority.lock"
            lock.write_bytes(b"")
            lock.chmod(0o600)
            with preflight.exclusive_authority_lock(db):
                with self.assertRaisesRegex(
                    preflight.CutoverPreflightError,
                    "writers are not quiescent",
                ):
                    with preflight.exclusive_authority_lock(db):
                        pass
            self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_restore_governance_rejects_legacy_v6_and_requires_v2_journal(self) -> None:
        base = {
            "schema": preflight.LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA,
            "governance_mode": "authoritative-v6",
            "store_identity": "store-" + "a" * 24,
            "store_generation": "epoch-7",
            "authority_epoch_number": 7,
        }
        with self.assertRaisesRegex(preflight.CutoverPreflightError, "legacy"):
            preflight._validate_restore_governance(base)

        governed = {
            **base,
            "schema": preflight.RECOVERY_BUNDLE_RESTORE_SCHEMA,
            "database_logical_snapshot_schema": (
                preflight.LOGICAL_SNAPSHOT_DIGEST_SCHEMA
            ),
            "database_logical_snapshot_sha256": "d" * 64,
            "capture_manifest_sha256": "e" * 64,
            "runtime_state_required": True,
            "runtime_state_present": True,
            "runtime_state_artifact_relative": "runtime_state.json",
            "runtime_state_sha256": "f" * 64,
            "runtime_state_canonical_sha256": "1" * 64,
            "source_runtime_state_sha256": "2" * 64,
            "source_runtime_state_canonical_sha256": "3" * 64,
        }
        with self.assertRaisesRegex(preflight.CutoverPreflightError, "request-journal"):
            preflight._validate_restore_governance(governed)
        governed.update(
            {
                "request_journal_sha256": "b" * 64,
                "request_journal_binding_receipt_digest": "c" * 64,
                "source_request_journal_binding_receipt_digest": "4" * 64,
                "request_journal_id": "journal-" + "6" * 24,
                "request_journal_schema_identity": (
                    preflight.JOURNAL_SCHEMA_IDENTITY
                ),
                "request_journal_logical_snapshot_schema": (
                    preflight.LOGICAL_SNAPSHOT_DIGEST_SCHEMA
                ),
                "request_journal_logical_snapshot_sha256": "5" * 64,
                "request_journal_artifact_relative": "core/requests.sqlite3",
                "request_journal_binding_receipt_relative": (
                    "core/requests.sqlite3.binding.receipt.json"
                ),
                "request_journal_binding_verified": True,
            }
        )
        self.assertEqual(
            preflight._validate_restore_governance(governed),
            "authoritative-v6",
        )

    def test_v5_database_inspection_is_read_only_and_v6_without_marker_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-db-") as temporary:
            db = Path(temporary) / "memory.sqlite3"
            with closing(sqlite3.connect(db)) as connection:
                connection.execute(
                    "CREATE TABLE store_metadata "
                    "(key TEXT PRIMARY KEY, value_json TEXT)"
                )
                connection.execute("PRAGMA user_version = 5")
            db.chmod(0o600)
            before = {path.name for path in db.parent.iterdir()}
            result = preflight.inspect_database_contract(db)
            after = {path.name for path in db.parent.iterdir()}
            self.assertEqual(result["user_version"], 5)
            self.assertFalse(result["authority_marker"])
            self.assertEqual(before, after)
            with closing(sqlite3.connect(db)) as connection:
                connection.execute("PRAGMA user_version = 6")
            with self.assertRaisesRegex(preflight.CutoverPreflightError, "lacks"):
                preflight.inspect_database_contract(db)

    def test_nonempty_wal_is_a_quiescence_blocker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-wal-") as temporary:
            db = Path(temporary) / "memory.sqlite3"
            with closing(sqlite3.connect(db)) as connection:
                connection.execute(
                    "CREATE TABLE store_metadata "
                    "(key TEXT PRIMARY KEY, value_json TEXT)"
                )
                connection.execute("PRAGMA user_version = 5")
            db.chmod(0o600)
            wal = db.with_name(db.name + "-wal")
            wal.write_bytes(b"not-quiescent")
            wal.chmod(0o600)
            with self.assertRaisesRegex(preflight.CutoverPreflightError, "WAL"):
                preflight.inspect_database_contract(db)

    def test_evidence_contract_requires_all_three_verified_recovery_gates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-evidence-") as temporary:
            evidence_root = Path(temporary).resolve()
            pack = evidence_root / "pack"
            artifacts = pack / "artifacts"
            artifacts.mkdir(parents=True)
            receipt = Path(temporary) / "verified.bundle.receipt.json"
            receipt.write_text("{}", encoding="utf-8")
            receipt.chmod(0o600)
            parsed = artifacts / "recovery_verify.parsed.json"
            parsed.write_text(
                json.dumps(
                    {
                        "verified": True,
                        "verified_at": time.time(),
                        "cutover_ready": True,
                        "receipt_identity_trusted": True,
                        "bundle_receipt_path": str(receipt),
                        "governance_mode": "pre-governed-v5",
                        "store_identity": "store-" + "a" * 24,
                        "store_generation": "legacy-v5",
                        "capture_ledger_binding": {"verified": True},
                        "reconciliation": {
                            "missing_authoritative_ledger_count": 0,
                            "replay_required_capture_count": 0,
                            "replay_required_file_count": 0,
                            "unclassified_file_count": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            parsed.chmod(0o600)
            restore_proof = artifacts / "recovery_restore_proof.receipt.json"
            restore_proof.write_text(
                json.dumps(
                    {
                        "schema": preflight.LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA,
                        "mode": "isolated-recovery-proof",
                        "governance_mode": "pre-governed-v5",
                        "store_identity": "store-" + "a" * 24,
                        "store_generation": "legacy-v5",
                        "authority_epoch_number": None,
                        "verified": True,
                        "cutover_ready": True,
                        "missing_transport_ledger_count": 0,
                        "capture_ledger_binding": {"verified": True},
                        "reconciliation": {
                            "missing_authoritative_ledger_count": 0,
                            "replay_required_capture_count": 0,
                            "replay_required_file_count": 0,
                            "unclassified_file_count": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            restore_proof.chmod(0o600)
            metrics = {
                "verified": True,
                "cutover_ready": True,
                "capture_ledger_binding": {"verified": True},
                "reconciliation": {
                    "missing_authoritative_ledger_count": 0,
                    "replay_required_capture_count": 0,
                    "replay_required_file_count": 0,
                    "unclassified_file_count": 0,
                },
            }
            checks = []
            for check_id in ("recovery_backup", "recovery_verify", "recovery_restore"):
                check = {
                    "check_id": check_id,
                    "required": True,
                    "status": "ready",
                    "metrics": dict(metrics),
                    "artifact_paths": {},
                }
                if check_id == "recovery_verify":
                    check["artifact_paths"] = {"parsed": str(parsed)}
                elif check_id == "recovery_restore":
                    check["artifact_paths"] = {
                        "recovery_proof": str(restore_proof)
                    }
                checks.append(check)
            candidate_config = self._core_config(evidence_root)
            manifest = pack / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "overall_status": "ready",
                        "operator_trustworthy": True,
                        "created_at": time.time(),
                        "git": {"head": "0" * 40, "status_short": ""},
                        "core_config_contract": (
                            preflight.core_config_evidence_contract(candidate_config)
                        ),
                        "checks": checks,
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            (
                parsed_value,
                receipt_value,
                restore_value,
                restore_path,
            ) = preflight.validate_evidence_contract(
                manifest,
                root=ROOT,
                maximum_age_seconds=7200,
                require_git_binding=False,
            )
            self.assertTrue(parsed_value["verified"])
            self.assertEqual(receipt_value, receipt)
            self.assertTrue(restore_value["verified"])
            self.assertEqual(restore_path, restore_proof)
            checks[-1]["metrics"]["reconciliation"]["unclassified_file_count"] = 1
            manifest.write_text(
                json.dumps(
                    {
                        "overall_status": "ready",
                        "operator_trustworthy": True,
                        "created_at": time.time(),
                        "git": {"head": "0" * 40, "status_short": ""},
                        "core_config_contract": (
                            preflight.core_config_evidence_contract(candidate_config)
                        ),
                        "checks": checks,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(preflight.CutoverPreflightError, "unresolved"):
                preflight.validate_evidence_contract(
                    manifest,
                    root=ROOT,
                    maximum_age_seconds=7200,
                    require_git_binding=False,
                )

    def test_recovery_binding_reverifies_real_signed_temp_bundle_and_restore(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-recovery-") as temporary:
            root = Path(temporary)
            db = root / "memory.sqlite3"
            store = DurableMemoryStore(db)
            try:
                store.upsert_entry(
                    tag="core-cutover-proof",
                    context_id="installer-tests",
                    source_text="Synthetic non-secret cutover recovery proof.",
                    metadata={"fixture": True},
                    embedding_dimensions=8,
                    spike_indices=[1, 3],
                    neuron_indices=[2, 4],
                    registered_at=100.0,
                )
                daemon = CaptureInboxDaemon(root=root)
                daemon._ensure_transport_dirs(daemon.paths())
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "cutover.sqlite3",
                    purpose="core-installer-test",
                    pinned=False,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])
                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "isolated-restore",
                    confirm=True,
                )
            finally:
                store.close()
            proof_path = Path(restored["recovery_proof_path"])
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            git_head = "9" * 40
            candidate_config = self._core_config(root, memory_path=db)
            manifest, evidence_proof_path = self._write_cutover_evidence_pack(
                root=root,
                verified=verified,
                proof=proof,
                git_head=git_head,
                config=candidate_config,
            )
            result = preflight.verify_recovery_binding(
                parsed=verified,
                receipt_path=Path(bundle["bundle_receipt_path"]),
                restore_proof=proof,
                restore_proof_path=evidence_proof_path,
                memory_db=db,
                capture_root=root,
            )
            self.assertTrue(result["restore_eligible"])
            self.assertTrue(result["isolated_restore_verified"])
            self.assertEqual(
                result["database_logical_snapshot_schema"],
                preflight.LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
            )
            self.assertRegex(
                result["database_logical_snapshot_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertRegex(
                result["capture_manifest_sha256"],
                r"^[0-9a-f]{64}$",
            )

            capture_drift = write_capture_drop(
                root=root,
                context_id="installer-tests",
                source_tag="post-proof-drift",
                speaker="codex",
                text="Synthetic post-proof capture drift.",
                metadata={"fixture": True},
            )
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "capture",
            ):
                preflight.verify_recovery_binding(
                    parsed=verified,
                    receipt_path=Path(bundle["bundle_receipt_path"]),
                    restore_proof=proof,
                    restore_proof_path=proof_path,
                    memory_db=db,
                    capture_root=root,
                )
            capture_drift.unlink()

            changed_store = DurableMemoryStore(db)
            try:
                changed_store.upsert_entry(
                    tag="post-proof-drift",
                    context_id="installer-tests",
                    source_text="Synthetic post-proof database drift.",
                    metadata={"fixture": True},
                    embedding_dimensions=8,
                    spike_indices=[2],
                    neuron_indices=[3],
                    registered_at=101.0,
                )
            finally:
                changed_store.close()
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "live database",
            ):
                preflight.verify_recovery_binding(
                    parsed=verified,
                    receipt_path=Path(bundle["bundle_receipt_path"]),
                    restore_proof=proof,
                    restore_proof_path=evidence_proof_path,
                    memory_db=db,
                    capture_root=root,
                )
            self.assertTrue(result["database_digest_verified"])
            self.assertTrue(result["capture_digest_verified"])
            self.assertTrue(result["live_snapshot_matches"])

    def test_v6_recovery_binding_attests_runtime_and_request_journal_exactly(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="synapse-preflight-v6-recovery-"
        ) as temporary:
            root = Path(temporary).resolve()
            db = root / "memory.sqlite3"
            bootstrap = DurableMemoryStore(db)
            bootstrap.close()
            authority = CoreAuthorityLease.acquire_core(
                db,
                timeout_seconds=0.0,
                instance_id="core-cutover-v6-test",
            )
            journal: CoreRequestJournal | None = None
            store: DurableMemoryStore | None = None
            try:
                store = DurableMemoryStore(db, authority_lease=authority)
                inspection = store.inspect_core_authority_preclaim()
                preclaim = inspection["logical_snapshot"]
                journal = CoreRequestJournal(
                    root / "core" / "requests.sqlite3",
                    authority_epoch="epoch-1",
                    store_identity=str(inspection["store_identity"]),
                )
                journal_binding = journal.binding()
                claim = store.claim_core_authority(
                    instance_id=authority.instance_id,
                    config_fingerprint=hashlib.sha256(b"cutover-v6").hexdigest(),
                    build_id="cutover-v6-test",
                    protocol_version="synapse-core.v1",
                    expected_store_identity=str(inspection["store_identity"]),
                    request_journal_id=str(journal_binding["journal_id"]),
                    request_journal_binding_schema=str(journal_binding["schema"]),
                    request_journal_schema_version=int(
                        journal_binding["journal_schema_version"]
                    ),
                    expected_preclaim_logical_snapshot_sha256=str(
                        preclaim["sha256"]
                    ),
                    expected_previous_epoch=0,
                    expected_next_epoch=1,
                    root_generation_id="generation-" + ("d" * 24),
                    embedding_space_identity="d" * 64,
                    attestation_receipt_digest="d" * 64,
                    attestation_expires_at_unix_ms=int(time.time() * 1000) + 60_000,
                )
                journal.accept(
                    caller="cutover-test",
                    request_id="request-before-bundle",
                    operation="capture",
                    request_fingerprint=hashlib.sha256(b"before").hexdigest(),
                )
                runtime_state = root / "runtime_state.json"
                runtime_state.write_text(
                    json.dumps(
                        {
                            "version": 2,
                            "global_enabled": True,
                            "context_overrides": {},
                            "cortex_sessions": {},
                            "runtime_state_repair": {},
                            "memory_db_path": str(db),
                            "updated_at": 100.0,
                        },
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                runtime_state.chmod(0o600)
                daemon = CaptureInboxDaemon(root=root)
                daemon._ensure_transport_dirs(daemon.paths())
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "cutover-v6.sqlite3",
                    purpose="core-installer-v6-test",
                    pinned=False,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])
                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "isolated-v6-restore",
                    confirm=True,
                )
            finally:
                if journal is not None:
                    journal.close()
                if store is not None:
                    store.close()
                authority.close()
            proof_path = Path(restored["recovery_proof_path"])
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            git_head = "9" * 40
            candidate_config = self._core_config(root, memory_path=db)
            manifest, evidence_proof_path = self._write_cutover_evidence_pack(
                root=root,
                verified=verified,
                proof=proof,
                git_head=git_head,
                config=candidate_config,
            )
            verify_arguments = {
                "parsed": verified,
                "receipt_path": Path(bundle["bundle_receipt_path"]),
                "restore_proof": proof,
                "restore_proof_path": evidence_proof_path,
                "memory_db": db,
                "capture_root": root,
                "restored_target": True,
            }
            live_binding_path = (
                root / "core" / "requests.sqlite3.binding.receipt.json"
            )
            self.assertFalse(live_binding_path.exists())
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "binding",
            ):
                preflight.verify_recovery_binding(**verify_arguments)
            live_binding_path.write_text("{}\n", encoding="utf-8")
            live_binding_path.chmod(0o600)
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "binding",
            ):
                preflight.verify_recovery_binding(**verify_arguments)
            live_binding_path.unlink()
            restored_binding_digest = "b" * 64
            restored_binding_result = {
                "memory_logical_snapshot_sha256": verified["database"][
                    "logical_snapshot_sha256"
                ],
                "request_journal_logical_snapshot_sha256": verified[
                    "request_journal"
                ]["logical_snapshot_sha256"],
                "request_journal_id": verified["request_journal"]["journal_id"],
                "request_journal_schema_identity": verified[
                    "request_journal"
                ]["schema_identity"],
                "runtime_state_canonical_sha256": verified["runtime_state"][
                    "canonical_sha256"
                ],
                "receipt_digest": restored_binding_digest,
                "verified": True,
            }
            with mock.patch.object(
                VerifiedRecoveryManager,
                "verify_restored_request_journal_binding",
                return_value=restored_binding_result,
            ):
                result = preflight.verify_recovery_binding(**verify_arguments)
            self.assertEqual(result["governance_mode"], "authoritative-v6")
            self.assertTrue(result["runtime_state_present"])
            self.assertRegex(
                result["runtime_state_canonical_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                result["request_journal_logical_snapshot_schema"],
                preflight.LOGICAL_SNAPSHOT_DIGEST_SCHEMA,
            )
            self.assertRegex(
                result["request_journal_logical_snapshot_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                result["request_journal_id"],
                verified["request_journal"]["journal_id"],
            )
            self.assertEqual(
                result["request_journal_schema_identity"],
                preflight.JOURNAL_SCHEMA_IDENTITY,
            )
            expected_build_id = installer._manifest_build_id(ROOT)
            config_fingerprint = candidate_config.fingerprint
            attestation_path = root / "core" / preflight.CUTOVER_ATTESTATION_NAME
            with mock.patch.object(
                preflight,
                "_git_snapshot",
                return_value=(git_head, ""),
            ):
                preflight.publish_cutover_attestation(
                    request=preflight.CutoverAttestationRequest(
                        path=attestation_path,
                        build_id=expected_build_id,
                        config_fingerprint=config_fingerprint,
                        restored_target=True,
                    ),
                    root=ROOT,
                    memory_db=db,
                    evidence_manifest=manifest,
                    maximum_evidence_age_seconds=7200,
                    recovery=result,
                )
            evidence_sha256 = hashlib.sha256(manifest.read_bytes()).hexdigest()

            def verify_core() -> dict:
                with mock.patch.object(
                    preflight,
                    "_git_snapshot",
                    return_value=(git_head, ""),
                ), mock.patch.object(
                    VerifiedRecoveryManager,
                    "verify_restored_request_journal_binding",
                    return_value=restored_binding_result,
                ):
                    return preflight.verify_cutover_attestation_for_core(
                        root=ROOT,
                        memory_db=db,
                        capture_root=root,
                        attestation_path=attestation_path,
                        evidence_manifest=manifest,
                        expected_build_id=expected_build_id,
                        expected_config_fingerprint=config_fingerprint,
                        expected_git_head=git_head,
                        expected_evidence_manifest_sha256=evidence_sha256,
                    )

            admission = verify_core()
            self.assertEqual(
                admission["request_journal_binding_receipt_digest"],
                result["request_journal_binding_receipt_digest"],
            )
            self.assertEqual(
                admission["request_journal_id"], result["request_journal_id"]
            )
            self.assertEqual(
                admission["request_journal_schema_identity"],
                preflight.JOURNAL_SCHEMA_IDENTITY,
            )
            self.assertEqual(
                admission["recovery_restore_proof_receipt_digest"],
                proof["receipt_digest"],
            )
            self.assertTrue(admission["restored_target"])
            self.assertEqual(
                admission["restored_target_binding_receipt_digest"],
                restored_binding_digest,
            )

            changed_journal = CoreRequestJournal(
                root / "core" / "requests.sqlite3",
                authority_epoch=str(claim["authority_epoch"]),
            )
            try:
                changed_journal.accept(
                    caller="cutover-test",
                    request_id="request-after-bundle",
                    operation="capture",
                    request_fingerprint=hashlib.sha256(b"after").hexdigest(),
                )
            finally:
                changed_journal.close()
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "request journal",
            ):
                verify_core()


if __name__ == "__main__":
    unittest.main()

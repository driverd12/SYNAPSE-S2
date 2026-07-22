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
from dataclasses import replace
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
from core_authority import CoreAuthorityError, CoreAuthorityLease
from core_protocol import canonical_json_bytes
from core_request_journal import CoreRequestJournal
from core_service import AuthoritativeCoreService
from operator_readiness_contract import (
    OPERATOR_READINESS_REQUIRED_PROOF_IDS,
    quiescence_policy_contract,
    quiescence_policy_digest,
    ready_operator_proof_contract,
)


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
            log=self.home / "Library" / "Logs" / "SYNAPSE-S2" / "core-service.log",
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
elif command == 'print-disabled':
    value = 'disabled' if disabled.exists() else 'enabled'
    print('{{')
    print('  "aero.boom.synapse-s2.core.test" => ' + value)
    print('  "aero.boom.synapse-s2.capture-daemon" => disabled')
    print('  "aero.boom.synapse-s2.dashboard" => disabled')
    print('  "com.master-mold.imprint.inboxworker" => disabled')
    print('}}')
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
    def _seal_sqlite_fixture(path: Path) -> None:
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            checkpoint = connection.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)"
            ).fetchone()
            if checkpoint is None or int(checkpoint[0]) != 0:
                raise AssertionError("fixture SQLite WAL could not be checkpointed")
        for suffix in ("-journal", "-wal", "-shm"):
            Path(f"{path}{suffix}").unlink(missing_ok=True)

    def _filesystem_snapshot(
        self,
        *extra_roots: Path,
    ) -> dict[str, tuple[object, ...]]:
        snapshot: dict[str, tuple[object, ...]] = {}
        for root in (self.base, *extra_roots):
            paths = [root, *sorted(root.rglob("*"))]
            for path in paths:
                observed = path.lstat()
                key = str(path)
                digest: str | None = None
                link_target: str | None = None
                if stat.S_ISREG(observed.st_mode):
                    digest = hashlib.sha256(path.read_bytes()).hexdigest()
                elif stat.S_ISLNK(observed.st_mode):
                    link_target = os.readlink(path)
                snapshot[key] = (
                    int(observed.st_dev),
                    int(observed.st_ino),
                    int(observed.st_mode),
                    int(observed.st_uid),
                    int(observed.st_gid),
                    int(observed.st_nlink),
                    int(observed.st_size),
                    int(observed.st_mtime_ns),
                    int(observed.st_ctime_ns),
                    digest,
                    link_target,
                )
        return snapshot

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

    def _prepare_recoverable_v6(self) -> object:
        self.memory_db.unlink()
        bootstrap = DurableMemoryStore(self.memory_db)
        bootstrap.close()
        self.core.mkdir(mode=0o700, exist_ok=True)
        environment = {
            "SYNAPSE_S2_DIMENSION": "8",
            "SYNAPSE_S2_NEURONS": "16",
            "SYNAPSE_S2_TOP_K": "4",
            "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "false",
            "SYNAPSE_S2_TRANSCRIPT_POLL": "false",
            "SYNAPSE_S2_EMBEDDING_PROVIDER": "semantic-hash",
            "MLX_DEVICE": "cpu",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            config = installer.build_config(self.paths)
        installer.write_core_config(self.paths.config, config)
        token_path = self.paths.socket.with_name(self.paths.socket.name + ".token")
        token_path.write_bytes(b"a" * 64)
        token_path.chmod(0o600)
        root_generation_id = "generation-" + ("d" * 24)
        root_generation_path = self.core / "store-generation.json"
        root_generation_path.write_bytes(
            canonical_json_bytes(
                {
                    "schema": installer.STORE_GENERATION_SCHEMA,
                    "root_generation_id": root_generation_id,
                    "store_identity": installer._store_identity(self.memory_db),
                }
            )
        )
        root_generation_path.chmod(0o600)
        installer._atomic_private_bytes(
            self.paths.plist,
            installer.plist_payload(
                label="aero.boom.synapse-s2.core.test",
                paths=self.paths,
                config=config,
            ),
        )
        installer.publish_client_binding(
            paths=self.paths,
            label="aero.boom.synapse-s2.core.test",
            config=config,
            authority_mode="candidate-local-v5",
        )

        authority = CoreAuthorityLease.acquire_core(
            self.memory_db,
            timeout_seconds=0.0,
            instance_id="core-recover-existing-fixture",
        )
        store: DurableMemoryStore | None = None
        journal: CoreRequestJournal | None = None
        try:
            store = DurableMemoryStore(self.memory_db, authority_lease=authority)
            inspection = store.inspect_core_authority_preclaim()
            journal = CoreRequestJournal(
                self.core / "requests.sqlite3",
                authority_epoch="epoch-1",
                store_identity=str(inspection["store_identity"]),
            )
            journal_binding = journal.binding()
            store.claim_core_authority(
                instance_id=authority.instance_id,
                config_fingerprint=config.fingerprint,
                build_id=installer._manifest_build_id(ROOT),
                protocol_version=installer.PROTOCOL_VERSION,
                expected_store_identity=str(inspection["store_identity"]),
                request_journal_id=str(journal_binding["journal_id"]),
                request_journal_binding_schema=str(journal_binding["schema"]),
                request_journal_schema_version=int(
                    journal_binding["journal_schema_version"]
                ),
                expected_preclaim_logical_snapshot_sha256=str(
                    inspection["logical_snapshot"]["sha256"]
                ),
                expected_previous_epoch=0,
                expected_next_epoch=1,
                root_generation_id=root_generation_id,
                embedding_space_identity=config.embedding_space_identity,
                attestation_receipt_digest="a" * 64,
                attestation_expires_at_unix_ms=int(time.time() * 1000) + 60_000,
            )
            runtime_payload = {
                "version": 3,
                "global_enabled": True,
                "context_overrides": {},
                "cortex_sessions": {},
                "runtime_state_repair": {},
                "memory_db_path": str(self.memory_db),
                "updated_at": time.time(),
                "authority_binding": store.runtime_state_authority_binding(),
            }
            self.paths.state.write_text(
                json.dumps(
                    runtime_payload,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n",
                encoding="utf-8",
            )
            self.paths.state.chmod(0o600)
            store.complete_runtime_state_authority_publication(
                runtime_state_path=self.paths.state,
            )
        finally:
            if journal is not None:
                journal.close()
            if store is not None:
                store.close()
            authority.close()
        self._seal_sqlite_fixture(self.memory_db)
        self._seal_sqlite_fixture(self.core / "requests.sqlite3")
        return config

    def _advance_recoverable_v6_epoch_pending(self, config: object) -> None:
        authority = CoreAuthorityLease.acquire_core(
            self.memory_db,
            timeout_seconds=0.0,
            instance_id="core-recover-existing-successor-fixture",
        )
        store: DurableMemoryStore | None = None
        journal: CoreRequestJournal | None = None
        try:
            store = DurableMemoryStore(self.memory_db, authority_lease=authority)
            inspection = store.inspect_core_authority_preclaim()
            marker = inspection["marker"]
            journal = CoreRequestJournal(
                self.core / "requests.sqlite3",
                authority_epoch=f"epoch-{int(inspection['next_epoch'])}",
                require_existing=True,
                prune_on_open=False,
                allow_migration=False,
                store_identity=str(inspection["store_identity"]),
                expected_journal_id=str(marker["request_journal_id"]),
            )
            journal_binding = journal.binding()
            store.claim_core_authority(
                instance_id=authority.instance_id,
                config_fingerprint=config.fingerprint,
                build_id=installer._manifest_build_id(ROOT),
                protocol_version=installer.PROTOCOL_VERSION,
                expected_store_identity=str(inspection["store_identity"]),
                request_journal_id=str(journal_binding["journal_id"]),
                request_journal_binding_schema=str(journal_binding["schema"]),
                request_journal_schema_version=int(
                    journal_binding["journal_schema_version"]
                ),
                expected_preclaim_logical_snapshot_sha256=str(
                    inspection["logical_snapshot"]["sha256"]
                ),
                expected_previous_epoch=int(inspection["previous_epoch"]),
                expected_next_epoch=int(inspection["next_epoch"]),
                root_generation_id=str(marker["root_generation_id"]),
                embedding_space_identity=config.embedding_space_identity,
            )
        finally:
            if journal is not None:
                journal.close()
            if store is not None:
                store.close()
            authority.close()
        self._seal_sqlite_fixture(self.memory_db)
        self._seal_sqlite_fixture(self.core / "requests.sqlite3")

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
                "MLX_DEVICE": "gpu",
            },
        )
        self.assertEqual(plist["StandardOutPath"], str(self.paths.log))
        self.assertEqual(plist["StandardErrorPath"], str(self.paths.log))
        self.assertEqual(
            self.paths.log,
            self.home / "Library" / "Logs" / "SYNAPSE-S2" / "core-service.log",
        )
        self.assertNotIn(canary, self.paths.plist.read_text(encoding="utf-8"))
        self.assertNotIn(canary, self.paths.config.read_text(encoding="utf-8"))
        log = (self.base / "launchctl.log").read_text(encoding="utf-8")
        self.assertIn("bootstrap", log)
        self.assertIn("kickstart", log)
        self.assertNotIn(canary, log)

    def test_stage_replacement_is_signed_temporary_and_nonpersistent(self) -> None:
        environment = {
            "SYNAPSE_S2_DIMENSION": "8",
            "SYNAPSE_S2_NEURONS": "16",
            "SYNAPSE_S2_TOP_K": "4",
            "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "false",
            "SYNAPSE_S2_EMBEDDING_PROVIDER": "semantic-hash",
            "SYNAPSE_S2_TRANSCRIPT_POLL": "false",
            "MLX_DEVICE": "cpu",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            config = installer.build_config(self.paths)
        revision = "a" * 64
        marker = {
            "service_required": True,
            "lock_generation_id": "lockfs-v1-1-2",
            "config_fingerprint": config.fingerprint,
            "build_id": "source-" + ("b" * 24),
            "root_generation_id": "generation-" + ("c" * 24),
        }
        inspection = {
            "governance_mode": "authoritative-v6",
            "schema_identity": installer.EXPECTED_SCHEMA_IDENTITY,
            "marker": marker,
            "store_identity": "store-" + ("d" * 24),
        }
        audit = {
            "status": "ready",
            "repair_required": False,
            "audit_revision": revision,
        }
        capture = {
            "transport_ready": True,
            "missing_transport_directories": [],
            "unsafe_transport_directories": [],
            "pending_file_count": 2,
            "inbox_temp_file_count": 0,
            "processing_file_count": 1,
            "processing_empty_claim_count": 0,
            "processing_malformed_claim_count": 0,
            "error_file_count": 0,
            "unresolved_error_count": 0,
            "terminal_error_evidence_count": 0,
            "historical_error_evidence_count": 0,
            "unsafe_error_artifact_count": 0,
            "error_resolution_pending_count": 0,
            "error_resolution_failed_count": 0,
            "processed_file_count": 17,
            "receipt_count": 17,
        }
        post_capture_status = {
            **capture,
            "pending_file_count": 0,
            "processing_file_count": 0,
            "processed_file_count": 20,
            "receipt_count": 20,
        }
        guarded = {
            "verified": True,
            "cutover_ready": False,
            "replacement_stage_ready": True,
            "pending_file_count": 3,
            "replay_required_file_count": 2,
            "replay_required_capture_count": 2,
            "receipt_backed_file_count": 0,
            "bundle": {"bundle_receipt_path": str(self.base / "bundle.json")},
            "restore": {"recovery_proof_path": str(self.base / "proof.json")},
        }

        class FakeLease:
            lock_generation_id = marker["lock_generation_id"]

            def assert_core_for(self, path: Path) -> None:
                self.asserted_path = path

            def close(self) -> None:
                self.closed = True

        class FakeStore:
            def inspect_core_authority_preclaim(self) -> dict[str, object]:
                return dict(inspection)

            def audit_context_delivery_publication_repair(self) -> dict[str, object]:
                return dict(audit)

            def close(self) -> None:
                self.closed = True

        class FakePublication:
            evidence = guarded

            def publish(self, callback: object) -> dict[str, object]:
                return callback(self.evidence)

        class FakeGuard:
            def __enter__(self) -> FakePublication:
                return FakePublication()

            def __exit__(self, *args: object) -> None:
                return None

        manager = mock.Mock()
        manager.daemon.status.return_value = capture
        manager.guarded_recovery_transaction.return_value = FakeGuard()
        admission = {
            "receipt_digest": "e" * 64,
            "expires_at_unix_ms": int(time.time() * 1000) + 600_000,
            "candidate_build_id": installer._manifest_build_id(ROOT),
            "candidate_config_fingerprint": config.fingerprint,
            "delivery_audit_revision": revision,
        }
        (self.base / "launchctl-disabled").write_text("disabled", encoding="utf-8")
        lease = FakeLease()
        store = FakeStore()
        with mock.patch.object(
            installer,
            "_validate_install_sources",
        ), mock.patch.object(
            installer,
            "build_config",
            return_value=config,
        ), mock.patch.object(
            installer,
            "_load_recovery_root_generation",
            return_value=marker["root_generation_id"],
        ), mock.patch.object(
            CoreAuthorityLease,
            "acquire_core",
            return_value=lease,
        ), mock.patch.object(
            DurableMemoryStore,
            "open_existing_for_core_maintenance",
            return_value=store,
        ), mock.patch(
            "recovery_manager.VerifiedRecoveryManager",
            return_value=manager,
        ), mock.patch.object(
            installer,
            "publish_replacement_admission",
            return_value=admission,
        ) as publisher, mock.patch.object(
            installer,
            "wait_for_health",
            return_value={
                **self._health(),
                "pid": 4242,
                "deployment_mode": "replacement-certification",
            },
        ) as health, mock.patch.object(
            installer,
            "capture_transport_status",
            return_value=post_capture_status,
        ) as post_capture:
            result = installer.stage_replacement(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
                maximum_evidence_age_seconds=7200,
                confirm=True,
                expected_revision=revision,
            )

        self.assertEqual(result["status"], "staged-healthy")
        self.assertTrue(result["provisional"])
        self.assertFalse(result["persistent"])
        self.assertEqual(result["drained_pending_file_count"], 3)
        self.assertFalse(self.paths.plist.exists())
        staged_plist = Path(result["staged_plist"])
        payload = plistlib.loads(staged_plist.read_bytes())
        self.assertFalse(payload["KeepAlive"])
        self.assertEqual(
            payload["EnvironmentVariables"][
                "SYNAPSE_S2_REPLACEMENT_ADMISSION"
            ],
            "1",
        )
        self.assertFalse(
            installer.default_binding_path(self.home).exists()
        )
        publisher.assert_called_once()
        self.assertEqual(
            publisher.call_args.kwargs[
                "request"
            ].expected_pending_file_count,
            3,
        )
        self.assertEqual(
            publisher.call_args.kwargs[
                "request"
            ].expected_replay_required_file_count,
            2,
        )
        self.assertEqual(
            publisher.call_args.kwargs["request"].ttl_seconds,
            installer.replacement_admission_ttl_seconds(2),
        )
        manager.guarded_recovery_transaction.assert_called_once_with(
            mock.ANY,
            purpose="replacement-admission",
            pinned=True,
            replacement_pending_limit=3,
        )
        post_capture.assert_called_once_with(self.paths.capture_root)
        health.assert_called_once_with(
            launchctl=mock.ANY,
            config=config,
            prior_pid=None,
            wait_seconds=2,
            expected_deployment_mode="replacement-certification",
        )
        launch_log = (self.base / "launchctl.log").read_text(encoding="utf-8")
        self.assertIn(str(staged_plist), launch_log)

    def test_stage_replacement_refuses_unreviewed_or_enabled_service(self) -> None:
        with self.assertRaisesRegex(installer.CoreInstallerError, "--confirm"):
            installer.stage_replacement(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
                maximum_evidence_age_seconds=7200,
                confirm=False,
                expected_revision="a" * 64,
            )
        with self.assertRaisesRegex(installer.CoreInstallerError, "disabled"):
            installer.stage_replacement(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
                maximum_evidence_age_seconds=7200,
                confirm=True,
                expected_revision="a" * 64,
            )

    def test_replacement_certification_requires_post_health_time_budget(self) -> None:
        now = 1_000_000.0
        with mock.patch.object(installer.time, "time", return_value=now):
            self.assertEqual(
                installer.replacement_certification_seconds_remaining(
                    {
                        "expires_at_unix_ms": int(now * 1000)
                        + int(
                            (
                                installer.REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS
                                + 17
                            )
                            * 1000
                        )
                    }
                ),
                int(installer.REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS)
                + 17,
            )
            with self.assertRaisesRegex(
                installer.CoreInstallerError,
                "too little signed time",
            ):
                installer.replacement_certification_seconds_remaining(
                    {
                        "expires_at_unix_ms": int(now * 1000)
                        + int(
                            (
                                installer.REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS
                                - 1
                            )
                            * 1000
                        )
                    }
                )
            with self.assertRaisesRegex(
                installer.CoreInstallerError,
                "expiry is invalid",
            ):
                installer.replacement_certification_seconds_remaining(None)

    def test_replacement_activation_uses_bounded_dynamic_ticket_budget(self) -> None:
        self.assertEqual(
            installer.replacement_admission_ttl_seconds(150),
            900.0,
        )
        self.assertEqual(
            installer.replacement_admission_ttl_seconds(600),
            installer.REPLACEMENT_ADMISSION_MAX_TTL_SECONDS,
        )
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "signed admission bound",
        ):
            installer.replacement_admission_ttl_seconds(601)

        now = 1_000_000.0
        required = (
            (2 * 600)
            + installer.REPLACEMENT_CERTIFICATION_MIN_REMAINING_SECONDS
        )
        with mock.patch.object(installer.time, "time", return_value=now):
            self.assertEqual(
                installer.replacement_activation_seconds_remaining(
                    {
                        "expires_at_unix_ms": int(
                            (now + required + 7) * 1000
                        )
                    },
                    wait_seconds=600,
                ),
                int(required + 7),
            )
            with self.assertRaisesRegex(
                installer.CoreInstallerError,
                "too little signed time remaining for activation",
            ):
                installer.replacement_activation_seconds_remaining(
                    {
                        "expires_at_unix_ms": int(
                            (now + required - 1) * 1000
                        )
                    },
                    wait_seconds=600,
                )

    def test_replacement_capture_transport_admits_only_one_clean_pending_batch(
        self,
    ) -> None:
        clean = {
            "transport_ready": True,
            "pending_file_count": 23,
            "processing_file_count": 0,
            **{
                field: 0
                for field in installer.CAPTURE_TRANSPORT_ZERO_DEBT_FIELDS
            },
        }
        self.assertEqual(
            installer.validate_replacement_capture_transport(
                clean,
                maximum_pending_files=50,
            ),
            23,
        )
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "bounded, unambiguous",
        ):
            installer.validate_replacement_capture_transport(
                clean,
                maximum_pending_files=0,
            )
        claimed = dict(clean)
        claimed["pending_file_count"] = 0
        claimed["processing_file_count"] = 1
        self.assertEqual(
            installer.validate_replacement_capture_transport(
                claimed,
                maximum_pending_files=50,
            ),
            1,
        )
        malformed = dict(claimed)
        malformed["processing_malformed_claim_count"] = 1
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "bounded, unambiguous",
        ):
            installer.validate_replacement_capture_transport(
                malformed,
                maximum_pending_files=50,
            )

        admitted = {
            **clean,
            "processed_file_count": 10,
            "receipt_count": 10,
        }
        in_flight = {
            **admitted,
            "pending_file_count": 2,
            "processing_file_count": 1,
        }
        drained = {
            **admitted,
            "pending_file_count": 0,
            "processed_file_count": 13,
            "receipt_count": 13,
        }
        with mock.patch.object(
            installer,
            "capture_transport_status",
            side_effect=(in_flight, drained),
        ), mock.patch.object(installer.time, "sleep"):
            self.assertEqual(
                installer.wait_for_replacement_capture_drain(
                    capture_root=self.paths.capture_root,
                    admitted_status=admitted,
                    admitted_pending_file_count=3,
                    wait_seconds=2,
                ),
                drained,
            )

    def test_capture_transport_status_holds_global_gate_while_scanning(self) -> None:
        daemon = mock.Mock()
        daemon.paths.return_value = {"lock_dir": self.data / "capture_locks"}

        class Gate:
            held = False

            def __enter__(self):
                self.held = True
                return True

            def __exit__(self, exc_type, exc, traceback):
                self.held = False
                return False

        gate = Gate()
        daemon._exclusive_lock.return_value = gate

        def status() -> dict[str, object]:
            self.assertTrue(gate.held)
            return {"transport_ready": True, "pending_file_count": 0}

        daemon.status.side_effect = status
        with mock.patch(
            "capture_daemon.CaptureInboxDaemon",
            return_value=daemon,
        ):
            observed = installer.capture_transport_status(self.data)

        self.assertTrue(observed["transport_ready"])
        self.assertFalse(gate.held)
        daemon._exclusive_lock.assert_called_once_with(
            self.data / "capture_locks" / ".capture-maintenance.lock",
            blocking=True,
        )

    def test_exact_label_cleanup_requires_both_launchd_readbacks(self) -> None:
        cases = (
            "clean",
            "bootout",
            "disable",
            "snapshot-error",
            "still-running",
            "disabled-error",
            "disabled-false",
        )
        for case in cases:
            with self.subTest(case=case):
                launchctl = mock.Mock()
                if case == "bootout":
                    launchctl.bootout.side_effect = installer.CoreInstallerError(
                        "bootout failed"
                    )
                if case == "disable":
                    launchctl.disable.side_effect = installer.CoreInstallerError(
                        "disable failed"
                    )
                if case == "snapshot-error":
                    launchctl.snapshot.side_effect = installer.CoreInstallerError(
                        "snapshot failed"
                    )
                else:
                    launchctl.snapshot.return_value = {
                        "loaded": False,
                        "running": case == "still-running",
                    }
                if case == "disabled-error":
                    launchctl.disabled.side_effect = installer.CoreInstallerError(
                        "disabled readback failed"
                    )
                else:
                    launchctl.disabled.return_value = case != "disabled-false"

                errors = installer.verified_exact_label_cleanup(
                    launchctl=launchctl,
                    wait_seconds=2.0,
                )

                self.assertEqual(errors == [], case == "clean")
                launchctl.bootout.assert_called_once_with(wait_seconds=2.0)
                launchctl.disable.assert_called_once_with()
                launchctl.snapshot.assert_called_once_with()
                launchctl.disabled.assert_called_once_with()

    def test_build_config_defaults_to_closed_production_neural_contract(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            config = installer.build_config(self.paths)

        self.assertEqual(config.embedding_provider_name, "mlx-neural")
        self.assertEqual(
            config.embedding_neural_model_id,
            installer.DEFAULT_PRODUCTION_NEURAL_MODEL,
        )
        self.assertEqual(
            config.embedding_neural_revision,
            installer.DEFAULT_PRODUCTION_NEURAL_REVISION,
        )
        self.assertEqual(
            config.embedding_neural_cache_dir,
            self.data / "models",
        )
        self.assertEqual(config.embedding_neural_pooling, "mean")
        self.assertEqual(config.embedding_neural_max_tokens, 512)
        self.assertTrue(config.embedding_neural_normalize)
        self.assertTrue(config.embedding_neural_local_files_only)
        self.assertEqual(config.mlx_device, "gpu")
        self.assertTrue(config.require_native)

    def test_build_config_keeps_offline_semantic_hash_explicit(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SYNAPSE_S2_EMBEDDING_PROVIDER": "semantic-hash"},
            clear=True,
        ):
            config = installer.build_config(self.paths)

        self.assertEqual(config.embedding_provider_name, "semantic-hash")
        self.assertIsNone(config.embedding_neural_model_id)
        self.assertIsNone(config.embedding_neural_revision)
        self.assertIsNone(config.embedding_neural_cache_dir)
        self.assertIsNone(config.embedding_neural_local_files_only)

    def test_build_config_requires_revision_for_custom_neural_model(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "mlx-neural",
                "SYNAPSE_S2_NEURAL_MODEL": "mlx-community/custom-model",
            },
            clear=True,
        ), self.assertRaises(installer.CoreInstallerError):
            installer.build_config(self.paths)

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
                "MLX_DEVICE": "cpu",
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "semantic-hash",
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
        self.assertEqual(launch_environment["MLX_DEVICE"], "cpu")

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

    def test_failed_install_never_claims_unverified_exact_label_cleanup(self) -> None:
        launchctl = mock.Mock()
        launchctl.snapshot.return_value = {
            "loaded": False,
            "running": False,
            "pid": None,
        }
        environment = {
            "SYNAPSE_S2_DIMENSION": "8",
            "SYNAPSE_S2_NEURONS": "16",
            "SYNAPSE_S2_TOP_K": "4",
            "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "0",
        }
        with mock.patch.dict(
            os.environ,
            environment,
            clear=False,
        ), mock.patch.object(
            installer,
            "_preflight",
            return_value={"ready": True},
        ), mock.patch.object(
            installer,
            "wait_for_health",
            side_effect=installer.CoreInstallerError("health failed"),
        ), mock.patch.object(
            installer,
            "verified_exact_label_cleanup",
            return_value=["bootout"],
        ) as cleanup:
            with self.assertRaisesRegex(
                installer.CoreInstallerError,
                "cleanup could not be verified",
            ):
                installer.install(
                    paths=self.paths,
                    label="aero.boom.synapse-s2.core.test",
                    launchctl=launchctl,
                    launchctl_bin=str(self.launchctl_path),
                    ps_bin="/bin/false",
                    evidence_manifest=self.base / "evidence" / "manifest.json",
                    maximum_evidence_age_seconds=7200,
                    wait_seconds=2,
                    force_restart=True,
                )
        cleanup.assert_called_once_with(launchctl=launchctl, wait_seconds=2)
        launchctl.enable.assert_called_once_with()
        launchctl.bootstrap.assert_called_once_with(self.paths.plist)
        launchctl.kickstart.assert_called_once_with()

    def test_recover_existing_is_identity_bound_and_idempotent(self) -> None:
        config = self._prepare_recoverable_v6()
        config_before = self.paths.config.read_bytes()
        config_identity_before = self.paths.config.stat()
        plist_before = self.paths.plist.read_bytes()
        plist_identity_before = self.paths.plist.stat()
        with mock.patch.object(
            installer,
            "wait_for_health",
            return_value={**self._health(), "pid": 4242},
        ):
            first = installer.recover_existing(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
            )
            first_log = (self.base / "launchctl.log").read_text(encoding="utf-8")
            second = installer.recover_existing(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
            )
            second_log = (self.base / "launchctl.log").read_text(encoding="utf-8")

        self.assertEqual(first["status"], "healthy")
        self.assertTrue(first["recovery_admission"]["verified"])
        self.assertEqual(second["status"], "already-healthy")
        self.assertEqual(first_log.count("bootstrap"), 1)
        self.assertEqual(second_log.count("bootstrap"), 1)
        self.assertEqual(self.paths.config.read_bytes(), config_before)
        self.assertEqual(self.paths.plist.read_bytes(), plist_before)
        self.assertEqual(self.paths.config.stat().st_ino, config_identity_before.st_ino)
        self.assertEqual(self.paths.plist.stat().st_ino, plist_identity_before.st_ino)
        binding = installer.load_core_client_binding(
            installer.default_binding_path(self.home)
        )
        self.assertEqual(binding.authority_mode, "authoritative-core-v6")
        self.assertEqual(binding.config_fingerprint, config.fingerprint)

    def test_recovery_admission_is_observation_only(self) -> None:
        config = self._prepare_recoverable_v6()
        # SQLite header bytes 18/19 are the read/write format versions; 2/2
        # proves this is a WAL-mode main database even though every transient
        # sidecar has been sealed away for immutable admission.
        self.assertEqual(self.memory_db.read_bytes()[18:20], b"\x02\x02")
        before = self._filesystem_snapshot()
        result = installer._verify_recovery_admission(
            paths=self.paths,
            config=config,
        )
        after = self._filesystem_snapshot()
        self.assertTrue(result["verified"])
        self.assertEqual(after, before)
        self.assertFalse((self.base / "launchctl.log").exists())

    def test_recovery_rejects_unsafe_sqlite_sidecars_without_touching_them(self) -> None:
        config = self._prepare_recoverable_v6()
        for database in (self.memory_db, self.core / "requests.sqlite3"):
            for suffix in ("-journal", "-wal", "-shm"):
                with self.subTest(database=database.name, suffix=suffix):
                    sidecar = Path(f"{database}{suffix}")
                    sidecar.write_bytes((database.name + suffix).encode("utf-8"))
                    sidecar.chmod(0o600)
                    before = self._filesystem_snapshot()
                    with self.assertRaisesRegex(
                        installer.CoreInstallerError,
                        "SQLite sidecar",
                    ):
                        installer._verify_recovery_admission(
                            paths=self.paths,
                            config=config,
                        )
                    self.assertEqual(self._filesystem_snapshot(), before)
                    if suffix == "-wal":
                        self.assertFalse(Path(f"{database}-shm").exists())
                    sidecar.unlink()

    def test_recovery_accepts_sealed_zero_wal_pair_without_touching_it(self) -> None:
        config = self._prepare_recoverable_v6()
        for database in (self.memory_db, self.core / "requests.sqlite3"):
            for shm_size in (32_768, 65_536):
                with self.subTest(database=database.name, shm_size=shm_size):
                    wal = Path(f"{database}-wal")
                    shm = Path(f"{database}-shm")
                    wal.write_bytes(b"")
                    shm.write_bytes(b"\0" * shm_size)
                    wal.chmod(0o600)
                    shm.chmod(0o600)
                    before = self._filesystem_snapshot()
                    result = installer._verify_recovery_admission(
                        paths=self.paths,
                        config=config,
                    )
                    self.assertTrue(result["verified"])
                    self.assertEqual(self._filesystem_snapshot(), before)
                    wal.unlink()
                    shm.unlink()

    def test_recovery_rejects_nonzero_wal_and_invalid_shm_bounds(self) -> None:
        self._prepare_recoverable_v6()
        database = self.memory_db
        wal = Path(f"{database}-wal")
        shm = Path(f"{database}-shm")
        cases = (
            (b"frame", 32_768),
            (b"", 0),
            (b"", 32_769),
            (b"", (8 * 1024 * 1024) + 32_768),
        )
        for wal_bytes, shm_size in cases:
            with self.subTest(wal_size=len(wal_bytes), shm_size=shm_size):
                wal.write_bytes(wal_bytes)
                shm.write_bytes(b"\0" * shm_size)
                wal.chmod(0o600)
                shm.chmod(0o600)
                before = self._filesystem_snapshot()
                with self.assertRaisesRegex(
                    installer.CoreInstallerError,
                    "unsafe size",
                ):
                    installer._validate_sqlite_transients(
                        database,
                        kind="test database",
                    )
                self.assertEqual(self._filesystem_snapshot(), before)
                wal.unlink()
                shm.unlink()

    def test_launchctl_disabled_policy_parser_is_exact_and_bounded(self) -> None:
        launchctl = self._launchctl()
        for value, expected in (
            ("disabled", True),
            ("enabled", False),
            ("true", True),
            ("false", False),
        ):
            completed = mock.Mock(
                returncode=0,
                stdout=(
                    "{\n"
                    f'  "aero.boom.synapse-s2.core.test" => {value}\n'
                    "}\n"
                ),
                stderr="",
            )
            with self.subTest(value=value), mock.patch.object(
                launchctl,
                "_run",
                return_value=completed,
            ):
                self.assertIs(launchctl.disabled(), expected)
        for output in (
            "{}\n",
            '"aero.boom.synapse-s2.core.test" => disabled\n'
            '"aero.boom.synapse-s2.core.test" => enabled\n',
            '"aero.boom.synapse-s2.core.other" => disabled\n',
            '"aero.boom.synapse-s2.core.test" => maybe\n',
            "x" * ((1024 * 1024) + 1),
            '"aero.boom.synapse-s2.core.test" => disabled\x00\n',
        ):
            with self.subTest(output_size=len(output)), mock.patch.object(
                launchctl,
                "_run",
                return_value=mock.Mock(returncode=0, stdout=output, stderr=""),
            ), self.assertRaises(installer.CoreInstallerError):
                launchctl.disabled()
        with mock.patch.object(
            launchctl,
            "_run",
            return_value=mock.Mock(
                returncode=0,
                stdout='"aero.boom.synapse-s2.core.test" => disabled\n',
                stderr="x" * ((1024 * 1024) + 1),
            ),
        ), self.assertRaises(installer.CoreInstallerError):
            launchctl.disabled()

    def test_context_delivery_integrity_repairs_only_after_reviewed_offline_audit(
        self,
    ) -> None:
        self._prepare_recoverable_v6()
        with closing(sqlite3.connect(self.memory_db)) as connection:
            cursor = connection.execute(
                """
                INSERT INTO agent_context_events (
                    context_id, source_surface, event_type, summary,
                    payload_json, agent_targets_json, created_at
                ) VALUES (
                    'default', 'installer-test', 'late-event',
                    'installer repair fixture', '{}', '["mcp-clients"]', 200.0
                )
                """
            )
            event_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO agent_context_event_targets (
                    event_id, target_kind, target_id, created_at
                ) VALUES (?, 'group', 'mcp-clients', 200.0)
                """,
                (event_id,),
            )
            connection.commit()
        launchctl = self._launchctl()
        launchctl.disable()

        audited = installer.context_delivery_integrity(
            paths=self.paths,
            launchctl=launchctl,
            wait_seconds=2.0,
            repair=False,
            confirm=False,
            expected_revision=None,
        )
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "requires --confirm",
        ):
            installer.context_delivery_integrity(
                paths=self.paths,
                launchctl=launchctl,
                wait_seconds=2.0,
                repair=True,
                confirm=False,
                expected_revision=audited["audit"]["audit_revision"],
            )
        repaired = installer.context_delivery_integrity(
            paths=self.paths,
            launchctl=launchctl,
            wait_seconds=2.0,
            repair=True,
            confirm=True,
            expected_revision=audited["audit"]["audit_revision"],
        )
        verified = installer.context_delivery_integrity(
            paths=self.paths,
            launchctl=launchctl,
            wait_seconds=2.0,
            repair=False,
            confirm=False,
            expected_revision=None,
        )
        with closing(sqlite3.connect(self.memory_db)) as connection:
            cursor = connection.execute(
                """
                INSERT INTO agent_context_events (
                    context_id, source_surface, event_type, summary,
                    payload_json, agent_targets_json, created_at
                ) VALUES (
                    'default', 'successor-test', 'successor-event',
                    'post-repair successor fixture', '{}', '["mcp-clients"]',
                    300.0
                )
                """
            )
            successor_event_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO agent_context_event_targets (
                    event_id, target_kind, target_id, created_at
                ) VALUES (?, 'group', 'mcp-clients', 300.0)
                """,
                (successor_event_id,),
            )
            connection.execute(
                """
                UPDATE store_metadata
                SET value_json = ?, updated_at = 300.0
                WHERE key = 'context_event_targets_reconciled_through'
                """,
                (json.dumps(successor_event_id),),
            )
            connection.commit()
        advanced = installer.context_delivery_integrity(
            paths=self.paths,
            launchctl=launchctl,
            wait_seconds=2.0,
            repair=False,
            confirm=False,
            expected_revision=None,
        )
        reproved = installer.context_delivery_integrity(
            paths=self.paths,
            launchctl=launchctl,
            wait_seconds=2.0,
            repair=True,
            confirm=True,
            expected_revision=advanced["audit"]["audit_revision"],
        )
        with closing(sqlite3.connect(self.memory_db)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("DELETE FROM agent_context_events")
            connection.execute(
                """
                UPDATE store_metadata
                SET value_json = '0', updated_at = 400.0
                WHERE key = 'context_event_targets_reconciled_through'
                """
            )
            connection.commit()
        pruned = installer.context_delivery_integrity(
            paths=self.paths,
            launchctl=launchctl,
            wait_seconds=2.0,
            repair=False,
            confirm=False,
            expected_revision=None,
        )
        pruned_reproved = installer.context_delivery_integrity(
            paths=self.paths,
            launchctl=launchctl,
            wait_seconds=2.0,
            repair=True,
            confirm=True,
            expected_revision=pruned["audit"]["audit_revision"],
        )

        self.assertEqual(audited["status"], "repairable")
        self.assertEqual(repaired["status"], "repaired")
        self.assertTrue(repaired["repair"]["verification_passed"])
        self.assertEqual(verified["status"], "ready")
        self.assertEqual(advanced["status"], "ready")
        self.assertEqual(reproved["status"], "ready")
        self.assertTrue(reproved["repair"]["maintenance_receipt_verified"])
        self.assertEqual(pruned["status"], "ready")
        self.assertEqual(pruned_reproved["status"], "ready")
        self.assertTrue(
            pruned_reproved["repair"]["maintenance_receipt_verified"]
        )
        self.assertEqual(verified["audit"]["target_highwater"], event_id)
        self.assertEqual(
            advanced["audit"]["target_highwater"],
            successor_event_id,
        )
        self.assertEqual(
            repaired["service_state"],
            {"loaded": False, "running": False, "disabled": True},
        )
        log_verbs = {
            line.split()[0]
            for line in (self.base / "launchctl.log")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        }
        self.assertTrue(
            log_verbs.isdisjoint(
                {"enable", "bootstrap", "bootout", "kickstart"}
            )
        )

    def test_context_delivery_integrity_refuses_loaded_or_enabled_core(self) -> None:
        self._prepare_recoverable_v6()
        launchctl = self._launchctl()
        launchctl.bootstrap(self.paths.plist)
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "disabled and unloaded",
        ):
            installer.context_delivery_integrity(
                paths=self.paths,
                launchctl=launchctl,
                wait_seconds=2.0,
                repair=False,
                confirm=False,
                expected_revision=None,
            )
        launchctl.bootout(wait_seconds=2.0)
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "disabled and unloaded",
        ):
            installer.context_delivery_integrity(
                paths=self.paths,
                launchctl=launchctl,
                wait_seconds=2.0,
                repair=False,
                confirm=False,
                expected_revision=None,
            )

    def test_recovery_identity_failures_never_mutate_launchd(self) -> None:
        self._prepare_recoverable_v6()

        def assert_no_launch_mutation() -> None:
            log_path = self.base / "launchctl.log"
            verbs = {
                line.split()[0]
                for line in log_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            } if log_path.exists() else set()
            self.assertTrue(
                verbs.isdisjoint(
                    {"enable", "disable", "bootstrap", "bootout", "kickstart"}
                ),
                verbs,
            )

        token = self.paths.socket.with_name(self.paths.socket.name + ".token")
        token.write_bytes(b"a" * 63)
        with self.assertRaises(installer.CoreInstallerError):
            installer.recover_existing(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
            )
        assert_no_launch_mutation()
        token.write_bytes(b"a" * 64)
        (self.base / "launchctl.log").unlink(missing_ok=True)

        restored = self.core / "requests.sqlite3.binding.receipt.json"
        restored.write_bytes(b"{}\n")
        restored.chmod(0o600)
        with self.assertRaises(installer.CoreInstallerError):
            installer.recover_existing(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
            )
        assert_no_launch_mutation()
        restored.unlink()
        (self.base / "launchctl.log").unlink(missing_ok=True)

        lease = CoreAuthorityLease.acquire_core(
            self.memory_db,
            timeout_seconds=0.0,
            instance_id="active-authority-recovery-test",
        )
        try:
            with self.assertRaises(installer.CoreInstallerError):
                installer.recover_existing(
                    paths=self.paths,
                    label="aero.boom.synapse-s2.core.test",
                    launchctl=self._launchctl(),
                    wait_seconds=2,
                )
        finally:
            lease.close()
        assert_no_launch_mutation()

    def test_recovery_activation_error_runs_verified_exact_label_cleanup(self) -> None:
        self._prepare_recoverable_v6()
        launchctl = mock.Mock()
        launchctl.snapshot.side_effect = [
            {"loaded": False, "running": False},
            {"loaded": False, "running": False},
            {"loaded": False, "running": False},
        ]
        launchctl.enable.side_effect = installer.CoreInstallerError(
            "enable applied then response failed"
        )
        launchctl.disabled.return_value = True
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "verified unloaded and disabled",
        ):
            installer.recover_existing(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=launchctl,
                wait_seconds=2,
            )
        launchctl.bootout.assert_called_once_with(wait_seconds=2)
        launchctl.disable.assert_called_once_with()
        launchctl.disabled.assert_called_once_with()
        launchctl.bootstrap.assert_not_called()

    def test_recovery_never_claims_cleanup_when_any_readback_fails(self) -> None:
        self._prepare_recoverable_v6()
        cases = (
            "bootout",
            "disable",
            "snapshot-error",
            "still-loaded",
            "disabled-error",
            "disabled-false",
            "unexpected-error",
        )
        for case in cases:
            with self.subTest(case=case):
                launchctl = mock.Mock()
                cleanup_snapshot: object = {
                    "loaded": case == "still-loaded",
                    "running": False,
                }
                if case == "snapshot-error":
                    cleanup_snapshot = installer.CoreInstallerError(
                        "snapshot unavailable"
                    )
                launchctl.snapshot.side_effect = [
                    {"loaded": False, "running": False},
                    {"loaded": False, "running": False},
                    cleanup_snapshot,
                ]
                launchctl.enable.side_effect = (
                    KeyboardInterrupt()
                    if case == "unexpected-error"
                    else installer.CoreInstallerError("activation failed")
                )
                if case == "bootout":
                    launchctl.bootout.side_effect = installer.CoreInstallerError(
                        "bootout failed"
                    )
                if case == "disable":
                    launchctl.disable.side_effect = installer.CoreInstallerError(
                        "disable failed"
                    )
                if case == "disabled-error":
                    launchctl.disabled.side_effect = installer.CoreInstallerError(
                        "readback failed"
                    )
                else:
                    launchctl.disabled.return_value = case not in {
                        "disabled-false",
                        "unexpected-error",
                    }
                with self.assertRaisesRegex(
                    installer.CoreInstallerError,
                    "cleanup could not be verified",
                ):
                    installer.recover_existing(
                        paths=self.paths,
                        label="aero.boom.synapse-s2.core.test",
                        launchctl=launchctl,
                        wait_seconds=2,
                    )
                launchctl.bootout.assert_called_once_with(wait_seconds=2)
                launchctl.disable.assert_called_once_with()
                launchctl.disabled.assert_called_once_with()

    def test_clean_authoritative_service_close_is_recoverable_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="s2r-", dir="/tmp") as raw_short:
            short_root = Path(raw_short).resolve()
            self.data = short_root / "data"
            self.core = self.data / "core"
            self.capture = self.data
            self.memory_db = self.data / "memory.sqlite3"
            self.data.mkdir(mode=0o700)
            self.memory_db.write_bytes(b"temporary test database")
            self.memory_db.chmod(0o600)
            self.paths = replace(
                self.paths,
                data_root=self.data,
                core_root=self.core,
                config=self.core / "service.json",
                socket=self.core / "service.sock",
                state=self.data / "runtime_state.json",
                memory_db=self.memory_db,
                capture_root=self.capture,
                log=self.core / "service.log",
            )
            config = self._prepare_recoverable_v6()
            service = AuthoritativeCoreService(config)
            try:
                with mock.patch.dict(
                    os.environ,
                    {"MLX_DEVICE": "cpu"},
                    clear=False,
                ):
                    service.start()
            finally:
                service.close()
            memory_wal = Path(f"{self.memory_db}-wal")
            memory_shm = Path(f"{self.memory_db}-shm")
            self.assertTrue(memory_wal.is_file())
            self.assertEqual(memory_wal.stat().st_size, 0)
            self.assertTrue(memory_shm.is_file())
            self.assertEqual(memory_shm.stat().st_size, 32_768)
            before = self._filesystem_snapshot(short_root)
            result = installer._verify_recovery_admission(
                paths=self.paths,
                config=config,
            )
            self.assertTrue(result["verified"])
            self.assertEqual(self._filesystem_snapshot(short_root), before)

    def test_recovery_accepts_valid_path_not_authorized_terminal_row(self) -> None:
        config = self._prepare_recoverable_v6()
        journal_path = self.core / "requests.sqlite3"
        with closing(sqlite3.connect(journal_path)) as connection:
            journal_id = str(
                connection.execute(
                    "SELECT value FROM request_journal_metadata WHERE key = 'journal_id'"
                ).fetchone()[0]
            )
        journal = CoreRequestJournal(
            journal_path,
            authority_epoch="epoch-1",
            require_existing=True,
            prune_on_open=False,
            allow_migration=False,
            store_identity=installer._store_identity(self.memory_db),
            expected_journal_id=journal_id,
        )
        try:
            request = {
                "caller": "recovery-test",
                "request_id": "path-policy-1",
                "operation": "capture",
                "request_fingerprint": "b" * 64,
            }
            self.assertEqual(journal.accept(**request).disposition, "accepted")
            journal.finish(
                **request,
                result=None,
                safe_error_code="path_not_authorized",
            )
        finally:
            journal.close()
        self._seal_sqlite_fixture(journal_path)
        result = installer._verify_recovery_admission(
            paths=self.paths,
            config=config,
        )
        self.assertTrue(result["verified"])

    def test_recovery_rejects_inconsistent_request_journal_row(self) -> None:
        config = self._prepare_recoverable_v6()
        journal_path = self.core / "requests.sqlite3"
        now_ms = int(time.time() * 1000)
        with closing(sqlite3.connect(journal_path)) as connection:
            connection.execute(
                "INSERT INTO request_journal ("
                "caller, request_id, operation, request_fingerprint, "
                "authority_epoch, state, result_kind, safe_error_code, "
                "accepted_at_unix_ms, finished_at_unix_ms"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "recovery-test",
                    "invalid-terminal-1",
                    "capture",
                    "c" * 64,
                    "epoch-1",
                    "failed",
                    None,
                    "not_a_safe_error",
                    now_ms,
                    now_ms,
                ),
            )
            connection.commit()
        self._seal_sqlite_fixture(journal_path)
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "admission proof failed",
        ):
            installer._verify_recovery_admission(
                paths=self.paths,
                config=config,
            )

    def test_immutable_memory_admission_runs_integrity_checks_first(self) -> None:
        self._prepare_recoverable_v6()
        uri = self.memory_db.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            root_page = int(
                connection.execute(
                    "SELECT rootpage FROM sqlite_schema "
                    "WHERE type = 'index' AND rootpage > 0 ORDER BY rootpage LIMIT 1"
                ).fetchone()[0]
            )
        with self.memory_db.open("r+b") as handle:
            handle.seek((root_page - 1) * page_size)
            handle.write(b"\0" * 32)
            handle.flush()
            os.fsync(handle.fileno())
        lease = CoreAuthorityLease.acquire_core(
            self.memory_db,
            timeout_seconds=0.0,
            instance_id="immutable-integrity-test",
        )
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        store._authority_lease = lease
        try:
            with self.assertRaisesRegex(
                CoreAuthorityError,
                "integrity verification",
            ):
                store.inspect_core_authority_preclaim_immutable()
        finally:
            store.close()
            lease.close()

    def test_pending_runtime_publication_pure_validator_is_identity_closed(self) -> None:
        config = self._prepare_recoverable_v6()
        self._advance_recoverable_v6_epoch_pending(config)
        lease = CoreAuthorityLease.acquire_core(
            self.memory_db,
            timeout_seconds=0.0,
            instance_id="pending-validator-test",
        )
        store = DurableMemoryStore.open_existing_for_audit(self.memory_db)
        store._authority_lease = lease
        try:
            inspection = store.inspect_core_authority_preclaim_immutable()
            marker = dict(inspection["marker"])
            publication = dict(inspection["runtime_publication"])
            kwargs = {
                "marker": marker,
                "publication": publication,
                "runtime_state_path": self.paths.state,
                "expected_lock_generation_id": lease.lock_generation_id,
                "expected_config_fingerprint": config.fingerprint,
                "expected_build_id": installer._manifest_build_id(ROOT),
                "expected_protocol_version": installer.PROTOCOL_VERSION,
                "expected_root_generation_id": str(marker["root_generation_id"]),
                "expected_embedding_space_identity": (
                    config.embedding_space_identity
                ),
            }
            binding = (
                DurableMemoryStore.validate_interrupted_runtime_publication_binding(
                    **kwargs
                )
            )
            self.assertEqual(binding["authority_epoch_number"], 2)
            tampered = dict(publication)
            tampered["runtime_state_path_sha256"] = "f" * 64
            with self.assertRaises(CoreAuthorityError):
                DurableMemoryStore.validate_interrupted_runtime_publication_binding(
                    **{**kwargs, "publication": tampered}
                )
            with self.assertRaises(CoreAuthorityError):
                DurableMemoryStore.validate_interrupted_runtime_publication_binding(
                    **{**kwargs, "expected_root_generation_id": "generation-" + "e" * 24}
                )
        finally:
            store.close()
            lease.close()

    def test_recovery_rejects_semantically_invalid_canonical_runtime(self) -> None:
        config = self._prepare_recoverable_v6()
        runtime = json.loads(self.paths.state.read_text(encoding="utf-8"))
        runtime["global_enabled"] = "true"
        self.paths.state.write_text(
            json.dumps(runtime, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        self.paths.state.chmod(0o600)
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "runtime state is invalid",
        ):
            installer._verify_recovery_admission(
                paths=self.paths,
                config=config,
            )

    def test_recover_existing_rejects_static_plist_and_binding_drift(self) -> None:
        config = self._prepare_recoverable_v6()
        self.paths.plist.write_bytes(self.paths.plist.read_bytes() + b"\n")
        self.paths.plist.chmod(0o600)
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "plist does not match",
        ):
            installer.recover_existing(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
            )
        self.assertFalse((self.base / "launchctl.log").exists())

        installer._atomic_private_bytes(
            self.paths.plist,
            installer.plist_payload(
                label="aero.boom.synapse-s2.core.test",
                paths=self.paths,
                config=config,
            ),
        )
        wrong = installer.binding_for_config(
            repo_root=self.paths.root,
            data_root=self.paths.data_root,
            config=config,
            core_label="aero.boom.synapse-s2.core.other",
            authority_mode="candidate-local-v5",
        )
        installer.write_core_client_binding(
            installer.default_binding_path(self.home),
            wrong,
        )
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "binding does not identify",
        ):
            installer.recover_existing(
                paths=self.paths,
                label="aero.boom.synapse-s2.core.test",
                launchctl=self._launchctl(),
                wait_seconds=2,
            )
        self.assertFalse((self.base / "launchctl.log").exists())

    def test_recovery_admission_rejects_config_and_build_drift(self) -> None:
        config = self._prepare_recoverable_v6()
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "durable v6 marker",
        ):
            installer._verify_recovery_admission(
                paths=self.paths,
                config=replace(config, dimension=config.dimension + 1),
            )
        with mock.patch.object(
            installer,
            "_manifest_build_id",
            return_value="source-" + ("f" * 24),
        ), self.assertRaisesRegex(
            installer.CoreInstallerError,
            "durable v6 marker",
        ):
            installer._verify_recovery_admission(
                paths=self.paths,
                config=config,
            )

    def test_recovery_admission_rejects_root_journal_and_runtime_drift(self) -> None:
        config = self._prepare_recoverable_v6()
        root_path = self.core / "store-generation.json"
        root_payload = json.loads(root_path.read_text(encoding="utf-8"))
        root_payload["root_generation_id"] = "generation-" + ("e" * 24)
        root_path.write_bytes(canonical_json_bytes(root_payload))
        root_path.chmod(0o600)
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "root generation",
        ):
            installer._verify_recovery_admission(
                paths=self.paths,
                config=config,
            )

        root_payload["root_generation_id"] = "generation-" + ("d" * 24)
        root_path.write_bytes(canonical_json_bytes(root_payload))
        with closing(
            sqlite3.connect(self.core / "requests.sqlite3")
        ) as connection:
            original_journal_id = str(
                connection.execute(
                    "SELECT value FROM request_journal_metadata WHERE key = ?",
                    ("journal_id",),
                ).fetchone()[0]
            )
            connection.execute(
                "UPDATE request_journal_metadata SET value = ? WHERE key = ?",
                ("journal-" + ("e" * 24), "journal_id"),
            )
            connection.commit()
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "request journal",
        ):
            installer._verify_recovery_admission(
                paths=self.paths,
                config=config,
            )

        with closing(
            sqlite3.connect(self.core / "requests.sqlite3")
        ) as connection:
            connection.execute(
                "UPDATE request_journal_metadata SET value = ? WHERE key = ?",
                (original_journal_id, "journal_id"),
            )
            connection.commit()
        runtime = json.loads(self.paths.state.read_text(encoding="utf-8"))
        runtime["authority_binding"]["marker_sha256"] = "f" * 64
        self.paths.state.write_text(
            json.dumps(runtime, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            installer.CoreInstallerError,
            "runtime state",
        ):
            installer._verify_recovery_admission(
                paths=self.paths,
                config=config,
            )

    def test_recovery_admission_accepts_same_identity_successor_pending_epoch(self) -> None:
        config = self._prepare_recoverable_v6()
        self._advance_recoverable_v6_epoch_pending(config)
        result = installer._verify_recovery_admission(
            paths=self.paths,
            config=config,
        )
        self.assertTrue(result["verified"])
        self.assertEqual(result["authority_epoch_number"], 2)
        self.assertEqual(result["runtime_publication_status"], "pending")

    def test_uninstall_is_idempotent_and_preserves_data_config_token_and_logs(self) -> None:
        self.core.mkdir(mode=0o700)
        self.plist.parent.mkdir(mode=0o700, parents=True)
        installer.ensure_private_directory(self.paths.log.parent)
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
        self.assertFalse(result["runtime_healthy"])
        self.assertFalse(result["production_ready"])
        self.assertFalse(result["provisional"])
        self.assertIsNone(result["deployment_mode"])
        self.assertFalse(self.home.exists())
        self.assertFalse(self.core.exists())

    def test_status_reports_provisional_runtime_without_production_readiness(
        self,
    ) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "semantic-hash",
                "SYNAPSE_S2_CORE_REQUIRE_NATIVE": "false",
                "MLX_DEVICE": "cpu",
            },
            clear=True,
        ):
            config = installer.build_config(self.paths)
        installer.write_core_config(self.paths.config, config)
        (self.base / "launchctl-loaded").write_text("loaded", encoding="utf-8")
        provisional_health = {
            **self._health(),
            "ready": True,
            "capture_ready": True,
            "deployment_mode": "replacement-certification",
        }
        with mock.patch.object(
            installer,
            "probe_health",
            side_effect=[
                installer.CoreInstallerError("not authoritative"),
                provisional_health,
            ],
        ) as probe:
            result = installer.status(paths=self.paths, launchctl=self._launchctl())

        self.assertTrue(result["loaded"])
        self.assertTrue(result["running"])
        self.assertFalse(result["healthy"])
        self.assertTrue(result["runtime_healthy"])
        self.assertFalse(result["production_ready"])
        self.assertTrue(result["provisional"])
        self.assertTrue(result["capture_ready"])
        self.assertEqual(
            result["deployment_mode"],
            "replacement-certification",
        )
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(
            probe.call_args_list[1].kwargs["expected_deployment_mode"],
            "replacement-certification",
        )

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
        layout = installer._canonical_layout(self.data, home=self.home)
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
        self.assertEqual(
            paths.log,
            self.home / "Library" / "Logs" / "SYNAPSE-S2" / "core-service.log",
        )
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

    def test_resolved_paths_reject_protected_documents_log_override(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "SYNAPSE_S2_CORE_LOG": str(self.core / "service.log"),
            },
            clear=True,
        ):
            with self.assertRaisesRegex(installer.CoreInstallerError, "canonical layout"):
                installer.resolve_paths(label="aero.boom.synapse-s2.core.test")

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
            "deployment_mode": "authoritative",
            "capture": {"enabled": True, "ready": True, "iteration_count": 1},
        }
        type(client).authority_identity = mock.PropertyMock(return_value=identity)
        with mock.patch("core_client.CoreClient", return_value=client), mock.patch.object(
            installer,
            "_private_socket",
        ), mock.patch.object(installer, "_private_token"):
            self.assertTrue(installer.probe_health(config)["ready"])
            client.health.return_value["deployment_mode"] = (
                "replacement-certification"
            )
            with self.assertRaisesRegex(
                installer.CoreInstallerError,
                "not ready",
            ):
                installer.probe_health(config)
            self.assertTrue(
                installer.probe_health(
                    config,
                    expected_deployment_mode="replacement-certification",
                )["ready"]
            )
            client.health.return_value["deployment_mode"] = "authoritative"
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
            "deployment_mode": "authoritative",
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
    def _complete_ready_proofs(
        recovery_checks: list[dict],
        *,
        config: installer.CoreConfig,
    ) -> tuple[list[dict], dict[str, dict]]:
        recovery_by_id = {
            str(check["check_id"]): check for check in recovery_checks
        }
        checks: list[dict] = []
        for check_id in OPERATOR_READINESS_REQUIRED_PROOF_IDS:
            runtime_metrics = {
                "schema": preflight.RUNTIME_BUILD_IDENTITY_SCHEMA,
                "proof_mode": "candidate-local-source",
                "authority_mode": "candidate-local-v5",
                "expected_source_build_id": installer._manifest_build_id(ROOT),
                "observed_runtime_build_id": installer._manifest_build_id(ROOT),
                "expected_config_fingerprint": config.fingerprint,
                "observed_config_fingerprint": config.fingerprint,
                "matched": True,
            }
            check = recovery_by_id.get(
                check_id,
                {
                    "check_id": check_id,
                    "required": True,
                    "status": "ready",
                    "metrics": (
                        runtime_metrics
                        if check_id == "runtime_build_identity"
                        else {}
                    ),
                    "artifact_paths": {},
                },
            )
            checks.append(check)
        return checks, {str(check["check_id"]): check for check in checks}

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
        recovery_checks = [
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
        checks, proofs = CoreCutoverPreflightTests._complete_ready_proofs(
            recovery_checks,
            config=config,
        )
        manifest = pack / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "overall_status": "ready",
                    "operator_trustworthy": True,
                    "created_at": time.time(),
                    "git": {"head": git_head, "status_short": ""},
                    "expected_source_build_id": installer._manifest_build_id(ROOT),
                    "core_config_contract": (
                        preflight.core_config_evidence_contract(config)
                    ),
                    "authority_route": {
                        "mode": "candidate-local-v5",
                        "candidate_config_fingerprint": config.fingerprint,
                    },
                    "quiescence_policy_contract": quiescence_policy_contract(),
                    "quiescence_policy_digest": quiescence_policy_digest(),
                    "required_total": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                    "required_ready": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                    "failed_required": [],
                    "required_proof_contract": ready_operator_proof_contract(),
                    "checks": checks,
                    "proofs": proofs,
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
if sys.argv[1] == 'print-disabled':
    print('disabled services = {{')
    print('  "test.capture" => true')
    print('  "test.dashboard" => true')
    print('  "test.core" => true')
    print('  "com.master-mold.imprint.inboxworker" => true')
    print('}}')
    raise SystemExit(0)
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
            self.assertEqual(len(calls), 8)
            self.assertTrue(all(line.startswith("print") for line in calls))
            self.assertTrue(result["master_mold_capture_respawner"]["disabled"])

    def test_launchctl_inventory_fails_closed_when_domain_query_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="synapse-preflight-launchctl-error-") as temporary:
            fake = Path(temporary) / "launchctl"
            fake.write_text(f"#!{sys.executable}\nraise SystemExit(70)\n", encoding="utf-8")
            fake.chmod(0o700)
            with self.assertRaisesRegex(
                preflight.CutoverPreflightError,
                "disabled-state inventory is unavailable",
            ):
                preflight.collect_launchagent_inventory(
                    launchctl_bin=fake,
                    labels={"core": "test.core"},
                )

    def test_enabled_unloaded_respawner_is_a_quiescence_blocker(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="synapse-preflight-respawner-"
        ) as temporary:
            root = Path(temporary)
            disabled_state = root / "respawner-disabled"
            fake = root / "launchctl"
            fake.write_text(
                f"""#!{sys.executable}
import pathlib
import sys
disabled = pathlib.Path({str(disabled_state)!r}).exists()
if sys.argv[1] == 'print-disabled':
    print('disabled services = {{')
    print('  "aero.boom.synapse-s2.capture-daemon" => true')
    print('  "aero.boom.synapse-s2.dashboard" => true')
    print('  "aero.boom.synapse-s2.core" => true')
    print('  "com.master-mold.imprint.inboxworker" => ' + ('true' if disabled else 'false'))
    print('}}')
    raise SystemExit(0)
if sys.argv[1] == 'print' and sys.argv[2].count('/') == 1:
    print('services = {{')
    print('}}')
    raise SystemExit(0)
raise SystemExit(3)
""",
                encoding="utf-8",
            )
            fake.chmod(0o700)

            enabled = preflight.collect_launchagent_inventory(
                launchctl_bin=fake
            )
            self.assertFalse(
                enabled["master_mold_capture_respawner"]["loaded"]
            )
            self.assertTrue(
                enabled["master_mold_capture_respawner"]["enabled"]
            )
            self.assertIn(
                "master_mold_capture_respawner",
                preflight.launchagent_quiescence_blockers(enabled),
            )

            disabled_state.write_text("disabled", encoding="utf-8")
            disabled = preflight.collect_launchagent_inventory(
                launchctl_bin=fake
            )
            self.assertNotIn(
                "master_mold_capture_respawner",
                preflight.launchagent_quiescence_blockers(disabled),
            )

    def test_operator_proof_contract_rejects_gaps_shadows_and_forged_summaries(
        self,
    ) -> None:
        checks = [
            {
                "check_id": check_id,
                "required": True,
                "status": "ready",
                "metrics": {},
                "artifact_paths": {},
            }
            for check_id in OPERATOR_READINESS_REQUIRED_PROOF_IDS
        ]
        valid = {
            "checks": checks,
            "required_total": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
            "required_ready": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
            "failed_required": [],
            "required_proof_contract": ready_operator_proof_contract(),
            "proofs": {str(check["check_id"]): check for check in checks},
        }
        self.assertEqual(
            set(preflight._validate_operator_readiness_proof_contract(valid)),
            set(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
        )

        missing = json.loads(json.dumps(valid))
        missing["checks"] = missing["checks"][:-1]
        with self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "required proof set",
        ):
            preflight._validate_operator_readiness_proof_contract(missing)

        shadow = json.loads(json.dumps(valid))
        shadow["checks"].append(
            {
                "check_id": "local_launcher",
                "required": False,
                "status": "ready",
            }
        )
        with self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "not unique",
        ):
            preflight._validate_operator_readiness_proof_contract(shadow)

        for field in (
            "required_total",
            "required_proof_contract",
            "proofs",
        ):
            with self.subTest(field=field):
                forged = json.loads(json.dumps(valid))
                if field == "required_total":
                    forged[field] -= 1
                elif field == "required_proof_contract":
                    forged[field]["version"] += 1
                else:
                    forged[field]["dashboard"]["status"] = "blocked"
                with self.assertRaises(preflight.CutoverPreflightError):
                    preflight._validate_operator_readiness_proof_contract(forged)

    def test_runtime_build_identity_consumer_rejects_different_source_build(self) -> None:
        build_id = installer._manifest_build_id(ROOT)
        config_fingerprint = "c" * 64
        check = {
            "metrics": {
                "schema": preflight.RUNTIME_BUILD_IDENTITY_SCHEMA,
                "proof_mode": "authoritative-core-health",
                "authority_mode": "authoritative-core-v6",
                "expected_source_build_id": build_id,
                "observed_runtime_build_id": build_id,
                "expected_config_fingerprint": config_fingerprint,
                "observed_config_fingerprint": config_fingerprint,
                "matched": True,
                "exact_matches": {
                    "command_succeeded": True,
                    "health_ready": True,
                    "build_id_shape": True,
                    "source_build": True,
                    "config_fingerprint": True,
                },
            }
        }
        preflight._validate_runtime_build_identity_proof(
            check,
            root=ROOT,
            expected_config_fingerprint=config_fingerprint,
            expected_authority_mode="authoritative-core-v6",
        )

        check["metrics"]["observed_runtime_build_id"] = "source-" + "0" * 24
        with self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "does not match the current deterministic source",
        ):
            preflight._validate_runtime_build_identity_proof(
                check,
                root=ROOT,
                expected_config_fingerprint=config_fingerprint,
                expected_authority_mode="authoritative-core-v6",
            )

    def test_identifierless_replay_debt_is_rejected_at_every_consumer(self) -> None:
        reconciliation = {
            "missing_authoritative_ledger_count": 0,
            "replay_required_capture_count": 0,
            "replay_required_file_count": 0,
            "identifierless_replay_file_count": 1,
            "unclassified_file_count": 0,
        }
        with self.assertRaisesRegex(
            preflight.CutoverPreflightError,
            "unresolved work",
        ):
            preflight._validate_zero_replay_debt(
                reconciliation,
                name="unit-test reconciliation",
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
                            "identifierless_replay_file_count": 0,
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
                            "identifierless_replay_file_count": 0,
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
                    "identifierless_replay_file_count": 0,
                    "unclassified_file_count": 0,
                },
            }
            recovery_checks = []
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
                recovery_checks.append(check)
            candidate_config = self._core_config(evidence_root)
            checks, proofs = self._complete_ready_proofs(
                recovery_checks,
                config=candidate_config,
            )
            manifest = pack / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "overall_status": "ready",
                        "operator_trustworthy": True,
                        "created_at": time.time(),
                        "git": {"head": "0" * 40, "status_short": ""},
                        "expected_source_build_id": installer._manifest_build_id(ROOT),
                        "core_config_contract": (
                            preflight.core_config_evidence_contract(candidate_config)
                        ),
                        "authority_route": {
                            "mode": "candidate-local-v5",
                            "candidate_config_fingerprint": (
                                candidate_config.fingerprint
                            ),
                        },
                        "quiescence_policy_contract": quiescence_policy_contract(),
                        "quiescence_policy_digest": quiescence_policy_digest(),
                        "required_total": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                        "required_ready": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                        "failed_required": [],
                        "required_proof_contract": ready_operator_proof_contract(),
                        "checks": checks,
                        "proofs": proofs,
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
            next(
                check
                for check in checks
                if check["check_id"] == "recovery_restore"
            )["metrics"]["reconciliation"]["unclassified_file_count"] = 1
            proofs = {str(check["check_id"]): check for check in checks}
            manifest.write_text(
                json.dumps(
                    {
                        "overall_status": "ready",
                        "operator_trustworthy": True,
                        "created_at": time.time(),
                        "git": {"head": "0" * 40, "status_short": ""},
                        "expected_source_build_id": installer._manifest_build_id(ROOT),
                        "core_config_contract": (
                            preflight.core_config_evidence_contract(candidate_config)
                        ),
                        "authority_route": {
                            "mode": "candidate-local-v5",
                            "candidate_config_fingerprint": (
                                candidate_config.fingerprint
                            ),
                        },
                        "quiescence_policy_contract": quiescence_policy_contract(),
                        "quiescence_policy_digest": quiescence_policy_digest(),
                        "required_total": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                        "required_ready": len(OPERATOR_READINESS_REQUIRED_PROOF_IDS),
                        "failed_required": [],
                        "required_proof_contract": ready_operator_proof_contract(),
                        "checks": checks,
                        "proofs": proofs,
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

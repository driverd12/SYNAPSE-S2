from __future__ import annotations

import json
import os
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from core_authority import CoreAuthorityError
from core_client import CoreClient, CoreRemoteError
from core_protocol import CoreProtocolError
from core_service import (
    CORE_OPERATION_CONTRACTS,
    AuthoritativeCoreService,
    CoreConfig,
)
from memory_store import DurableMemoryStore


RECOVERY_OPERATIONS = (
    "backup_recovery_bundle",
    "audit_capture_ledger",
    "repair_capture_ledger",
    "verify_recovery_bundle",
    "restore_recovery_bundle_isolated",
    "plan_recovery_retention",
    "apply_recovery_retention",
    "restore_retired_recovery",
)


class _CaptureWorker:
    def process_once(self, *, max_files: int) -> dict[str, int]:
        _ = max_files
        return {"processed_file_count": 0, "error_file_count": 0}


class _RecoveryBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.memory_store: DurableMemoryStore | None = None

    def handler(self, operation: str):
        def invoke(**arguments: Any) -> dict[str, Any]:
            self.calls.append((operation, dict(arguments)))
            return {"operation": operation, "accepted": True}

        return invoke

    def close(self) -> None:
        if self.memory_store is not None:
            self.memory_store.close()

    def attach_memory_store(
        self,
        store: DurableMemoryStore,
    ) -> "_RecoveryBackend":
        self.memory_store = store
        return self

    def _runtime_state_path(self) -> Path:
        assert self.memory_store is not None
        return self.memory_store.db_path.parent / "runtime_state.json"

    def assert_runtime_state_authority_marker(self, marker: dict[str, Any]) -> None:
        assert self.memory_store is not None
        payload = json.loads(self._runtime_state_path().read_text(encoding="utf-8"))
        if payload.get("authority_binding") != (
            self.memory_store.runtime_state_authority_binding_for_marker(marker)
        ):
            raise CoreAuthorityError("runtime state binding changed")

    def publish_runtime_state_authority_binding(self) -> None:
        assert self.memory_store is not None
        binding = self.memory_store.runtime_state_authority_binding()
        if binding is None:
            raise CoreAuthorityError("runtime state authority unavailable")
        path = self._runtime_state_path()
        path.write_text(
            json.dumps(
                {
                    "version": 3,
                    "global_enabled": True,
                    "context_overrides": {},
                    "cortex_sessions": {},
                    "runtime_state_repair": {},
                    "memory_db_path": str(self.memory_store.db_path),
                    "updated_at": time.time(),
                    "authority_binding": binding,
                },
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)


class CoreRecoveryRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.data_root = self.root / "data"
        self.data_root.mkdir(mode=0o700)
        os.chmod(self.data_root, 0o700)
        self.config = CoreConfig(
            socket_path=self.data_root / "core" / "service.sock",
            state_path=self.data_root / "runtime_state.json",
            memory_path=self.data_root / "memory.sqlite3",
            capture_root=self.data_root / "capture",
            dimension=8,
            num_neurons=8,
            default_top_k=4,
            recall_count=2,
            capture_poll_seconds=60.0,
            authority_timeout_seconds=0.0,
        )
        self.backend = _RecoveryBackend()
        contracts = {
            "health": CORE_OPERATION_CONTRACTS["health"],
            **{
                name: CORE_OPERATION_CONTRACTS[name]
                for name in RECOVERY_OPERATIONS
            },
        }
        handlers = {
            name: self.backend.handler(name) for name in RECOVERY_OPERATIONS
        }
        self.service = AuthoritativeCoreService(
            self.config,
            backend_factory=lambda lease: self.backend.attach_memory_store(
                DurableMemoryStore(
                    self.config.memory_path,
                    authority_lease=lease,
                )
            ),
            operation_contracts=contracts,
            operation_handlers_factory=lambda _backend: handlers,
            capture_worker_factory=lambda _backend, _root: _CaptureWorker(),
        )
        self.thread = threading.Thread(
            target=self.service.serve_forever,
            name="core-recovery-route-test",
            daemon=True,
        )
        self.thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not self.service._started_event.is_set():
            time.sleep(0.01)
        if not self.service._started_event.is_set():
            self.service.close()
            self.thread.join(timeout=2.0)
            raise AssertionError("authoritative core did not start")
        self.addCleanup(self._close_service)
        self.client = CoreClient(
            socket_path=self.config.socket_path,
            caller="recovery-route-test",
            default_timeout_seconds=3.0,
        )

    def _close_service(self) -> None:
        self.service.close()
        self.thread.join(timeout=3.0)

    def test_public_contracts_exclude_every_server_owned_recovery_path(self) -> None:
        forbidden = {
            "capture_root",
            "allow_noncanonical_capture_root",
            "directory",
        }
        for operation in RECOVERY_OPERATIONS:
            with self.subTest(operation=operation):
                self.assertFalse(
                    forbidden
                    & set(CORE_OPERATION_CONTRACTS[operation].allowed_arguments)
                )

    def test_core_client_routes_every_recovery_operation_with_server_paths(self) -> None:
        receipt = self.data_root / "backups" / "bundle.receipt.json"
        receipt.write_text("{}", encoding="utf-8")
        os.chmod(receipt, 0o600)
        restore_root = self.data_root / "recovery" / "route-proof"

        self.client.backup_recovery_bundle(purpose="test", pinned=True)
        self.client.audit_capture_ledger(sample_limit=7)
        self.client.repair_capture_ledger(
            confirm=True,
            expected_revision="a" * 64,
            sample_limit=8,
        )
        self.client.verify_recovery_bundle(
            receipt,
            expected_database_sha256="b" * 64,
            expected_capture_sha256="c" * 64,
            expected_request_journal_sha256="d" * 64,
            expected_runtime_state_sha256="e" * 64,
        )
        self.client.restore_recovery_bundle_isolated(
            receipt,
            restore_root,
            expected_database_sha256="b" * 64,
            expected_capture_sha256="c" * 64,
            expected_request_journal_sha256="d" * 64,
            expected_runtime_state_sha256="e" * 64,
            confirm=True,
        )
        self.client.plan_recovery_retention(keep_latest=3, max_age_days=9.0)
        self.client.apply_recovery_retention(
            plan_token="d" * 64,
            cutoff_created_at=1234.5,
            keep_latest=3,
            max_age_days=9.0,
            confirm=True,
        )
        self.client.restore_retired_recovery(
            plan_token="d" * 64,
            confirm=True,
        )

        calls = dict(self.backend.calls)
        capture_root = str(self.config.capture_root)
        backup_root = str(self.data_root / "backups")
        self.assertEqual(
            calls["backup_recovery_bundle"],
            {
                "path": None,
                "purpose": "test",
                "pinned": True,
                "capture_root": capture_root,
                "allow_noncanonical_capture_root": False,
            },
        )
        self.assertEqual(
            calls["audit_capture_ledger"],
            {"sample_limit": 7, "capture_root": capture_root},
        )
        self.assertEqual(
            calls["repair_capture_ledger"],
            {
                "confirm": True,
                "expected_revision": "a" * 64,
                "sample_limit": 8,
                "capture_root": capture_root,
            },
        )
        self.assertEqual(
            calls["verify_recovery_bundle"],
            {
                "receipt_path": str(receipt),
                "expected_database_sha256": "b" * 64,
                "expected_capture_sha256": "c" * 64,
                "expected_request_journal_sha256": "d" * 64,
                "expected_runtime_state_sha256": "e" * 64,
                "capture_root": capture_root,
            },
        )
        self.assertEqual(
            calls["restore_recovery_bundle_isolated"],
            {
                "receipt_path": str(receipt),
                "output_root": str(restore_root),
                "expected_database_sha256": "b" * 64,
                "expected_capture_sha256": "c" * 64,
                "expected_request_journal_sha256": "d" * 64,
                "expected_runtime_state_sha256": "e" * 64,
                "confirm": True,
                "capture_root": capture_root,
            },
        )
        self.assertEqual(
            calls["plan_recovery_retention"],
            {
                "keep_latest": 3,
                "max_age_days": 9.0,
                "directory": backup_root,
            },
        )
        self.assertEqual(
            calls["apply_recovery_retention"],
            {
                "plan_token": "d" * 64,
                "cutoff_created_at": 1234.5,
                "keep_latest": 3,
                "max_age_days": 9.0,
                "confirm": True,
                "directory": backup_root,
            },
        )
        self.assertEqual(
            calls["restore_retired_recovery"],
            {"plan_token": "d" * 64, "confirm": True},
        )

    def test_core_lane_rejects_explicit_recovery_path_overrides(self) -> None:
        outside = self.root / "outside"
        before = list(self.backend.calls)
        for operation, invoke in (
            (
                "backup_recovery_bundle",
                lambda: self.client.backup_recovery_bundle(capture_root=outside),
            ),
            (
                "audit_capture_ledger",
                lambda: self.client.audit_capture_ledger(capture_root=outside),
            ),
            (
                "verify_recovery_bundle",
                lambda: self.client.verify_recovery_bundle(
                    self.data_root / "backups" / "missing.json",
                    capture_root=outside,
                ),
            ),
            (
                "plan_recovery_retention",
                lambda: self.client.plan_recovery_retention(directory=outside),
            ),
        ):
            with self.subTest(operation=operation), self.assertRaises(
                CoreProtocolError
            ):
                invoke()
        self.assertEqual(self.backend.calls, before)

        with self.assertRaises(CoreRemoteError) as denied:
            self.client.backup_recovery_bundle(path=self.root / "outside.sqlite3")
        self.assertEqual(denied.exception.code, "path_not_authorized")
        self.assertEqual(self.backend.calls, before)


if __name__ == "__main__":
    unittest.main()

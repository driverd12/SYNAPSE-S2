from __future__ import annotations

import io
import inspect
import json
import fcntl
import os
import socket
import sqlite3
import subprocess
import sys
import stat
import threading
import time
import unittest
from contextlib import closing
from unittest import mock
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from core_authority import CoreAuthorityError, CoreAuthorityLease
from core_request_journal import (
    CoreRequestJournal,
    CoreRequestJournalError,
    repair_empty_preclaim_journal_residue,
)
from core_client import CoreClient, CoreOutcomeUnknown, CoreRemoteError, CoreUnavailable
from core_protocol import (
    PROTOCOL_VERSION,
    build_request,
    canonical_json_bytes,
    receive_frame,
    send_frame,
    validate_response,
)
from core_service import (
    BUILD_SOURCE_MANIFEST,
    CORE_OPERATION_CONTRACTS,
    LOGGER,
    MAX_ACTIVE_CONNECTIONS,
    REPLICATION_MAINTENANCE_LANE_SECONDS,
    REPLICATION_OPERATIONS,
    SAFE_READ_OPERATIONS,
    SERVICE_CONTROL_OPERATIONS,
    AuthoritativeCoreService,
    CoreConfig,
    CoreServiceError,
    _bind_default_backend_handlers,
    _bind_replication_handlers,
    _ensure_private_directory,
    _load_or_create_authentication_key,
    _load_or_create_store_generation,
    _manifest_build_id,
    _source_build_id,
    config_from_wire,
    load_core_config,
    write_core_config,
)
from memory_store import ContextDeliveryRejected, DurableMemoryStore
from mlx_backend import SpikingAttentionBackend
from redaction import SECRET_SAFE_LOG_FORMAT, SecretRedactingFormatter


TEST_CONTRACTS = {
    name: CORE_OPERATION_CONTRACTS[name]
    for name in (
        "health",
        "request_status",
        "status",
        "set_enabled",
        "register_text_trace",
        "register_trace",
        "query",
        "repair_semantic_indexes",
        "list_memory",
        "embedding_provider_info",
    )
}


class FakeBackend:
    def __init__(self) -> None:
        self.mutation_count = 0
        self.read_count = 0
        self.active_handlers = 0
        self.maximum_active_handlers = 0
        self.block_entered = threading.Event()
        self.block_release = threading.Event()
        self.closed = False
        self.reap_count = 0
        self.raw_embedding_dimensions: list[int] = []
        self._counter_lock = threading.Lock()
        self.memory_store: DurableMemoryStore | None = None

    def _enter(self) -> None:
        with self._counter_lock:
            self.active_handlers += 1
            self.maximum_active_handlers = max(
                self.maximum_active_handlers,
                self.active_handlers,
            )

    def _leave(self) -> None:
        with self._counter_lock:
            self.active_handlers -= 1

    def status(self, *, context_id: str = "default") -> dict[str, Any]:
        self._enter()
        try:
            self.read_count += 1
            if context_id == "block":
                self.block_entered.set()
                if not self.block_release.wait(10.0):
                    raise RuntimeError("blocked handler timed out")
            return {"runtime": "ready", "context_id": context_id}
        finally:
            self._leave()

    def set_enabled(
        self,
        enabled: bool,
        *,
        context_id: str | None = None,
    ) -> dict[str, Any]:
        self._enter()
        try:
            self.mutation_count += 1
            return {"enabled": bool(enabled), "context_id": context_id}
        finally:
            self._leave()

    def list_memory(self, **arguments: Any) -> dict[str, Any]:
        self._enter()
        try:
            if arguments.get("context_id") == "secret":
                raise RuntimeError("token=sk-secret-canary-12345678901234567890")
            return {"entries": [], "arguments": arguments}
        finally:
            self._leave()

    def register_text_trace(self, **arguments: Any) -> dict[str, Any]:
        self._enter()
        try:
            self.mutation_count += 1
            return {"registered": True, "arguments": arguments}
        finally:
            self._leave()

    def register_trace(self, **arguments: Any) -> dict[str, Any]:
        self._enter()
        try:
            self.mutation_count += 1
            self.raw_embedding_dimensions.append(len(arguments["embedding"]))
            return {"registered": True, "dimension": len(arguments["embedding"])}
        finally:
            self._leave()

    def query(self, **arguments: Any) -> str:
        self._enter()
        try:
            self.mutation_count += 1
            self.raw_embedding_dimensions.append(len(arguments["embedding"]))
            return "query-complete"
        finally:
            self._leave()

    def repair_semantic_indexes(self, **arguments: Any) -> dict[str, Any]:
        self._enter()
        try:
            self.mutation_count += 1
            return {"repaired": True, "arguments": arguments}
        finally:
            self._leave()

    def embedding_provider_info(self) -> dict[str, Any]:
        return {"provider": "fake"}

    def reap_orphaned_cortex_sessions(self) -> dict[str, Any]:
        self.reap_count += 1
        return {"reaped_count": 0, "session_ids": []}

    def close(self) -> None:
        self.closed = True
        if self.memory_store is not None:
            self.memory_store.close()

    def attach_memory_store(self, store: DurableMemoryStore) -> "FakeBackend":
        self.memory_store = store
        return self

    def _runtime_state_path(self) -> Path:
        assert self.memory_store is not None
        return self.memory_store.db_path.parent / "runtime_state.json"

    def assert_runtime_state_authority_marker(self, marker: dict[str, Any]) -> None:
        assert self.memory_store is not None
        payload = json.loads(self._runtime_state_path().read_text(encoding="utf-8"))
        expected = self.memory_store.runtime_state_authority_binding_for_marker(
            marker
        )
        if payload.get("authority_binding") != expected:
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

    def recover_interrupted_runtime_state_authority_publication(
        self,
        *,
        marker: dict[str, Any],
        publication: dict[str, Any],
        expected_config_fingerprint: str,
        expected_build_id: str,
        expected_protocol_version: str,
        expected_root_generation_id: str,
        expected_embedding_space_identity: str,
    ) -> None:
        assert self.memory_store is not None
        binding = self.memory_store.interrupted_runtime_publication_binding(
            marker=marker,
            publication=publication,
            runtime_state_path=self._runtime_state_path(),
            expected_config_fingerprint=expected_config_fingerprint,
            expected_build_id=expected_build_id,
            expected_protocol_version=expected_protocol_version,
            expected_root_generation_id=expected_root_generation_id,
            expected_embedding_space_identity=expected_embedding_space_identity,
        )
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


class FakeCaptureWorker:
    def __init__(self) -> None:
        self.iterations = 0

    def process_once(self, *, max_files: int) -> dict[str, int]:
        self.iterations += 1
        return {
            "processed_file_count": min(1, max_files),
            "error_file_count": 0,
        }


class ServiceHarness:
    def __init__(self, *, capture: bool = False) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state_root = self.root / "state"
        self.state_root.mkdir(mode=0o700)
        os.chmod(self.state_root, 0o700)
        self.config = CoreConfig(
            socket_path=self.state_root / "core" / "service.sock",
            state_path=self.state_root / "runtime_state.json",
            memory_path=self.state_root / "memory.sqlite3",
            capture_root=(self.state_root / "capture" if capture else None),
            dimension=8,
            num_neurons=8,
            default_top_k=4,
            recall_count=2,
            capture_poll_seconds=0.25,
            authority_timeout_seconds=0.0,
        )
        self.backend = FakeBackend()
        self.capture_worker = FakeCaptureWorker()
        self.service = AuthoritativeCoreService(
            self.config,
            backend_factory=lambda lease: self.backend.attach_memory_store(
                DurableMemoryStore(
                    self.config.memory_path,
                    authority_lease=lease,
                )
            ),
            operation_contracts=TEST_CONTRACTS,
            operation_handlers_factory=lambda backend: {
                "status": backend.status,
                "set_enabled": backend.set_enabled,
                "register_text_trace": backend.register_text_trace,
                "register_trace": backend.register_trace,
                "query": backend.query,
                "repair_semantic_indexes": backend.repair_semantic_indexes,
                "list_memory": backend.list_memory,
                "embedding_provider_info": backend.embedding_provider_info,
            },
            capture_worker_factory=(
                (lambda _backend, _root: self.capture_worker) if capture else None
            ),
        )
        self.thread = threading.Thread(
            target=self.service.serve_forever,
            name="test-core-service",
            daemon=True,
        )
        self.thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self.service._started_event.is_set():
                break
            time.sleep(0.01)
        if not self.service._started_event.is_set():
            raise AssertionError("test service did not start")

    def client(self, *, caller: str = "test-client") -> CoreClient:
        return CoreClient(
            socket_path=self.config.socket_path,
            caller=caller,
            default_timeout_seconds=2.0,
        )

    def key(self) -> bytes:
        return bytes.fromhex(
            self.config.socket_path.with_suffix(".sock.token").read_text("ascii")
        )

    def raw_request(
        self,
        operation: str,
        arguments: dict[str, Any],
        *,
        request_id: str | None = None,
        caller: str = "raw-client",
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        request = build_request(
            request_id=request_id or f"req-{time.time_ns()}",
            caller=caller,
            deadline_unix_ms=int((time.time() + 2.0) * 1000),
            operation=operation,
            arguments=arguments,
            authentication_key=self.key(),
        )
        return request, self.exchange_request(request)

    def exchange_request(self, request: dict[str, Any]) -> dict[str, Any]:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(3.0)
        try:
            connection.connect(str(self.config.socket_path))
            send_frame(connection, request)
            response = receive_frame(connection)
        finally:
            connection.close()
        return response

    def close(self) -> None:
        self.backend.block_release.set()
        self.service.close()
        self.thread.join(timeout=3.0)
        self.temporary.cleanup()


class CoreServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServiceHarness()
        self.addCleanup(self.harness.close)

    def test_startup_does_not_reap_orphaned_cortex_sessions(self) -> None:
        self.assertEqual(self.harness.backend.reap_count, 0)

    def test_raw_core_client_cannot_export_outside_server_owned_root(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            config = CoreConfig(
                socket_path=root / "core" / "service.sock",
                state_path=root / "runtime_state.json",
                memory_path=root / "memory.sqlite3",
                dimension=8,
                num_neurons=8,
                default_top_k=4,
                authority_timeout_seconds=0.0,
            )
            observed: list[str | None] = []
            backend = FakeBackend()
            contracts = {
                "health": CORE_OPERATION_CONTRACTS["health"],
                "export_memory": CORE_OPERATION_CONTRACTS["export_memory"],
            }
            service = AuthoritativeCoreService(
                config,
                backend_factory=lambda lease: backend.attach_memory_store(
                    DurableMemoryStore(
                        config.memory_path,
                        authority_lease=lease,
                    )
                ),
                operation_contracts=contracts,
                operation_handlers_factory=lambda _backend: {
                    "export_memory": lambda **arguments: (
                        observed.append(arguments["path"])
                        or {"path": arguments["path"]}
                    )
                },
            )
            thread = threading.Thread(target=service.serve_forever, daemon=True)
            thread.start()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not config.socket_path.exists():
                time.sleep(0.01)
            client = CoreClient(socket_path=config.socket_path)
            try:
                with self.assertRaises(CoreRemoteError) as denied:
                    client.export_memory(path=root / "outside.json")
                self.assertEqual(denied.exception.code, "path_not_authorized")
                self.assertEqual(observed, [])
                allowed = root / "exports" / "inside.json"
                result = client.export_memory(path=allowed)
                self.assertEqual(result["path"], str(allowed))
                self.assertEqual(observed, [str(allowed)])
                default_result = client.export_memory()
                self.assertIsNone(default_result["path"])
                self.assertEqual(observed, [str(allowed), None])
            finally:
                service.close()
                thread.join(timeout=3.0)

    def test_private_socket_authenticated_health_and_monotonic_envelopes(self) -> None:
        socket_stat = self.harness.config.socket_path.lstat()
        token_stat = self.harness.config.socket_path.with_suffix(".sock.token").lstat()
        self.assertEqual(stat.S_IMODE(socket_stat.st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(token_stat.st_mode), 0o600)
        self.assertEqual(
            stat.S_IMODE(self.harness.config.socket_path.parent.lstat().st_mode),
            0o700,
        )

        first_request, first = self.harness.raw_request("health", {})
        second_request, second = self.harness.raw_request("health", {})
        validate_response(first, expected_request=first_request)
        validate_response(second, expected_request=second_request)
        self.assertTrue(first["result"]["ready"])
        self.assertEqual(first["protocol_version"], PROTOCOL_VERSION)
        self.assertGreater(second["operation_sequence"], first["operation_sequence"])
        self.assertEqual(
            frozenset(first["identity"]),
            {
                "authority_id",
                "neural_epoch",
                "config_fingerprint",
                "build_id",
                "store_identity",
                "schema_identity",
            },
        )

    def test_health_cli_emits_closed_health_and_authority_identity(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "core_service.py",
                "health",
                "--socket",
                str(self.harness.config.socket_path),
                "--timeout",
                "2",
            ],
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(frozenset(payload), {"health", "identity"})
        self.assertTrue(payload["health"]["ready"])
        self.assertEqual(
            frozenset(payload["identity"]),
            {
                "authority_id",
                "neural_epoch",
                "config_fingerprint",
                "build_id",
                "store_identity",
                "schema_identity",
            },
        )
        self.assertNotIn(str(self.harness.root), completed.stdout)

    def test_health_cli_config_pins_the_reviewed_config_fingerprint(self) -> None:
        config_path = self.harness.config.socket_path.parent / "health-service.json"
        write_core_config(config_path, self.harness.config)
        command = [
            sys.executable,
            "core_service.py",
            "health",
            "--config",
            str(config_path),
            "--timeout",
            "2",
        ]
        completed = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["health"]["ready"])

        mismatched_wire = self.harness.config.to_wire()
        mismatched_wire["recall_count"] = self.harness.config.recall_count + 1
        write_core_config(config_path, config_from_wire(mismatched_wire))
        rejected = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        self.assertEqual(rejected.returncode, 1, rejected.stderr)
        self.assertEqual(rejected.stdout, "")

    def test_health_cli_exits_nonzero_after_emitting_unready_health(self) -> None:
        journal = self.harness.service._request_journal
        self.assertIsNotNone(journal)
        assert journal is not None
        unhealthy = journal.health(
            exact_response_keys=self.harness.service._cached_request_keys()
        )
        unhealthy.update(
            {
                "ready": False,
                "accepting_mutations": False,
                "blocker": "request_journal_capacity",
            }
        )
        with mock.patch.object(journal, "health", return_value=unhealthy):
            completed = subprocess.run(
                [
                    sys.executable,
                    "core_service.py",
                    "health",
                    "--socket",
                    str(self.harness.config.socket_path),
                    "--timeout",
                    "2",
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertIs(payload["health"]["ready"], False)

    def test_unknown_operation_and_arguments_are_content_free(self) -> None:
        request, response = self.harness.raw_request("unknown-operation", {})
        validate_response(response, expected_request=request)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "operation_unavailable")

        canary = "sk-secret-canary-12345678901234567890"
        request, response = self.harness.raw_request("status", {"unknown": canary})
        rendered = canonical_json_bytes(response)
        self.assertNotIn(canary.encode("ascii"), rendered)
        self.assertEqual(response["error"]["code"], "protocol_violation")
        self.assertEqual(response["error"], {"code": "protocol_violation", "retryable": False})

    def test_backend_exception_and_logs_do_not_expose_secret_canary(self) -> None:
        stream = io.StringIO()
        handler = __import__("logging").StreamHandler(stream)
        handler.setFormatter(SecretRedactingFormatter(SECRET_SAFE_LOG_FORMAT))
        LOGGER.addHandler(handler)
        self.addCleanup(LOGGER.removeHandler, handler)
        canary = "sk-secret-canary-12345678901234567890"
        with self.assertRaises(CoreRemoteError) as raised:
            self.harness.client().list_memory(context_id="secret")
        self.assertEqual(raised.exception.code, "operation_failed")
        self.assertNotIn(canary, stream.getvalue())
        self.assertNotIn(canary, str(raised.exception))

    def test_duplicate_mutation_request_is_served_once(self) -> None:
        request = build_request(
            request_id="req-deduplicated",
            caller="dedup-client",
            deadline_unix_ms=int((time.time() + 2.0) * 1000),
            operation="set_enabled",
            arguments={"enabled": True, "context_id": "default"},
            authentication_key=self.harness.key(),
        )
        responses = []
        for _index in range(2):
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(3.0)
            try:
                connection.connect(str(self.harness.config.socket_path))
                send_frame(connection, request)
                responses.append(receive_frame(connection))
            finally:
                connection.close()
        self.assertEqual(responses[0], responses[1])
        self.assertEqual(self.harness.backend.mutation_count, 1)

    def test_invalid_mutation_values_never_reach_or_consume_journal(self) -> None:
        journal = self.harness.service._request_journal
        self.assertIsNotNone(journal)
        assert journal is not None
        before = journal.health(
            exact_response_keys=self.harness.service._cached_request_keys()
        )
        invalid_requests = (
            (
                "set_enabled",
                {"enabled": "true", "context_id": "default"},
                "req-invalid-mutation-type",
            ),
            (
                "register_text_trace",
                {"tag": "audit", "text": ["not", "text"]},
                "req-invalid-mutation-text-shape",
            ),
            (
                "register_text_trace",
                {
                    "tag": "audit",
                    "text": "bounded",
                    "metadata": {f"key-{index}": index for index in range(257)},
                },
                "req-invalid-mutation-metadata-shape",
            ),
            (
                "repair_semantic_indexes",
                {"confirm": True},
                "req-invalid-mutation-missing-revision",
            ),
            (
                "repair_semantic_indexes",
                {"confirm": False, "expected_revision": "a" * 64},
                "req-invalid-mutation-confirmation",
            ),
        )
        with mock.patch.object(
            self.harness.service,
            "_journal_accept",
            wraps=self.harness.service._journal_accept,
        ) as accept:
            for operation, arguments, request_id in invalid_requests:
                _request, response = self.harness.raw_request(
                    operation,
                    arguments,
                    request_id=request_id,
                    caller="semantic-validation-client",
                )
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"], {
                    "code": "protocol_violation",
                    "retryable": False,
                })
                status = self.harness.client().request_status(
                    caller="semantic-validation-client",
                    request_id=request_id,
                )
                self.assertFalse(status["known"])
                self.assertEqual(status["state"], "not_found")
            self.assertEqual(accept.call_count, 0)

            _request, valid = self.harness.raw_request(
                "set_enabled",
                {"enabled": True, "context_id": "default"},
                request_id="req-valid-after-semantic-rejections",
                caller="semantic-validation-client",
            )
            self.assertTrue(valid["ok"])
            self.assertEqual(accept.call_count, 1)

        after = journal.health(
            exact_response_keys=self.harness.service._cached_request_keys()
        )
        self.assertEqual(after["used_rows"], before["used_rows"] + 1)
        self.assertEqual(after["accepted_count"], before["accepted_count"])
        self.assertEqual(
            after["explicit_ambiguous_count"],
            before["explicit_ambiguous_count"],
        )
        self.assertEqual(self.harness.backend.mutation_count, 1)

    def test_delivery_rejection_marker_cannot_downgrade_other_mutation_failure(
        self,
    ) -> None:
        def fail_closed(**_arguments: Any) -> dict[str, Any]:
            raise ContextDeliveryRejected("wrong operation")

        self.harness.service._handlers["set_enabled"] = fail_closed
        _request, response = self.harness.raw_request(
            "set_enabled",
            {"enabled": True, "context_id": "default"},
            request_id="req-unexpected-delivery-rejection",
            caller="unexpected-delivery-rejection-client",
        )

        self.assertFalse(response["ok"])
        self.assertEqual(
            response["error"],
            {"code": "outcome_unknown", "retryable": False},
        )
        status = self.harness.client().request_status(
            caller="unexpected-delivery-rejection-client",
            request_id="req-unexpected-delivery-rejection",
        )
        self.assertEqual(status["state"], "ambiguous")

    def test_raw_embedding_dimension_is_rejected_before_journal_admission(self) -> None:
        journal = self.harness.service._request_journal
        self.assertIsNotNone(journal)
        assert journal is not None
        before = journal.health(
            exact_response_keys=self.harness.service._cached_request_keys()
        )
        oversized_embedding = [0.0] * 10_000
        rejected = (
            (
                "register_trace",
                {"tag": "oversized", "embedding": oversized_embedding},
                "req-oversized-register-trace",
            ),
            (
                "query",
                {"embedding": oversized_embedding},
                "req-oversized-query",
            ),
            (
                "register_trace",
                {"tag": "dimension-drift", "embedding": [0.0] * 7},
                "req-drifted-register-trace",
            ),
        )
        with mock.patch.object(
            self.harness.service,
            "_journal_accept",
            wraps=self.harness.service._journal_accept,
        ) as accept:
            for operation, arguments, request_id in rejected:
                _request, response = self.harness.raw_request(
                    operation,
                    arguments,
                    request_id=request_id,
                    caller="embedding-budget-client",
                )
                self.assertFalse(response["ok"])
                self.assertEqual(
                    response["error"],
                    {"code": "protocol_violation", "retryable": False},
                )
                status = self.harness.client().request_status(
                    caller="embedding-budget-client",
                    request_id=request_id,
                )
                self.assertFalse(status["known"])
                self.assertEqual(status["state"], "not_found")

            _request, accepted = self.harness.raw_request(
                "register_trace",
                {"tag": "configured", "embedding": [0.0] * 8},
                request_id="req-valid-configured-embedding",
                caller="embedding-budget-client",
            )
            self.assertTrue(accepted["ok"])
            self.assertEqual(accepted["result"]["dimension"], 8)
            self.assertEqual(accept.call_count, 1)

        after = journal.health(
            exact_response_keys=self.harness.service._cached_request_keys()
        )
        self.assertEqual(after["used_rows"], before["used_rows"] + 1)
        self.assertEqual(self.harness.backend.raw_embedding_dimensions, [8])

    def test_delivery_rejections_do_not_exhaust_accepted_journal_capacity(self) -> None:
        from mlx_backend import SpikingAttentionBackend

        with TemporaryDirectory() as temporary:
            state_root = Path(temporary).resolve() / "state"
            state_root.mkdir(mode=0o700)
            config = CoreConfig(
                socket_path=state_root / "core" / "service.sock",
                state_path=state_root / "runtime_state.json",
                memory_path=state_root / "memory.sqlite3",
                dimension=8,
                num_neurons=8,
                default_top_k=4,
                recall_count=2,
                authority_timeout_seconds=0.0,
            )
            contracts = {
                name: CORE_OPERATION_CONTRACTS[name]
                for name in (
                    "health",
                    "request_status",
                    "set_enabled",
                    "ack_context_events",
                    "release_context_events",
                    "dead_letter_context_delivery",
                )
            }
            backend_holder: dict[str, SpikingAttentionBackend] = {}

            def backend_factory(lease: CoreAuthorityLease) -> SpikingAttentionBackend:
                backend = SpikingAttentionBackend(
                    dimension=config.dimension,
                    num_neurons=config.num_neurons,
                    default_top_k=config.default_top_k,
                    recall_count=config.recall_count,
                    quick_pruning_interval_seconds=(
                        config.quick_pruning_interval_seconds
                    ),
                    idle_deep_sleep_seconds=config.idle_deep_sleep_seconds,
                    compile_graph=False,
                    state_path=config.state_path,
                    memory_path=config.memory_path,
                    embedding_provider_name=config.embedding_provider_name,
                    require_native=config.require_native,
                    control_plane_only=True,
                    authority_lease=lease,
                )
                backend_holder["backend"] = backend
                return backend

            service = AuthoritativeCoreService(
                config,
                backend_factory=backend_factory,
                operation_contracts=contracts,
                operation_handlers_factory=lambda backend: {
                    "set_enabled": backend.set_enabled,
                    "ack_context_events": backend.ack_context_events,
                    "release_context_events": backend.release_context_events,
                    "dead_letter_context_delivery": (
                        backend.dead_letter_context_delivery
                    ),
                },
            )
            failures: list[BaseException] = []

            def run() -> None:
                try:
                    service.serve_forever()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            deadline = time.monotonic() + 5.0
            while (
                time.monotonic() < deadline
                and not service._started_event.is_set()
            ):
                if failures:
                    raise failures[0]
                time.sleep(0.01)
            if failures:
                raise failures[0]
            self.assertTrue(service._started_event.is_set())

            try:
                journal = service._request_journal
                self.assertIsNotNone(journal)
                assert journal is not None
                journal.max_accepted_rows = 2
                journal.max_rows = 32
                journal._health_cache = None

                backend = backend_holder["backend"]
                self.assertIs(backend, service._backend)
                authentication_key = bytes.fromhex(
                    config.socket_path.with_suffix(".sock.token").read_text(
                        "ascii"
                    )
                )

                def request(
                    operation: str,
                    arguments: dict[str, Any],
                    *,
                    request_id: str,
                ) -> dict[str, Any]:
                    return build_request(
                        request_id=request_id,
                        caller="delivery-adversary",
                        deadline_unix_ms=int((time.time() + 5.0) * 1000),
                        operation=operation,
                        arguments=arguments,
                        authentication_key=authentication_key,
                    )

                def exchange(raw_request: dict[str, Any]) -> dict[str, Any]:
                    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    connection.settimeout(3.0)
                    try:
                        connection.connect(str(config.socket_path))
                        send_frame(connection, raw_request)
                        response = receive_frame(connection)
                    finally:
                        connection.close()
                    return validate_response(response, expected_request=raw_request)

                invalid_requests: list[dict[str, Any]] = []
                for index in range(6):
                    token = f"{index:043d}"
                    invalid_receipt = "ctxrcpt_" + token
                    invalid_delivery = "ctxdel_" + token
                    invalid_requests.extend(
                        (
                            request(
                                "ack_context_events",
                                {
                                    "context_id": "delivery-test",
                                    "agent_id": "delivery-adversary",
                                    "receipt_id": invalid_receipt,
                                },
                                request_id=f"req-invalid-ack-{index}",
                            ),
                            request(
                                "release_context_events",
                                {
                                    "context_id": "delivery-test",
                                    "agent_id": "delivery-adversary",
                                    "consumer_instance_id": "delivery-instance",
                                    "receipt_ids": [invalid_receipt],
                                },
                                request_id=f"req-invalid-release-{index}",
                            ),
                            request(
                                "dead_letter_context_delivery",
                                {
                                    "context_id": "delivery-test",
                                    "agent_id": "delivery-adversary",
                                    "delivery_id": invalid_delivery,
                                    "reason": "retry budget exhausted",
                                    "confirm": True,
                                },
                                request_id=f"req-invalid-dead-letter-{index}",
                            ),
                        )
                    )

                credential_shaped_identity = "sk-" + ("A" * 24)
                pre_journal_rejections = (
                    request(
                        "ack_context_events",
                        {
                            "context_id": credential_shaped_identity,
                            "agent_id": "delivery-adversary",
                            "receipt_id": "ctxrcpt_" + ("a" * 43),
                        },
                        request_id="req-secret-shaped-ack-context",
                    ),
                    request(
                        "release_context_events",
                        {
                            "context_id": "delivery-test",
                            "agent_id": "delivery-adversary",
                            "consumer_instance_id": credential_shaped_identity,
                            "receipt_ids": ["ctxrcpt_" + ("b" * 43)],
                        },
                        request_id="req-secret-shaped-release-consumer",
                    ),
                    request(
                        "dead_letter_context_delivery",
                        {
                            "context_id": "delivery-test",
                            "agent_id": "delivery-adversary",
                            "delivery_id": credential_shaped_identity,
                            "reason": "retry budget exhausted",
                            "confirm": True,
                        },
                        request_id="req-secret-shaped-dead-letter-delivery",
                    ),
                )

                pre_journal_responses = [
                    exchange(item) for item in pre_journal_rejections
                ]
                self.assertTrue(
                    all(
                        response["error"]
                        == {"code": "protocol_violation", "retryable": False}
                        for response in pre_journal_responses
                    )
                )

                responses = [exchange(item) for item in invalid_requests]
                self.assertTrue(
                    all(
                        response["error"]
                        == {"code": "invalid_request", "retryable": False}
                        for response in responses
                    )
                )
                self.assertEqual(exchange(invalid_requests[0]), responses[0])

                status_client = CoreClient(
                    socket_path=config.socket_path,
                    caller="delivery-status-reader",
                )
                for raw_request in pre_journal_rejections:
                    status = status_client.request_status(
                        caller="delivery-adversary",
                        request_id=raw_request["request_id"],
                    )
                    self.assertFalse(status["known"])
                    self.assertEqual(status["state"], "not_found")
                for raw_request in invalid_requests:
                    status = status_client.request_status(
                        caller="delivery-adversary",
                        request_id=raw_request["request_id"],
                    )
                    self.assertEqual(status["state"], "failed")
                    self.assertEqual(status["safe_error_code"], "invalid_request")

                before_valid = status_client.health()["request_journal"]
                self.assertTrue(before_valid["accepting_mutations"])
                self.assertEqual(before_valid["accepted_count"], 0)
                self.assertEqual(before_valid["failed_count"], 18)
                self.assertEqual(before_valid["explicit_ambiguous_count"], 0)
                self.assertEqual(before_valid["accepted_capacity_remaining"], 2)

                valid_request = request(
                    "set_enabled",
                    {
                        "context_id": "delivery-test",
                        "enabled": True,
                    },
                    request_id="req-valid-mutation-after-rejections",
                )
                valid_response = exchange(valid_request)
                self.assertTrue(valid_response["ok"])
                self.assertTrue(valid_response["result"]["effective_enabled"])

                after_valid = status_client.health()["request_journal"]
                self.assertTrue(after_valid["accepting_mutations"])
                self.assertEqual(after_valid["completed_count"], 1)
                self.assertEqual(after_valid["failed_count"], 18)
                self.assertEqual(after_valid["explicit_ambiguous_count"], 0)
                self.assertEqual(after_valid["accepted_capacity_remaining"], 2)
            finally:
                service.close()
                thread.join(timeout=3.0)
                self.assertFalse(thread.is_alive())

    def test_health_bypasses_serialized_backend_lane_and_backend_stays_serial(self) -> None:
        results: list[dict[str, Any]] = []

        def blocked_read() -> None:
            results.append(self.harness.client(caller=f"reader-{len(results)}").status(context_id="block"))

        first = threading.Thread(target=blocked_read)
        second = threading.Thread(target=blocked_read)
        first.start()
        self.assertTrue(self.harness.backend.block_entered.wait(2.0))
        second.start()
        started = time.monotonic()
        health = self.harness.client(caller="health-client").health(timeout_seconds=1.0)
        self.assertLess(time.monotonic() - started, 0.75)
        self.assertTrue(health["ready"])
        self.assertEqual(self.harness.backend.maximum_active_handlers, 1)
        self.harness.backend.block_release.set()
        first.join(3.0)
        second.join(3.0)
        self.assertEqual(len(results), 2)
        self.assertEqual(self.harness.backend.maximum_active_handlers, 1)

    def test_replaced_authority_lock_fences_health_and_every_handler(self) -> None:
        lock_path = self.harness.config.memory_path.parent / "core" / "authority.lock"
        displaced = lock_path.with_name("authority.lock.displaced")
        lock_path.rename(displaced)
        lock_path.write_bytes(b"replacement")
        os.chmod(lock_path, 0o600)

        try:
            health = self.harness.client(caller="fence-health").health()
        except CoreUnavailable:
            # The listener may close between accept and the authenticated
            # health response once the fencing failure is observed.
            health = None
        except CoreRemoteError as exc:
            # Or the already-authenticated request may receive the service's
            # closed error before the listener teardown wins the race.
            self.assertEqual(exc.code, "service_unavailable")
            health = None
        if health is not None:
            self.assertFalse(health["ready"])
            self.assertFalse(health["authority"]["ready"])
        before = self.harness.backend.mutation_count
        try:
            self.harness.client(caller="fence-mutation").set_enabled(True)
        except CoreUnavailable:
            pass
        except CoreRemoteError as exc:
            self.assertEqual(exc.code, "service_unavailable")
        else:
            self.fail("fenced mutation unexpectedly reached the backend")
        self.assertEqual(self.harness.backend.mutation_count, before)

    def test_replaced_database_inode_fences_health_and_every_handler(self) -> None:
        displaced = self.harness.config.memory_path.with_suffix(".sqlite3.displaced")
        self.harness.config.memory_path.rename(displaced)
        self.harness.config.memory_path.write_bytes(b"")
        os.chmod(self.harness.config.memory_path, 0o600)

        try:
            health = self.harness.client(caller="database-fence-health").health()
        except CoreUnavailable:
            health = None
        except CoreRemoteError as exc:
            self.assertEqual(exc.code, "service_unavailable")
            health = None
        if health is not None:
            self.assertFalse(health["ready"])
            self.assertFalse(health["authority"]["ready"])
        before = self.harness.backend.read_count
        try:
            self.harness.client(caller="database-fence-read").status()
        except CoreUnavailable:
            pass
        except CoreRemoteError as exc:
            self.assertEqual(exc.code, "service_unavailable")
        else:
            self.fail("fenced read unexpectedly reached the backend")
        self.assertEqual(self.harness.backend.read_count, before)

    def test_changed_durable_authority_marker_fences_service(self) -> None:
        connection = sqlite3.connect(self.harness.config.memory_path)
        try:
            connection.execute(
                "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                ('{"service_required":false}', "core_authority"),
            )
            connection.commit()
        finally:
            connection.close()

        health = self.harness.service._health_result()
        self.assertFalse(health["ready"])
        self.assertFalse(health["authority"]["ready"])
        before = self.harness.backend.mutation_count
        with self.assertRaises(CoreUnavailable):
            self.harness.client(caller="marker-fence-mutation").set_enabled(True)
        self.assertEqual(self.harness.backend.mutation_count, before)

    def test_every_claimed_authority_marker_field_is_an_immutable_live_fence(
        self,
    ) -> None:
        def alternate(current: str, *, prefix: str, width: int) -> str:
            first = prefix + ("a" * width)
            return first if current != first else prefix + ("b" * width)

        def replace_identifier(
            field: str,
            *,
            prefix: str,
            width: int,
        ) -> Any:
            return lambda marker: marker.__setitem__(
                field,
                alternate(str(marker[field]), prefix=prefix, width=width),
            )

        cases = (
            (
                "store_identity",
                replace_identifier("store_identity", prefix="store-", width=24),
            ),
            (
                "request_journal_id",
                replace_identifier(
                    "request_journal_id", prefix="journal-", width=24
                ),
            ),
            (
                "request_journal_binding_schema",
                lambda marker: marker.__setitem__(
                    "request_journal_binding_schema",
                    "synapse-s2.request-journal-binding.v2",
                ),
            ),
            (
                "request_journal_schema_version",
                lambda marker: marker.__setitem__(
                    "request_journal_schema_version",
                    int(marker["request_journal_schema_version"]) + 1,
                ),
            ),
            (
                "root_generation_id",
                replace_identifier(
                    "root_generation_id", prefix="generation-", width=24
                ),
            ),
            (
                "lock_generation_id",
                lambda marker: marker.__setitem__(
                    "lock_generation_id",
                    "lockfs-v1-1-2",
                ),
            ),
            (
                "embedding_space_identity",
                replace_identifier(
                    "embedding_space_identity", prefix="", width=64
                ),
            ),
            (
                "restored_target_binding_receipt_digest",
                lambda marker: marker.__setitem__(
                    "restored_target_binding_receipt_digest",
                    alternate(
                        str(
                            marker["restored_target_binding_receipt_digest"]
                            or ""
                        ),
                        prefix="",
                        width=64,
                    ),
                ),
            ),
            (
                "claimed_at",
                lambda marker: marker.__setitem__(
                    "claimed_at", float(marker["claimed_at"]) - 0.25
                ),
            ),
            (
                "updated_at",
                lambda marker: marker.__setitem__(
                    "updated_at", float(marker["updated_at"]) + 0.25
                ),
            ),
        )
        for field, mutate in cases:
            with self.subTest(field=field):
                harness = ServiceHarness()
                try:
                    with closing(sqlite3.connect(harness.config.memory_path)) as conn:
                        row = conn.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_authority",),
                        ).fetchone()
                        self.assertIsNotNone(row)
                        marker = json.loads(str(row[0]))
                        mutate(marker)
                        conn.execute(
                            """
                            UPDATE store_metadata
                            SET value_json = ?, updated_at = ?
                            WHERE key = ?
                            """,
                            (
                                json.dumps(
                                    marker,
                                    sort_keys=True,
                                    separators=(",", ":"),
                                ),
                                float(marker["updated_at"]),
                                "core_authority",
                            ),
                        )
                        conn.commit()

                    health = harness.service._health_result()
                    self.assertFalse(health["ready"])
                    self.assertFalse(health["authority"]["ready"])
                    before = harness.backend.read_count
                    with self.assertRaises(CoreUnavailable):
                        harness.client(caller=f"marker-{field}").status()
                    self.assertEqual(harness.backend.read_count, before)
                finally:
                    harness.close()

    def test_unknown_authority_marker_field_fences_closed_contract(self) -> None:
        with closing(sqlite3.connect(self.harness.config.memory_path)) as conn:
            row = conn.execute(
                "SELECT value_json FROM store_metadata WHERE key = ?",
                ("core_authority",),
            ).fetchone()
            self.assertIsNotNone(row)
            marker = json.loads(str(row[0]))
            marker["unclaimed_extension"] = "valid-looking-but-unclaimed"
            conn.execute(
                "UPDATE store_metadata SET value_json = ? WHERE key = ?",
                (
                    json.dumps(marker, sort_keys=True, separators=(",", ":")),
                    "core_authority",
                ),
            )
            conn.commit()

        health = self.harness.service._health_result()
        self.assertFalse(health["ready"])
        self.assertFalse(health["authority"]["ready"])

    def test_stale_backend_lane_is_unready_and_close_retains_authority(self) -> None:
        outcomes: list[Any] = []

        def blocked_read() -> None:
            try:
                outcomes.append(
                    self.harness.client(caller="stale-lane-reader").status(
                        context_id="block"
                    )
                )
            except Exception as exc:
                outcomes.append(exc)

        caller = threading.Thread(target=blocked_read)
        caller.start()
        self.assertTrue(self.harness.backend.block_entered.wait(2.0))
        with self.harness.service._backend_lane_state_lock:
            self.harness.service._backend_lane_deadline_monotonic = (
                time.monotonic() - 1.0
            )
        health = self.harness.service._health_result()
        self.assertFalse(health["ready"])
        self.assertEqual(health["backend_lane"]["blocker"], "backend_lane_stalled")

        with mock.patch("core_service.BACKEND_LANE_CLOSE_GRACE_SECONDS", 0.05):
            started = time.monotonic()
            self.harness.service.close()
            self.assertLess(time.monotonic() - started, 1.5)
        with self.assertRaises(CoreAuthorityError):
            CoreAuthorityLease.acquire_core(
                self.harness.config.memory_path,
                timeout_seconds=0.0,
            )
        self.harness.backend.block_release.set()
        caller.join(3.0)
        self.harness.service.close()
        lease = CoreAuthorityLease.acquire_core(
            self.harness.config.memory_path,
            timeout_seconds=0.0,
        )
        lease.close()

    def test_replication_lane_is_bounded_and_health_reports_maintenance(self) -> None:
        service = self.harness.service
        floor = service._backend_lane_timeout_floor(
            "replication_create_checkpoint"
        )
        self.assertEqual(floor, REPLICATION_MAINTENANCE_LANE_SECONDS)
        self.assertEqual(floor, 300.0)
        started = time.monotonic() - 31.0
        acquired = service._acquire_backend_lane(
            owner="replication-maintenance",
            timeout=0.0,
            deadline_monotonic=started + floor,
        )
        self.assertTrue(acquired)
        try:
            with service._backend_lane_state_lock:
                service._backend_lane_started_monotonic = started
            health = service._health_result()
            self.assertTrue(health["ready"])
            self.assertEqual(health["operational_state"], "maintenance")
            self.assertTrue(health["backend_lane"]["ready"])
            self.assertTrue(health["backend_lane"]["active"])
            self.assertTrue(health["backend_lane"]["maintenance"])
            self.assertTrue(health["backend_lane"]["degraded"])
            self.assertFalse(
                health["backend_lane"]["accepting_ordinary_operations"]
            )
            self.assertGreaterEqual(health["backend_lane"]["active_age_ms"], 30_000)
            self.assertIsNone(health["backend_lane"]["blocker"])
            reconciliation = self.harness.client().request_status(
                caller="replication-timeout-check",
                request_id="req-replication-timeout-check",
            )
            self.assertFalse(reconciliation["known"])
            self.assertEqual(reconciliation["state"], "not_found")
        finally:
            service._release_backend_lane()

    def test_hanging_backend_close_is_bounded_and_retains_all_references(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        original_close = self.harness.backend.close

        def hanging_close() -> None:
            entered.set()
            release.wait(5.0)
            original_close()

        self.harness.backend.close = hanging_close  # type: ignore[method-assign]
        backend = self.harness.service._backend
        journal = self.harness.service._request_journal
        authority = self.harness.service._authority_lease
        try:
            with mock.patch("core_service.BACKEND_LANE_CLOSE_GRACE_SECONDS", 0.05):
                started = time.monotonic()
                self.harness.service.close()
                elapsed = time.monotonic() - started
            self.assertTrue(entered.is_set())
            self.assertLess(elapsed, 0.5)
            self.assertIs(self.harness.service._backend, backend)
            self.assertIs(self.harness.service._request_journal, journal)
            self.assertIs(self.harness.service._authority_lease, authority)
            self.assertEqual(
                self.harness.service._backend_lane_owner,
                "shutdown",
            )
            assert authority is not None
            authority.assert_core_for(self.harness.config.memory_path)
            with self.assertRaises(CoreAuthorityError):
                CoreAuthorityLease.acquire_core(
                    self.harness.config.memory_path,
                    timeout_seconds=0.0,
                )
        finally:
            release.set()
            self.harness.service._shutdown_teardown_complete.wait(2.0)

    def test_hanging_store_close_fallback_is_bounded_and_retains_authority(self) -> None:
        entered = threading.Event()
        release = threading.Event()
        store = self.harness.backend.memory_store
        assert store is not None
        original_store_close = store.close

        def hanging_store_close() -> None:
            entered.set()
            release.wait(5.0)
            original_store_close()

        self.harness.backend.close = None  # type: ignore[method-assign]
        store.close = hanging_store_close  # type: ignore[method-assign]
        authority = self.harness.service._authority_lease
        try:
            with mock.patch("core_service.BACKEND_LANE_CLOSE_GRACE_SECONDS", 0.05):
                started = time.monotonic()
                self.harness.service.close()
                elapsed = time.monotonic() - started
            self.assertTrue(entered.is_set())
            self.assertLess(elapsed, 0.5)
            self.assertIs(self.harness.service._backend, self.harness.backend)
            self.assertIs(self.harness.service._authority_lease, authority)
            assert authority is not None
            authority.assert_core_for(self.harness.config.memory_path)
        finally:
            release.set()
            self.harness.service._shutdown_teardown_complete.wait(2.0)

    def test_raising_backend_close_retains_lane_journal_and_authority(self) -> None:
        original_close = self.harness.backend.close

        def raising_close() -> None:
            raise RuntimeError("synthetic close failure")

        self.harness.backend.close = raising_close  # type: ignore[method-assign]
        backend = self.harness.service._backend
        journal = self.harness.service._request_journal
        authority = self.harness.service._authority_lease
        try:
            with mock.patch("core_service.BACKEND_LANE_CLOSE_GRACE_SECONDS", 0.05):
                started = time.monotonic()
                self.harness.service.close()
                elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.5)
            self.assertIs(self.harness.service._backend, backend)
            self.assertIs(self.harness.service._request_journal, journal)
            self.assertIs(self.harness.service._authority_lease, authority)
            self.assertEqual(
                self.harness.service._backend_lane_owner,
                "shutdown",
            )
            assert authority is not None
            authority.assert_core_for(self.harness.config.memory_path)
        finally:
            # An injected raising hook creates deliberately unknowable partial
            # teardown. Reset only the test double so normal harness cleanup can
            # prove a fresh complete close; production never performs this retry.
            self.harness.backend.close = original_close  # type: ignore[method-assign]
            with self.harness.service._backend_lane_state_lock:
                self.harness.service._backend_lane_owner = None
                self.harness.service._backend_lane_started_monotonic = None
                self.harness.service._backend_lane_deadline_monotonic = None
            if self.harness.service._backend_lane.locked():
                self.harness.service._backend_lane.release()
            self.harness.service._shutdown_teardown_thread = None
            self.harness.service._shutdown_teardown_complete.clear()
            self.harness.service._shutdown_teardown_succeeded = False

    def test_raising_store_close_fallback_retains_every_reference(self) -> None:
        store = self.harness.backend.memory_store
        assert store is not None
        original_backend_close = self.harness.backend.close
        original_store_close = store.close

        def raising_store_close() -> None:
            raise RuntimeError("synthetic store close failure")

        self.harness.backend.close = None  # type: ignore[method-assign]
        store.close = raising_store_close  # type: ignore[method-assign]
        backend = self.harness.service._backend
        journal = self.harness.service._request_journal
        authority = self.harness.service._authority_lease
        try:
            with mock.patch("core_service.BACKEND_LANE_CLOSE_GRACE_SECONDS", 0.05):
                self.harness.service.close()
            self.assertIs(self.harness.service._backend, backend)
            self.assertIs(self.harness.service._request_journal, journal)
            self.assertIs(self.harness.service._authority_lease, authority)
            assert authority is not None
            authority.assert_core_for(self.harness.config.memory_path)
        finally:
            self.harness.backend.close = original_backend_close  # type: ignore[method-assign]
            store.close = original_store_close  # type: ignore[method-assign]
            with self.harness.service._backend_lane_state_lock:
                self.harness.service._backend_lane_owner = None
                self.harness.service._backend_lane_started_monotonic = None
                self.harness.service._backend_lane_deadline_monotonic = None
            if self.harness.service._backend_lane.locked():
                self.harness.service._backend_lane.release()
            self.harness.service._shutdown_teardown_thread = None
            self.harness.service._shutdown_teardown_complete.clear()
            self.harness.service._shutdown_teardown_succeeded = False

    def test_partial_frame_flood_releases_every_connection_slot(self) -> None:
        for _index in range(48):
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.connect(str(self.harness.config.socket_path))
            connection.sendall(b"\x00\x00")
            connection.close()
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            with self.harness.service._workers_lock:
                if not self.harness.service._workers:
                    break
            time.sleep(0.02)
        self.assertTrue(self.harness.client().health()["ready"])
        with self.harness.service._workers_lock:
            self.assertLessEqual(len(self.harness.service._workers), 1)

    def test_held_partial_frames_cannot_starve_authenticated_health(self) -> None:
        partial_connections: list[socket.socket] = []
        try:
            for _index in range(MAX_ACTIVE_CONNECTIONS):
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    connection.settimeout(3.0)
                    connection.connect(str(self.harness.config.socket_path))
                    connection.sendall(b"\x00\x00\x10\x00{")
                except BaseException:
                    connection.close()
                    raise
                partial_connections.append(connection)

            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                with self.harness.service._workers_lock:
                    if len(self.harness.service._workers) == MAX_ACTIVE_CONNECTIONS:
                        break
                time.sleep(0.01)
            with self.harness.service._workers_lock:
                self.assertEqual(
                    len(self.harness.service._workers),
                    MAX_ACTIVE_CONNECTIONS,
                )

            started = time.monotonic()
            health = self.harness.client(caller="health-under-partial-flood").health(
                timeout_seconds=3.0
            )
            self.assertTrue(health["ready"])
            self.assertLess(time.monotonic() - started, 3.0)
        finally:
            for connection in partial_connections:
                connection.close()

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            with self.harness.service._workers_lock:
                if not self.harness.service._workers:
                    break
            time.sleep(0.01)
        with self.harness.service._workers_lock:
            self.assertFalse(self.harness.service._workers)
        self.assertTrue(
            self.harness.client(caller="health-after-partial-flood").health()[
                "ready"
            ]
        )

    def test_unavailable_peer_uid_fails_closed_before_dispatch(self) -> None:
        with mock.patch("core_service.peer_uid", return_value=None):
            with self.assertRaises(CoreUnavailable):
                self.harness.client().status()
        self.assertEqual(self.harness.backend.read_count, 0)

    def test_safe_reads_are_not_cached_and_oversized_reads_fail_bounded(self) -> None:
        calls = 0

        def oversized_read(**_arguments: Any) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            return {"chunks": ["x" * 250_000 for _index in range(5)]}

        self.harness.service._handlers["list_memory"] = oversized_read
        for _index in range(2):
            with self.assertRaises(CoreRemoteError) as raised:
                self.harness.client().list_memory(context_id="default")
            self.assertEqual(raised.exception.code, "operation_failed")
        self.assertEqual(calls, 2)
        self.assertEqual(len(self.harness.service._request_cache), 0)
        self.assertEqual(self.harness.service._request_cache_bytes, 0)

    def test_oversized_mutation_result_is_ambiguous_and_never_replayed(self) -> None:
        def oversized_mutation(**_arguments: Any) -> dict[str, Any]:
            self.harness.backend.mutation_count += 1
            return {"chunks": ["x" * 250_000 for _index in range(5)]}

        self.harness.service._handlers["set_enabled"] = oversized_mutation
        client = self.harness.client(caller="oversized-mutation")
        request, response = self.harness.raw_request(
            "set_enabled",
            {"enabled": True, "context_id": "default"},
            request_id="req-oversized-result",
            caller="oversized-mutation",
        )
        self.assertEqual(response["error"]["code"], "outcome_unknown")
        self.assertEqual(self.harness.backend.mutation_count, 1)
        status = client.request_status(
            caller="oversized-mutation",
            request_id="req-oversized-result",
        )
        self.assertEqual(status["state"], "ambiguous")
        repeated = self.harness.exchange_request(request)
        self.assertEqual(repeated["error"]["code"], "outcome_unknown")
        self.assertEqual(self.harness.backend.mutation_count, 1)

    def test_mutation_cache_eviction_never_reexecutes_old_request(self) -> None:
        with mock.patch("core_service.MAX_REQUEST_CACHE_ENTRIES", 1):
            first_request, first = self.harness.raw_request(
                "set_enabled",
                {"enabled": True, "context_id": "default"},
                request_id="req-cache-first",
                caller="cache-client",
            )
            _second_request, second = self.harness.raw_request(
                "set_enabled",
                {"enabled": False, "context_id": "default"},
                request_id="req-cache-second",
                caller="cache-client",
            )
            repeated = self.harness.exchange_request(first_request)
        self.assertTrue(first["ok"])
        self.assertTrue(second["ok"])
        self.assertEqual(repeated["error"]["code"], "outcome_unknown")
        self.assertEqual(self.harness.backend.mutation_count, 2)
        self.assertLessEqual(len(self.harness.service._request_cache), 1)
        self.assertLessEqual(
            self.harness.service._request_cache_bytes,
            32 * 1024 * 1024,
        )

    def test_mutation_cache_byte_budget_evicts_without_reexecution(self) -> None:
        with mock.patch("core_service.MAX_REQUEST_CACHE_BYTES", 1):
            request, first = self.harness.raw_request(
                "set_enabled",
                {"enabled": True, "context_id": "default"},
                request_id="req-byte-budget",
                caller="byte-budget-client",
            )
            repeated = self.harness.exchange_request(request)
        self.assertTrue(first["ok"])
        self.assertEqual(repeated["error"]["code"], "outcome_unknown")
        self.assertEqual(self.harness.backend.mutation_count, 1)
        self.assertEqual(len(self.harness.service._request_cache), 0)
        self.assertEqual(self.harness.service._request_cache_bytes, 0)

    def test_cache_failure_after_journal_finish_returns_outcome_unknown(self) -> None:
        with mock.patch.object(
            self.harness.service,
            "_cache_store",
            side_effect=RuntimeError("synthetic cache failure"),
        ):
            _request, response = self.harness.raw_request(
                "set_enabled",
                {"enabled": True, "context_id": "default"},
                request_id="req-cache-failure",
                caller="cache-failure-client",
            )
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "outcome_unknown")
        self.assertEqual(self.harness.backend.mutation_count, 1)
        status = self.harness.client().request_status(
            caller="cache-failure-client",
            request_id="req-cache-failure",
        )
        self.assertEqual(status["state"], "completed")

    def test_close_preserves_replacement_socket_identity(self) -> None:
        original_path = self.harness.config.socket_path
        moved_path = original_path.with_name("old-service.sock")
        original_path.rename(moved_path)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement.bind(str(original_path))
        os.chmod(original_path, 0o600)
        replacement_identity = (
            original_path.lstat().st_dev,
            original_path.lstat().st_ino,
        )
        self.harness.service.close()
        self.assertTrue(original_path.exists())
        self.assertEqual(
            (original_path.lstat().st_dev, original_path.lstat().st_ino),
            replacement_identity,
        )
        replacement.close()
        original_path.unlink()

    def test_shutdown_drains_handler_before_releasing_authority(self) -> None:
        client_result: list[Any] = []

        def blocked_read() -> None:
            try:
                client_result.append(self.harness.client().status(context_id="block"))
            except Exception as exc:  # response delivery is not the authority assertion
                client_result.append(exc)

        caller = threading.Thread(target=blocked_read)
        caller.start()
        self.assertTrue(self.harness.backend.block_entered.wait(2.0))
        closer = threading.Thread(target=self.harness.service.close)
        closer.start()
        time.sleep(0.1)
        with self.assertRaises(CoreAuthorityError):
            CoreAuthorityLease.acquire_core(
                self.harness.config.memory_path,
                timeout_seconds=0.0,
            )
        self.assertTrue(closer.is_alive())
        self.harness.backend.block_release.set()
        caller.join(3.0)
        closer.join(3.0)
        self.assertFalse(closer.is_alive())
        lease = CoreAuthorityLease.acquire_core(
            self.harness.config.memory_path,
            timeout_seconds=0.0,
        )
        lease.close()

    def test_real_backend_surface_matches_closed_operation_contracts(self) -> None:
        from mlx_backend import SpikingAttentionBackend
        from replication_manager import ReplicationManager

        # These backend-only parameters remain available for explicit offline-v5
        # maintenance. They are absent from the RPC contracts and are injected
        # exclusively by the authoritative service after path authorization.
        server_owned_arguments = {
            "backup_recovery_bundle": frozenset(
                {"capture_root", "allow_noncanonical_capture_root"}
            ),
            "audit_capture_ledger": frozenset({"capture_root"}),
            "repair_capture_ledger": frozenset({"capture_root"}),
            "verify_recovery_bundle": frozenset({"capture_root"}),
            "restore_recovery_bundle_isolated": frozenset({"capture_root"}),
            "plan_recovery_retention": frozenset({"directory"}),
            "apply_recovery_retention": frozenset({"directory"}),
        }
        uninitialized_backend = SpikingAttentionBackend.__new__(SpikingAttentionBackend)
        backend_handlers = _bind_default_backend_handlers(uninitialized_backend)
        uninitialized_manager = ReplicationManager.__new__(ReplicationManager)
        replication_handlers = _bind_replication_handlers(uninitialized_manager)
        self.assertEqual(
            frozenset(backend_handlers),
            frozenset(CORE_OPERATION_CONTRACTS)
            - SERVICE_CONTROL_OPERATIONS
            - REPLICATION_OPERATIONS,
        )
        self.assertEqual(
            frozenset(replication_handlers),
            REPLICATION_OPERATIONS,
        )
        self.assertEqual(
            frozenset(backend_handlers) | frozenset(replication_handlers),
            frozenset(CORE_OPERATION_CONTRACTS) - SERVICE_CONTROL_OPERATIONS,
        )
        for operation, contract in CORE_OPERATION_CONTRACTS.items():
            if operation in SERVICE_CONTROL_OPERATIONS:
                continue
            if operation in REPLICATION_OPERATIONS:
                signature = inspect.signature(replication_handlers[operation])
                parameters = dict(signature.parameters)
            else:
                method_name = (
                    "resource_profile"
                    if operation == "benchmark_resource_profile"
                    else operation
                )
                signature = inspect.signature(
                    getattr(SpikingAttentionBackend, method_name)
                )
                parameters = {
                    name: parameter
                    for name, parameter in signature.parameters.items()
                    if name != "self"
                }
                if operation in {
                    "resource_profile",
                    "benchmark_resource_profile",
                }:
                    parameters.pop("benchmark_quick_prune")
            self.assertEqual(
                contract.allowed_arguments
                | server_owned_arguments.get(operation, frozenset()),
                frozenset(parameters),
                operation,
            )
            required = frozenset(
                name
                for name, parameter in parameters.items()
                if parameter.default is inspect.Parameter.empty
            )
            self.assertEqual(contract.required_arguments, required, operation)


class CoreCaptureHealthTests(unittest.TestCase):
    def test_capture_loop_uses_core_and_exposes_only_content_free_heartbeat(self) -> None:
        harness = ServiceHarness(capture=True)
        self.addCleanup(harness.close)
        deadline = time.monotonic() + 2.0
        health: dict[str, Any] = {}
        while time.monotonic() < deadline:
            health = harness.client().health()
            if health["capture"]["ready"]:
                break
            time.sleep(0.02)
        capture = health["capture"]
        self.assertTrue(capture["enabled"])
        self.assertTrue(capture["ready"])
        self.assertGreaterEqual(capture["iteration_count"], 1)
        self.assertNotIn("root", capture)
        self.assertNotIn("file", canonical_json_bytes(capture).decode("utf-8"))


class RealBackendCoreIntegrationTests(unittest.TestCase):
    def config(self, root: Path) -> CoreConfig:
        state_root = root / "state"
        state_root.mkdir(mode=0o700)
        os.chmod(state_root, 0o700)
        return CoreConfig(
            socket_path=state_root / "core" / "service.sock",
            state_path=state_root / "runtime_state.json",
            memory_path=state_root / "memory.sqlite3",
            dimension=8,
            num_neurons=8,
            default_top_k=4,
            recall_count=2,
            authority_timeout_seconds=0.0,
        )

    def test_fresh_real_backend_starts_claims_v6_and_serves_health(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            service = AuthoritativeCoreService(config)
            failures: list[BaseException] = []

            def run() -> None:
                try:
                    service.serve_forever()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not config.socket_path.exists():
                if failures:
                    break
                time.sleep(0.02)
            try:
                self.assertEqual(failures, [])
                health = CoreClient(
                    socket_path=config.socket_path,
                    default_timeout_seconds=3.0,
                ).health()
                self.assertTrue(health["ready"])
                self.assertRegex(service.identity["neural_epoch"], r"^epoch-[1-9][0-9]*$")
                self.assertEqual(service.identity["schema_identity"], "sqlite-53324442-v6")
                connection = sqlite3.connect(config.memory_path)
                try:
                    self.assertEqual(
                        int(connection.execute("PRAGMA user_version").fetchone()[0]),
                        6,
                    )
                    marker = connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                finally:
                    connection.close()
                self.assertIsNotNone(marker)
                marker_payload = json.loads(marker[0])
                self.assertRegex(
                    marker_payload["root_generation_id"],
                    r"^generation-[0-9a-f]{24}$",
                )
                self.assertEqual(
                    marker_payload["embedding_space_identity"],
                    config.embedding_space_identity,
                )
                self.assertEqual(
                    marker_payload["lock_generation_id"],
                    service._authority_lease.lock_generation_id,
                )
                runtime_payload = json.loads(
                    config.state_path.read_text(encoding="utf-8")
                )
                self.assertEqual(runtime_payload["version"], 3)
                self.assertEqual(
                    runtime_payload["authority_binding"],
                    DurableMemoryStore.runtime_state_authority_binding_for_marker(
                        marker_payload
                    ),
                )
                self.assertTrue(
                    (config.socket_path.parent / "store-generation.json").is_file()
                )
            finally:
                service.close()
                thread.join(timeout=5.0)

    def test_replication_fingerprint_mismatch_is_rejected_before_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary).resolve())
            service = AuthoritativeCoreService(config)
            failures: list[BaseException] = []

            def run() -> None:
                try:
                    service.serve_forever()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not config.socket_path.exists():
                if failures:
                    break
                time.sleep(0.02)
            try:
                self.assertEqual(failures, [])
                client = CoreClient(
                    socket_path=config.socket_path,
                    caller="replication-prevalidation-test",
                    default_timeout_seconds=3.0,
                )
                descriptor = client.replication_identity()
                descriptor_path = (
                    config.memory_path.parent
                    / "replication"
                    / "inbox"
                    / "peer.json"
                )
                descriptor_path.write_text(
                    json.dumps(descriptor, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                os.chmod(descriptor_path, 0o600)
                journal = service._request_journal
                self.assertIsNotNone(journal)
                assert journal is not None

                def journal_rows() -> int:
                    with closing(sqlite3.connect(journal.path)) as connection:
                        return int(
                            connection.execute(
                                "SELECT count(*) FROM request_journal"
                            ).fetchone()[0]
                        )

                before = journal_rows()
                request_id = "req-replication-bad-fingerprint"
                with self.assertRaises(CoreRemoteError) as raised:
                    client.call(
                        "replication_pair_peer",
                        {
                            "descriptor_path": str(descriptor_path),
                            "expected_descriptor_digest": "0" * 64,
                            "lineage_id": "s2lineage_" + ("1" * 32),
                            "direction": "send",
                            "confirm": True,
                        },
                        request_id=request_id,
                    )
                self.assertEqual(raised.exception.code, "invalid_request")
                self.assertEqual(journal_rows(), before)
                reconciliation = client.request_status(
                    caller=client.delivery_instance_id,
                    request_id=request_id,
                )
                self.assertFalse(reconciliation["known"])
                self.assertEqual(reconciliation["state"], "not_found")
            finally:
                service.close()
                thread.join(timeout=5.0)

    def test_core_binds_bridge_actor_and_keeps_pending_recall_isolated(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            service = AuthoritativeCoreService(config)
            failures: list[BaseException] = []

            def run() -> None:
                try:
                    service.serve_forever()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not config.socket_path.exists():
                if failures:
                    break
                time.sleep(0.02)
            try:
                self.assertEqual(failures, [])
                client = CoreClient(
                    socket_path=config.socket_path,
                    caller="claimed-alice",
                    default_timeout_seconds=3.0,
                )
                reviewer_client = CoreClient(
                    socket_path=config.socket_path,
                    caller="claimed-bob",
                    default_timeout_seconds=3.0,
                )
                for context in ("alpha", "beta"):
                    client.register_text_trace(
                        tag=f"{context}-bridge-memory",
                        text=f"{context} governed bridge evidence",
                        context_id=context,
                    )
                proposed = client.propose_namespace_link(
                    source_context_id="alpha",
                    target_context_id="beta",
                    proposed_by="forged-proposer",
                    reason="The bridge requires an explicit current review.",
                    governance_request_id="core-bridge-proposal",
                )
                proposal = proposed["proposal"]
                pending_scope = client.resolve_recall_contexts(
                    context_id="alpha", recall_scope="connected"
                )
                reviewed = reviewer_client.review_namespace_link(
                    proposal_id=proposal["proposal_id"],
                    decision="approve",
                    expected_revision=proposal["revision"],
                    reviewed_by="forged-reviewer",
                    reason="The authenticated client approved current evidence.",
                    governance_request_id="core-bridge-review",
                )
                active_scope = client.resolve_recall_contexts(
                    context_id="alpha", recall_scope="connected"
                )

                self.assertTrue(
                    proposal["proposed_by"].startswith("core:local-owner:")
                )
                self.assertNotEqual(proposal["proposed_by"], "forged-proposer")
                self.assertEqual(
                    [row["context_id"] for row in pending_scope],
                    ["alpha", "global"],
                )
                self.assertTrue(
                    reviewed["proposal"]["reviewed_by"].startswith(
                        "core:local-owner:"
                    )
                )
                self.assertEqual(
                    reviewed["proposal"]["reviewed_by"],
                    proposal["proposed_by"],
                )
                self.assertNotEqual(
                    reviewed["proposal"]["reviewed_by"], "forged-reviewer"
                )
                self.assertEqual(
                    [row["context_id"] for row in active_scope],
                    ["alpha", "beta", "global"],
                )
                self.assertEqual(client.audit_namespace_link_governance()["status"], "ready")

                link = reviewed["link"]
                with closing(sqlite3.connect(config.memory_path)) as connection:
                    connection.execute(
                        "UPDATE context_relationships SET source_context_id = ? "
                        "WHERE context_link_id = ?",
                        ("tampered", link["context_link_id"]),
                    )
                    connection.commit()
                request_id = "req-core-bridge-integrity-failure"
                with self.assertRaises(CoreRemoteError) as raised:
                    client.call(
                        "disable_namespace_link",
                        {
                            "context_link_id": link["context_link_id"],
                            "expected_revision": reviewed["proposal"]["revision"],
                            "disabled_by": "forged-disabler",
                            "reason": "The core must classify projection tamper safely.",
                            "governance_request_id": "core-bridge-integrity-failure",
                            "confirm": True,
                        },
                        request_id=request_id,
                    )
                self.assertEqual(raised.exception.code, "service_unavailable")
                status = client.request_status(
                    caller=client.delivery_instance_id,
                    request_id=request_id,
                )
                self.assertEqual(status["state"], "failed")
                self.assertEqual(status["safe_error_code"], "service_unavailable")
            finally:
                service.close()
                thread.join(timeout=5.0)

    def test_retrieval_v2_is_structured_and_never_admitted_to_mutation_journal(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            service = AuthoritativeCoreService(config)
            failures: list[BaseException] = []

            def run() -> None:
                try:
                    service.serve_forever()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not config.socket_path.exists():
                if failures:
                    break
                time.sleep(0.02)
            try:
                self.assertEqual(failures, [])
                client = CoreClient(
                    socket_path=config.socket_path,
                    caller="retrieval-v2-core-test",
                    default_timeout_seconds=3.0,
                )
                client.register_text_trace(
                    tag="ptz-control-room",
                    text="PTZ camera control room routing evidence.",
                    context_id="ops",
                )

                journal = service._request_journal
                self.assertIsNotNone(journal)
                assert journal is not None

                def journal_rows() -> int:
                    with closing(sqlite3.connect(journal.path)) as connection:
                        return int(
                            connection.execute(
                                "SELECT COUNT(*) FROM request_journal"
                            ).fetchone()[0]
                        )

                before_rows = journal_rows()
                original_handler = service._handlers["retrieve_text_v2"]
                handler = mock.Mock(wraps=original_handler)
                service._handlers["retrieve_text_v2"] = handler
                arguments = {
                    "prompt": "PTZ camera control room",
                    "context_id": "ops",
                    "recall_scope": "local",
                    "result_limit": 1,
                    "candidate_limit": 8,
                    "include_graph_neighbors": False,
                }
                with mock.patch.object(
                    service,
                    "_journal_accept",
                    wraps=service._journal_accept,
                ) as journal_accept:
                    result = client.call(
                        "retrieve_text_v2",
                        arguments,
                        request_id="req-retrieval-v2-read-only",
                    )
                    request_status = client.request_status(
                        caller="retrieval-v2-core-test",
                        request_id="req-retrieval-v2-read-only",
                    )

                journal_accept.assert_not_called()
                self.assertEqual(journal_rows(), before_rows)
                self.assertFalse(request_status["known"])
                self.assertEqual(request_status["state"], "not_found")
                handler.assert_called_once_with(**arguments)
                self.assertEqual(result["schema"], "synapse-retrieval.v2")
                self.assertEqual(result["schema_version"], 2)
                self.assertEqual(result["query"]["context_id"], "ops")
                self.assertEqual(result["query"]["recall_scope"], "local")
                self.assertFalse(result["query"]["raw_input_stored"])
                self.assertFalse(result["raw_input_stored"])
                self.assertEqual(result["ranker"]["version"], "2.0.0")
                self.assertEqual(result["result_count"], 1)
                self.assertEqual(len(result["items"]), 1)
                self.assertEqual(result["items"][0]["context_id"], "ops")
            finally:
                service.close()
                thread.join(timeout=5.0)

    def test_restart_refuses_valid_shaped_stale_runtime_epoch_binding(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()

            payload = json.loads(config.state_path.read_text(encoding="utf-8"))
            payload["authority_binding"]["marker_sha256"] = "f" * 64
            config.state_path.write_text(
                json.dumps(
                    payload,
                    indent=2,
                    sort_keys=True,
                    allow_nan=False,
                )
                + "\n",
                encoding="utf-8",
            )
            config.state_path.chmod(0o600)

            restarted = AuthoritativeCoreService(config)
            with self.assertRaises(CoreServiceError):
                restarted.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                marker = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()[0]
                )
            self.assertEqual(marker["epoch"], 1)

    def test_first_cutover_publish_failure_is_recovered_by_same_lock_restart(
        self,
    ) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            with mock.patch(
                "mlx_backend.SpikingAttentionBackend."
                "publish_runtime_state_authority_binding",
                side_effect=RuntimeError("injected publication failure"),
            ):
                with self.assertRaises(CoreServiceError):
                    first.start()

            with closing(sqlite3.connect(config.memory_path)) as connection:
                marker = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()[0]
                )
                publication = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_runtime_state_publication",),
                    ).fetchone()[0]
                )
            self.assertEqual(marker["epoch"], 1)
            self.assertEqual(publication["status"], "pending")
            self.assertFalse(config.state_path.exists())

            restarted = AuthoritativeCoreService(config)
            restarted.start()
            try:
                with closing(sqlite3.connect(config.memory_path)) as connection:
                    recovered_marker = json.loads(
                        connection.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_authority",),
                        ).fetchone()[0]
                    )
                    recovered_publication = json.loads(
                        connection.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_runtime_state_publication",),
                        ).fetchone()[0]
                    )
                runtime_payload = json.loads(
                    config.state_path.read_text(encoding="utf-8")
                )
                self.assertEqual(recovered_marker["epoch"], 2)
                self.assertEqual(recovered_publication["status"], "complete")
                self.assertEqual(
                    runtime_payload["authority_binding"],
                    DurableMemoryStore.runtime_state_authority_binding_for_marker(
                        recovered_marker
                    ),
                )
            finally:
                restarted.close()

    def test_first_cutover_retry_archives_only_empty_preclaim_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            with mock.patch.object(
                first,
                "_bind_listener",
                side_effect=CoreServiceError("service_unavailable"),
            ):
                with self.assertRaises(CoreServiceError):
                    first.start()
            journal_path = config.socket_path.parent / "requests.sqlite3"
            self.assertTrue(journal_path.is_file())
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(
                    int(connection.execute("PRAGMA user_version").fetchone()[0]),
                    5,
                )
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()
                )

            restarted = AuthoritativeCoreService(config)
            def verify_after_repair(*, inspection):
                self.assertFalse(journal_path.exists())
                receipts = tuple(
                    config.socket_path.parent.glob(
                        "requests.sqlite3.preclaim-repair-*.json"
                    )
                )
                self.assertEqual(len(receipts), 1)
                self.assertEqual(
                    json.loads(receipts[0].read_text(encoding="utf-8"))["status"],
                    "complete",
                )
                self.assertEqual(inspection["governance_mode"], "pre-governed-v5")
                return {
                    "receipt_digest": "a" * 64,
                    "expires_at_unix_ms": int(time.time() * 1000) + 60_000,
                }

            with mock.patch.object(
                restarted,
                "_verify_required_cutover_attestation",
                side_effect=verify_after_repair,
            ):
                restarted.start()
            try:
                receipts = tuple(
                    config.socket_path.parent.glob(
                        "requests.sqlite3.preclaim-repair-*.json"
                    )
                )
                self.assertEqual(len(receipts), 1)
                receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
                self.assertEqual(receipt["status"], "complete")
                self.assertEqual(receipt["request_row_count"], 0)
                self.assertTrue(journal_path.is_file())
                with closing(sqlite3.connect(config.memory_path)) as connection:
                    marker = json.loads(
                        connection.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_authority",),
                        ).fetchone()[0]
                    )
                self.assertEqual(marker["epoch"], 1)
            finally:
                restarted.close()

    def test_first_cutover_retry_refuses_nonempty_preclaim_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            with mock.patch.object(
                first,
                "_bind_listener",
                side_effect=CoreServiceError("service_unavailable"),
            ):
                with self.assertRaises(CoreServiceError):
                    first.start()
            journal_path = config.socket_path.parent / "requests.sqlite3"
            store_identity = DurableMemoryStore.store_identity_for_path(
                config.memory_path
            )
            residue = CoreRequestJournal(
                journal_path,
                authority_epoch="epoch-1",
                require_existing=True,
                prune_on_open=False,
                allow_migration=False,
                store_identity=store_identity,
            )
            residue.accept(
                caller="preclaim-test",
                request_id="must-not-discard",
                operation="set_enabled",
                request_fingerprint="a" * 64,
            )
            residue.close()

            restarted = AuthoritativeCoreService(config)
            with self.assertRaises(CoreServiceError):
                restarted.start()
            self.assertTrue(journal_path.is_file())
            self.assertFalse(
                tuple(
                    config.socket_path.parent.glob(
                        "requests.sqlite3.preclaim-repair-*.json"
                    )
                )
            )
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(
                    int(connection.execute("PRAGMA user_version").fetchone()[0]),
                    5,
                )

    def test_first_cutover_repair_oserror_is_content_free_unavailable(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            with mock.patch.object(
                first,
                "_bind_listener",
                side_effect=CoreServiceError("service_unavailable"),
            ):
                with self.assertRaises(CoreServiceError):
                    first.start()
            journal_path = config.socket_path.parent / "requests.sqlite3"
            lock_path = config.socket_path.parent / "requests.sqlite3.lock"
            before = {
                path: (path.read_bytes(), path.lstat())
                for path in (journal_path, lock_path)
            }
            secret = "sk-repair-oserror-canary-123456789"
            restarted = AuthoritativeCoreService(config)
            with mock.patch(
                "core_service.repair_empty_preclaim_journal_residue",
                side_effect=OSError(secret),
            ), self.assertRaises(CoreServiceError) as raised:
                restarted.start()
            self.assertEqual(str(raised.exception), "service_unavailable")
            self.assertNotIn(secret, str(raised.exception))
            for path, (content, observed) in before.items():
                visible = path.lstat()
                self.assertEqual(path.read_bytes(), content)
                self.assertEqual(
                    (visible.st_dev, visible.st_ino, visible.st_size),
                    (observed.st_dev, observed.st_ino, observed.st_size),
                )
            self.assertFalse(
                tuple(
                    config.socket_path.parent.glob(
                        "requests.sqlite3.preclaim-repair-*.json"
                    )
                )
            )
            self.assertFalse(
                tuple(
                    config.socket_path.parent.glob(
                        ".requests.sqlite3.preclaim-*.archive"
                    )
                )
            )

    def test_first_cutover_pending_repair_lock_contention_is_unavailable(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            with mock.patch.object(
                first,
                "_bind_listener",
                side_effect=CoreServiceError("service_unavailable"),
            ):
                with self.assertRaises(CoreServiceError):
                    first.start()
            journal_path = config.socket_path.parent / "requests.sqlite3"
            store_identity = DurableMemoryStore.store_identity_for_path(
                config.memory_path
            )
            repair_lease = CoreAuthorityLease.acquire_core(
                config.memory_path,
                timeout_seconds=0.0,
                instance_id="pending-service-lock-fixture",
            )
            try:
                with mock.patch(
                    "core_request_journal.os.rename",
                    side_effect=OSError("injected pre-rename interruption"),
                ), self.assertRaises(OSError):
                    repair_empty_preclaim_journal_residue(
                        journal_path,
                        expected_store_identity=store_identity,
                        memory_db_path=config.memory_path,
                        authority_lease=repair_lease,
                    )
            finally:
                repair_lease.close()
            receipt_path = next(
                config.socket_path.parent.glob(
                    "requests.sqlite3.preclaim-repair-*.json"
                )
            )
            receipt_before = receipt_path.read_bytes()
            main_before = (journal_path.read_bytes(), journal_path.lstat())
            lock_path = config.socket_path.parent / "requests.sqlite3.lock"
            lock_before = (lock_path.read_bytes(), lock_path.lstat())
            descriptor = os.open(lock_path, os.O_RDWR)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                restarted = AuthoritativeCoreService(config)
                with self.assertRaises(CoreServiceError) as raised:
                    restarted.start()
                self.assertEqual(str(raised.exception), "service_unavailable")
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            self.assertEqual(receipt_path.read_bytes(), receipt_before)
            for path, (content, observed) in (
                (journal_path, main_before),
                (lock_path, lock_before),
            ):
                visible = path.lstat()
                self.assertEqual(path.read_bytes(), content)
                self.assertEqual(
                    (visible.st_dev, visible.st_ino, visible.st_size),
                    (observed.st_dev, observed.st_ino, observed.st_size),
                )
            self.assertFalse(
                tuple(
                    config.socket_path.parent.glob(
                        ".requests.sqlite3.preclaim-*.archive"
                    )
                )
            )

    def test_restart_publish_failure_is_recovered_before_next_epoch(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()

            second = AuthoritativeCoreService(config)
            with mock.patch(
                "mlx_backend.SpikingAttentionBackend."
                "publish_runtime_state_authority_binding",
                side_effect=RuntimeError("injected restart publication failure"),
            ):
                with self.assertRaises(CoreServiceError):
                    second.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                stranded_marker = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()[0]
                )
                stranded_publication = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_runtime_state_publication",),
                    ).fetchone()[0]
                )
            self.assertEqual(stranded_marker["epoch"], 2)
            self.assertEqual(stranded_publication["status"], "pending")

            third = AuthoritativeCoreService(config)
            third.start()
            try:
                with closing(sqlite3.connect(config.memory_path)) as connection:
                    live_marker = json.loads(
                        connection.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_authority",),
                        ).fetchone()[0]
                    )
                    live_publication = json.loads(
                        connection.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("core_runtime_state_publication",),
                        ).fetchone()[0]
                    )
                self.assertEqual(live_marker["epoch"], 3)
                self.assertEqual(live_publication["status"], "complete")
            finally:
                third.close()

    def test_replacement_lock_cannot_repair_pending_runtime_publication(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            with mock.patch(
                "mlx_backend.SpikingAttentionBackend."
                "publish_runtime_state_authority_binding",
                side_effect=RuntimeError("injected publication failure"),
            ):
                with self.assertRaises(CoreServiceError):
                    first.start()
            lock_path = config.memory_path.parent / "core" / "authority.lock"
            lock_path.unlink()
            lock_path.write_bytes(b"replacement generation")
            lock_path.chmod(0o600)

            replacement = AuthoritativeCoreService(config)
            with self.assertRaises(CoreServiceError):
                replacement.start()
            self.assertFalse(config.state_path.exists())
            with closing(sqlite3.connect(config.memory_path)) as connection:
                marker = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_authority",),
                    ).fetchone()[0]
                )
                publication = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = ?",
                        ("core_runtime_state_publication",),
                    ).fetchone()[0]
                )
            self.assertEqual(marker["epoch"], 1)
            self.assertEqual(publication["status"], "pending")

    def test_service_refuses_backend_without_durable_authority_surface(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            backend = FakeBackend()
            contracts = {
                "health": CORE_OPERATION_CONTRACTS["health"],
                "status": CORE_OPERATION_CONTRACTS["status"],
            }
            service = AuthoritativeCoreService(
                config,
                backend_factory=lambda _lease: backend,
                operation_contracts=contracts,
                operation_handlers_factory=lambda value: {"status": value.status},
            )
            with self.assertRaises(CoreServiceError):
                service.start()
            self.assertFalse(config.socket_path.exists())
            self.assertFalse(config.memory_path.exists())
            self.assertEqual(service.identity["schema_identity"], "sqlite-0-v0")

    def test_private_token_full_write_and_crash_hardlink_repair(self) -> None:
        with TemporaryDirectory() as temporary:
            core_root = Path(temporary) / "core"
            core_root.mkdir(mode=0o700)
            token_path = core_root / "service.sock.token"
            real_write = os.write

            def partial_write(descriptor: int, payload: Any) -> int:
                return real_write(descriptor, payload[: min(3, len(payload))])

            with mock.patch("core_service.os.write", side_effect=partial_write):
                key = _load_or_create_authentication_key(token_path)
            self.assertEqual(len(key), 32)
            self.assertEqual(len(token_path.read_bytes()), 64)

            orphan = core_root / (
                f".{token_path.name}.tmp-{os.getpid()}-{'a' * 12}"
            )
            os.link(token_path, orphan)
            self.assertEqual(token_path.lstat().st_nlink, 2)
            self.assertEqual(_load_or_create_authentication_key(token_path), key)
            self.assertFalse(orphan.exists())
            self.assertEqual(token_path.lstat().st_nlink, 1)

    def test_store_generation_repairs_one_proven_crash_hardlink(self) -> None:
        with TemporaryDirectory() as temporary:
            core_root = Path(temporary) / "core"
            core_root.mkdir(mode=0o700)
            generation_path = core_root / "store-generation.json"
            store_identity = "store-" + "b" * 24
            generation = _load_or_create_store_generation(
                generation_path,
                store_identity=store_identity,
            )
            orphan = core_root / (
                f".{generation_path.name}.tmp-{os.getpid()}-{'c' * 12}"
            )
            os.link(generation_path, orphan)
            self.assertEqual(generation_path.lstat().st_nlink, 2)
            self.assertEqual(
                _load_or_create_store_generation(
                    generation_path,
                    store_identity=store_identity,
                ),
                generation,
            )
            self.assertFalse(orphan.exists())
            self.assertEqual(generation_path.lstat().st_nlink, 1)

    def test_restored_v6_target_adopts_restarts_and_rejects_forged_lineage(self) -> None:
        from memory_store import DurableMemoryStore
        from recovery_manager import VerifiedRecoveryManager

        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source_root = root / "source"
            source_root.mkdir(mode=0o700)
            source_config = CoreConfig(
                socket_path=source_root / "core" / "service.sock",
                state_path=source_root / "runtime_state.json",
                memory_path=source_root / "memory.sqlite3",
                capture_root=source_root,
                dimension=8,
                num_neurons=8,
                default_top_k=4,
                recall_count=2,
                capture_poll_seconds=0.25,
                authority_timeout_seconds=0.0,
            )
            source = AuthoritativeCoreService(source_config)
            source.start()
            try:
                manager = VerifiedRecoveryManager(
                    source._backend.memory_store,
                    capture_root=source_root,
                    runtime_state_path=source_config.state_path,
                )
                bundle = manager.create_bundle(
                    source_root / "backups" / "continuity.sqlite3",
                    purpose="restored-core-continuity-test",
                )
                restore_root = root / "restored"
                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    restore_root,
                    confirm=True,
                )
            finally:
                source.close()

            receipt_path = Path(restored["request_journal_binding_receipt_path"])
            original_receipt = receipt_path.read_bytes()
            receipt = json.loads(original_receipt.decode("utf-8"))
            target_config = CoreConfig(
                socket_path=restore_root / "core" / "service.sock",
                state_path=restore_root / "runtime_state.json",
                memory_path=restore_root / "memory.sqlite3",
                capture_root=restore_root / "capture-root",
                dimension=8,
                num_neurons=8,
                default_top_k=4,
                recall_count=2,
                capture_poll_seconds=0.25,
                authority_timeout_seconds=0.0,
            )
            adopted = AuthoritativeCoreService(target_config)
            attestation = {
                "receipt_digest": "a" * 64,
                "expires_at_unix_ms": int(time.time() * 1000) + 60_000,
                "restored_target_binding_receipt_digest": receipt[
                    "receipt_digest"
                ],
                "request_journal_logical_snapshot_sha256": receipt[
                    "request_journal_logical_snapshot_sha256"
                ],
            }
            with mock.patch.object(
                adopted,
                "_verify_required_cutover_attestation",
                return_value=attestation,
            ) as verifier:
                adopted.start()
            verifier.assert_called_once()
            source_store_identity = str(receipt["store_identity"])
            self.assertEqual(adopted.identity["store_identity"], source_store_identity)
            self.assertEqual(adopted.identity["neural_epoch"], "epoch-2")
            adopted.close()

            restarted = AuthoritativeCoreService(target_config)
            restarted.start()
            self.assertEqual(restarted.identity["store_identity"], source_store_identity)
            self.assertEqual(restarted.identity["neural_epoch"], "epoch-3")
            restarted.close()

            audit_store = DurableMemoryStore.open_existing_for_audit(
                target_config.memory_path
            )
            try:
                lineage = VerifiedRecoveryManager(
                    audit_store,
                    capture_root=target_config.capture_root,
                    runtime_state_path=target_config.state_path,
                )
                verified = lineage.verify_adopted_restored_store_identity(
                    restore_root,
                    expected_store_identity=source_store_identity,
                    expected_authority_epoch_number=3,
                )
                self.assertTrue(verified["verified"])
                with self.assertRaisesRegex(RuntimeError, "lineage"):
                    lineage.verify_adopted_restored_store_identity(
                        restore_root,
                        expected_store_identity="store-" + ("f" * 24),
                        expected_authority_epoch_number=3,
                    )
            finally:
                audit_store.close()

            forged = dict(receipt)
            forged["store_identity"] = "store-" + ("e" * 24)
            receipt_path.write_text(
                json.dumps(forged, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)
            rejected = AuthoritativeCoreService(target_config)
            with self.assertRaises(CoreServiceError):
                rejected.start()
            rejected.close()
            with closing(sqlite3.connect(target_config.memory_path)) as connection:
                marker = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()[0]
                )
            self.assertEqual(marker["epoch"], 3)

            receipt_path.write_bytes(original_receipt)
            receipt_path.chmod(0o600)
            recovered = AuthoritativeCoreService(target_config)
            recovered.start()
            self.assertEqual(recovered.identity["neural_epoch"], "epoch-4")
            recovered.close()

    def test_v6_restart_requires_existing_request_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()
            journal_path = config.socket_path.parent / "requests.sqlite3"
            self.assertTrue(journal_path.is_file())

            journal_path.unlink()
            for suffix in ("-wal", "-shm"):
                try:
                    Path(f"{journal_path}{suffix}").unlink()
                except FileNotFoundError:
                    pass
            second = AuthoritativeCoreService(config)
            with self.assertRaises(CoreRequestJournalError):
                second.start()
            self.assertFalse(journal_path.exists())

    def test_v6_restart_accepts_existing_request_journal(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()

            second = AuthoritativeCoreService(config)
            try:
                second.start()
                self.assertTrue(second.identity["neural_epoch"].startswith("epoch-"))
            finally:
                second.close()

    def test_missing_governed_database_never_silently_bootstraps_empty_store(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()
            journal_path = config.socket_path.parent / "requests.sqlite3"
            journal_before = journal_path.read_bytes()
            config.memory_path.unlink()

            second = AuthoritativeCoreService(config)
            with self.assertRaises(CoreServiceError):
                second.start()

            self.assertFalse(config.memory_path.exists())
            self.assertEqual(journal_path.read_bytes(), journal_before)

    def test_nonempty_replication_tree_blocks_missing_database_bootstrap(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            replication_inbox = (
                config.memory_path.parent / "replication" / "inbox"
            )
            replication_inbox.mkdir(parents=True, mode=0o700)
            os.chmod(replication_inbox.parent, 0o700)
            os.chmod(replication_inbox, 0o700)
            sentinel = replication_inbox / "checkpoint.json"
            sentinel.write_text("{}\n", encoding="utf-8")
            os.chmod(sentinel, 0o600)

            service = AuthoritativeCoreService(config)
            with self.assertRaises(CoreServiceError):
                service.start()

            self.assertFalse(config.memory_path.exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "{}\n")

    def test_root_generation_blocks_empty_bootstrap_after_paired_state_loss(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()
            sentinel = config.socket_path.parent / "store-generation.json"
            sentinel_before = sentinel.read_bytes()

            config.memory_path.unlink()
            for candidate in tuple(config.socket_path.parent.iterdir()):
                if candidate == sentinel:
                    continue
                candidate.unlink()
            config.state_path.unlink(missing_ok=True)

            second = AuthoritativeCoreService(config)
            with self.assertRaises(CoreServiceError):
                second.start()

            self.assertFalse(config.memory_path.exists())
            self.assertEqual(sentinel.read_bytes(), sentinel_before)

    def test_backend_init_failure_leaves_store_v5_and_unclaimed(self) -> None:
        from memory_store import DurableMemoryStore

        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))

            def fail_after_store(authority: CoreAuthorityLease) -> Any:
                DurableMemoryStore(config.memory_path, authority_lease=authority)
                raise RuntimeError("synthetic init failure")

            service = AuthoritativeCoreService(
                config,
                backend_factory=fail_after_store,
            )
            with self.assertRaisesRegex(RuntimeError, "synthetic init failure"):
                service.start()
            self.assertFalse(
                (config.memory_path.parent / "replication").exists()
            )
            connection = sqlite3.connect(config.memory_path)
            try:
                self.assertEqual(
                    int(connection.execute("PRAGMA user_version").fetchone()[0]),
                    5,
                )
                marker = connection.execute(
                    "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                ).fetchone()
            finally:
                connection.close()
            self.assertIsNone(marker)

    def test_journal_preclaim_failure_leaves_store_v5_and_unclaimed(self) -> None:
        from memory_store import DurableMemoryStore

        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            bootstrap = DurableMemoryStore(config.memory_path)
            bootstrap.close()
            core_root = config.socket_path.parent
            unsafe = core_root / "requests.sqlite3"
            unsafe.write_bytes(b"not-a-private-journal")
            os.chmod(unsafe, 0o644)
            service = AuthoritativeCoreService(config)
            with mock.patch.object(
                service,
                "_verify_required_cutover_attestation",
                return_value={
                    "receipt_digest": "a" * 64,
                    "expires_at_unix_ms": int(time.time() * 1000) + 60_000,
                },
            ):
                with self.assertRaises(CoreServiceError):
                    service.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                )
            self.assertEqual(stat.S_IMODE(unsafe.lstat().st_mode), 0o644)
            self.assertEqual(unsafe.read_bytes(), b"not-a-private-journal")

    def test_socket_bind_failure_leaves_store_v5_and_unclaimed(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            service = AuthoritativeCoreService(config)
            with mock.patch.object(
                service,
                "_bind_listener",
                side_effect=OSError("synthetic bind failure"),
            ):
                with self.assertRaisesRegex(OSError, "synthetic bind failure"):
                    service.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                )

    def test_startup_never_prunes_journal_between_attestation_and_claim(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            service = AuthoritativeCoreService(config)
            with mock.patch.object(
                CoreRequestJournal,
                "prune",
                side_effect=CoreRequestJournalError(),
            ):
                service.start()
            service.close()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 6)
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                )

    def test_capture_thread_start_failure_leaves_store_v5_and_unclaimed(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            capture_root = config.memory_path.parent / "capture"
            capture_root.mkdir(mode=0o700)
            config = CoreConfig(**{**config.__dict__, "capture_root": capture_root})
            service = AuthoritativeCoreService(
                config,
                capture_worker_factory=lambda _backend, _root: FakeCaptureWorker(),
            )
            with mock.patch.object(
                service,
                "_start_prepared_capture_worker",
                side_effect=RuntimeError("synthetic thread-start failure"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "synthetic thread-start failure",
                ):
                    service.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                )

    def test_preexisting_v5_requires_signed_cutover_attestation(self) -> None:
        from memory_store import DurableMemoryStore

        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            bootstrap = DurableMemoryStore(config.memory_path)
            bootstrap.close()
            service = AuthoritativeCoreService(config)
            with self.assertRaises(CoreServiceError):
                service.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                )

    def test_post_attestation_database_drift_rolls_back_v6_claim(self) -> None:
        from memory_store import DurableMemoryStore

        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            capture_root = config.memory_path.parent / "capture"
            capture_root.mkdir(mode=0o700)
            config = CoreConfig(**{**config.__dict__, "capture_root": capture_root})
            bootstrap = DurableMemoryStore(config.memory_path)
            bootstrap.close()
            service = AuthoritativeCoreService(config)

            def attest_and_drift(*, inspection: Any) -> dict[str, Any]:
                with closing(sqlite3.connect(config.memory_path)) as connection:
                    connection.execute(
                        "INSERT INTO store_metadata (key, value_json, updated_at) "
                        "VALUES ('post_attestation_drift', '{}', 1.0)"
                    )
                    connection.commit()
                return {
                    "receipt_digest": "a" * 64,
                    "expires_at_unix_ms": int(time.time() * 1000) + 60_000,
                }

            with mock.patch.object(
                service,
                "_verify_required_cutover_attestation",
                side_effect=attest_and_drift,
            ):
                with self.assertRaisesRegex(
                    CoreAuthorityError,
                    "changed after core cutover preflight",
                ):
                    service.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 5)
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()
                )

    def test_foreign_valid_journal_is_rejected_without_epoch_advance(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                marker = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()[0]
                )
            foreign_root = config.memory_path.parent / "foreign-core"
            foreign_root.mkdir(mode=0o700)
            foreign_path = foreign_root / "requests.sqlite3"
            foreign = CoreRequestJournal(
                foreign_path,
                authority_epoch="epoch-2",
                store_identity=str(marker["store_identity"]),
            )
            self.assertNotEqual(
                foreign.binding()["journal_id"],
                marker["request_journal_id"],
            )
            foreign.close()
            canonical = config.socket_path.parent / "requests.sqlite3"
            os.replace(foreign_path, canonical)

            second = AuthoritativeCoreService(config)
            with self.assertRaises(CoreRequestJournalError):
                second.start()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                after = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()[0]
                )
            self.assertEqual(after["epoch"], marker["epoch"])

    def test_v6_identity_change_requires_fresh_attestation_before_epoch_advance(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                before = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()[0]
                )
            changed = CoreConfig(**{**config.__dict__, "recall_count": 3})
            second = AuthoritativeCoreService(changed)
            with mock.patch.object(
                second,
                "_verify_required_cutover_attestation",
                side_effect=CoreServiceError("service_unavailable"),
            ) as verifier:
                with self.assertRaises(CoreServiceError):
                    second.start()
            verifier.assert_called_once()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                after = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()[0]
                )
            self.assertEqual(after, before)

    def test_embedding_space_change_is_rejected_even_with_cutover_attestation(self) -> None:
        with TemporaryDirectory() as temporary:
            config = self.config(Path(temporary))
            first = AuthoritativeCoreService(config)
            first.start()
            first.close()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                before = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()[0]
                )
            changed = CoreConfig(
                **{**config.__dict__, "embedding_provider_name": "lexical-hash"}
            )
            second = AuthoritativeCoreService(changed)
            with mock.patch.object(
                second,
                "_verify_required_cutover_attestation",
                return_value={
                    "receipt_digest": "a" * 64,
                    "expires_at_unix_ms": int(time.time() * 1000) + 60_000,
                },
            ) as verifier:
                with self.assertRaises(CoreServiceError):
                    second.start()
            verifier.assert_not_called()
            with closing(sqlite3.connect(config.memory_path)) as connection:
                after = json.loads(
                    connection.execute(
                        "SELECT value_json FROM store_metadata WHERE key = 'core_authority'"
                    ).fetchone()[0]
                )
            self.assertEqual(after, before)


class CoreConfigTests(unittest.TestCase):
    def config(self, root: Path) -> CoreConfig:
        root = root.resolve()
        return CoreConfig(
            socket_path=root / "core" / "service.sock",
            state_path=root / "runtime_state.json",
            memory_path=root / "memory.sqlite3",
            dimension=8,
            num_neurons=8,
            default_top_k=4,
        )

    def test_private_canonical_config_round_trip_and_unknown_field_rejection(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            path = root / "core" / "config.json"
            write_core_config(path, config)
            self.assertEqual(load_core_config(path), config)
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
            raw = config.to_wire()
            raw["unknown"] = True
            path.write_bytes(canonical_json_bytes(raw))
            os.chmod(path, 0o600)
            with self.assertRaises(CoreServiceError):
                load_core_config(path)

    def test_runtime_never_chmods_an_existing_configured_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            insecure = root / "caller-owned"
            insecure.mkdir(mode=0o755)
            os.chmod(insecure, 0o755)
            before = insecure.lstat()

            with self.assertRaises(CoreServiceError):
                _ensure_private_directory(insecure)

            after = insecure.lstat()
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o755)
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))

            created = root / "runtime-created"
            _ensure_private_directory(created)
            self.assertEqual(stat.S_IMODE(created.lstat().st_mode), 0o700)

    def test_config_writer_never_repairs_an_existing_unsafe_lock(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            core = root / "core"
            core.mkdir(mode=0o700)
            os.chmod(core, 0o700)
            path = core / "config.json"
            lock = core / ".config.json.lock"
            lock.write_text("caller-owned-lock", encoding="utf-8")
            os.chmod(lock, 0o644)
            before = lock.lstat()

            with self.assertRaises(CoreServiceError):
                write_core_config(path, self.config(root))

            after = lock.lstat()
            self.assertEqual(lock.read_text(encoding="utf-8"), "caller-owned-lock")
            self.assertEqual(stat.S_IMODE(after.st_mode), 0o644)
            self.assertEqual((after.st_dev, after.st_ino), (before.st_dev, before.st_ino))
            self.assertFalse(path.exists())

    def test_config_rejects_symlink_target_and_oversized_neural_allocation(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            core = root / "core"
            core.mkdir(mode=0o700)
            config = self.config(root)
            target = core / "target.json"
            target.write_text("{}", encoding="utf-8")
            os.chmod(target, 0o600)
            link = core / "config.json"
            link.symlink_to(target)
            with self.assertRaises(CoreServiceError):
                write_core_config(link, config)

            oversized = config.to_wire()
            oversized["dimension"] = 65_536
            oversized["num_neurons"] = 131_072
            oversized["default_top_k"] = 256
            with self.assertRaises(CoreServiceError):
                config_from_wire(oversized)

            ten_thousand_by_default_topology = config.to_wire()
            ten_thousand_by_default_topology["dimension"] = 10_000
            ten_thousand_by_default_topology["num_neurons"] = 8_192
            ten_thousand_by_default_topology["default_top_k"] = 256
            with self.assertRaises(CoreServiceError):
                config_from_wire(ten_thousand_by_default_topology)

            valid_nondefault = config.to_wire()
            valid_nondefault["dimension"] = 2_048
            valid_nondefault["num_neurons"] = 8_192
            valid_nondefault["default_top_k"] = 256
            validated = config_from_wire(valid_nondefault)
            self.assertEqual(
                (validated.dimension, validated.num_neurons),
                (2_048, 8_192),
            )

    def test_config_rejects_implicit_or_unpinned_embedding_runtime(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            base = self.config(root).to_wire()
            for provider in ("auto", "python", "mlx"):
                candidate = dict(base)
                candidate["embedding_provider_name"] = provider
                with self.subTest(provider=provider), self.assertRaises(CoreServiceError):
                    config_from_wire(candidate)

            neural = dict(base)
            neural.update(
                {
                    "embedding_provider_name": "mlx-neural",
                    "embedding_neural_model_id": "sentence-transformers/all-MiniLM-L6-v2",
                    "embedding_neural_revision": "a" * 40,
                    "embedding_neural_cache_dir": str(root / "model-cache"),
                    "embedding_neural_pooling": "mean",
                    "embedding_neural_max_tokens": 256,
                    "embedding_neural_normalize": True,
                    "embedding_neural_local_files_only": True,
                }
            )
            validated = config_from_wire(neural)
            self.assertEqual(validated.embedding_neural_revision, "a" * 40)

            required = (
                "embedding_neural_model_id",
                "embedding_neural_revision",
                "embedding_neural_cache_dir",
                "embedding_neural_pooling",
                "embedding_neural_max_tokens",
                "embedding_neural_normalize",
                "embedding_neural_local_files_only",
            )
            for field in required:
                candidate = dict(neural)
                candidate[field] = None
                with self.subTest(field=field), self.assertRaises(CoreServiceError):
                    config_from_wire(candidate)

            mutable_revision = dict(neural)
            mutable_revision["embedding_neural_revision"] = "main"
            with self.assertRaises(CoreServiceError):
                config_from_wire(mutable_revision)
            network_enabled = dict(neural)
            network_enabled["embedding_neural_local_files_only"] = False
            with self.assertRaises(CoreServiceError):
                config_from_wire(network_enabled)

    def test_explicit_neural_identity_is_environment_independent_and_fingerprinted(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            wire = self.config(root).to_wire()
            wire.update(
                {
                    "embedding_provider_name": "mlx-neural-v1",
                    "embedding_neural_model_id": "sentence-transformers/all-MiniLM-L6-v2",
                    "embedding_neural_revision": "b" * 40,
                    "embedding_neural_cache_dir": str(root / "model-cache"),
                    "embedding_neural_pooling": "mean",
                    "embedding_neural_max_tokens": 256,
                    "embedding_neural_normalize": True,
                    "embedding_neural_local_files_only": True,
                    "mlx_device": "default",
                }
            )
            hostile_environment = {
                "SYNAPSE_S2_EMBEDDING_PROVIDER": "lexical-hash",
                "SYNAPSE_S2_NEURAL_MODEL": "attacker/model",
                "SYNAPSE_S2_NEURAL_REVISION": "c" * 40,
                "SYNAPSE_S2_NEURAL_CACHE_DIR": str(root / "other-cache"),
                "SYNAPSE_S2_NEURAL_POOLING": "cls",
                "SYNAPSE_S2_NEURAL_MAX_TOKENS": "999",
                "SYNAPSE_S2_NEURAL_NORMALIZE": "0",
                "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY": "0",
            }
            with mock.patch.dict(os.environ, hostile_environment, clear=False):
                configured = config_from_wire(wire)
            self.assertEqual(configured.to_wire(), wire)

            alternatives = {
                "embedding_neural_model_id": "sentence-transformers/all-mpnet-base-v2",
                "embedding_neural_revision": "d" * 40,
                "embedding_neural_cache_dir": str(root / "other-model-cache"),
                "embedding_neural_pooling": "cls",
                "embedding_neural_max_tokens": 128,
                "embedding_neural_normalize": False,
                "mlx_device": "cpu",
            }
            for field, replacement in alternatives.items():
                candidate = dict(wire)
                candidate[field] = replacement
                changed = config_from_wire(candidate)
                with self.subTest(field=field):
                    self.assertNotEqual(configured.fingerprint, changed.fingerprint)

    def test_concurrent_config_writers_publish_one_complete_identity(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self.config(root)
            second_wire = first.to_wire()
            second_wire["recall_count"] = 7
            second = config_from_wire(second_wire)
            path = root / "core" / "config.json"
            errors: list[BaseException] = []

            def writer(config: CoreConfig) -> None:
                try:
                    write_core_config(path, config)
                except BaseException as exc:
                    errors.append(exc)

            threads = [
                threading.Thread(target=writer, args=(first,)),
                threading.Thread(target=writer, args=(second,)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(3.0)
            self.assertEqual(errors, [])
            self.assertIn(load_core_config(path), (first, second))

    def test_build_identity_covers_every_critical_source_manifest_entry(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for filename in BUILD_SOURCE_MANIFEST:
                source = root / filename
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(f"source:{filename}".encode("utf-8"))
            before = _manifest_build_id(root)
            for filename in BUILD_SOURCE_MANIFEST:
                critical = root / filename
                original = critical.read_bytes()
                critical.write_bytes(original + b"\nchanged")
                with self.subTest(filename=filename):
                    self.assertNotEqual(before, _manifest_build_id(root))
                critical.write_bytes(original)
                self.assertEqual(before, _manifest_build_id(root))

    def test_configured_build_id_is_an_expected_assertion_not_an_override(self) -> None:
        computed = _manifest_build_id(Path(__file__).resolve().parents[1])
        with mock.patch.dict(os.environ, {"SYNAPSE_S2_BUILD_ID": computed}):
            self.assertEqual(_source_build_id(), computed)
        with mock.patch.dict(
            os.environ,
            {"SYNAPSE_S2_BUILD_ID": "source-000000000000000000000000"},
        ):
            with self.assertRaises(CoreServiceError):
                _source_build_id()


class CoreClientRetryTests(unittest.TestCase):
    def client(self, root: Path) -> CoreClient:
        core = root / "core"
        core.mkdir(mode=0o700)
        os.chmod(core, 0o700)
        socket_path = core / "service.sock"
        token_path = socket_path.with_suffix(".sock.token")
        token_path.write_text(bytes(range(32)).hex(), encoding="ascii")
        os.chmod(token_path, 0o600)
        return CoreClient(
            socket_path=socket_path,
            caller="retry-client",
            default_timeout_seconds=2.0,
        )

    @staticmethod
    def response(request: dict[str, Any], result: Any) -> dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request["request_id"],
            "caller": request["caller"],
            "operation": request["operation"],
            "request_fingerprint": request["request_fingerprint"],
            "operation_sequence": 1,
            "server_time_unix_ms": int(time.time() * 1000),
            "identity": {
                "authority_id": "core-test",
                "neural_epoch": "epoch-1",
                "config_fingerprint": "a" * 64,
                "build_id": "build-test",
                "store_identity": "store-test",
                "schema_identity": "sqlite-test-v6",
            },
            "ok": True,
            "result": result,
            "error": None,
        }

    def test_safe_read_reconnects_once_but_mutation_never_retries(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            read_attempts = 0

            def read_exchange(request: dict[str, Any], *, timeout_seconds: float) -> Any:
                nonlocal read_attempts
                read_attempts += 1
                if read_attempts == 1:
                    raise CoreUnavailable()
                return self.response(request, {"runtime": "ready"})

            client._exchange = read_exchange  # type: ignore[method-assign]
            self.assertEqual(client.status()["runtime"], "ready")
            self.assertEqual(read_attempts, 2)

            mutation_attempts = 0

            def mutation_exchange(
                _request: dict[str, Any],
                *,
                timeout_seconds: float,
            ) -> Any:
                nonlocal mutation_attempts
                mutation_attempts += 1
                raise CoreUnavailable()

            client._exchange = mutation_exchange  # type: ignore[method-assign]
            with self.assertRaises(CoreUnavailable):
                client.set_enabled(True)
            self.assertEqual(mutation_attempts, 1)

    def test_retrieval_v2_contract_matches_backend_and_client_forwarding(self) -> None:
        contract = CORE_OPERATION_CONTRACTS["retrieve_text_v2"]
        signature = inspect.signature(SpikingAttentionBackend.retrieve_text_v2)
        backend_arguments = {
            name for name in signature.parameters if name != "self"
        }
        required_backend_arguments = {
            name
            for name, parameter in signature.parameters.items()
            if name != "self" and parameter.default is inspect.Parameter.empty
        }
        self.assertEqual(contract.allowed_arguments, backend_arguments)
        self.assertEqual(contract.required_arguments, required_backend_arguments)
        self.assertFalse(contract.mutation)
        self.assertTrue(contract.retry_safe)
        self.assertIn("retrieve_text_v2", SAFE_READ_OPERATIONS)

        with TemporaryDirectory() as temporary:
            client = CoreClient(
                socket_path=Path(temporary) / "core" / "service.sock",
                caller="retrieval-contract-client",
            )
            expected = {"schema": "synapse-retrieval.v2"}
            arguments = {
                "context_id": "ops",
                "recall_scope": "connected",
                "result_limit": 7,
                "candidate_limit": 31,
                "include_graph_neighbors": False,
            }
            with mock.patch.object(
                client,
                "call",
                return_value=expected,
            ) as call:
                result = client.retrieve_text_v2("camera routing", **arguments)
        self.assertEqual(result, expected)
        call.assert_called_once_with(
            "retrieve_text_v2",
            {"prompt": "camera routing", **arguments},
        )

    def test_retrieval_v2_reconnects_once_with_the_same_request(self) -> None:
        with TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            requests: list[dict[str, Any]] = []
            expected = {
                "schema": "synapse-retrieval.v2",
                "schema_version": 2,
                "items": [],
                "result_count": 0,
            }

            def exchange(
                request: dict[str, Any],
                *,
                timeout_seconds: float,
            ) -> Any:
                _ = timeout_seconds
                requests.append(request)
                if len(requests) == 1:
                    raise CoreUnavailable()
                return self.response(request, expected)

            client._exchange = exchange  # type: ignore[method-assign]
            result = client.retrieve_text_v2(
                "camera routing",
                context_id="ops",
                recall_scope="connected",
                result_limit=7,
                candidate_limit=31,
                include_graph_neighbors=False,
            )

            self.assertEqual(result, expected)
            self.assertEqual(len(requests), 2)
            self.assertEqual(requests[0], requests[1])
            self.assertEqual(requests[0]["operation"], "retrieve_text_v2")
            self.assertEqual(
                requests[0]["arguments"],
                {
                    "prompt": "camera routing",
                    "context_id": "ops",
                    "recall_scope": "connected",
                    "result_limit": 7,
                    "candidate_limit": 31,
                    "include_graph_neighbors": False,
                },
            )

    def test_resource_profile_benchmark_routes_to_journaled_mutation(self) -> None:
        self.assertTrue(CORE_OPERATION_CONTRACTS["resource_profile"].retry_safe)
        self.assertFalse(CORE_OPERATION_CONTRACTS["resource_profile"].mutation)
        self.assertTrue(
            CORE_OPERATION_CONTRACTS["benchmark_resource_profile"].mutation
        )
        self.assertFalse(
            CORE_OPERATION_CONTRACTS["benchmark_resource_profile"].retry_safe
        )
        with TemporaryDirectory() as temporary:
            client = self.client(Path(temporary))
            with mock.patch.object(
                client,
                "call",
                return_value={"within_target_envelope": True},
            ) as call:
                client.resource_profile(
                    benchmark_quick_prune=False,
                    target_min_mb=96.0,
                )
                call.assert_called_once_with(
                    "resource_profile",
                    {"target_min_mb": 96.0},
                )
                call.reset_mock()
                client.resource_profile(
                    benchmark_quick_prune=True,
                    target_max_mb=384.0,
                )
                call.assert_called_once_with(
                    "benchmark_resource_profile",
                    {"target_max_mb": 384.0},
                )

    def test_cortex_observation_and_orphan_reaping_have_distinct_contracts(self) -> None:
        self.assertTrue(CORE_OPERATION_CONTRACTS["get_cortex_state"].retry_safe)
        self.assertFalse(CORE_OPERATION_CONTRACTS["get_cortex_state"].mutation)
        self.assertTrue(
            CORE_OPERATION_CONTRACTS["reap_orphaned_cortex_sessions"].mutation
        )
        self.assertFalse(
            CORE_OPERATION_CONTRACTS["reap_orphaned_cortex_sessions"].retry_safe
        )


if __name__ == "__main__":
    unittest.main()

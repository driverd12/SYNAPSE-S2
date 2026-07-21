from __future__ import annotations

import os
import secrets
import socket
import stat
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

from core_protocol import (
    DEFAULT_MAX_FRAME_BYTES,
    MAX_DEADLINE_HORIZON_MS,
    CoreProtocolError,
    CoreTransportError,
    build_request,
    contains_secret_shape,
    receive_frame,
    send_frame,
    validate_max_frame_bytes,
    validate_private_file,
    validate_private_socket,
    validate_reconciliation_projection,
    validate_response,
)
from core_service import CORE_OPERATION_CONTRACTS, SAFE_READ_OPERATIONS


class CoreUnavailable(RuntimeError):
    """The authoritative service could not be reached or authenticated."""

    def __init__(self) -> None:
        super().__init__("service_unavailable")
        self.code = "service_unavailable"


class CoreOutcomeUnknown(RuntimeError):
    """A mutation may have reached the core; automatic replay is forbidden."""

    def __init__(self, *, caller: str, request_id: str, operation: str) -> None:
        reconciliation = validate_reconciliation_projection(
            {
                "code": "outcome_unknown",
                "caller": caller,
                "request_id": request_id,
                "operation": operation,
                "replay_safe": False,
            }
        )
        super().__init__("outcome_unknown")
        self.code = "outcome_unknown"
        self.retryable = False
        self.caller = reconciliation["caller"]
        self.request_id = reconciliation["request_id"]
        self.operation = reconciliation["operation"]

    @property
    def reconciliation(self) -> dict[str, Any]:
        return validate_reconciliation_projection(
            {
                "code": self.code,
                "caller": self.caller,
                "request_id": self.request_id,
                "operation": self.operation,
                "replay_safe": False,
            }
        )


def outcome_unknown_projection(error: CoreOutcomeUnknown) -> dict[str, Any]:
    """Return a fixed, content-free reconciliation handle for public surfaces."""

    if not isinstance(error, CoreOutcomeUnknown):
        raise CoreProtocolError()
    return validate_reconciliation_projection(error.reconciliation)


class CoreRemoteError(RuntimeError):
    """A stable, content-free operation error returned by the core."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = bool(retryable)


def _token_path(socket_path: Path) -> Path:
    return socket_path.with_suffix(socket_path.suffix + ".token")


def _read_authentication_key(path: Path) -> bytes:
    try:
        parent = path.parent.lstat()
    except FileNotFoundError as exc:
        raise CoreUnavailable() from exc
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        raise CoreUnavailable()
    validate_private_file(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        visible = path.lstat()
        if (
            before.st_nlink != 1
            or (before.st_dev, before.st_ino) != (visible.st_dev, visible.st_ino)
        ):
            raise CoreUnavailable()
        raw = os.read(descriptor, 256)
        if os.read(descriptor, 1):
            raise CoreUnavailable()
    except OSError as exc:
        raise CoreUnavailable() from exc
    finally:
        os.close(descriptor)
    try:
        key = bytes.fromhex(raw.decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise CoreUnavailable() from exc
    if len(key) != 32:
        raise CoreUnavailable()
    return key


class CoreClient:
    """Explicit facade for the authoritative core; never a local-backend fallback."""

    def __init__(
        self,
        *,
        socket_path: str | os.PathLike[str] | None = None,
        state_path: str | os.PathLike[str] | None = None,
        replication_inbox_root: str | os.PathLike[str] | None = None,
        caller: str | None = None,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        default_timeout_seconds: float = 15.0,
        expected_config_fingerprint: str | None = None,
    ) -> None:
        configured_socket = socket_path or os.getenv("SYNAPSE_S2_CORE_SOCKET")
        if configured_socket is None:
            configured_socket = Path.cwd() / ".synapse_s2" / "core" / "service.sock"
        self.socket_path = Path(configured_socket).expanduser()
        if not self.socket_path.is_absolute() or ".." in self.socket_path.parts:
            raise CoreUnavailable()
        self.authentication_path = _token_path(self.socket_path)
        configured_fingerprint = expected_config_fingerprint or os.getenv(
            "SYNAPSE_S2_EXPECTED_CORE_CONFIG_FINGERPRINT"
        )
        if configured_fingerprint is not None:
            configured_fingerprint = str(configured_fingerprint)
            if (
                len(configured_fingerprint) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in configured_fingerprint
                )
            ):
                raise CoreUnavailable()
        self.expected_config_fingerprint = configured_fingerprint
        configured_state = state_path or os.getenv("SYNAPSE_S2_STATE_PATH")
        self.state_path = (
            Path(configured_state).expanduser()
            if configured_state is not None
            else self.socket_path.parent.parent / "runtime_state.json"
        )
        configured_replication_inbox = replication_inbox_root or os.getenv(
            "SYNAPSE_S2_REPLICATION_INBOX_ROOT"
        )
        self.replication_inbox_root = (
            None
            if configured_replication_inbox is None
            else Path(configured_replication_inbox).expanduser()
        )
        if self.replication_inbox_root is not None and (
            not self.replication_inbox_root.is_absolute()
            or ".." in self.replication_inbox_root.parts
        ):
            raise CoreUnavailable()
        self.delivery_instance_id = caller or (
            f"core-client-{os.getpid()}-{secrets.token_hex(6)}"
        )
        if (
            not self.delivery_instance_id
            or len(self.delivery_instance_id) > 128
            or any(
                not (character.isalnum() or character in "._:-")
                for character in self.delivery_instance_id
            )
            or contains_secret_shape(self.delivery_instance_id)
        ):
            raise CoreUnavailable()
        self.control_plane_only = False
        self.max_frame_bytes = validate_max_frame_bytes(max_frame_bytes)
        self.default_timeout_seconds = self._timeout(default_timeout_seconds)
        self._last_identity: dict[str, str] | None = None

    @classmethod
    def from_environment(cls, *, control_plane_only: bool = False) -> "CoreClient":
        # The authoritative core always owns the full neural substrate. The
        # flag remains accepted for drop-in caller ergonomics, not fallback.
        _ = control_plane_only
        return cls()

    @staticmethod
    def _timeout(value: float) -> float:
        try:
            timeout = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise CoreUnavailable() from exc
        maximum = MAX_DEADLINE_HORIZON_MS / 1000.0
        if timeout <= 0.0 or timeout > maximum or timeout != timeout:
            raise CoreUnavailable()
        return timeout

    @property
    def authority_identity(self) -> dict[str, str] | None:
        return None if self._last_identity is None else dict(self._last_identity)

    def close(self) -> None:
        """Each request owns its connection; retained for backend compatibility."""

    def call(
        self,
        operation: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        timeout_seconds: float | None = None,
        request_id: str | None = None,
    ) -> Any:
        contract = CORE_OPERATION_CONTRACTS.get(operation)
        if contract is None:
            raise CoreRemoteError("operation_unavailable")
        clean_arguments = contract.validate_arguments(dict(arguments or {}))
        timeout = self._timeout(
            self.default_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        authentication_key = _read_authentication_key(self.authentication_path)
        deadline_unix_ms = int((time.time() + timeout) * 1000)
        request = build_request(
            request_id=request_id or f"req-{uuid.uuid4().hex}",
            caller=self.delivery_instance_id,
            deadline_unix_ms=deadline_unix_ms,
            operation=operation,
            arguments=clean_arguments,
            authentication_key=authentication_key,
            expected_config_fingerprint=self.expected_config_fingerprint,
        )
        attempts = 2 if operation in SAFE_READ_OPERATIONS else 1
        last_error: BaseException | None = None
        for _attempt in range(attempts):
            remaining = (deadline_unix_ms / 1000.0) - time.time()
            if remaining <= 0.0:
                break
            try:
                response = self._exchange(request, timeout_seconds=remaining)
                validated = validate_response(response, expected_request=request)
            except CoreOutcomeUnknown as exc:
                last_error = exc
                if contract.mutation:
                    raise
                continue
            except CoreProtocolError as exc:
                last_error = exc
                if contract.mutation:
                    raise CoreOutcomeUnknown(
                        caller=request["caller"],
                        request_id=request["request_id"],
                        operation=request["operation"],
                    ) from exc
                continue
            except (CoreTransportError, CoreUnavailable, OSError, TimeoutError) as exc:
                last_error = exc
                continue
            identity = dict(validated["identity"])
            if (
                self.expected_config_fingerprint is not None
                and not secrets.compare_digest(
                    identity["config_fingerprint"],
                    self.expected_config_fingerprint,
                )
            ):
                if contract.mutation:
                    raise CoreOutcomeUnknown(
                        caller=request["caller"],
                        request_id=request["request_id"],
                        operation=request["operation"],
                    )
                raise CoreUnavailable()
            self._last_identity = identity
            if not validated["ok"]:
                error = validated["error"]
                if error["code"] == "outcome_unknown":
                    raise CoreOutcomeUnknown(
                        caller=request["caller"],
                        request_id=request["request_id"],
                        operation=request["operation"],
                    )
                raise CoreRemoteError(
                    error["code"],
                    retryable=error["retryable"],
                )
            return validated["result"]
        raise CoreUnavailable() from last_error

    def _exchange(
        self,
        request: Mapping[str, Any],
        *,
        timeout_seconds: float,
    ) -> Any:
        validate_private_socket(self.socket_path)
        try:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(max(0.01, timeout_seconds))
            connection.connect(str(self.socket_path))
        except (OSError, TimeoutError) as exc:
            try:
                connection.close()
            except (NameError, OSError):
                pass
            raise CoreUnavailable() from exc
        try:
            send_frame(
                connection,
                request,
                max_frame_bytes=self.max_frame_bytes,
            )
            return receive_frame(
                connection,
                max_frame_bytes=self.max_frame_bytes,
            )
        except (CoreProtocolError, CoreTransportError, OSError, TimeoutError) as exc:
            # The connection completed, so a failed send/receive cannot prove
            # whether a mutation was durably accepted or committed.
            raise CoreOutcomeUnknown(
                caller=request["caller"],
                request_id=request["request_id"],
                operation=request["operation"],
            ) from exc
        finally:
            connection.close()

    def health(self, *, timeout_seconds: float | None = None) -> dict[str, Any]:
        return self.call("health", timeout_seconds=timeout_seconds)

    def request_status(self, *, caller: str, request_id: str) -> dict[str, Any]:
        return self.call(
            "request_status",
            {"caller": caller, "request_id": request_id},
        )

    def status(self, *, context_id: str = "default") -> dict[str, Any]:
        return self.call("status", {"context_id": context_id})

    def is_enabled(self, context_id: str = "default") -> bool:
        return self.call("is_enabled", {"context_id": context_id})

    def set_enabled(
        self,
        enabled: bool,
        *,
        context_id: str | None = None,
    ) -> dict[str, Any]:
        return self.call("set_enabled", {"enabled": enabled, "context_id": context_id})

    def embedding_provider_info(self) -> dict[str, Any]:
        return self.call("embedding_provider_info")

    def embed_text_payload(
        self,
        text: str,
        *,
        dimensions: int | None = None,
    ) -> dict[str, Any]:
        return self.call("embed_text_payload", {"text": text, "dimensions": dimensions})

    def benchmark_embedding_provider(self, **arguments: Any) -> dict[str, Any]:
        return self.call("benchmark_embedding_provider", arguments)

    def register_text_trace(self, **arguments: Any) -> dict[str, Any]:
        return self.call("register_text_trace", arguments)

    def register_trace(self, **arguments: Any) -> dict[str, Any]:
        return self.call("register_trace", arguments)

    def query_text(self, prompt: str, **arguments: Any) -> str:
        return self.call("query_text", {"prompt": prompt, **arguments})

    def retrieve_text_v2(self, prompt: str, **arguments: Any) -> dict[str, Any]:
        return self.call("retrieve_text_v2", {"prompt": prompt, **arguments})

    def query(self, embedding: Any, **arguments: Any) -> str:
        return self.call("query", {"embedding": embedding, **arguments})

    def list_memory(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_memory", arguments)

    def publish_context_event(self, **arguments: Any) -> dict[str, Any]:
        return self.call("publish_context_event", arguments)

    def list_context_events(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_context_events", arguments)

    def lease_context_events(self, **arguments: Any) -> dict[str, Any]:
        return self.call("lease_context_events", arguments)

    def ack_context_events(self, **arguments: Any) -> dict[str, Any]:
        return self.call("ack_context_events", arguments)

    def release_context_events(self, **arguments: Any) -> dict[str, Any]:
        return self.call("release_context_events", arguments)

    def dead_letter_context_delivery(self, **arguments: Any) -> dict[str, Any]:
        return self.call("dead_letter_context_delivery", arguments)

    def list_context_cursors(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_context_cursors", arguments)

    def context_delivery_health(self, **arguments: Any) -> dict[str, Any]:
        return self.call("context_delivery_health", arguments)

    def enter_spiking_cortex(self, **arguments: Any) -> dict[str, Any]:
        return self.call("enter_spiking_cortex", arguments)

    def cortex_tick(self, **arguments: Any) -> dict[str, Any]:
        return self.call("cortex_tick", arguments)

    def close_spiking_cortex(self, **arguments: Any) -> dict[str, Any]:
        return self.call("close_spiking_cortex", arguments)

    def commit_cortical_trace(self, **arguments: Any) -> dict[str, Any]:
        return self.call("commit_cortical_trace", arguments)

    def get_cortex_state(self, **arguments: Any) -> dict[str, Any]:
        return self.call("get_cortex_state", arguments)

    def reap_orphaned_cortex_sessions(self, **arguments: Any) -> dict[str, Any]:
        return self.call("reap_orphaned_cortex_sessions", arguments)

    def attach_client_cortex_session(self, **arguments: Any) -> dict[str, Any]:
        return self.call("attach_client_cortex_session", arguments)

    def finish_client_cortex_session(self, **arguments: Any) -> dict[str, Any]:
        return self.call("finish_client_cortex_session", arguments)

    def create_goal(self, **arguments: Any) -> dict[str, Any]:
        return self.call("create_goal", arguments)

    def update_goal(self, **arguments: Any) -> dict[str, Any]:
        return self.call("update_goal", arguments)

    def list_goals(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_goals", arguments)

    def moderate_cortex_trace(self, **arguments: Any) -> dict[str, Any]:
        return self.call("moderate_cortex_trace", arguments)

    def hydrate_agent_context(self, **arguments: Any) -> dict[str, Any]:
        return self.call("hydrate_agent_context", arguments)

    def ingest_text_events(self, **arguments: Any) -> dict[str, Any]:
        return self.call("ingest_text_events", arguments)

    def capture_conversation(self, **arguments: Any) -> dict[str, Any]:
        return self.call("capture_conversation", arguments)

    def replay_capture_operation(self, capture_id: str, **arguments: Any) -> dict[str, Any]:
        return self.call(
            "replay_capture_operation",
            {"capture_id": capture_id, **arguments},
        )

    def prune_memory(self, **arguments: Any) -> dict[str, Any]:
        return self.call("prune_memory", arguments)

    def approve_namespace_link(self, **arguments: Any) -> dict[str, Any]:
        return self.call("approve_namespace_link", arguments)

    def propose_namespace_link(self, **arguments: Any) -> dict[str, Any]:
        return self.call("propose_namespace_link", arguments)

    def review_namespace_link(self, **arguments: Any) -> dict[str, Any]:
        return self.call("review_namespace_link", arguments)

    def disable_namespace_link(self, **arguments: Any) -> dict[str, Any]:
        return self.call("disable_namespace_link", arguments)

    def revoke_namespace_link(self, **arguments: Any) -> dict[str, Any]:
        return self.call("revoke_namespace_link", arguments)

    def expire_namespace_links(self) -> dict[str, Any]:
        return self.call("expire_namespace_links")

    def delete_namespace_link(self, **arguments: Any) -> dict[str, Any]:
        return self.call("delete_namespace_link", arguments)

    def list_namespace_link_proposals(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_namespace_link_proposals", arguments)

    def list_namespace_link_history(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_namespace_link_history", arguments)

    def audit_namespace_link_governance(self) -> dict[str, Any]:
        return self.call("audit_namespace_link_governance")

    def suggest_namespace_links(self, **arguments: Any) -> dict[str, Any]:
        return self.call("suggest_namespace_links", arguments)

    def list_namespace_map(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_namespace_map", arguments)

    def list_namespace_detail(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_namespace_detail", arguments)

    def list_memory_graph(self, **arguments: Any) -> dict[str, Any]:
        return self.call("list_memory_graph", arguments)

    def audit_semantic_indexes(self, **arguments: Any) -> dict[str, Any]:
        return self.call("audit_semantic_indexes", arguments)

    def repair_semantic_indexes(self, **arguments: Any) -> dict[str, Any]:
        return self.call("repair_semantic_indexes", arguments)

    def resolve_recall_contexts(self, **arguments: Any) -> list[dict[str, Any]]:
        return self.call("resolve_recall_contexts", arguments)

    def memory_entries_revision(self, **arguments: Any) -> dict[str, Any]:
        return self.call("memory_entries_revision", arguments)

    def get_memory_entry(
        self,
        memory_id: str,
        *,
        include_vectors: bool = False,
    ) -> dict[str, Any] | None:
        return self.call(
            "get_memory_entry",
            {"memory_id": memory_id, "include_vectors": include_vectors},
        )

    def resource_profile(self, **arguments: Any) -> dict[str, Any]:
        clean_arguments = dict(arguments)
        benchmark = clean_arguments.pop("benchmark_quick_prune", False)
        if not isinstance(benchmark, bool):
            raise CoreProtocolError()
        return self.call(
            "benchmark_resource_profile" if benchmark else "resource_profile",
            clean_arguments,
        )

    def certify_runtime(self, **arguments: Any) -> dict[str, Any]:
        return self.call("certify_runtime", arguments)

    def export_memory(
        self,
        path: str | os.PathLike[str] | None = None,
        **arguments: Any,
    ) -> dict[str, Any]:
        return self.call(
            "export_memory",
            {"path": None if path is None else str(path), **arguments},
        )

    def backup_memory(
        self,
        path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        return self.call(
            "backup_memory",
            {"path": None if path is None else str(path)},
        )

    def backup_recovery_bundle(
        self,
        path: str | os.PathLike[str] | None = None,
        **arguments: Any,
    ) -> dict[str, Any]:
        return self.call(
            "backup_recovery_bundle",
            {"path": None if path is None else str(path), **arguments},
        )

    def audit_capture_ledger(self, **arguments: Any) -> dict[str, Any]:
        return self.call("audit_capture_ledger", arguments)

    def repair_capture_ledger(self, **arguments: Any) -> dict[str, Any]:
        return self.call("repair_capture_ledger", arguments)

    def verify_recovery_bundle(
        self,
        receipt_path: str | os.PathLike[str],
        **arguments: Any,
    ) -> dict[str, Any]:
        return self.call(
            "verify_recovery_bundle",
            {"receipt_path": str(receipt_path), **arguments},
        )

    def restore_recovery_bundle_isolated(
        self,
        receipt_path: str | os.PathLike[str],
        output_root: str | os.PathLike[str],
        **arguments: Any,
    ) -> dict[str, Any]:
        return self.call(
            "restore_recovery_bundle_isolated",
            {
                "receipt_path": str(receipt_path),
                "output_root": str(output_root),
                **arguments,
            },
        )

    def plan_recovery_retention(self, **arguments: Any) -> dict[str, Any]:
        return self.call("plan_recovery_retention", arguments)

    def apply_recovery_retention(self, **arguments: Any) -> dict[str, Any]:
        return self.call("apply_recovery_retention", arguments)

    def restore_retired_recovery(self, **arguments: Any) -> dict[str, Any]:
        return self.call("restore_retired_recovery", arguments)

    def replication_identity(self) -> dict[str, Any]:
        return self.call("replication_identity")

    def replication_status(self) -> dict[str, Any]:
        return self.call("replication_status")

    def replication_pair_peer(
        self,
        descriptor_path: str | os.PathLike[str],
        expected_descriptor_digest: str,
        **arguments: Any,
    ) -> dict[str, Any]:
        return self.call(
            "replication_pair_peer",
            {
                "descriptor_path": str(descriptor_path),
                "expected_descriptor_digest": expected_descriptor_digest,
                **arguments,
            },
        )

    def replication_revoke_peer(self, **arguments: Any) -> dict[str, Any]:
        return self.call("replication_revoke_peer", arguments)

    def replication_create_checkpoint(
        self,
        peer_id: str,
        *,
        timeout_seconds: float = 300.0,
    ) -> dict[str, Any]:
        return self.call(
            "replication_create_checkpoint",
            {"peer_id": peer_id},
            timeout_seconds=timeout_seconds,
        )

    def replication_stage_checkpoint(
        self,
        manifest_path: str | os.PathLike[str],
        *,
        timeout_seconds: float = 300.0,
    ) -> dict[str, Any]:
        return self.call(
            "replication_stage_checkpoint",
            {"manifest_path": str(manifest_path)},
            timeout_seconds=timeout_seconds,
        )

    def replication_record_acknowledgement(
        self,
        acknowledgement_path: str | os.PathLike[str],
        *,
        timeout_seconds: float = 300.0,
    ) -> dict[str, Any]:
        return self.call(
            "replication_record_acknowledgement",
            {"acknowledgement_path": str(acknowledgement_path)},
            timeout_seconds=timeout_seconds,
        )

    def run_quick_pruning(self, **arguments: Any) -> dict[str, Any]:
        return self.call("run_quick_pruning", arguments)

    def run_idle_maintenance(self, **arguments: Any) -> dict[str, Any]:
        return self.call("run_idle_maintenance", arguments)

    def run_deep_sleep_consolidation(self, **arguments: Any) -> dict[str, Any]:
        return self.call("run_deep_sleep_consolidation", arguments)

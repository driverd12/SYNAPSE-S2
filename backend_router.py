from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from core_authority import (
    CORE_AUTHORITY_INSTANCE_RE,
    CORE_AUTHORITY_LOCK_GENERATION_RE,
    CORE_AUTHORITY_SCHEMA_VERSION,
)
from core_client_binding import apply_binding_environment
from core_request_journal import JOURNAL_BINDING_SCHEMA, JOURNAL_SCHEMA_VERSION
from core_runtime_paths import (
    CoreRuntimePathError,
    canonical_core_socket_path,
    supported_core_socket_path,
)


CORE_SOCKET_ENV = "SYNAPSE_S2_CORE_SOCKET"
MEMORY_DB_ENV = "SYNAPSE_S2_MEMORY_DB"
STATE_PATH_ENV = "SYNAPSE_S2_STATE_PATH"
LEGACY_CORE_CONFIG_ENV = frozenset(
    {
        "SYNAPSE_S2_DIMENSION",
        "SYNAPSE_S2_EMBEDDING_PROVIDER",
        "SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS",
        "SYNAPSE_S2_NEURAL_CACHE_DIR",
        "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY",
        "SYNAPSE_S2_NEURAL_MODEL",
        "SYNAPSE_S2_NEURAL_MODEL_ID",
        "SYNAPSE_S2_NEURAL_REVISION",
        "SYNAPSE_S2_NEURAL_POOLING",
        "SYNAPSE_S2_NEURAL_MAX_TOKENS",
        "SYNAPSE_S2_NEURAL_NORMALIZE",
        "SYNAPSE_S2_NEURONS",
        "SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS",
        "SYNAPSE_S2_RECALL_COUNT",
        "SYNAPSE_S2_REQUIRE_NATIVE",
        "SYNAPSE_S2_TOP_K",
    }
)


class BackendRoutingError(RuntimeError):
    """A safe routing/configuration error that never triggers local fallback."""


class DatabaseInspectionState(str, Enum):
    """Read-only routing states; none of them implicitly initializes SQLite."""

    MISSING = "missing"
    BLANK = "blank"
    LEGACY_V5 = "legacy-v5"
    AUTHORITATIVE_V6 = "authoritative-core-v6"
    INVALID = "invalid"
    UNINSPECTABLE = "uninspectable"


@dataclass(frozen=True)
class DatabaseInspection:
    state: DatabaseInspectionState
    user_version: int | None
    config_fingerprint: str | None = None
    failure: str | None = None


@dataclass(frozen=True)
class BackendRoute:
    mode: str
    socket_path: Path | None
    memory_path: Path | None
    state_path: Path | None
    source: str
    config_fingerprint: str | None = None


class LocalMaintenanceBackend:
    """Non-initializing v5 audit/repair facade for explicit offline work."""

    def __init__(self, memory_path: str | os.PathLike[str]) -> None:
        from memory_store import DurableMemoryStore

        self.memory_store = DurableMemoryStore.open_existing_for_audit(memory_path)

    def close(self) -> None:
        self.memory_store.close()

    def audit_semantic_indexes(self, **arguments: Any) -> dict[str, Any]:
        return self.memory_store.audit_semantic_indexes(**arguments)

    def repair_semantic_indexes(self, **arguments: Any) -> dict[str, Any]:
        return self.memory_store.repair_semantic_indexes(**arguments)

    def _recovery_manager(
        self,
        capture_root: str | os.PathLike[str] | None,
    ) -> Any:
        from recovery_manager import VerifiedRecoveryManager

        return VerifiedRecoveryManager(
            self.memory_store,
            capture_root=capture_root or self.memory_store.db_path.parent,
        )

    def audit_capture_ledger(
        self,
        *,
        capture_root: str | os.PathLike[str] | None = None,
        sample_limit: int = 20,
        adopt_legacy_ledger_schema: bool = False,
    ) -> dict[str, Any]:
        return self._recovery_manager(capture_root).audit_capture_ledger(
            sample_limit=sample_limit,
            adopt_legacy_ledger_schema=adopt_legacy_ledger_schema,
        )

    def repair_capture_ledger(
        self,
        *,
        capture_root: str | os.PathLike[str] | None = None,
        confirm: bool = False,
        expected_revision: str | None = None,
        sample_limit: int = 20,
        adopt_legacy_ledger_schema: bool = False,
    ) -> dict[str, Any]:
        return self._recovery_manager(capture_root).repair_capture_ledger(
            confirm=confirm,
            expected_revision=expected_revision,
            sample_limit=sample_limit,
            adopt_legacy_ledger_schema=adopt_legacy_ledger_schema,
        )


def _absolute_path(value: str | os.PathLike[str], *, field: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise BackendRoutingError(f"{field} must be an absolute normalized path")
    return path


def _default_memory_path(
    *,
    memory_path: str | os.PathLike[str] | None = None,
    state_path: str | os.PathLike[str] | None = None,
) -> Path:
    configured_memory = memory_path or os.getenv(MEMORY_DB_ENV)
    if configured_memory:
        return Path(configured_memory).expanduser()
    project_dir = os.getenv("CLAUDE_PROJECT_DIR") or os.getenv("CODEX_PROJECT_DIR")
    if project_dir:
        return Path(project_dir).expanduser() / ".synapse_s2" / "memory.sqlite3"
    configured_state = state_path or os.getenv(STATE_PATH_ENV)
    if configured_state:
        return Path(configured_state).expanduser().parent / "memory.sqlite3"
    return Path.cwd() / ".synapse_s2" / "memory.sqlite3"


def canonical_core_socket(memory_path: str | os.PathLike[str]) -> Path:
    memory = _absolute_path(memory_path, field="memory database path")
    try:
        return canonical_core_socket_path(memory.parent)
    except CoreRuntimePathError as exc:
        raise BackendRoutingError(
            "authoritative core transport path is unavailable"
        ) from exc


_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_STORE_ID_RE = re.compile(r"\Astore-[0-9a-f]{24}\Z")
_JOURNAL_ID_RE = re.compile(r"\Ajournal-[0-9a-f]{24}\Z")
_GENERATION_ID_RE = re.compile(r"\Ageneration-[0-9a-f]{24}\Z")
_CORE_MARKER_FIELDS = frozenset(
    {
        "schema_version",
        "service_required",
        "epoch",
        "instance_id",
        "config_fingerprint",
        "build_id",
        "protocol_version",
        "lock_generation_id",
        "store_identity",
        "request_journal_id",
        "request_journal_binding_schema",
        "request_journal_schema_version",
        "root_generation_id",
        "embedding_space_identity",
        "restored_target_binding_receipt_digest",
        "claimed_at",
        "updated_at",
    }
)
_DURABLE_CORE_EVIDENCE_NAMES = (
    "store-generation.json",
    "requests.sqlite3",
    "requests.sqlite3-wal",
    "requests.sqlite3-shm",
    "requests.sqlite3.binding.receipt.json",
)


def _validated_marker_fingerprint(
    marker: Any,
    *,
    row_updated_at: Any,
) -> str | None:
    """Return the pinned fingerprint only for the complete v1 marker schema."""

    if not isinstance(marker, dict) or frozenset(marker) != _CORE_MARKER_FIELDS:
        return None
    timestamps = (marker.get("claimed_at"), marker.get("updated_at"))
    timestamps_valid = all(
        type(value) in {int, float}
        and math.isfinite(float(value))
        and float(value) > 0.0
        for value in timestamps
    )
    restored_digest = marker.get("restored_target_binding_receipt_digest")
    fingerprint = marker.get("config_fingerprint")
    if (
        type(marker.get("schema_version")) is not int
        or marker["schema_version"] != CORE_AUTHORITY_SCHEMA_VERSION
        or marker.get("service_required") is not True
        or type(marker.get("epoch")) is not int
        or marker["epoch"] <= 0
        or marker["epoch"] > (2**63 - 1)
        or not isinstance(marker.get("instance_id"), str)
        or CORE_AUTHORITY_INSTANCE_RE.fullmatch(marker["instance_id"]) is None
        or not isinstance(fingerprint, str)
        or _SHA256_RE.fullmatch(fingerprint) is None
        or not isinstance(marker.get("build_id"), str)
        or CORE_AUTHORITY_INSTANCE_RE.fullmatch(marker["build_id"]) is None
        or not isinstance(marker.get("protocol_version"), str)
        or CORE_AUTHORITY_INSTANCE_RE.fullmatch(marker["protocol_version"]) is None
        or not isinstance(marker.get("lock_generation_id"), str)
        or CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(
            marker["lock_generation_id"]
        )
        is None
        or not isinstance(marker.get("store_identity"), str)
        or _STORE_ID_RE.fullmatch(marker["store_identity"]) is None
        or not isinstance(marker.get("request_journal_id"), str)
        or _JOURNAL_ID_RE.fullmatch(marker["request_journal_id"]) is None
        or marker.get("request_journal_binding_schema") != JOURNAL_BINDING_SCHEMA
        or type(marker.get("request_journal_schema_version")) is not int
        or marker["request_journal_schema_version"] != JOURNAL_SCHEMA_VERSION
        or not isinstance(marker.get("root_generation_id"), str)
        or _GENERATION_ID_RE.fullmatch(marker["root_generation_id"]) is None
        or not isinstance(marker.get("embedding_space_identity"), str)
        or _SHA256_RE.fullmatch(marker["embedding_space_identity"]) is None
        or (
            restored_digest is not None
            and (
                not isinstance(restored_digest, str)
                or _SHA256_RE.fullmatch(restored_digest) is None
            )
        )
        or not timestamps_valid
        or float(marker["claimed_at"]) > float(marker["updated_at"])
    ):
        return None
    try:
        persisted_updated_at = float(row_updated_at)
    except (TypeError, ValueError, OverflowError):
        return None
    if (
        not math.isfinite(persisted_updated_at)
        or persisted_updated_at != float(marker["updated_at"])
    ):
        return None
    return fingerprint


def _inspect_database(path: Path) -> DatabaseInspection:
    """Classify one existing/missing SQLite path without creating or repairing it."""

    try:
        observed = path.lstat()
    except FileNotFoundError:
        return DatabaseInspection(DatabaseInspectionState.MISSING, None)
    except OSError:
        return DatabaseInspection(
            DatabaseInspectionState.UNINSPECTABLE,
            None,
            failure="existing memory database could not be inspected safely",
        )
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or observed.st_nlink != 1
    ):
        return DatabaseInspection(
            DatabaseInspectionState.UNINSPECTABLE,
            None,
            failure="existing memory database could not be inspected safely",
        )
    if observed.st_size == 0:
        return DatabaseInspection(DatabaseInspectionState.BLANK, 0)

    absolute = path.absolute()
    uri = f"file:{quote(str(absolute), safe='/')}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=1.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("BEGIN")
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            object_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%'"
                ).fetchone()[0]
            )
            table_exists = connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'store_metadata' LIMIT 1"
            ).fetchone()
            marker_row = (
                None
                if table_exists is None
                else connection.execute(
                    "SELECT value_json, updated_at FROM store_metadata WHERE key = ?",
                    ("core_authority",),
                ).fetchone()
            )
            migrations_table_exists = connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' "
                "AND name = 'store_migrations' LIMIT 1"
            ).fetchone()
            migration_present = bool(
                migrations_table_exists is not None
                and connection.execute(
                    "SELECT 1 FROM store_migrations WHERE key = ? LIMIT 1",
                    ("authoritative_core_v1",),
                ).fetchone()
                is not None
            )
        finally:
            connection.close()
    except (OSError, sqlite3.Error, TypeError, ValueError, OverflowError):
        return DatabaseInspection(
            DatabaseInspectionState.UNINSPECTABLE,
            None,
            failure="existing memory database could not be inspected safely",
        )

    marker_present = marker_row is not None
    adopted_version = user_version >= 6
    if not marker_present:
        if adopted_version or migration_present:
            return DatabaseInspection(
                DatabaseInspectionState.INVALID,
                user_version,
                failure="memory database authority adoption state is inconsistent",
            )
        if user_version == 0 and object_count == 0:
            return DatabaseInspection(DatabaseInspectionState.BLANK, user_version)
        return DatabaseInspection(DatabaseInspectionState.LEGACY_V5, user_version)

    try:
        marker = json.loads(str(marker_row["value_json"]))
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeError):
        return DatabaseInspection(
            DatabaseInspectionState.INVALID,
            user_version,
            failure="authoritative core marker is invalid",
        )
    fingerprint = _validated_marker_fingerprint(
        marker,
        row_updated_at=marker_row["updated_at"],
    )
    if fingerprint is None:
        return DatabaseInspection(
            DatabaseInspectionState.INVALID,
            user_version,
            failure="authoritative core marker is invalid",
        )
    if not adopted_version or not migration_present:
        return DatabaseInspection(
            DatabaseInspectionState.INVALID,
            user_version,
            failure="memory database authority adoption state is inconsistent",
        )
    return DatabaseInspection(
        DatabaseInspectionState.AUTHORITATIVE_V6,
        user_version,
        config_fingerprint=fingerprint,
    )


def _has_adjacent_durable_core_evidence(path: Path) -> bool:
    """Detect deployment evidence that makes an empty local bootstrap unsafe."""

    candidates = [
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
        path.parent / "runtime_state.json",
        *(path.parent / "core" / name for name in _DURABLE_CORE_EVIDENCE_NAMES),
    ]
    for candidate in candidates:
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return True
        return True
    return False


def _safe_database_inspection(path: Path) -> DatabaseInspection:
    inspection = _inspect_database(path)
    if inspection.state in {
        DatabaseInspectionState.INVALID,
        DatabaseInspectionState.UNINSPECTABLE,
    }:
        raise BackendRoutingError(
            inspection.failure or "existing memory database could not be inspected safely"
        )
    if inspection.state in {
        DatabaseInspectionState.MISSING,
        DatabaseInspectionState.BLANK,
    } and _has_adjacent_durable_core_evidence(path):
        raise BackendRoutingError(
            "memory database loss conflicts with durable core evidence"
        )
    return inspection


def database_requires_core(path: str | os.PathLike[str]) -> bool:
    inspection = _safe_database_inspection(Path(path).expanduser())
    return inspection.state is DatabaseInspectionState.AUTHORITATIVE_V6


def resolve_backend_route(
    *,
    memory_path: str | os.PathLike[str] | None = None,
    state_path: str | os.PathLike[str] | None = None,
    socket_path: str | os.PathLike[str] | None = None,
    capture_root: str | os.PathLike[str] | None = None,
) -> BackendRoute:
    """Select the service or local lane without mutating runtime state."""

    binding = apply_binding_environment()
    binding_inspection: DatabaseInspection | None = None
    if binding is not None:
        for supplied, expected, field in (
            (socket_path, binding.socket_path, "authoritative core socket"),
            (memory_path, binding.memory_path, "memory database path"),
            (state_path, binding.state_path, "runtime state path"),
            (capture_root, binding.capture_root, "capture root"),
        ):
            if supplied is not None and _absolute_path(supplied, field=field) != expected:
                raise BackendRoutingError(
                    "explicit client path conflicts with the reviewed core binding"
                )
        binding_inspection = _safe_database_inspection(binding.memory_path)
        governed = (
            binding_inspection.state is DatabaseInspectionState.AUTHORITATIVE_V6
        )
        if binding.authority_mode == "candidate-local-v5" and governed:
            raise BackendRoutingError(
                "candidate client binding is stale after authoritative adoption"
            )
        if binding.authority_mode == "authoritative-core-v6" and not governed:
            raise BackendRoutingError(
                "authoritative client binding does not match database governance"
            )
        if (
            governed
            and binding_inspection.config_fingerprint != binding.config_fingerprint
        ):
            raise BackendRoutingError(
                "authoritative client binding does not match database governance"
            )

    configured_socket = socket_path
    if configured_socket is None and CORE_SOCKET_ENV in os.environ:
        configured_socket = os.environ.get(CORE_SOCKET_ENV)
        if not configured_socket:
            raise BackendRoutingError("authoritative core socket is empty")
    memory = (
        binding.memory_path
        if binding is not None
        else _default_memory_path(memory_path=memory_path, state_path=state_path)
    )
    explicitly_configured_memory = binding is not None or bool(
        memory_path or os.getenv(MEMORY_DB_ENV)
    )
    # A configured socket is the complete installed-client authority pointer.
    # Do not probe an unrelated cwd database unless the caller also supplied a
    # database constraint that must be checked for agreement.
    inspection: DatabaseInspection | None = None
    if configured_socket is None or explicitly_configured_memory:
        inspection = (
            binding_inspection
            if binding_inspection is not None and memory == binding.memory_path
            else _safe_database_inspection(memory)
        )
    requires_core = bool(
        inspection is not None
        and inspection.state is DatabaseInspectionState.AUTHORITATIVE_V6
    )
    if configured_socket is None and requires_core:
        configured_state = state_path or os.getenv(STATE_PATH_ENV)
        if configured_state:
            state = _absolute_path(configured_state, field="runtime state path")
            derived_state = memory.parent / "runtime_state.json"
            if state != derived_state:
                raise BackendRoutingError(
                    "runtime state path and service-required database do not match"
                )
        return BackendRoute(
            mode="service",
            socket_path=canonical_core_socket(memory),
            memory_path=memory,
            state_path=memory.parent / "runtime_state.json",
            source="durable-marker",
            config_fingerprint=inspection.config_fingerprint,
        )
    if configured_socket is None:
        return BackendRoute(
            mode="local",
            socket_path=None,
            memory_path=memory,
            state_path=memory.parent / "runtime_state.json",
            source="local-v5",
            config_fingerprint=None,
        )
    socket = _absolute_path(configured_socket, field="authoritative core socket")
    if (
        binding is None
        and not explicitly_configured_memory
        and (
            socket.name != "service.sock"
            or socket.parent.name != "core"
        )
    ):
        raise BackendRoutingError(
            "split authoritative transport requires a reviewed binding "
            "or explicit memory database"
        )
    if inspection is None and binding_inspection is None:
        # A raw configured Unix socket still has one canonical adjacent store.
        # Inspect it read-only so an already governed deployment pins the exact
        # service configuration instead of silently omitting the assertion.
        inspection = _safe_database_inspection(
            socket.parent.parent / "memory.sqlite3"
        )
    if explicitly_configured_memory:
        if not requires_core:
            raise BackendRoutingError(
                "memory database configuration conflicts with authoritative core mode"
            )
        try:
            supported_socket = supported_core_socket_path(
                socket,
                memory_path=memory,
            )
        except CoreRuntimePathError as exc:
            raise BackendRoutingError(
                "memory database and authoritative core socket do not match"
            ) from exc
        if binding is not None and supported_socket != binding.socket_path:
            raise BackendRoutingError(
                "memory database and authoritative core socket do not match"
            )
    configured_state = state_path or os.getenv(STATE_PATH_ENV)
    derived_state = (
        binding.state_path
        if binding is not None
        else (
            memory.parent / "runtime_state.json"
            if explicitly_configured_memory
            else socket.parent.parent / "runtime_state.json"
        )
    )
    if configured_state:
        state = _absolute_path(configured_state, field="runtime state path")
        if state != derived_state:
            raise BackendRoutingError(
                "runtime state path and authoritative core socket do not match"
            )
    return BackendRoute(
        mode="service",
        socket_path=socket,
        memory_path=memory if explicitly_configured_memory else None,
        state_path=derived_state,
        source="configured-socket",
        config_fingerprint=(
            inspection.config_fingerprint
            if inspection is not None
            else (
                binding_inspection.config_fingerprint
                if binding_inspection is not None
                else None
            )
        ),
    )


def _reject_legacy_core_configuration(
    *,
    actual: Mapping[str, Any] | None = None,
    defaults: Mapping[str, Any] | None = None,
) -> None:
    present = sorted(key for key in LEGACY_CORE_CONFIG_ENV if key in os.environ)
    if present:
        raise BackendRoutingError(
            "authoritative core clients must not configure local neural runtime fields: "
            + ", ".join(present)
        )
    if actual is None:
        return
    expected = dict(defaults or {})
    changed = sorted(
        key for key, value in actual.items() if key not in expected or value != expected[key]
    )
    if changed:
        raise BackendRoutingError(
            "authoritative core clients cannot override local backend fields: "
            + ", ".join(changed)
        )


def core_client_if_required(
    *,
    memory_path: str | os.PathLike[str] | None = None,
    state_path: str | os.PathLike[str] | None = None,
    socket_path: str | os.PathLike[str] | None = None,
    capture_root: str | os.PathLike[str] | None = None,
    caller: str | None = None,
    local_config: Mapping[str, Any] | None = None,
    local_defaults: Mapping[str, Any] | None = None,
) -> Any | None:
    route = resolve_backend_route(
        memory_path=memory_path,
        state_path=state_path,
        socket_path=socket_path,
        capture_root=capture_root,
    )
    if route.mode == "local":
        return None
    _reject_legacy_core_configuration(actual=local_config, defaults=local_defaults)
    from core_client import CoreClient

    return CoreClient(
        socket_path=route.socket_path,
        state_path=route.state_path,
        caller=caller,
        expected_config_fingerprint=route.config_fingerprint,
    )


def build_environment_backend(*, control_plane_only: bool) -> Any:
    client = core_client_if_required()
    if client is not None:
        return client
    from mlx_backend import DEFAULT_NUM_NEURONS, SpikingAttentionBackend

    return SpikingAttentionBackend(
        dimension=int(os.getenv("SYNAPSE_S2_DIMENSION", "1024")),
        num_neurons=int(os.getenv("SYNAPSE_S2_NEURONS", str(DEFAULT_NUM_NEURONS))),
        default_top_k=int(os.getenv("SYNAPSE_S2_TOP_K", "256")),
        recall_count=int(os.getenv("SYNAPSE_S2_RECALL_COUNT", "10")),
        quick_pruning_interval_seconds=float(
            os.getenv("SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS", "300")
        ),
        idle_deep_sleep_seconds=float(
            os.getenv("SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS", "1800")
        ),
        embedding_provider_name=os.getenv("SYNAPSE_S2_EMBEDDING_PROVIDER", "auto"),
        require_native=(
            not control_plane_only
            and os.getenv("SYNAPSE_S2_REQUIRE_NATIVE", "").lower()
            in {"1", "true", "yes", "on"}
        ),
        control_plane_only=control_plane_only,
    )


def build_maintenance_backend(
    *,
    memory_path: str | os.PathLike[str] | None = None,
    state_path: str | os.PathLike[str] | None = None,
    caller: str | None = None,
) -> Any:
    """Route maintenance through core, or a non-initializing explicit v5 facade."""

    client = core_client_if_required(
        memory_path=memory_path,
        state_path=state_path,
        caller=caller,
    )
    if client is not None:
        return client
    route = resolve_backend_route(memory_path=memory_path, state_path=state_path)
    assert route.memory_path is not None
    return LocalMaintenanceBackend(route.memory_path)

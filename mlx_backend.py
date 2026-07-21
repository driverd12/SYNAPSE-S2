from __future__ import annotations

import fcntl
import hashlib
import logging
import json
import math
import os
import platform
import re
import secrets
import stat
import sys
import threading
import time
import uuid
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from embedding_providers import (
    EmbeddingProvider,
    EmbeddingProviderConfig,
    EmbeddingProviderError,
    resolve_embedding_provider,
    resolve_embedding_provider_config,
)
from event_segmenter import BayesianSurpriseEventSegmenter
from bridge_governance import (
    BridgeGovernance,
    BridgeGovernanceInvalidTransition,
    BridgeGovernanceNotFound,
    BridgeGovernanceStaleRevision,
)
from core_authority import (
    CORE_AUTHORITY_LOCK_GENERATION_RE,
    CoreAuthorityError,
    CoreAuthorityLease,
)
from memory_store import (
    CAPTURE_ID_RE,
    CAPTURE_PROTOCOL_VERSION,
    DurableMemoryStore,
    RetrievalSnapshotStaleError,
    RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA,
    capture_request_fingerprint,
)
from retrieval_cursor import (
    DEFAULT_RETRIEVAL_CURSOR_TTL_SECONDS,
    RetrievalCursorCodec,
    RetrievalCursorFilterMismatchError,
    RetrievalCursorSnapshotMismatchError,
    canonical_ordering,
)
from redaction import (
    SECRET_SAFE_LOG_FORMAT,
    SecretRedactingFormatter,
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    safe_public_error,
    strip_untrusted_raw_digest_fields,
    strip_untrusted_raw_digest_text,
)

try:
    import mlx.core as mx
except Exception as exc:  # pragma: no cover - exercised only on non-MLX hosts
    mx = None  # type: ignore[assignment]
    _MLX_IMPORT_ERROR: Exception | None = exc
else:
    _MLX_IMPORT_ERROR = None

try:
    import mlxsnn  # type: ignore[import-not-found]
except Exception as exc:  # pragma: no cover - optional runtime dependency
    mlxsnn = None  # type: ignore[assignment]
    _MLXSNN_IMPORT_ERROR: Exception | None = exc
else:
    _MLXSNN_IMPORT_ERROR = None


LOGGER = logging.getLogger("synapse_s2.backend")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(SecretRedactingFormatter(SECRET_SAFE_LOG_FORMAT))
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

MAX_EMBEDDING_DIMS = 32_768
MAX_RUNTIME_STATE_BYTES = 8_000_000
MAX_RUNTIME_QUARANTINE_SNAPSHOT_BYTES = 1_000_000
DEFAULT_NUM_NEURONS = 8192
DEFAULT_RESOURCE_TARGET_MIN_MB = 96.0
DEFAULT_RESOURCE_TARGET_MAX_MB = 384.0
NEURAL_ARRAY_BYTES_PER_ELEMENT = 4
MAX_NEURAL_MATRIX_BYTES = int(
    DEFAULT_RESOURCE_TARGET_MAX_MB * 1024 * 1024
)
CONTEXT_ID_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
TAG_RE = re.compile(r"[^A-Za-z0-9_.: /#-]+")
AGENT_ID_RE = re.compile(r"[^A-Za-z0-9_.:@-]+")
CONSOLIDATION_PHASES = (
    "connection-weight-decay",
    "synaptic-clustering",
    "semantic-merging",
    "threshold-rescoring",
    "trace-promotion",
    "relationship-extraction",
    "neurogenesis",
)


def _estimated_neural_substrate_bytes(*, dimension: int, num_neurons: int) -> int:
    """Return the exact steady-state float32 dense-topology footprint."""

    return NEURAL_ARRAY_BYTES_PER_ELEMENT * (
        dimension * num_neurons
        + num_neurons * num_neurons
        + (3 * num_neurons)  # membrane, spikes, and active-trace vectors
    )


def _require_neural_resource_envelope(*, dimension: int, num_neurons: int) -> None:
    if dimension <= 0:
        raise ValueError("dimension must be positive")
    if num_neurons <= 0:
        raise ValueError("num_neurons must be positive")
    if _estimated_neural_substrate_bytes(
        dimension=dimension,
        num_neurons=num_neurons,
    ) > MAX_NEURAL_MATRIX_BYTES:
        raise ValueError("neural topology exceeds the 384 MiB resource envelope")


DEFAULT_AGENT_TARGETS = ("mcp-clients", "codex-desktop", "local-ide-adapters")
CONTEXT_BUS_DELIVERY_MODE = "leased-at-least-once"
CONTEXT_BUS_PROTOCOL_VERSION = "context-delivery.v2"
CONSUMER_GROUPS_BY_AGENT = {
    "codex-desktop": ("mcp-clients", "local-ide-adapters"),
    "claude-desktop": ("mcp-clients", "local-ide-adapters"),
    "claude-code": ("mcp-clients", "local-ide-adapters"),
    "project-mcp": ("mcp-clients", "local-ide-adapters"),
    "local-mcp-client": ("mcp-clients",),
    "mcp-client": ("mcp-clients",),
    "dashboard-ui": ("mcp-clients", "local-ide-adapters"),
}
CORTEX_TRACE_TYPES = {
    "goal",
    "objective",
    "decision",
    "constraint",
    "evidence",
    "blocker",
    "implementation",
    "validation",
    "risk",
    "correction",
    "follow_up",
    "assumption",
}
CORTEX_TRUTH_POSTURES = {
    "observed",
    "inferred",
    "operator-confirmed",
    "test-validated",
    "stale",
}
CORTEX_MODES = {"strict", "creative", "operator", "security", "demo"}
CORTEX_TERMINAL_SESSION_STATUSES = {"closed", "finished", "orphaned"}
GOAL_LEDGER_STATES = {"planned", "in_progress", "blocked", "done", "stale"}
SURFACE_DETAIL_STOP_WORDS = {
    "about",
    "after",
    "again",
    "against",
    "also",
    "because",
    "before",
    "being",
    "between",
    "could",
    "from",
    "have",
    "into",
    "only",
    "should",
    "that",
    "their",
    "there",
    "these",
    "this",
    "with",
    "would",
}
MAX_SURFACE_RECALL_SOURCE_CHARS = 4096
SURFACE_RECALL_TERM_RE = re.compile(r"[a-z0-9][a-z0-9_./:-]{1,63}")

# Retrieval v2 is deliberately a separate, read-only contract.  These limits are
# server-owned so callers cannot turn a recall request into unbounded token,
# SQLite-placeholder, graph, or quadratic-diversity work.
RETRIEVAL_V2_SCHEMA = "synapse-retrieval.v2"
RETRIEVAL_V2_RANKER_ID = "synapse-hybrid-mmr"
RETRIEVAL_V2_RANKER_VERSION = "2.0.0"
RETRIEVAL_V2_MAX_PROMPT_BYTES = 16_384
RETRIEVAL_V2_MAX_QUERY_TERMS = 64
RETRIEVAL_V2_MAX_QUERY_SPIKES = 256
RETRIEVAL_V2_MAX_RESULT_LIMIT = 50
RETRIEVAL_V2_MAX_CANDIDATE_LIMIT = 512
RETRIEVAL_V2_MAX_SCOPE_CONTEXTS = 256
RETRIEVAL_V2_MAX_SCOPE_LINKS = 512
RETRIEVAL_V2_MAX_GRAPH_ANCHORS = 8
RETRIEVAL_V2_MAX_GRAPH_EDGES_PER_ANCHOR = 16
RETRIEVAL_V2_MAX_GRAPH_EDGES = 64
RETRIEVAL_V2_MAX_ITEM_TERMS = 128
RETRIEVAL_V2_MAX_DIVERSITY_TERMS = 32
RETRIEVAL_V2_MMR_LAMBDA = 0.82
RETRIEVAL_V2_RANK_WEIGHTS = {
    "spike_index": 0.55,
    "surface_index": 0.40,
    "same_context_graph": 0.05,
}
RETRIEVAL_PAGE_SCHEMA = "synapse-s2.retrieval-page.v2"
NAMESPACE_DETAIL_LEVELS = {"cortex", "ganglion", "neurons"}
NAMESPACE_DETAIL_ENTRY_SCAN_LIMIT = 10_000
NAMESPACE_DETAIL_RELATIONSHIP_SCAN_LIMIT = 20_000
NAMESPACE_DETAIL_MAX_RETURNED_NODES = 500
NAMESPACE_DETAIL_MAX_RETURNED_CLUSTERS = 500
NAMESPACE_DETAIL_MAX_RETURNED_EDGES = 2_000


class BackendUnavailable(RuntimeError):
    """Raised when the native MLX runtime is unavailable."""


@dataclass(frozen=True)
class ConsolidationTiming:
    started_at: float

    def elapsed_ms(self) -> float:
        return round((time.perf_counter() - self.started_at) * 1000.0, 3)


def _require_mx() -> Any:
    if mx is None:
        raise BackendUnavailable(
            "mlx.core import failed: "
            f"{safe_public_error(_MLX_IMPORT_ERROR or 'unavailable', fallback='unavailable')}"
        )
    return mx


def sanitize_context_id(context_id: str) -> str:
    raw = reject_sensitive_identifier(
        context_id or "default",
        field="context_id",
    ).strip()
    cleaned = CONTEXT_ID_RE.sub("_", raw).strip("._-:")
    return (cleaned or "default")[:128]


def sanitize_tag(tag: str) -> str:
    raw = reject_sensitive_identifier(tag or "", field="tag").strip()
    cleaned = TAG_RE.sub("_", raw).strip()
    return (cleaned or "untagged-trace")[:200]


def sanitize_agent_id(agent_id: str) -> str:
    raw = reject_sensitive_identifier(agent_id or "", field="agent_id").strip()
    cleaned = AGENT_ID_RE.sub("_", raw).strip("._-:@")
    return (cleaned or "unknown-agent")[:128]


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write_private_json(
    path: Path,
    payload: dict[str, Any],
    *,
    before_replace: Callable[[], None] | None = None,
    after_replace: Callable[[], None] | None = None,
) -> None:
    _ensure_private_directory(path.parent)
    temp_path = path.parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
    fd = -1
    try:
        fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(temp_path, path)
        path.chmod(0o600)
        _fsync_directory(path.parent)
        if after_replace is not None:
            after_replace()
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _file_identity(stat_result: os.stat_result) -> tuple[int, int, int]:
    return (
        int(stat_result.st_dev),
        int(stat_result.st_ino),
        int(stat.S_IFMT(stat_result.st_mode)),
    )


def _read_bounded_regular_text(
    path: Path,
    *,
    max_bytes: int,
    allow_truncate: bool = False,
    errors: str = "strict",
) -> tuple[str, os.stat_result, bool]:
    """Read a stable regular file by descriptor without following symlinks."""

    observed = os.lstat(path)
    if stat.S_ISLNK(observed.st_mode) or not stat.S_ISREG(observed.st_mode):
        raise ValueError("runtime state must be a regular non-symlink file")
    bounded_max = max(1, int(max_bytes))
    if int(observed.st_size) > bounded_max and not allow_truncate:
        raise ValueError("runtime state exceeds the supported size limit")

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _file_identity(opened) != _file_identity(observed)
        ):
            raise ValueError("runtime state changed during secure open")
        if int(opened.st_size) > bounded_max and not allow_truncate:
            raise ValueError("runtime state exceeds the supported size limit")

        remaining = bounded_max + 1
        chunks: list[bytes] = []
        while remaining > 0:
            try:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(int(getattr(opened, key)) != int(getattr(after, key)) for key in stable_fields):
            raise ValueError("runtime state changed while it was being read")
        truncated = len(raw) > bounded_max or int(after.st_size) > bounded_max
        if truncated and not allow_truncate:
            raise ValueError("runtime state exceeds the supported size limit")
        return raw[:bounded_max].decode("utf-8", errors=errors), opened, truncated
    finally:
        os.close(descriptor)


def _ensure_private_directory(path: Path) -> None:
    """Create missing directories privately without chmodding existing owners."""

    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            # A concurrently created directory is caller-owned; do not mutate it.
            if not directory.is_dir():
                raise


@contextmanager
def _exclusive_runtime_state_lock(state_path: Path):
    """Serialize runtime-state read/merge/replace across local processes."""

    _ensure_private_directory(state_path.parent)
    lock_path = state_path.with_name(f".{state_path.name}.lock")
    flags = os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(lock_path, flags)
    try:
        opened = os.fstat(descriptor)
        if created:
            os.fchmod(descriptor, 0o600)
            opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise RuntimeError("runtime state lock identity is unsafe")
        visible = lock_path.lstat()
        if (
            stat.S_ISLNK(visible.st_mode)
            or _file_identity(visible) != _file_identity(opened)
            or visible.st_uid != opened.st_uid
            or visible.st_nlink != 1
            or stat.S_IMODE(visible.st_mode) != 0o600
        ):
            raise RuntimeError("runtime state lock path changed during open")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        held = os.fstat(descriptor)
        visible = lock_path.lstat()
        if (
            _file_identity(held) != _file_identity(opened)
            or _file_identity(visible) != _file_identity(opened)
            or visible.st_uid != opened.st_uid
            or visible.st_nlink != 1
            or stat.S_IMODE(visible.st_mode) != 0o600
        ):
            raise RuntimeError("runtime state lock identity changed after acquisition")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def context_consumer_groups(agent_id: str) -> tuple[str, ...]:
    """Resolve only explicitly registered local consumer group memberships."""

    return tuple(
        CONSUMER_GROUPS_BY_AGENT.get(sanitize_agent_id(agent_id).casefold(), ())
    )


def sanitize_recall_scope(recall_scope: str) -> str:
    normalized = str(recall_scope or "local").strip().lower()
    if normalized == "broad":
        normalized = "all"
    if normalized not in {"local", "connected", "all"}:
        raise ValueError("recall_scope must be local, connected, or all")
    return normalized


def _array_to_int_list(array: Any) -> list[int]:
    return [int(item) for item in array.tolist()]


class SpikingAttentionBackend:
    """Metal-oriented spiking associative memory backend.

    The implementation keeps the public math explicit instead of hiding state
    behind a mutable neuron object. That preserves compatibility with MLX's
    functional execution model and lets the process run even when the optional
    `mlxsnn` package is not installed yet.
    """

    def __init__(
        self,
        *,
        dimension: int = 1024,
        num_neurons: int = DEFAULT_NUM_NEURONS,
        default_top_k: int = 256,
        recall_count: int = 10,
        beta: float = 0.95,
        threshold: float = 1.0,
        w_syn_scale: float = 0.01,
        w_lateral_scale: float = 0.002,
        excitatory_ratio: float = 0.8,
        trace_decay: float = 0.92,
        quick_decay_syn: float = 0.99,
        quick_decay_lateral: float = 0.98,
        stdp_a_plus: float = 0.012,
        stdp_a_minus: float = 0.010,
        stdp_tau_plus: float = 20.0,
        stdp_tau_minus: float = 24.0,
        stdp_clip: float = 0.05,
        stdp_active_limit: int = 512,
        quick_pruning_interval_seconds: float = 300.0,
        idle_deep_sleep_seconds: float = 1800.0,
        quick_pruning_eager_decay_elements: int = 4_000_000,
        compile_graph: bool = True,
        state_path: str | os.PathLike[str] | None = None,
        memory_path: str | os.PathLike[str] | None = None,
        embedding_provider_name: str | None = None,
        embedding_provider_config: EmbeddingProviderConfig | None = None,
        embedding_provider: EmbeddingProvider | None = None,
        require_native: bool = False,
        control_plane_only: bool = False,
        authority_lease: CoreAuthorityLease | None = None,
    ) -> None:
        if dimension <= 0:
            raise ValueError("dimension must be positive")
        if num_neurons <= 0:
            raise ValueError("num_neurons must be positive")
        resolved_dimension = int(dimension)
        resolved_num_neurons = int(num_neurons)
        _require_neural_resource_envelope(
            dimension=resolved_dimension,
            num_neurons=resolved_num_neurons,
        )
        if not 0.0 < beta < 1.0:
            raise ValueError("beta must be in the open interval (0, 1)")
        if threshold <= 0.0:
            raise ValueError("threshold must be positive")
        if quick_pruning_interval_seconds < 0.0:
            raise ValueError("quick_pruning_interval_seconds must be non-negative")
        if idle_deep_sleep_seconds < 0.0:
            raise ValueError("idle_deep_sleep_seconds must be non-negative")

        native_mx = _require_mx()
        self.dimension = resolved_dimension
        self.num_neurons = resolved_num_neurons
        self.default_top_k = int(max(1, default_top_k))
        self.recall_count = int(max(1, recall_count))
        self.beta = float(beta)
        self.threshold = float(threshold)
        self.trace_decay = float(trace_decay)
        self.quick_decay_syn = float(quick_decay_syn)
        self.quick_decay_lateral = float(quick_decay_lateral)
        self.stdp_a_plus = float(stdp_a_plus)
        self.stdp_a_minus = float(stdp_a_minus)
        self.stdp_tau_plus = float(stdp_tau_plus)
        self.stdp_tau_minus = float(stdp_tau_minus)
        self.stdp_clip = float(stdp_clip)
        self.stdp_active_limit = int(max(0, stdp_active_limit))
        self.quick_pruning_interval_seconds = float(quick_pruning_interval_seconds)
        self.idle_deep_sleep_seconds = float(idle_deep_sleep_seconds)
        self.quick_pruning_eager_decay_elements = int(
            max(0, quick_pruning_eager_decay_elements)
        )
        self.W_syn_decay_multiplier = 1.0
        self.W_lateral_decay_multiplier = 1.0
        self.control_plane_only = bool(control_plane_only)
        self._mx = native_mx
        self._lif_step = (
            None
            if self.control_plane_only
            else self._build_lif_step(compile_graph)
        )
        self._mlxsnn_available = mlxsnn is not None
        self._mlxsnn_lif_layer = (
            None
            if self.control_plane_only
            else self._build_mlxsnn_lif_layer()
        )
        if embedding_provider is not None:
            if embedding_provider_name is not None or embedding_provider_config is not None:
                raise ValueError(
                    "embedding_provider cannot be combined with provider name or config"
                )
            if not isinstance(embedding_provider, EmbeddingProvider):
                raise TypeError("embedding_provider must be an EmbeddingProvider")
            self.embedding_provider = embedding_provider
            self.embedding_provider_name = str(embedding_provider.provider_id)
        elif embedding_provider_config is not None:
            if embedding_provider_name is not None:
                raise ValueError(
                    "embedding_provider_config cannot be combined with provider name"
                )
            if not isinstance(embedding_provider_config, EmbeddingProviderConfig):
                raise TypeError(
                    "embedding_provider_config must be EmbeddingProviderConfig"
                )
            self.embedding_provider = resolve_embedding_provider_config(
                embedding_provider_config
            )
            self.embedding_provider_name = str(self.embedding_provider.provider_id)
        else:
            self.embedding_provider_name = embedding_provider_name or os.getenv(
                "SYNAPSE_S2_EMBEDDING_PROVIDER",
                "auto",
            )
            self.embedding_provider = resolve_embedding_provider(
                self.embedding_provider_name
            )
        self.state_path = self._resolve_state_path(state_path)
        if memory_path is None and state_path is not None:
            resolved_memory_path = self.state_path.parent / "memory.sqlite3"
        else:
            resolved_memory_path = self._resolve_memory_path(memory_path)
        self.memory_store = DurableMemoryStore(
            resolved_memory_path,
            authority_lease=authority_lease,
        )
        # Keep the lifecycle engine strict by default for direct callers while
        # the single-user backend uses an explicit proposal/review workflow
        # without pretending that two local process identifiers are two human
        # approvers. The authoritative core binds every actor field to the
        # OS-verified local-owner principal; all decisions require a fresh CAS
        # revision, but this local deployment does not claim two-person review.
        self.bridge_governance = BridgeGovernance(
            self.memory_store,
            require_distinct_reviewer=False,
            allow_compatibility_approval=True,
        )
        self._core_preclaim_bootstrap = bool(
            authority_lease is not None
            and authority_lease.role == "core"
            and authority_lease.durable_epoch is None
        )
        self.delivery_instance_id = f"backend-{os.getpid()}-{uuid.uuid4().hex[:12]}"
        self.global_enabled = True
        self.context_overrides: dict[str, bool] = {}
        self._global_enabled_dirty = False
        self._dirty_context_overrides: set[str] = set()
        self.runtime_state_repair: dict[str, Any] = {}
        self._loaded_runtime_authority_binding: dict[str, Any] | None = None
        self.cortex_sessions: dict[str, dict[str, Any]] = {}
        self.registered_traces: list[dict[str, Any]] = []
        self._surface_recall_cache: dict[str, dict[str, Any]] = {}
        self._retrieval_cursor_codec: RetrievalCursorCodec | None = None
        self._retrieval_cursor_lock = threading.Lock()

        if self.control_plane_only:
            # MCP discovery, health, graph hydration, and Cortex bookkeeping do
            # not need the dense recurrent substrate.  Avoid constructing the
            # O(neurons^2) lateral matrix in short-lived control-plane clients;
            # neural tools materialize the authoritative full backend lazily.
            self.W_syn = None
            self.W_lateral = None
            self.state = {"mem": None, "spk": None}
            self.active_traces = None
        else:
            self.W_syn = self._balanced_matrix(
                (self.dimension, self.num_neurons),
                scale=w_syn_scale,
                excitatory_ratio=excitatory_ratio,
            )
            self.W_lateral = self._balanced_lateral_matrix(
                self.num_neurons,
                scale=w_lateral_scale,
                excitatory_ratio=excitatory_ratio,
            )
            self.state = {
                "mem": native_mx.zeros((self.num_neurons,)),
                "spk": native_mx.zeros((self.num_neurons,)),
            }
            self.active_traces = native_mx.zeros((self.num_neurons,))
        self.memory_mapping: dict[int, str] = {}
        self.semantic_hierarchy: dict[str, dict[str, Any]] = {}
        self.last_pruning_monotonic = time.monotonic()
        self.last_activity_monotonic = time.monotonic()
        self.quick_pruning_count = 0
        self.deep_sleep_count = 0
        self.last_maintenance: dict[str, Any] = {}
        self.consolidation_phase_history: list[dict[str, Any]] = []
        if self._core_preclaim_bootstrap:
            self._load_runtime_state_observation_only()
        else:
            self._load_runtime_state()
        if not self.control_plane_only:
            self._refresh_registered_traces()

        if not self._mlxsnn_available:
            LOGGER.warning(
                "mlxsnn import failed; using explicit MLX LIF math until installed: %s",
                _MLXSNN_IMPORT_ERROR,
            )
        if require_native:
            try:
                provider_probe = self.embedding_provider.embed(
                    "synapse-s2 authoritative provider readiness",
                    dimensions=min(8, self.dimension),
                )
                if (
                    len(provider_probe.vector) != min(8, self.dimension)
                    or not all(math.isfinite(float(value)) for value in provider_probe.vector)
                ):
                    raise BackendUnavailable(
                        "embedding provider readiness vector is invalid"
                    )
            except Exception as exc:
                raise BackendUnavailable(
                    "SYNAPSE-S2 embedding provider readiness failed"
                ) from exc
            certification = self.certify_runtime(strict_native=True)
            if not certification["ready"]:
                raise BackendUnavailable(
                    "SYNAPSE-S2 native certification failed: "
                    + ", ".join(certification["failed_checks"])
                )

    def _resolve_state_path(self, state_path: str | os.PathLike[str] | None) -> Path:
        if state_path is not None:
            return self._validated_runtime_state_path(state_path)
        configured = os.getenv("SYNAPSE_S2_STATE_PATH")
        if configured:
            return self._validated_runtime_state_path(configured)
        project_dir = os.getenv("CLAUDE_PROJECT_DIR") or os.getenv("CODEX_PROJECT_DIR")
        if project_dir:
            safe_project_dir = reject_sensitive_identifier(
                project_dir,
                field="runtime project directory",
            )
            return (
                Path(safe_project_dir).expanduser()
                / ".synapse_s2"
                / "runtime_state.json"
            )
        return Path.cwd() / ".synapse_s2" / "runtime_state.json"

    def _require_neural_substrate(self) -> None:
        if self.control_plane_only:
            raise BackendUnavailable(
                "neural substrate is deferred in the control-plane backend; "
                "use get_backend() for neural capture, tick, and retrieval operations"
            )

    @staticmethod
    def _validated_runtime_state_path(
        value: str | os.PathLike[str],
    ) -> Path:
        try:
            safe_path = reject_sensitive_identifier(
                str(value),
                field="runtime state path",
            )
        except ValueError as exc:
            raise ValueError(
                "runtime state path must not contain credential material"
            ) from exc
        return Path(safe_path)

    def _resolve_memory_path(self, memory_path: str | os.PathLike[str] | None) -> Path:
        if memory_path is not None:
            return Path(memory_path)
        configured = os.getenv("SYNAPSE_S2_MEMORY_DB")
        if configured:
            return Path(configured)
        project_dir = os.getenv("CLAUDE_PROJECT_DIR") or os.getenv("CODEX_PROJECT_DIR")
        if project_dir:
            return Path(project_dir).expanduser() / ".synapse_s2" / "memory.sqlite3"
        return self.state_path.parent / "memory.sqlite3"

    def _load_runtime_state(self) -> None:
        with _exclusive_runtime_state_lock(self.state_path):
            self._load_runtime_state_locked()

    def _load_runtime_state_observation_only(self) -> None:
        """Load only an already-canonical state during core preclaim bootstrap.

        A core authority lease is not yet a durable SQLite authority claim.  At
        this point startup must remain rollback-free: it may observe a canonical
        runtime document, but it may not create a lock file, quarantine or
        rewrite state, or migrate retired embedded traces into SQLite.  Any
        document that the local maintenance loader would repair is rejected so
        an operator can repair it before retrying the authoritative service.
        """

        if self.state_path.is_symlink():
            raise RuntimeError("runtime state path must not be a symlink")
        if not self.state_path.exists():
            return
        try:
            raw_state, observed, truncated = _read_bounded_regular_text(
                self.state_path,
                max_bytes=MAX_RUNTIME_STATE_BYTES,
            )
            if truncated:
                raise ValueError("runtime state exceeds the supported size limit")
            if (
                observed.st_uid != os.getuid()
                or observed.st_nlink != 1
                or stat.S_IMODE(observed.st_mode) != 0o600
            ):
                raise ValueError("runtime state identity is not private")
            payload = json.loads(raw_state)
            if not isinstance(payload, dict):
                raise ValueError("runtime state root must be an object")
            self._apply_canonical_runtime_state(payload)
            canonical = json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            ) + "\n"
            if raw_state != canonical:
                raise ValueError("runtime state serialization is not canonical")
            visible = self.state_path.lstat()
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(
                int(getattr(observed, key)) != int(getattr(visible, key))
                for key in stable_fields
            ):
                raise ValueError("runtime state changed during bootstrap")
        except Exception as exc:
            LOGGER.error(
                "authoritative core refused noncanonical runtime state at %s: %s",
                self.state_path,
                safe_public_error(exc, fallback="invalid runtime state"),
            )
            raise RuntimeError(
                "authoritative core requires canonical runtime state; "
                "run local runtime-state repair before startup"
            ) from None

    def _apply_canonical_runtime_state(self, payload: dict[str, Any]) -> None:
        base_keys = {
            "version",
            "global_enabled",
            "context_overrides",
            "cortex_sessions",
            "runtime_state_repair",
            "memory_db_path",
            "updated_at",
        }
        version = payload.get("version")
        expected_keys = (
            base_keys if version == 2 else base_keys | {"authority_binding"}
        )
        authority_binding = self._validated_runtime_authority_binding(payload)
        if (
            set(payload) != expected_keys
            or version not in {2, 3}
            or (version == 3 and authority_binding is None)
        ):
            raise ValueError("runtime state schema is not canonical")
        if type(payload.get("global_enabled")) is not bool:
            raise ValueError("runtime global_enabled must be boolean")
        raw_overrides = payload.get("context_overrides")
        if not isinstance(raw_overrides, dict) or any(
            type(value) is not bool for value in raw_overrides.values()
        ):
            raise ValueError("runtime context_overrides must be canonical")
        normalized_overrides = self._normalize_persisted_context_overrides(
            raw_overrides
        )
        if normalized_overrides != raw_overrides:
            raise ValueError("runtime context_overrides require repair")
        raw_sessions = payload.get("cortex_sessions")
        if not isinstance(raw_sessions, dict):
            raise ValueError("runtime cortex_sessions must be an object")
        normalized_sessions = self._normalize_persisted_cortex_sessions(raw_sessions)
        if normalized_sessions != raw_sessions:
            raise ValueError("runtime cortex_sessions require repair")
        raw_repair = payload.get("runtime_state_repair")
        if not isinstance(raw_repair, dict):
            raise ValueError("runtime_state_repair must be an object")
        if self._json_safe_metadata(raw_repair) != raw_repair:
            raise ValueError("runtime_state_repair requires repair")
        if payload.get("memory_db_path") != str(self.memory_store.db_path):
            raise ValueError("runtime memory_db_path does not match the active store")
        updated_at = payload.get("updated_at")
        if (
            type(updated_at) not in {int, float}
            or not math.isfinite(float(updated_at))
            or float(updated_at) <= 0.0
        ):
            raise ValueError("runtime updated_at must be a positive finite number")

        self.global_enabled = payload["global_enabled"]
        self.context_overrides = normalized_overrides
        self.cortex_sessions = normalized_sessions
        self.runtime_state_repair = raw_repair
        self._loaded_runtime_authority_binding = authority_binding

    @staticmethod
    def _validated_runtime_authority_binding(
        payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        version = payload.get("version")
        if version == 2:
            return None
        binding = payload.get("authority_binding")
        if (
            version != 3
            or not isinstance(binding, dict)
            or set(binding)
            != {
                "schema",
                "marker_sha256",
                "authority_epoch_number",
                "lock_generation_id",
            }
            or binding.get("schema") != RUNTIME_STATE_AUTHORITY_BINDING_SCHEMA
            or re.fullmatch(r"[0-9a-f]{64}", str(binding.get("marker_sha256") or ""))
            is None
            or type(binding.get("authority_epoch_number")) is not int
            or int(binding["authority_epoch_number"]) <= 0
            or CORE_AUTHORITY_LOCK_GENERATION_RE.fullmatch(
                str(binding.get("lock_generation_id") or "")
            )
            is None
        ):
            raise ValueError("runtime authority binding is invalid")
        return dict(binding)

    def _read_runtime_authority_binding_locked(self) -> dict[str, Any]:
        if not self.state_path.exists() or self.state_path.is_symlink():
            raise CoreAuthorityError("governed runtime state is unavailable")
        raw_state, observed, truncated = _read_bounded_regular_text(
            self.state_path,
            max_bytes=MAX_RUNTIME_STATE_BYTES,
        )
        if (
            truncated
            or observed.st_uid != os.getuid()
            or observed.st_nlink != 1
            or stat.S_IMODE(observed.st_mode) != 0o600
        ):
            raise CoreAuthorityError("governed runtime state is invalid")
        try:
            payload = json.loads(raw_state)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CoreAuthorityError("governed runtime state is invalid") from exc
        if not isinstance(payload, dict):
            raise CoreAuthorityError("governed runtime state is invalid")
        try:
            binding = self._validated_runtime_authority_binding(payload)
        except ValueError as exc:
            raise CoreAuthorityError("governed runtime state is invalid") from exc
        if binding is None or payload.get("memory_db_path") != str(
            self.memory_store.db_path
        ):
            raise CoreAuthorityError("governed runtime state is invalid")
        canonical = json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ) + "\n"
        if raw_state != canonical:
            raise CoreAuthorityError("governed runtime state is invalid")
        return binding

    def assert_runtime_state_authority_marker(
        self,
        marker: dict[str, Any],
    ) -> None:
        """Require the runtime file to match the exact preceding v6 epoch."""

        expected = self.memory_store.runtime_state_authority_binding_for_marker(
            dict(marker)
        )
        with _exclusive_runtime_state_lock(self.state_path):
            observed = self._read_runtime_authority_binding_locked()
        if observed != expected:
            raise CoreAuthorityError(
                "runtime state does not match the durable authority marker"
            )

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
        """Finish only the exact pending publication committed with a claim."""

        def authorize() -> dict[str, Any]:
            return self.memory_store.interrupted_runtime_publication_binding(
                marker=marker,
                publication=publication,
                runtime_state_path=self.state_path,
                expected_config_fingerprint=expected_config_fingerprint,
                expected_build_id=expected_build_id,
                expected_protocol_version=expected_protocol_version,
                expected_root_generation_id=expected_root_generation_id,
                expected_embedding_space_identity=(
                    expected_embedding_space_identity
                ),
            )

        with _exclusive_runtime_state_lock(self.state_path):
            expected = authorize()

            def assert_authorized() -> None:
                if authorize() != expected:
                    raise CoreAuthorityError(
                        "interrupted runtime publication authority changed"
                    )

            payload = {
                "version": 3,
                "global_enabled": bool(self.global_enabled),
                "context_overrides": dict(self.context_overrides),
                "cortex_sessions": dict(self.cortex_sessions),
                "runtime_state_repair": self._json_safe_metadata(
                    self.runtime_state_repair
                ),
                "memory_db_path": str(self.memory_store.db_path),
                "updated_at": time.time(),
                "authority_binding": expected,
            }
            _atomic_write_private_json(
                self.state_path,
                payload,
                before_replace=assert_authorized,
                after_replace=assert_authorized,
            )
            observed = self._read_runtime_authority_binding_locked()
            if observed != expected:
                raise CoreAuthorityError(
                    "interrupted runtime publication did not persist exactly"
                )
            self._loaded_runtime_authority_binding = dict(expected)

    def publish_runtime_state_authority_binding(self) -> None:
        """Durably stamp runtime state with this process's exact claimed epoch."""

        expected = self.memory_store.runtime_state_authority_binding()
        if expected is None:
            raise CoreAuthorityError("runtime state authority is unavailable")
        self._persist_runtime_state()
        with _exclusive_runtime_state_lock(self.state_path):
            observed = self._read_runtime_authority_binding_locked()
        if observed != expected:
            raise CoreAuthorityError(
                "runtime state authority publication did not persist exactly"
            )

    def _load_runtime_state_locked(self) -> None:
        if self.state_path.is_symlink():
            raise RuntimeError("runtime state path must not be a symlink")
        if not self.state_path.exists():
            return
        try:
            raw_state, _state_stat, _truncated = _read_bounded_regular_text(
                self.state_path,
                max_bytes=MAX_RUNTIME_STATE_BYTES,
            )
            payload = json.loads(raw_state)
            if not isinstance(payload, dict):
                raise ValueError("runtime state root must be an object")
        except Exception as exc:
            LOGGER.error(
                "quarantining unreadable runtime state from %s: %s",
                self.state_path,
                safe_public_error(exc, fallback="invalid runtime state"),
            )
            self.runtime_state_repair = self._quarantine_runtime_state_locked(exc)
            self._persist_runtime_state(merge_existing=False, _lock_held=True)
            return

        migrated_trace_count = 0
        dropped_record_count = 0
        self.global_enabled = bool(payload.get("global_enabled", True))
        raw_repair = payload.get("runtime_state_repair", {})
        safe_repair = self._json_safe_metadata(
            raw_repair if isinstance(raw_repair, dict) else {}
        )
        self.runtime_state_repair = safe_repair

        overrides = payload.get("context_overrides", {})
        if isinstance(overrides, dict):
            self.context_overrides = self._normalize_persisted_context_overrides(
                overrides
            )
            dropped_record_count += max(
                0,
                len(overrides) - len(self.context_overrides),
            )
        elif overrides is not None:
            dropped_record_count += 1

        cortex_sessions = payload.get("cortex_sessions", {})
        if isinstance(cortex_sessions, dict):
            self.cortex_sessions = self._normalize_persisted_cortex_sessions(
                cortex_sessions
            )
            dropped_record_count += max(
                0,
                len(cortex_sessions) - len(self.cortex_sessions),
            )
        elif cortex_sessions is not None:
            dropped_record_count += 1

        traces = payload.get("registered_traces", [])
        if isinstance(traces, list):
            for ordinal, raw_trace in enumerate(traces):
                if not isinstance(raw_trace, dict):
                    dropped_record_count += 1
                    continue
                try:
                    trace = self._normalize_trace_payload(raw_trace)
                    self.memory_store.upsert_entry(
                        tag=trace["tag"],
                        context_id=trace["context_id"],
                        source_text=trace["source_text"],
                        metadata=trace["metadata"],
                        embedding_dimensions=trace["embedding_dimensions"],
                        spike_indices=trace["spike_indices"],
                        neuron_indices=trace["neuron_indices"],
                        registered_at=trace["registered_at"],
                    )
                    migrated_trace_count += 1
                except Exception as exc:
                    dropped_record_count += 1
                    LOGGER.warning(
                        "dropped unsafe legacy runtime trace at index %s: %s",
                        ordinal,
                        safe_public_error(exc, fallback="unsafe legacy trace"),
                    )
        elif traces is not None:
            dropped_record_count += 1

        if migrated_trace_count:
            LOGGER.info(
                "migrated %s legacy runtime traces into SQLite memory store",
                migrated_trace_count,
            )
        if dropped_record_count:
            LOGGER.warning(
                "dropped %s unsafe or invalid legacy runtime records",
                dropped_record_count,
            )

        # Always rewrite a successfully read legacy document into the canonical
        # schema. This removes unknown fields and retired embedded trace records,
        # and avoids leaving one rejected record in the raw source document.
        self._persist_runtime_state(merge_existing=False, _lock_held=True)

    def _quarantine_runtime_state_locked(self, error: BaseException) -> dict[str, Any]:
        """Preserve a sanitized repair artifact before replacing invalid state."""

        quarantine_dir = self.state_path.parent / "runtime_state_quarantine"
        if quarantine_dir.is_symlink():
            raise RuntimeError("runtime state quarantine must not be a symlink")
        _ensure_private_directory(quarantine_dir)
        quarantine_stat = quarantine_dir.lstat()
        if not stat.S_ISDIR(quarantine_stat.st_mode):
            raise RuntimeError("runtime state quarantine must be a directory")
        try:
            os.chmod(quarantine_dir, 0o700)
        except PermissionError:
            pass

        try:
            observed = self.state_path.lstat()
        except FileNotFoundError:
            observed = None
        raw_text = ""
        source_size_bytes = int(observed.st_size) if observed is not None else 0
        truncated = False
        snapshot_preserved = False
        if observed is not None and stat.S_ISREG(observed.st_mode):
            raw_text, opened, truncated = _read_bounded_regular_text(
                self.state_path,
                max_bytes=MAX_RUNTIME_QUARANTINE_SNAPSHOT_BYTES,
                allow_truncate=True,
                errors="replace",
            )
            observed = opened
            snapshot_preserved = True
        safe_text, redaction_count = redact_capture_text(raw_text)
        safe_text, digest_removals = strip_untrusted_raw_digest_text(safe_text)
        artifact_name = (
            f"runtime-state-repair-{time.strftime('%Y%m%d-%H%M%S')}-"
            f"{secrets.token_hex(8)}.json"
        )
        artifact_path = quarantine_dir / artifact_name
        repair = {
            "status": "repair-required",
            "reason": "unreadable-runtime-state",
            "error_type": error.__class__.__name__,
            "artifact_name": artifact_name,
            "raw_source_retained": False,
            "sanitized_snapshot_preserved": snapshot_preserved,
            "sanitized_snapshot_truncated": truncated,
            "redaction_count": int(redaction_count) + int(digest_removals),
            "detected_at": time.time(),
        }
        _atomic_write_private_json(
            artifact_path,
            {
                "version": 1,
                "artifact_type": "runtime-state-repair",
                **repair,
                "source_size_bytes": source_size_bytes,
                "sanitized_source_text": safe_text,
            },
        )
        if observed is not None:
            try:
                current = self.state_path.lstat()
            except FileNotFoundError:
                current = None
            if current is not None:
                if _file_identity(current) != _file_identity(observed):
                    raise RuntimeError(
                        "runtime state changed before quarantine cleanup"
                    )
                self.state_path.unlink()
        _fsync_directory(self.state_path.parent)
        return repair

    def _persist_runtime_state(
        self,
        *,
        merge_existing: bool = True,
        _lock_held: bool = False,
    ) -> None:
        try:
            if _lock_held:
                self._persist_runtime_state_locked(merge_existing=merge_existing)
            else:
                with _exclusive_runtime_state_lock(self.state_path):
                    self._persist_runtime_state_locked(merge_existing=merge_existing)
        except Exception:
            LOGGER.exception("failed to persist runtime state to %s", self.state_path)
            raise

    def _persist_runtime_state_locked(self, *, merge_existing: bool) -> None:
        self.memory_store.assert_active_authority()
        authority_binding = self.memory_store.runtime_state_authority_binding()
        existing_payload: dict[str, Any] = {}
        if self.state_path.is_symlink():
            raise RuntimeError("runtime state path must not be a symlink")
        if merge_existing and self.state_path.exists():
            try:
                raw_state, _state_stat, _truncated = _read_bounded_regular_text(
                    self.state_path,
                    max_bytes=MAX_RUNTIME_STATE_BYTES,
                )
                candidate = json.loads(raw_state)
                if isinstance(candidate, dict):
                    existing_payload = candidate
                else:
                    raise ValueError("runtime state root must be an object")
            except Exception as exc:
                LOGGER.warning(
                    "quarantining unreadable runtime state from %s: %s",
                    self.state_path,
                    safe_public_error(exc, fallback="invalid runtime state"),
                )
                self.runtime_state_repair = self._quarantine_runtime_state_locked(exc)

        if merge_existing:
            merged_sessions = self._merged_cortex_sessions_for_persist(
                existing_payload
            )
            raw_existing_overrides = existing_payload.get("context_overrides", {})
            merged_overrides = (
                self._normalize_persisted_context_overrides(raw_existing_overrides)
                if isinstance(raw_existing_overrides, dict)
                else {}
            )
            if not existing_payload:
                merged_overrides.update(self.context_overrides)
            for context in self._dirty_context_overrides:
                if context in self.context_overrides:
                    merged_overrides[context] = bool(self.context_overrides[context])
            merged_global_enabled = (
                bool(self.global_enabled)
                if self._global_enabled_dirty or not existing_payload
                else bool(existing_payload.get("global_enabled", True))
            )
            raw_existing_repair = existing_payload.get("runtime_state_repair", {})
            merged_repair = self._json_safe_metadata(
                self.runtime_state_repair
                or (raw_existing_repair if isinstance(raw_existing_repair, dict) else {})
            )
        else:
            merged_sessions = dict(self.cortex_sessions)
            merged_overrides = dict(self.context_overrides)
            merged_global_enabled = bool(self.global_enabled)
            merged_repair = self._json_safe_metadata(self.runtime_state_repair)

        payload = {
            "version": 3 if authority_binding is not None else 2,
            "global_enabled": merged_global_enabled,
            "context_overrides": merged_overrides,
            "cortex_sessions": merged_sessions,
            "runtime_state_repair": merged_repair,
            "memory_db_path": str(self.memory_store.db_path),
            "updated_at": time.time(),
        }
        if authority_binding is not None:
            payload["authority_binding"] = authority_binding
        _atomic_write_private_json(
            self.state_path,
            payload,
            before_replace=self.memory_store.assert_active_authority,
            after_replace=self.memory_store.assert_active_authority,
        )
        self.global_enabled = merged_global_enabled
        self.context_overrides = merged_overrides
        self.cortex_sessions = merged_sessions
        self.runtime_state_repair = merged_repair
        self._loaded_runtime_authority_binding = (
            None if authority_binding is None else dict(authority_binding)
        )
        self._global_enabled_dirty = False
        self._dirty_context_overrides.clear()

    def _merged_cortex_sessions_for_persist(
        self,
        existing_payload: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        existing_sessions: dict[str, dict[str, Any]] = {}
        raw_sessions = existing_payload.get("cortex_sessions", {})
        if isinstance(raw_sessions, dict):
            existing_sessions = self._normalize_persisted_cortex_sessions(
                raw_sessions
            )

        merged = dict(existing_sessions)
        for session_id, raw_session in self.cortex_sessions.items():
            candidate = dict(raw_session)
            candidate["session_id"] = str(
                candidate.get("session_id") or session_id
            )
            normalized = self._normalize_cortex_session(candidate)
            clean_session_id = normalized["session_id"]
            merged[clean_session_id] = self._prefer_cortex_session(
                merged.get(clean_session_id),
                normalized,
            )
        return merged

    def _normalize_persisted_context_overrides(
        self,
        raw_overrides: dict[Any, Any],
    ) -> dict[str, bool]:
        normalized: dict[str, bool] = {}
        for ordinal, (raw_context, raw_value) in enumerate(raw_overrides.items()):
            try:
                _, value_redactions = redact_sensitive_value(raw_value)
                if value_redactions:
                    raise ValueError(
                        "context override value must not contain credential material"
                    )
                context = sanitize_context_id(str(raw_context))
            except Exception as exc:
                LOGGER.warning(
                    "dropped unsafe runtime context override at index %s: %s",
                    ordinal,
                    safe_public_error(exc, fallback="unsafe context override"),
                )
                continue
            normalized[context] = bool(raw_value)
        return normalized

    def _normalize_persisted_cortex_sessions(
        self,
        raw_sessions: dict[Any, Any],
    ) -> dict[str, dict[str, Any]]:
        """Normalize legacy session maps without retaining secret-bearing keys."""

        normalized: dict[str, dict[str, Any]] = {}
        for ordinal, (stored_id, raw_session) in enumerate(raw_sessions.items()):
            if not isinstance(raw_session, dict):
                continue
            try:
                candidate = dict(raw_session)
                raw_context = str(candidate.get("context_id", "default"))
                raw_agent = str(candidate.get("agent_id", "unknown-agent"))
                candidate["context_id"] = reject_sensitive_identifier(
                    raw_context,
                    field="cortex context_id",
                )
                candidate["agent_id"] = reject_sensitive_identifier(
                    raw_agent,
                    field="cortex agent_id",
                )

                candidate_id = str(candidate.get("session_id") or stored_id).strip()
                try:
                    candidate["session_id"] = reject_sensitive_identifier(
                        candidate_id,
                        field="cortex session_id",
                    )
                except ValueError:
                    safe_candidate, _ = redact_sensitive_value(candidate)
                    if not isinstance(safe_candidate, dict):
                        safe_candidate = {}
                    safe_candidate.pop("session_id", None)
                    seed = json.dumps(
                        {
                            "legacy_session": safe_candidate,
                            "ordinal": ordinal,
                        },
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                    candidate = safe_candidate
                    candidate["session_id"] = (
                        "ctx_legacy_" + hashlib.sha256(seed).hexdigest()[:16]
                    )
                session = self._normalize_cortex_session(candidate)
                normalized[session["session_id"]] = session
            except Exception as exc:
                LOGGER.warning(
                    "dropped unsafe legacy cortex session at index %s: %s",
                    ordinal,
                    safe_public_error(exc, fallback="unsafe cortex session"),
                )
        return normalized

    @staticmethod
    def _prefer_cortex_session(
        existing: dict[str, Any] | None,
        incoming: dict[str, Any],
    ) -> dict[str, Any]:
        if not existing:
            return incoming
        existing_status = str(existing.get("status", "active"))
        incoming_status = str(incoming.get("status", "active"))
        if (
            existing_status in CORTEX_TERMINAL_SESSION_STATUSES
            and incoming_status == "active"
        ):
            return existing
        if (
            incoming_status in CORTEX_TERMINAL_SESSION_STATUSES
            and existing_status == "active"
        ):
            return incoming
        existing_updated_at = float(existing.get("updated_at", 0.0) or 0.0)
        incoming_updated_at = float(incoming.get("updated_at", 0.0) or 0.0)
        return incoming if incoming_updated_at >= existing_updated_at else existing

    def _refresh_registered_traces(self) -> None:
        try:
            entries = self.memory_store.list_entries(limit=10_000)
            self.registered_traces = [
                self._trace_from_memory_entry(entry)
                for entry in entries
            ]
            self.memory_mapping = {}
            for trace in self.registered_traces:
                for neuron_idx in trace["neuron_indices"]:
                    self.memory_mapping.setdefault(int(neuron_idx), trace["tag"])
        except Exception:
            LOGGER.exception("failed to refresh registered traces from %s", self.memory_store.db_path)
            raise

    def _trace_from_memory_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        safe_source_text, _ = redact_capture_text(str(entry.get("source_text", "")))
        return {
            "memory_id": str(entry["memory_id"]),
            "tag": sanitize_tag(str(entry["tag"])),
            "context_id": sanitize_context_id(str(entry["context_id"])),
            "embedding_dimensions": int(entry["embedding_dimensions"]),
            "spike_indices": [int(idx) for idx in entry.get("spike_indices", [])],
            "neuron_indices": [int(idx) for idx in entry.get("neuron_indices", [])],
            "metadata": self._json_safe_metadata(entry.get("metadata", {})),
            "registered_at": float(entry.get("created_at", time.time())),
            "updated_at": float(entry.get("updated_at", time.time())),
            "source_text": safe_source_text,
        }

    def _normalize_trace_payload(self, trace: dict[str, Any]) -> dict[str, Any]:
        metadata = trace.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {"value": str(metadata)}
        safe_source_text, source_redactions = redact_capture_text(
            str(trace.get("source_text", ""))
        )
        safe_metadata = self._json_safe_metadata(metadata)
        if source_redactions:
            safe_metadata = {
                **safe_metadata,
                "redaction_count": int(
                    source_redactions
                    + int(safe_metadata.get("redaction_count", 0) or 0)
                ),
                "raw_text_stored": False,
            }
        return {
            "tag": sanitize_tag(str(trace.get("tag", "untagged-trace"))),
            "context_id": sanitize_context_id(str(trace.get("context_id", "default"))),
            "embedding_dimensions": int(trace.get("embedding_dimensions", self.dimension)),
            "spike_indices": [int(idx) for idx in trace.get("spike_indices", [])],
            "neuron_indices": [int(idx) for idx in trace.get("neuron_indices", [])],
            "metadata": safe_metadata,
            "registered_at": float(trace.get("registered_at", time.time())),
            "source_text": safe_source_text,
        }

    def _json_safe_metadata(self, metadata: dict[str, Any] | None) -> dict[str, Any]:
        if not metadata:
            return {}
        safe_value, _ = redact_sensitive_value(metadata)
        safe_value, _ = strip_untrusted_raw_digest_fields(safe_value)
        if not isinstance(safe_value, dict):
            return {}
        try:
            decoded = json.loads(json.dumps(safe_value, allow_nan=False))
        except (TypeError, ValueError):
            return {}
        return decoded if isinstance(decoded, dict) else {}

    def _normalize_cortex_session(self, session: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        session_id = str(session.get("session_id") or "").strip()
        if not session_id:
            safe_session, _ = redact_sensitive_value(session)
            seed = json.dumps(safe_session, sort_keys=True, default=str).encode("utf-8")
            session_id = "ctx_" + hashlib.sha256(seed).hexdigest()[:16]
        else:
            session_id = reject_sensitive_identifier(
                session_id,
                field="cortex session_id",
            )
        mode = str(session.get("mode") or "strict").strip().lower()
        if mode not in CORTEX_MODES:
            mode = "strict"
        status = str(session.get("status") or "active").strip().lower()
        if status not in {"active", "closed", "finished", "orphaned"}:
            status = "active"
        task, _ = redact_capture_text(str(session.get("task", "")))
        observation, _ = redact_capture_text(
            str(session.get("last_observation", ""))
        )
        proposed_action, _ = redact_capture_text(
            str(session.get("last_proposed_action", ""))
        )
        last_decision, _ = redact_capture_text(
            str(session.get("last_decision", "enter"))
        )
        normalized = {
            "session_id": session_id,
            "context_id": sanitize_context_id(str(session.get("context_id", "default"))),
            "agent_id": sanitize_agent_id(str(session.get("agent_id", "unknown-agent"))),
            "task": task.strip()[:2000],
            "mode": mode,
            "status": status,
            "started_at": float(session.get("started_at", now) or now),
            "updated_at": float(session.get("updated_at", now) or now),
            "tick_count": int(max(0, int(session.get("tick_count", 0) or 0))),
            "last_decision": last_decision,
            "last_confidence": float(session.get("last_confidence", 0.0) or 0.0),
            "last_observation": observation[:2000],
            "last_proposed_action": proposed_action[:2000],
            "last_warnings": self._json_safe_metadata(
                {"items": session.get("last_warnings", [])}
            ).get("items", []),
            "last_intended_files": self._json_safe_metadata(
                {"items": session.get("last_intended_files", [])}
            ).get("items", []),
            "last_intended_tools": self._json_safe_metadata(
                {"items": session.get("last_intended_tools", [])}
            ).get("items", []),
            "last_recall_items": self._json_safe_metadata(
                {"items": session.get("last_recall_items", [])}
            ).get("items", []),
            "last_capture_recommendation": self._json_safe_metadata(
                {"value": session.get("last_capture_recommendation", {})}
            ).get("value", {}),
        }
        for key in (
            "client_bridge_session_id",
            "finish_reason",
            "lease_kind",
            "orphan_reason",
        ):
            if session.get(key):
                safe_value, _ = redact_capture_text(str(session.get(key, "")))
                normalized[key] = safe_value[:500]
        for key in ("finished_at", "owner_started_at"):
            if session.get(key) is not None:
                try:
                    normalized[key] = float(session.get(key, 0.0) or 0.0)
                except (TypeError, ValueError):
                    normalized[key] = 0.0
        for key in ("owner_pid", "owner_ppid"):
            if session.get(key) is not None:
                try:
                    normalized[key] = int(session.get(key, 0) or 0)
                except (TypeError, ValueError):
                    normalized[key] = 0
        return normalized

    def _build_lif_step(self, compile_graph: bool):
        native_mx = self._mx

        def lif_step(mem, input_current, beta, threshold):
            next_mem = beta * mem + input_current
            spikes = native_mx.where(next_mem >= threshold, 1.0, 0.0)
            next_mem = next_mem - spikes * threshold
            return spikes, next_mem

        if compile_graph and hasattr(native_mx, "compile"):
            try:
                return native_mx.compile(lif_step)
            except Exception as exc:  # pragma: no cover - compile varies by host
                LOGGER.warning("mx.compile unavailable for LIF step: %s", exc)
        return lif_step

    def _build_mlxsnn_lif_layer(self) -> Any | None:
        if mlxsnn is None:
            return None
        try:
            return mlxsnn.Leaky(
                beta=self.beta,
                threshold=self.threshold,
                reset_mechanism="subtract",
            )
        except Exception as exc:  # pragma: no cover - dependency implementation varies
            LOGGER.warning("failed to initialize mlxsnn.Leaky layer: %s", exc)
            return None

    def _eval_if_available(self, *arrays: Any) -> None:
        if not hasattr(self._mx, "eval"):
            return
        try:
            self._mx.eval(*arrays)
        except Exception as exc:  # pragma: no cover - host/runtime dependent
            LOGGER.warning("mx.eval failed: %s", exc)

    def _lif_update(self, mem: Any, input_current: Any) -> tuple[Any, Any]:
        if self._mlxsnn_lif_layer is None:
            return self._lif_step(mem, input_current, self.beta, self.threshold)
        try:
            batched_input = input_current.reshape((1, self.num_neurons))
            batched_state = {"mem": mem.reshape((1, self.num_neurons))}
            batched_spikes, next_state = self._mlxsnn_lif_layer(
                batched_input,
                batched_state,
            )
            return batched_spikes[0], next_state["mem"][0]
        except Exception as exc:  # pragma: no cover - fallback protects MCP runtime
            LOGGER.warning("mlxsnn.Leaky execution failed; falling back to explicit LIF math: %s", exc)
            self._mlxsnn_lif_layer = None
            return self._lif_step(mem, input_current, self.beta, self.threshold)

    def _balanced_matrix(
        self,
        shape: tuple[int, int],
        *,
        scale: float,
        excitatory_ratio: float,
    ):
        native_mx = self._mx
        rows, cols = shape
        raw = native_mx.abs(native_mx.random.normal(shape)) * float(scale)
        signs = self._ei_sign_vector(cols, excitatory_ratio)
        return raw * signs

    def _balanced_lateral_matrix(
        self,
        neurons: int,
        *,
        scale: float,
        excitatory_ratio: float,
    ):
        native_mx = self._mx
        matrix = self._balanced_matrix(
            (neurons, neurons),
            scale=scale,
            excitatory_ratio=excitatory_ratio,
        )
        return matrix * (1.0 - native_mx.eye(neurons))

    def _ei_sign_vector(self, length: int, excitatory_ratio: float):
        native_mx = self._mx
        exc_count = int(round(float(length) * float(excitatory_ratio)))
        exc_count = min(max(exc_count, 1), max(length - 1, 1))
        indices = native_mx.arange(length)
        return native_mx.where(indices < exc_count, 1.0, -1.0)

    def _embedding_dimension_before_materialization(self, embedding: Any) -> int:
        shape = getattr(embedding, "shape", None)
        if shape is not None:
            try:
                if len(shape) != 1:
                    raise ValueError(
                        "prompt_embedding must be a one-dimensional coordinate list"
                    )
                embedding_size = int(shape[0])
            except (IndexError, TypeError, ValueError, OverflowError) as exc:
                raise ValueError(
                    "prompt_embedding must be a one-dimensional coordinate list"
                ) from exc
        else:
            try:
                embedding_size = len(embedding)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(
                    "prompt_embedding must be a one-dimensional coordinate list"
                ) from exc
        if embedding_size <= 0:
            raise ValueError("prompt_embedding must not be empty")
        if embedding_size > MAX_EMBEDDING_DIMS:
            raise ValueError(
                f"prompt_embedding exceeds {MAX_EMBEDDING_DIMS} dimensions"
            )
        _require_neural_resource_envelope(
            dimension=int(embedding_size),
            num_neurons=self.num_neurons,
        )
        return int(embedding_size)

    def _coerce_embedding(self, embedding: Any):
        expected_size = self._embedding_dimension_before_materialization(embedding)
        native_mx = self._mx
        arr = native_mx.array(embedding, dtype=native_mx.float32)
        if len(arr.shape) != 1:
            raise ValueError("prompt_embedding must be a one-dimensional coordinate list")
        if int(arr.shape[0]) != expected_size:
            raise ValueError("prompt_embedding shape changed during materialization")
        _require_neural_resource_envelope(
            dimension=int(arr.shape[0]),
            num_neurons=self.num_neurons,
        )
        finite_mask = native_mx.isfinite(arr)
        if int(native_mx.sum(finite_mask).item()) != int(arr.shape[0]):
            raise ValueError("prompt_embedding must contain only finite float values")
        return arr

    def _ensure_projection_shape(self, embedding_size: int) -> None:
        resolved_embedding_size = int(embedding_size)
        _require_neural_resource_envelope(
            dimension=resolved_embedding_size,
            num_neurons=self.num_neurons,
        )
        if resolved_embedding_size == self.dimension:
            return
        resized_projection = self._balanced_matrix(
            (resolved_embedding_size, self.num_neurons),
            scale=0.01,
            excitatory_ratio=0.8,
        )
        self.W_syn = resized_projection
        self.dimension = resolved_embedding_size
        self.W_syn_decay_multiplier = 1.0
        LOGGER.info("resized sensory projection to %s dimensions", self.dimension)

    def encode_to_spikes_top_k(self, embedding: Any, k: int | None = None):
        """Encode dense prompt coordinates as a sparse z-score top-k spike mask."""
        native_mx = self._mx
        arr = self._coerce_embedding(embedding)
        top_k = min(max(int(k or self.default_top_k), 1), int(arr.shape[0]))

        mean = native_mx.mean(arr)
        variance = native_mx.mean((arr - mean) * (arr - mean))
        std = native_mx.sqrt(variance + 1e-6)
        z_scores = (arr - mean) / std
        selected_indices = native_mx.argsort(z_scores)[-top_k:]
        coordinate_indices = native_mx.arange(int(arr.shape[0]))
        selected_mask = native_mx.sum(
            native_mx.where(
                coordinate_indices[:, None] == selected_indices[None, :],
                1.0,
                0.0,
            ),
            axis=1,
        )
        return native_mx.where(selected_mask > 0.0, 1.0, 0.0)

    def embed_text(self, text: str, *, dimensions: int | None = None):
        """Map text to the configured local embedding provider."""
        return self.embed_text_payload(text, dimensions=dimensions)["embedding"]

    def embed_text_payload(
        self,
        text: str,
        *,
        dimensions: int | None = None,
    ) -> dict[str, Any]:
        self._require_neural_substrate()
        dims = int(dimensions or self.dimension)
        if dims <= 0 or dims > MAX_EMBEDDING_DIMS:
            raise ValueError(f"dimensions must be between 1 and {MAX_EMBEDDING_DIMS}")
        safe_text, redaction_count = redact_capture_text(str(text or ""))
        try:
            result = self.embedding_provider.embed(safe_text, dimensions=dims)
        except EmbeddingProviderError:
            raise
        except Exception as exc:
            raise EmbeddingProviderError(
                "embedding provider "
                f"{self.embedding_provider_name} failed: "
                f"{safe_public_error(exc, fallback='provider execution failed')}"
            ) from exc
        return {
            "embedding": self._mx.array(result.vector, dtype=self._mx.float32),
            "provenance": self._json_safe_metadata(result.provenance),
            "input_redaction_count": int(redaction_count),
            "raw_input_stored": False,
        }

    def embedding_provider_info(self) -> dict[str, Any]:
        try:
            return self._json_safe_metadata(
                self.embedding_provider.info(dimensions=min(8, self.dimension))
            )
        except Exception as exc:
            return {
                "provider": str(self.embedding_provider_name),
                "provider_type": "unavailable",
                "semantic": False,
                "local_only": True,
                "error": safe_public_error(
                    exc,
                    fallback="embedding provider unavailable",
                ),
            }

    def benchmark_embedding_provider(
        self,
        *,
        text: str,
        runs: int = 1,
        dimensions: int | None = None,
    ) -> dict[str, Any]:
        bounded_runs = max(1, min(int(runs), 25))
        dims = int(dimensions or self.dimension)
        if dims <= 0 or dims > MAX_EMBEDDING_DIMS:
            raise ValueError(f"dimensions must be between 1 and {MAX_EMBEDDING_DIMS}")
        raw_prompt = str(text or "")
        prompt, input_redaction_count = redact_capture_text(raw_prompt)
        sample_latencies: list[float] = []
        payload: dict[str, Any] | None = None
        started = time.perf_counter()
        for _ in range(bounded_runs):
            sample_started = time.perf_counter()
            payload = self.embed_text_payload(prompt, dimensions=dims)
            sample_latencies.append(
                round((time.perf_counter() - sample_started) * 1000, 3)
            )
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        embedding = payload["embedding"] if payload else []
        try:
            vector = [float(value) for value in embedding.tolist()]
        except AttributeError:
            vector = [float(value) for value in embedding]
        return {
            "action": "provider-benchmark",
            "input_chars": len(prompt),
            "input_redaction_count": int(input_redaction_count),
            "raw_input_stored": False,
            "dimensions": dims,
            "runs": bounded_runs,
            "elapsed_ms": elapsed_ms,
            "average_latency_ms": round(sum(sample_latencies) / len(sample_latencies), 3),
            "sample_latencies_ms": sample_latencies,
            "vector_nonzero_count": sum(
                1 for value in vector if abs(float(value)) > 1e-12
            ),
            "embedding_provider": payload["provenance"] if payload else {},
        }

    def register_text_trace(
        self,
        *,
        tag: str,
        text: str,
        context_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raw_text = str(text or "")
        redacted_text, redaction_count = redact_capture_text(raw_text)
        safe_metadata, metadata_redactions = redact_sensitive_value(metadata or {})
        if redaction_count or metadata_redactions:
            safe_metadata = {
                **(safe_metadata if isinstance(safe_metadata, dict) else {}),
                "redaction_count": int(
                    redaction_count
                    + metadata_redactions
                    + int(
                        (safe_metadata if isinstance(safe_metadata, dict) else {}).get(
                            "redaction_count",
                            0,
                        )
                        or 0
                    )
                ),
                "raw_text_stored": False,
            }
        payload = self.embed_text_payload(redacted_text)
        base_metadata = {
            **(safe_metadata if isinstance(safe_metadata, dict) else {}),
            "embedding_provider": payload["provenance"],
        }
        surface_details = self._surface_node_details(
            tag=tag,
            text=redacted_text,
            metadata=base_metadata,
        )
        merged_metadata = self._json_safe_metadata(
            {
                **base_metadata,
                **surface_details,
            }
        )
        registration = self.register_trace(
            tag=tag,
            embedding=payload["embedding"],
            context_id=context_id,
            metadata=merged_metadata,
            source_text=redacted_text,
        )
        registration["embedding_provider"] = payload["provenance"]
        return registration

    def retrieve_text_v2(
        self,
        prompt: str,
        *,
        context_id: str = "default",
        recall_scope: str = "local",
        result_limit: int = 10,
        candidate_limit: int = 128,
        include_graph_neighbors: bool = True,
    ) -> dict[str, Any]:
        """Return deterministic, structured, read-only hybrid retrieval results.

        Unlike :meth:`query_text`, this path never runs the recurrent network,
        applies STDP, prunes, writes runtime state, marks activity, or populates a
        result cache.  It reads the already-durable spike and surface indexes,
        fuses their independent scores with versioned weights, and optionally
        admits a strictly bounded set of same-context graph neighbors.

        The read is optimistic rather than a single SQLite transaction because
        the existing store APIs own their connections.  Entry, scope/link, and
        relevant graph revisions are therefore checked before and after the read;
        one retry is allowed and a second moving snapshot fails closed.
        """

        self._require_neural_substrate()
        context = sanitize_context_id(context_id)
        scope = sanitize_recall_scope(recall_scope)
        bounded_result_limit = self._retrieval_v2_bounded_int(
            result_limit,
            field="result_limit",
            minimum=1,
            maximum=RETRIEVAL_V2_MAX_RESULT_LIMIT,
        )
        bounded_candidate_limit = self._retrieval_v2_bounded_int(
            candidate_limit,
            field="candidate_limit",
            minimum=bounded_result_limit,
            maximum=RETRIEVAL_V2_MAX_CANDIDATE_LIMIT,
        )
        if type(include_graph_neighbors) is not bool:
            raise ValueError("include_graph_neighbors must be a boolean")

        prompt_text, prompt_metrics = self._retrieval_v2_sanitize_prompt(prompt)
        extracted_terms = self._surface_recall_terms(prompt_text)
        query_terms = self._retrieval_v2_select_terms(
            extracted_terms,
            limit=RETRIEVAL_V2_MAX_QUERY_TERMS,
        )
        embedding_payload = self.embed_text_payload(
            prompt_text,
            dimensions=self.dimension,
        )
        sensory_spikes = self.encode_to_spikes_top_k(
            embedding_payload["embedding"],
            k=min(self.default_top_k, RETRIEVAL_V2_MAX_QUERY_SPIKES),
        )
        query_spikes = set(self._active_indices_from_spikes(sensory_spikes))
        embedding_identity = self._retrieval_v2_embedding_identity(
            embedding_payload.get("provenance")
        )
        query_fingerprint = hashlib.sha256(
            (
                f"{RETRIEVAL_V2_SCHEMA}\x1f{context}\x1f{scope}\x1f"
                f"{prompt_text}"
            ).encode("utf-8")
        ).hexdigest()

        stable_read: dict[str, Any] | None = None
        attempts = 0
        for attempts in range(1, 3):
            scope_before = self._retrieval_v2_scope_snapshot(
                context=context,
                recall_scope=scope,
            )
            scope_context_ids = [
                str(record["context_id"])
                for record in scope_before["records"]
            ]
            entries_before = self._retrieval_v2_entries_snapshot(
                scope_context_ids
            )
            collected = self._retrieval_v2_collect_candidates(
                query_spikes=query_spikes,
                query_terms=query_terms,
                scope_records=scope_before["records"],
                result_limit=bounded_result_limit,
                candidate_limit=bounded_candidate_limit,
                include_graph_neighbors=include_graph_neighbors,
            )
            graph_after = self._retrieval_v2_graph_edges(
                collected["graph_anchors"],
                enabled=include_graph_neighbors,
            )
            entries_after = self._retrieval_v2_entries_snapshot(
                scope_context_ids
            )
            scope_after = self._retrieval_v2_scope_snapshot(
                context=context,
                recall_scope=scope,
            )
            if (
                entries_before.get("revision") == entries_after.get("revision")
                and scope_before["revision"] == scope_after["revision"]
                and collected["graph_snapshot"]["revision"]
                == graph_after["revision"]
            ):
                stable_read = {
                    "scope": scope_before,
                    "entries_revision": entries_before,
                    "collected": collected,
                }
                break
        if stable_read is None:
            raise RuntimeError("retrieval snapshot changed during bounded read")

        scope_snapshot = stable_read["scope"]
        collected = stable_read["collected"]
        entries_revision = stable_read["entries_revision"]
        snapshot_seed = {
            "schema": RETRIEVAL_V2_SCHEMA,
            "ranker_id": RETRIEVAL_V2_RANKER_ID,
            "ranker_version": RETRIEVAL_V2_RANKER_VERSION,
            "query_fingerprint": query_fingerprint,
            "entries_revision": entries_revision,
            "scope_revision": scope_snapshot["revision"],
            "graph_revision": collected["graph_snapshot"]["revision"],
            "embedding_identity": embedding_identity,
        }
        snapshot_id = "s2snap_" + self._retrieval_v2_digest(snapshot_seed)[:24]
        retrieval_id = "s2ret_" + self._retrieval_v2_digest(
            {
                "snapshot_id": snapshot_id,
                "query_fingerprint": query_fingerprint,
                "result_limit": bounded_result_limit,
                "candidate_limit": bounded_candidate_limit,
                "include_graph_neighbors": include_graph_neighbors,
            }
        )[:24]

        terms_truncated = len(extracted_terms) > len(query_terms)
        candidate_scan_truncated = bool(
            collected["work"]["spike_source_may_be_truncated"]
            or collected["work"]["surface_source_may_be_truncated"]
            or collected["work"]["candidate_pool_truncated"]
        )
        result_truncated = bool(collected["result_truncated"])
        scope_complete = not bool(scope_snapshot["truncated"])
        warnings: list[dict[str, str]] = []
        if terms_truncated:
            warnings.append(
                {
                    "code": "query-terms-truncated",
                    "message": "The deterministic query-term ceiling was reached.",
                }
            )
        if not scope_complete:
            warnings.append(
                {
                    "code": "scope-truncated",
                    "message": "The bounded namespace or bridge scope was not complete.",
                }
            )
        if candidate_scan_truncated:
            warnings.append(
                {
                    "code": "candidate-scan-truncated",
                    "message": "At least one bounded candidate source may have more matches.",
                }
            )
        if result_truncated:
            warnings.append(
                {
                    "code": "result-set-truncated",
                    "message": "More fused candidates existed than the requested result limit.",
                }
            )

        work = {
            **prompt_metrics,
            "query_terms_extracted": len(extracted_terms),
            "query_terms_used": len(query_terms),
            "query_terms_limit": RETRIEVAL_V2_MAX_QUERY_TERMS,
            "query_spikes_used": len(query_spikes),
            "query_spikes_limit": RETRIEVAL_V2_MAX_QUERY_SPIKES,
            "result_limit": bounded_result_limit,
            "candidate_limit": bounded_candidate_limit,
            "scope_context_limit": RETRIEVAL_V2_MAX_SCOPE_CONTEXTS,
            **collected["work"],
            "snapshot_attempts": attempts,
        }
        response = {
            "schema": RETRIEVAL_V2_SCHEMA,
            "schema_version": 2,
            "retrieval_id": retrieval_id,
            "query": {
                "fingerprint_sha256": query_fingerprint,
                "context_id": context,
                "recall_scope": scope,
                "raw_input_stored": False,
                "input_redaction_count": int(
                    prompt_metrics["input_redaction_count"]
                    + int(embedding_payload.get("input_redaction_count", 0) or 0)
                ),
            },
            "ranker": {
                "id": RETRIEVAL_V2_RANKER_ID,
                "version": RETRIEVAL_V2_RANKER_VERSION,
                "fusion": "weighted-sum",
                "weights": dict(RETRIEVAL_V2_RANK_WEIGHTS),
                "diversity": {
                    "method": "bounded-mmr-jaccard",
                    "lambda": RETRIEVAL_V2_MMR_LAMBDA,
                    "signature_term_limit": RETRIEVAL_V2_MAX_DIVERSITY_TERMS,
                },
                "confidence_semantics": {
                    "calibrated": False,
                    "probability": False,
                    "description": (
                        "Ranking scores are deterministic relevance signals, "
                        "not truth probabilities."
                    ),
                },
            },
            "snapshot": {
                "snapshot_id": snapshot_id,
                "consistency": "optimistic-before-after-verified",
                "entries_revision": entries_revision,
                "scope_revision": scope_snapshot["revision"],
                "graph_revision": collected["graph_snapshot"]["revision"],
                "embedding": embedding_identity,
            },
            "scope": scope_snapshot["public"],
            "items": collected["items"],
            "result_count": len(collected["items"]),
            "completeness": {
                "complete": bool(
                    scope_complete
                    and not terms_truncated
                    and not candidate_scan_truncated
                    and not result_truncated
                ),
                "scope_complete": scope_complete,
                "query_terms_truncated": terms_truncated,
                "candidate_scan_truncated": candidate_scan_truncated,
                "result_set_truncated": result_truncated,
                "has_more": bool(candidate_scan_truncated or result_truncated),
                "pagination_supported": False,
                "next_cursor": None,
                "warnings": warnings,
            },
            "work": work,
            "raw_input_stored": False,
        }
        # Refuse to publish unsupported floats or non-JSON values.  This is a
        # validation pass only; it does not reparse or coerce the result.
        json.dumps(response, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return response

    def _retrieval_v2_entries_snapshot(
        self,
        context_ids: Iterable[str],
    ) -> dict[str, Any]:
        """Bind ranking reads to transaction-coupled namespace generations.

        The page revision is backed by namespace-specific counters advanced in
        the same commit as memory mutations and also includes the semantic-index
        generation. It detects in-place content changes without rescanning and
        hashing every stored memory body for each retrieval attempt.
        """

        selected = sorted({str(value) for value in context_ids if str(value)})
        if not selected:
            raise RuntimeError("retrieval scope resolved no contexts")
        exact = self.memory_store.retrieval_memory_page(
            context_ids=selected,
            limit=1,
        )
        content_revision = str(exact["snapshot_revision"])
        revision = self._retrieval_v2_digest(
            {
                "schema": "synapse-s2.retrieval-entries-snapshot.v3",
                "context_ids": selected,
                "content_revision": content_revision,
            }
        )
        return {
            "revision": revision,
            "content_revision": content_revision,
            "context_ids": selected,
            "entry_count": int(exact["total"]),
        }

    @staticmethod
    def _retrieval_v2_bounded_int(
        value: Any,
        *,
        field: str,
        minimum: int,
        maximum: int,
    ) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{field} must be an integer")
        if value < minimum or value > maximum:
            raise ValueError(f"{field} must be between {minimum} and {maximum}")
        return int(value)

    def _retrieval_v2_sanitize_prompt(self, prompt: Any) -> tuple[str, dict[str, int]]:
        if not isinstance(prompt, str):
            raise ValueError("prompt must be a string")
        raw_bytes = len(prompt.encode("utf-8"))
        if raw_bytes > RETRIEVAL_V2_MAX_PROMPT_BYTES:
            raise ValueError(
                f"prompt exceeds {RETRIEVAL_V2_MAX_PROMPT_BYTES} UTF-8 bytes"
            )
        without_controls = "".join(
            " " if (ord(char) < 32 and char not in "\t\n\r") or 127 <= ord(char) < 160 else char
            for char in prompt
        )
        normalized = " ".join(without_controls.split())
        redacted, redaction_count = redact_capture_text(normalized)
        sanitized = " ".join(str(redacted or "").split())
        if not sanitized:
            raise ValueError("prompt must not be empty")
        sanitized_bytes = len(sanitized.encode("utf-8"))
        if sanitized_bytes > RETRIEVAL_V2_MAX_PROMPT_BYTES:
            raise ValueError(
                f"sanitized prompt exceeds {RETRIEVAL_V2_MAX_PROMPT_BYTES} UTF-8 bytes"
            )
        return sanitized, {
            "prompt_input_bytes": raw_bytes,
            "prompt_sanitized_bytes": sanitized_bytes,
            "prompt_byte_limit": RETRIEVAL_V2_MAX_PROMPT_BYTES,
            "input_redaction_count": int(redaction_count),
        }

    def _retrieval_v2_select_terms(
        self,
        terms: Iterable[str],
        *,
        limit: int,
    ) -> list[str]:
        unique = {
            str(term).strip().lower()
            for term in terms
            if str(term).strip()
        }
        return sorted(
            unique,
            key=lambda term: (
                0 if self._is_concrete_surface_recall_term(term) else 1,
                -len(term),
                term,
            ),
        )[: max(0, int(limit))]

    @staticmethod
    def _retrieval_v2_digest(value: Any) -> str:
        canonical = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _retrieval_v2_embedding_identity(self, provenance: Any) -> dict[str, Any]:
        source = provenance if isinstance(provenance, dict) else {}
        identity: dict[str, Any] = {}
        for key in (
            "provider",
            "provider_type",
            "dimensions",
            "semantic",
            "local_only",
            "model_id",
            "revision",
            "pooling",
            "normalize",
            "vector_sha256",
        ):
            value = source.get(key)
            if value is None:
                continue
            if isinstance(value, bool):
                identity[key] = value
            elif isinstance(value, int):
                identity[key] = int(value)
            elif isinstance(value, float):
                if math.isfinite(value):
                    identity[key] = float(value)
            elif isinstance(value, str):
                identity[key] = self._retrieval_v2_text(value, 160)[0]
        return identity

    def _retrieval_v2_scope_snapshot(
        self,
        *,
        context: str,
        recall_scope: str,
    ) -> dict[str, Any]:
        raw_records = self.bridge_governance.resolve_recall_contexts(
            context_id=context,
            scope=recall_scope,
        )
        raw_record_count = len(raw_records)
        origin = [
            dict(record)
            for record in raw_records
            if str(record.get("context_id") or "") == context
        ]
        inherited_global = [
            dict(record)
            for record in raw_records
            if str(record.get("context_id") or "") == "global"
        ]
        remaining = sorted(
            (
                dict(record)
                for record in raw_records
                if str(record.get("context_id") or "") not in {context, "global"}
            ),
            key=lambda record: str(record.get("context_id") or ""),
        )
        selected: list[dict[str, Any]] = []
        if origin:
            selected.append(origin[0])
        remaining_capacity = RETRIEVAL_V2_MAX_SCOPE_CONTEXTS - len(selected)
        reserve_global = 1 if inherited_global and remaining_capacity > 0 else 0
        selected.extend(remaining[: max(0, remaining_capacity - reserve_global)])
        if reserve_global:
            selected.append(inherited_global[0])
        scope_truncated = raw_record_count > len(selected)

        raw_links: list[dict[str, Any]] = []
        links_truncated = False
        if recall_scope == "connected":
            raw_links = self.bridge_governance.list_active_namespace_links(
                context_id=context,
                limit=RETRIEVAL_V2_MAX_SCOPE_LINKS + 1,
            )
            raw_links = sorted(
                (dict(link) for link in raw_links),
                key=lambda link: str(link.get("context_link_id") or ""),
            )
            links_truncated = len(raw_links) > RETRIEVAL_V2_MAX_SCOPE_LINKS
            raw_links = raw_links[:RETRIEVAL_V2_MAX_SCOPE_LINKS]
        link_by_id = {
            str(link.get("context_link_id") or ""): link
            for link in raw_links
            if str(link.get("context_link_id") or "")
        }

        normalized_records: list[dict[str, Any]] = []
        invalid_link_provenance_count = 0
        for record in selected:
            resolved_context = sanitize_context_id(
                str(record.get("context_id") or "default")
            )
            provenance = str(record.get("recall_provenance") or "local")
            normalized: dict[str, Any] = {
                "origin_context_id": context,
                "context_id": resolved_context,
                "recall_scope": recall_scope,
                "recall_provenance": provenance,
                "via_context_link_id": "",
                "via_relation_type": "",
                "via_direction": "",
                "context_link": None,
            }
            if provenance == "connected":
                link_id = str(record.get("via_context_link_id") or "")
                link = link_by_id.get(link_id)
                if link is None or not bool(link.get("enabled")):
                    invalid_link_provenance_count += 1
                    continue
                source = sanitize_context_id(str(link.get("source_context_id") or ""))
                target = sanitize_context_id(str(link.get("target_context_id") or ""))
                direction = str(link.get("direction") or "")
                reachable_neighbor = ""
                if source == context:
                    reachable_neighbor = target
                elif target == context and direction == "bidirectional":
                    reachable_neighbor = source
                if reachable_neighbor != resolved_context:
                    invalid_link_provenance_count += 1
                    continue
                link_provenance = self._retrieval_v2_link_provenance(link)
                normalized.update(
                    {
                        "via_context_link_id": link_id,
                        "via_relation_type": str(link.get("relation_type") or ""),
                        "via_direction": direction,
                        "context_link": link_provenance,
                    }
                )
            normalized_records.append(normalized)

        normalized_records.sort(
            key=lambda record: (
                0 if record["context_id"] == context else 2 if record["context_id"] == "global" else 1,
                str(record["context_id"]),
            )
        )
        exact_links = [self._retrieval_v2_link_provenance(link) for link in raw_links]
        revision_payload = {
            "schema": "retrieval-scope.v2",
            "origin_context_id": context,
            "recall_scope": recall_scope,
            "raw_record_count": raw_record_count,
            "records": normalized_records,
            "active_adjacent_links": exact_links,
            "limits": {
                "contexts": RETRIEVAL_V2_MAX_SCOPE_CONTEXTS,
                "links": RETRIEVAL_V2_MAX_SCOPE_LINKS,
            },
            "truncated": bool(scope_truncated or links_truncated),
            "invalid_link_provenance_count": invalid_link_provenance_count,
        }
        revision = self._retrieval_v2_digest(revision_payload)
        public_records = [
            self._retrieval_v2_public_scope_provenance(
                record,
                origin_context=context,
            )
            for record in normalized_records
        ]
        truncated = bool(
            scope_truncated or links_truncated or invalid_link_provenance_count
        )
        return {
            "records": normalized_records,
            "revision": revision,
            "truncated": truncated,
            "public": {
                "origin_context_id": context,
                "requested_scope": recall_scope,
                "one_hop_only": recall_scope == "connected",
                "inherits_global": any(
                    record["context_id"] == "global" for record in normalized_records
                ),
                "resolved_context_count": len(normalized_records),
                "resolved_context_count_before_limit": raw_record_count,
                "active_adjacent_link_count": len(exact_links),
                "link_provenance_complete": not bool(
                    links_truncated or invalid_link_provenance_count
                ),
                "truncated": truncated,
                "contexts": public_records,
            },
        }

    def _retrieval_v2_link_provenance(self, link: dict[str, Any]) -> dict[str, Any]:
        return {
            "context_link_id": self._retrieval_v2_text(
                str(link.get("context_link_id") or ""), 160
            )[0],
            "source_context_id": self._retrieval_v2_text(
                str(link.get("source_context_id") or ""), 160
            )[0],
            "target_context_id": self._retrieval_v2_text(
                str(link.get("target_context_id") or ""), 160
            )[0],
            "relation_type": self._retrieval_v2_text(
                str(link.get("relation_type") or ""), 96
            )[0],
            "direction": self._retrieval_v2_text(
                str(link.get("direction") or ""), 32
            )[0],
            "confidence": self._retrieval_v2_unit_float(link.get("confidence")),
            "enabled": bool(link.get("enabled")),
            "approved": bool(link.get("approved", True)),
            "approved_by": self._retrieval_v2_text(
                str(link.get("approved_by") or ""), 96
            )[0],
            "approved_at": self._retrieval_v2_finite_float(link.get("approved_at")),
            "updated_at": self._retrieval_v2_finite_float(link.get("updated_at")),
        }

    def _retrieval_v2_public_scope_provenance(
        self,
        record: dict[str, Any],
        *,
        origin_context: str,
    ) -> dict[str, Any]:
        return {
            "origin_context_id": origin_context,
            "resolved_context_id": str(record.get("context_id") or ""),
            "requested_scope": str(record.get("recall_scope") or "local"),
            "provenance": str(record.get("recall_provenance") or "local"),
            "context_link": record.get("context_link"),
        }

    def _retrieval_v2_collect_candidates(
        self,
        *,
        query_spikes: set[int],
        query_terms: list[str],
        scope_records: list[dict[str, Any]],
        result_limit: int,
        candidate_limit: int,
        include_graph_neighbors: bool,
    ) -> dict[str, Any]:
        if not scope_records:
            empty_graph = self._retrieval_v2_graph_edges([], enabled=False)
            return {
                "items": [],
                "result_truncated": False,
                "graph_anchors": [],
                "graph_snapshot": empty_graph,
                "work": {
                    "source_candidate_limit_each": 0,
                    "spike_candidates_returned": 0,
                    "surface_candidates_returned": 0,
                    "spike_source_may_be_truncated": False,
                    "surface_source_may_be_truncated": False,
                    "candidate_pool_truncated": False,
                    "candidate_memory_id_deduplications": 0,
                    "candidate_content_deduplications": 0,
                    "graph_relationship_rows_examined": 0,
                    "graph_neighbor_loads": 0,
                    "graph_cross_context_rejections": 0,
                    "mmr_candidate_evaluations": 0,
                },
            }

        scope_by_context = {
            str(record["context_id"]): record for record in scope_records
        }
        origin_record = next(
            (
                record
                for record in scope_records
                if str(record.get("recall_provenance") or "") == "local"
            ),
            scope_records[0],
        )
        origin_context = str(origin_record["context_id"])
        recall_scope = str(origin_record.get("recall_scope") or "local")
        source_limit = min(
            candidate_limit,
            max(result_limit, (candidate_limit + 1) // 2),
        )
        spike_rows = self.memory_store.recall_candidates(
            context_id=origin_context,
            query_spikes=query_spikes,
            firing_values=[],
            limit=source_limit,
            recall_scope=recall_scope,
            recall_contexts=scope_records,
        )
        surface_rows = (
            self.memory_store.surface_recall_candidates(
                context_id=origin_context,
                query_terms=query_terms,
                limit=source_limit,
                recall_scope=recall_scope,
                recall_contexts=scope_records,
            )
            if query_terms
            else []
        )

        pool: dict[str, dict[str, Any]] = {}
        memory_id_deduplications = 0

        def candidate_for(entry: dict[str, Any]) -> dict[str, Any] | None:
            nonlocal memory_id_deduplications
            memory_id = str(entry.get("memory_id") or "").strip()
            candidate_context = str(entry.get("context_id") or "").strip()
            if not memory_id or candidate_context not in scope_by_context:
                return None
            current = pool.get(memory_id)
            if current is not None:
                memory_id_deduplications += 1
                return current
            current = {
                "entry": dict(entry),
                "memory_id": memory_id,
                "context_id": candidate_context,
                "scope_record": dict(scope_by_context[candidate_context]),
                "spike_signal": 0.0,
                "surface_signal": 0.0,
                "graph_signal": 0.0,
                "spike_reason": None,
                "surface_reason": None,
                "graph_provenance": [],
            }
            pool[memory_id] = current
            return current

        spike_scored: list[tuple[float, str, dict[str, Any], dict[str, Any]]] = []
        for entry in spike_rows:
            signal, reason = self._retrieval_v2_spike_signal(entry, query_spikes)
            memory_id = str(entry.get("memory_id") or "")
            if signal > 0.0 and memory_id:
                spike_scored.append((signal, memory_id, entry, reason))
        spike_scored.sort(key=lambda item: (-item[0], item[1]))
        for source_rank, (signal, _memory_id, entry, reason) in enumerate(
            spike_scored,
            start=1,
        ):
            candidate = candidate_for(entry)
            if candidate is None:
                continue
            candidate["spike_signal"] = max(float(candidate["spike_signal"]), signal)
            candidate["spike_reason"] = {**reason, "source_rank": source_rank}

        surface_scored: list[tuple[float, str, dict[str, Any], dict[str, Any]]] = []
        for entry in surface_rows:
            signal, reason = self._retrieval_v2_surface_signal(entry, query_terms)
            memory_id = str(entry.get("memory_id") or "")
            if signal > 0.0 and memory_id:
                surface_scored.append((signal, memory_id, entry, reason))
        surface_scored.sort(key=lambda item: (-item[0], item[1]))
        for source_rank, (signal, _memory_id, entry, reason) in enumerate(
            surface_scored,
            start=1,
        ):
            candidate = candidate_for(entry)
            if candidate is None:
                continue
            candidate["surface_signal"] = max(float(candidate["surface_signal"]), signal)
            candidate["surface_reason"] = {**reason, "source_rank": source_rank}

        for candidate in pool.values():
            self._retrieval_v2_score_candidate(candidate)
        base_ranked = sorted(
            pool.values(),
            key=lambda candidate: (
                -float(candidate["relevance_score"]),
                str(candidate["memory_id"]),
            ),
        )
        base_pool_truncated = len(base_ranked) > candidate_limit
        base_ranked = base_ranked[:candidate_limit]
        pool = {str(candidate["memory_id"]): candidate for candidate in base_ranked}

        graph_anchors = [
            {
                "memory_id": str(candidate["memory_id"]),
                "context_id": str(candidate["context_id"]),
                "relevance_score": float(candidate["relevance_score"]),
            }
            for candidate in base_ranked[:RETRIEVAL_V2_MAX_GRAPH_ANCHORS]
        ]
        graph_snapshot = self._retrieval_v2_graph_edges(
            graph_anchors,
            enabled=include_graph_neighbors,
        )
        graph_neighbor_loads = 0
        graph_cross_context_rejections = 0
        anchor_by_id = {
            str(anchor["memory_id"]): anchor for anchor in graph_anchors
        }
        for edge in graph_snapshot["edges"]:
            anchor_id = str(edge["anchor_memory_id"])
            anchor = anchor_by_id.get(anchor_id)
            if anchor is None:
                continue
            neighbor_id = str(edge["neighbor_memory_id"])
            neighbor = self.memory_store.get_entry(neighbor_id)
            graph_neighbor_loads += 1
            if neighbor is None:
                continue
            neighbor_context = str(neighbor.get("context_id") or "")
            anchor_context = str(anchor["context_id"])
            if (
                neighbor_context != anchor_context
                or neighbor_context not in scope_by_context
                or str(edge.get("context_id") or "") != anchor_context
            ):
                graph_cross_context_rejections += 1
                continue
            candidate = candidate_for(neighbor)
            if candidate is None:
                continue
            graph_signal = self._retrieval_v2_unit_float(
                float(edge["weight"])
                * (0.5 + 0.5 * float(anchor["relevance_score"]))
            )
            candidate["graph_signal"] = max(
                float(candidate["graph_signal"]), graph_signal
            )
            provenance = {
                "relationship_id": str(edge["relationship_id"]),
                "anchor_memory_id": anchor_id,
                "neighbor_memory_id": neighbor_id,
                "context_id": anchor_context,
                "relation_type": str(edge["relation_type"]),
                "weight": float(edge["weight"]),
                "signal": graph_signal,
            }
            candidate["graph_provenance"].append(provenance)

        for candidate in pool.values():
            self._retrieval_v2_score_candidate(candidate)
            candidate["graph_provenance"] = sorted(
                candidate["graph_provenance"],
                key=lambda item: (
                    -float(item["signal"]),
                    str(item["relationship_id"]),
                    str(item["anchor_memory_id"]),
                ),
            )[:4]
            candidate["display"] = self._retrieval_v2_display(candidate["entry"])

        ranked = sorted(
            pool.values(),
            key=lambda candidate: (
                -float(candidate["relevance_score"]),
                str(candidate["memory_id"]),
            ),
        )
        graph_pool_truncated = len(ranked) > candidate_limit
        ranked = ranked[:candidate_limit]

        content_deduplications = 0
        content_seen: dict[str, dict[str, Any]] = {}
        deduplicated: list[dict[str, Any]] = []
        for candidate in ranked:
            content_key = self._retrieval_v2_content_key(candidate)
            prior = content_seen.get(content_key)
            if prior is not None:
                prior["content_duplicate_count"] = int(
                    prior.get("content_duplicate_count", 0)
                ) + 1
                content_deduplications += 1
                continue
            candidate["content_duplicate_count"] = 0
            content_seen[content_key] = candidate
            deduplicated.append(candidate)

        selected, mmr_evaluations = self._retrieval_v2_mmr_select(
            deduplicated,
            limit=result_limit,
        )
        items = [
            self._retrieval_v2_public_item(candidate, rank=rank)
            for rank, candidate in enumerate(selected, start=1)
        ]
        result_truncated = len(deduplicated) > len(selected)
        candidate_pool_truncated = bool(
            base_pool_truncated
            or graph_pool_truncated
            or graph_snapshot["truncated"]
        )
        return {
            "items": items,
            "result_truncated": result_truncated,
            "graph_anchors": graph_anchors,
            "graph_snapshot": graph_snapshot,
            "work": {
                "source_candidate_limit_each": source_limit,
                "spike_store_scan_ceiling": min(source_limit * 16, 10_000),
                "spike_candidates_returned": len(spike_rows),
                "surface_candidates_returned": len(surface_rows),
                "spike_source_may_be_truncated": len(spike_rows) >= source_limit,
                "surface_source_may_be_truncated": bool(
                    query_terms and len(surface_rows) >= source_limit
                ),
                "candidate_pool_before_content_dedupe": len(ranked),
                "candidate_pool_after_content_dedupe": len(deduplicated),
                "candidate_pool_truncated": candidate_pool_truncated,
                "candidate_memory_id_deduplications": memory_id_deduplications,
                "candidate_content_deduplications": content_deduplications,
                "graph_anchor_count": len(graph_anchors),
                "graph_relationship_rows_examined": len(graph_snapshot["edges"]),
                "graph_relationship_row_limit": RETRIEVAL_V2_MAX_GRAPH_EDGES,
                "graph_neighbor_loads": graph_neighbor_loads,
                "graph_cross_context_rejections": graph_cross_context_rejections,
                "mmr_candidate_evaluations": mmr_evaluations,
                "mmr_candidate_evaluation_ceiling": (
                    candidate_limit * result_limit
                ),
            },
        }

    def _retrieval_v2_spike_signal(
        self,
        entry: dict[str, Any],
        query_spikes: set[int],
    ) -> tuple[float, dict[str, Any]]:
        candidate_spikes = {
            int(value) for value in entry.get("spike_indices", [])
        }
        overlap_count = len(query_spikes & candidate_spikes)
        union_count = len(query_spikes | candidate_spikes)
        signal = overlap_count / max(1, union_count)
        return self._retrieval_v2_unit_float(signal), {
            "type": "spike-index-overlap",
            "overlap_count": overlap_count,
            "query_spike_count": len(query_spikes),
            "candidate_spike_count": len(candidate_spikes),
            "jaccard": round(self._retrieval_v2_unit_float(signal), 8),
        }

    def _retrieval_v2_surface_signal(
        self,
        entry: dict[str, Any],
        query_terms: list[str],
    ) -> tuple[float, dict[str, Any]]:
        if not query_terms:
            return 0.0, {"type": "surface-index-overlap", "overlap_count": 0}
        display = self._retrieval_v2_display(entry)
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        metadata_terms = " ".join(
            str(metadata.get(key) or "")
            for key in ("source", "source_tag", "speaker", "trace_type", "truth_posture")
        )
        corpus = " ".join(
            [
                display["tag"],
                display["label"],
                display["summary"],
                display["excerpt"],
                " ".join(display["facets"]),
                metadata_terms,
            ]
        )
        corpus_terms = set(
            self._retrieval_v2_select_terms(
                self._surface_recall_terms(corpus),
                limit=RETRIEVAL_V2_MAX_ITEM_TERMS,
            )
        )
        query_set = set(query_terms)
        matched_terms = sorted(query_set & corpus_terms)
        indexed_overlap = min(
            max(int(entry.get("surface_overlap_count", 0) or 0), 0),
            len(query_set),
        )
        term_weight = max(
            0.0,
            self._retrieval_v2_finite_float(entry.get("surface_term_weight")),
        )
        indexed_coverage = indexed_overlap / max(1, len(query_set))
        rendered_coverage = len(matched_terms) / max(1, len(query_set))
        weight_quality = min(1.0, term_weight / max(1.0, 4.0 * indexed_overlap))
        signal = (
            0.55 * indexed_coverage
            + 0.30 * rendered_coverage
            + 0.15 * weight_quality
        )
        return self._retrieval_v2_unit_float(signal), {
            "type": "surface-index-overlap",
            "indexed_overlap_count": indexed_overlap,
            "query_term_count": len(query_set),
            "matched_terms": matched_terms[:8],
            "indexed_coverage": round(indexed_coverage, 8),
            "rendered_coverage": round(rendered_coverage, 8),
            "indexed_term_weight": round(term_weight, 8),
        }

    def _retrieval_v2_score_candidate(self, candidate: dict[str, Any]) -> None:
        spike_signal = self._retrieval_v2_unit_float(candidate.get("spike_signal"))
        surface_signal = self._retrieval_v2_unit_float(candidate.get("surface_signal"))
        graph_signal = self._retrieval_v2_unit_float(candidate.get("graph_signal"))
        contributions = {
            "spike_index": RETRIEVAL_V2_RANK_WEIGHTS["spike_index"] * spike_signal,
            "surface_index": RETRIEVAL_V2_RANK_WEIGHTS["surface_index"] * surface_signal,
            "same_context_graph": (
                RETRIEVAL_V2_RANK_WEIGHTS["same_context_graph"] * graph_signal
            ),
        }
        candidate["score_contributions"] = contributions
        candidate["relevance_score"] = self._retrieval_v2_unit_float(
            sum(contributions.values())
        )

    def _retrieval_v2_graph_edges(
        self,
        anchors: list[dict[str, Any]],
        *,
        enabled: bool,
    ) -> dict[str, Any]:
        normalized_anchors = sorted(
            (
                {
                    "memory_id": str(anchor.get("memory_id") or ""),
                    "context_id": str(anchor.get("context_id") or ""),
                }
                for anchor in anchors[:RETRIEVAL_V2_MAX_GRAPH_ANCHORS]
                if str(anchor.get("memory_id") or "")
                and str(anchor.get("context_id") or "")
            ),
            key=lambda anchor: (anchor["memory_id"], anchor["context_id"]),
        )
        if not enabled or not normalized_anchors:
            payload = {
                "schema": "retrieval-graph-snapshot.v2",
                "enabled": bool(enabled),
                "anchors": normalized_anchors,
                "edges": [],
                "truncated": False,
            }
            return {**payload, "revision": self._retrieval_v2_digest(payload)}

        edges: list[dict[str, Any]] = []
        truncated = False
        fetch_limit = RETRIEVAL_V2_MAX_GRAPH_EDGES_PER_ANCHOR + 1
        for anchor in normalized_anchors:
            outgoing = self.memory_store.list_relationships(
                context_id=anchor["context_id"],
                source_memory_id=anchor["memory_id"],
                limit=fetch_limit,
            )
            incoming = self.memory_store.list_relationships(
                context_id=anchor["context_id"],
                target_memory_id=anchor["memory_id"],
                limit=fetch_limit,
            )
            if len(outgoing) > RETRIEVAL_V2_MAX_GRAPH_EDGES_PER_ANCHOR:
                truncated = True
            if len(incoming) > RETRIEVAL_V2_MAX_GRAPH_EDGES_PER_ANCHOR:
                truncated = True
            by_relationship: dict[str, dict[str, Any]] = {}
            for relationship in outgoing + incoming:
                relationship_id = str(relationship.get("relationship_id") or "")
                if relationship_id:
                    by_relationship[relationship_id] = relationship
            ordered = sorted(
                by_relationship.values(),
                key=lambda relationship: (
                    -self._retrieval_v2_unit_float(relationship.get("weight")),
                    str(relationship.get("relationship_id") or ""),
                ),
            )
            if len(ordered) > RETRIEVAL_V2_MAX_GRAPH_EDGES_PER_ANCHOR:
                truncated = True
            for relationship in ordered[:RETRIEVAL_V2_MAX_GRAPH_EDGES_PER_ANCHOR]:
                source_id = str(relationship.get("source_memory_id") or "")
                target_id = str(relationship.get("target_memory_id") or "")
                neighbor_id = target_id if source_id == anchor["memory_id"] else source_id
                edges.append(
                    {
                        "anchor_memory_id": anchor["memory_id"],
                        "neighbor_memory_id": neighbor_id,
                        "relationship_id": str(relationship.get("relationship_id") or ""),
                        "context_id": str(relationship.get("context_id") or ""),
                        "source_memory_id": source_id,
                        "target_memory_id": target_id,
                        "relation_type": self._retrieval_v2_text(
                            str(relationship.get("relation_type") or ""), 96
                        )[0],
                        "weight": self._retrieval_v2_unit_float(
                            relationship.get("weight")
                        ),
                        "created_at": self._retrieval_v2_finite_float(
                            relationship.get("created_at")
                        ),
                        "updated_at": self._retrieval_v2_finite_float(
                            relationship.get("updated_at")
                        ),
                    }
                )
        edges.sort(
            key=lambda edge: (
                str(edge["anchor_memory_id"]),
                -float(edge["weight"]),
                str(edge["relationship_id"]),
            )
        )
        if len(edges) > RETRIEVAL_V2_MAX_GRAPH_EDGES:
            truncated = True
        edges = edges[:RETRIEVAL_V2_MAX_GRAPH_EDGES]
        payload = {
            "schema": "retrieval-graph-snapshot.v2",
            "enabled": True,
            "anchors": normalized_anchors,
            "edges": edges,
            "truncated": truncated,
        }
        return {**payload, "revision": self._retrieval_v2_digest(payload)}

    def _retrieval_v2_display(self, entry: dict[str, Any]) -> dict[str, Any]:
        tag, tag_redactions = self._retrieval_v2_text(
            str(entry.get("tag") or "untagged"), 96
        )
        label, label_redactions = self._retrieval_v2_text(
            self._surface_label_for_entry(entry), 96
        )
        summary, summary_redactions = self._retrieval_v2_text(
            self._surface_summary_for_entry(entry), 180
        )
        excerpt, excerpt_redactions = self._retrieval_v2_text(
            str(entry.get("source_text") or ""), 320
        )
        facets: list[str] = []
        facet_redactions = 0
        for raw_facet in self._surface_facets_for_entry(entry)[:6]:
            facet, count = self._retrieval_v2_text(str(raw_facet), 48)
            facet_redactions += count
            if facet and facet not in facets:
                facets.append(facet)
        return {
            "tag": tag,
            "label": label or tag,
            "summary": summary,
            "excerpt": excerpt,
            "facets": facets,
            "output_redaction_count": int(
                tag_redactions
                + label_redactions
                + summary_redactions
                + excerpt_redactions
                + facet_redactions
            ),
        }

    def _retrieval_v2_text(self, value: str, limit: int) -> tuple[str, int]:
        without_controls = "".join(
            " " if (ord(char) < 32 and char not in "\t\n\r") or 127 <= ord(char) < 160 else char
            for char in str(value or "")
        )
        redacted, redaction_count = redact_capture_text(without_controls)
        return self._compact_text(str(redacted or ""), max(0, int(limit))), int(
            redaction_count
        )

    def _retrieval_v2_content_key(self, candidate: dict[str, Any]) -> str:
        display = candidate["display"]
        semantic_content = " ".join(
            str(value or "").casefold()
            for value in (
                display.get("label"),
                display.get("summary"),
                display.get("excerpt"),
            )
            if str(value or "").strip()
        )
        if not semantic_content:
            semantic_content = str(display.get("tag") or candidate["memory_id"]).casefold()
        return self._retrieval_v2_digest(
            {
                "context_id": str(candidate["context_id"]),
                "semantic_content": " ".join(semantic_content.split()),
            }
        )

    def _retrieval_v2_mmr_select(
        self,
        candidates: list[dict[str, Any]],
        *,
        limit: int,
    ) -> tuple[list[dict[str, Any]], int]:
        remaining = list(candidates)
        for candidate in remaining:
            display = candidate["display"]
            candidate["diversity_terms"] = set(
                self._retrieval_v2_select_terms(
                    self._surface_recall_terms(
                        " ".join(
                            [
                                str(display.get("label") or ""),
                                str(display.get("summary") or ""),
                                str(display.get("excerpt") or ""),
                                " ".join(display.get("facets") or []),
                            ]
                        )
                    ),
                    limit=RETRIEVAL_V2_MAX_DIVERSITY_TERMS,
                )
            )
        selected: list[dict[str, Any]] = []
        evaluations = 0
        while remaining and len(selected) < limit:
            evaluated: list[tuple[float, float, str, dict[str, Any], float]] = []
            for candidate in remaining:
                evaluations += 1
                candidate_terms = candidate["diversity_terms"]
                maximum_similarity = 0.0
                for prior in selected:
                    prior_terms = prior["diversity_terms"]
                    if not candidate_terms or not prior_terms:
                        similarity = 0.0
                    else:
                        similarity = len(candidate_terms & prior_terms) / max(
                            1, len(candidate_terms | prior_terms)
                        )
                    maximum_similarity = max(maximum_similarity, similarity)
                relevance = float(candidate["relevance_score"])
                selection_score = (
                    RETRIEVAL_V2_MMR_LAMBDA * relevance
                    - (1.0 - RETRIEVAL_V2_MMR_LAMBDA) * maximum_similarity
                )
                evaluated.append(
                    (
                        selection_score,
                        relevance,
                        str(candidate["memory_id"]),
                        candidate,
                        maximum_similarity,
                    )
                )
            evaluated.sort(key=lambda item: (-item[0], -item[1], item[2]))
            selection_score, _relevance, _memory_id, chosen, similarity = evaluated[0]
            chosen["mmr"] = {
                "lambda": RETRIEVAL_V2_MMR_LAMBDA,
                "maximum_selected_similarity": self._retrieval_v2_unit_float(similarity),
                "diversity_penalty": (
                    (1.0 - RETRIEVAL_V2_MMR_LAMBDA)
                    * self._retrieval_v2_unit_float(similarity)
                ),
                "selection_score": selection_score,
            }
            selected.append(chosen)
            remaining.remove(chosen)
        return selected, evaluations

    def _retrieval_v2_public_item(
        self,
        candidate: dict[str, Any],
        *,
        rank: int,
    ) -> dict[str, Any]:
        entry = candidate["entry"]
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        display = candidate["display"]
        reasons: list[dict[str, Any]] = []
        if isinstance(candidate.get("spike_reason"), dict):
            reasons.append(dict(candidate["spike_reason"]))
        if isinstance(candidate.get("surface_reason"), dict):
            reasons.append(dict(candidate["surface_reason"]))
        graph_provenance = [dict(item) for item in candidate["graph_provenance"]]
        if graph_provenance:
            reasons.append(
                {
                    "type": "same-context-graph-neighbor",
                    "relationship_count": len(graph_provenance),
                    "relationships": graph_provenance,
                }
            )
        source_provenance: dict[str, Any] = {
            "created_at": self._retrieval_v2_finite_float(entry.get("created_at")),
            "updated_at": self._retrieval_v2_finite_float(entry.get("updated_at")),
        }
        for key in (
            "source",
            "source_tag",
            "speaker",
            "capture_id",
            "trace_type",
            "truth_posture",
            "session_id",
        ):
            value = metadata.get(key)
            if value is not None and str(value).strip():
                source_provenance[key] = self._retrieval_v2_text(str(value), 128)[0]
        stored_confidence: float | None = None
        if metadata.get("confidence") is not None:
            try:
                parsed_confidence = float(metadata["confidence"])
            except (TypeError, ValueError, OverflowError):
                parsed_confidence = math.nan
            if math.isfinite(parsed_confidence):
                stored_confidence = self._retrieval_v2_unit_float(parsed_confidence)
        source_provenance["stored_confidence"] = stored_confidence

        relevance_score = self._retrieval_v2_unit_float(candidate["relevance_score"])
        contributions = candidate["score_contributions"]
        mmr = candidate.get("mmr") if isinstance(candidate.get("mmr"), dict) else {}
        scope_record = candidate["scope_record"]
        return {
            "rank": int(rank),
            "memory_id": str(candidate["memory_id"]),
            "context_id": str(candidate["context_id"]),
            "tag": display["tag"],
            "label": display["label"],
            "summary": display["summary"],
            "excerpt": display["excerpt"],
            "facets": list(display["facets"]),
            "score": round(relevance_score, 8),
            "score_breakdown": {
                "signals": {
                    "spike_index": round(
                        self._retrieval_v2_unit_float(candidate["spike_signal"]), 8
                    ),
                    "surface_index": round(
                        self._retrieval_v2_unit_float(candidate["surface_signal"]), 8
                    ),
                    "same_context_graph": round(
                        self._retrieval_v2_unit_float(candidate["graph_signal"]), 8
                    ),
                },
                "weights": dict(RETRIEVAL_V2_RANK_WEIGHTS),
                "contributions": {
                    key: round(self._retrieval_v2_unit_float(value), 8)
                    for key, value in contributions.items()
                },
                "relevance_score": round(relevance_score, 8),
                "diversity": {
                    "lambda": RETRIEVAL_V2_MMR_LAMBDA,
                    "maximum_selected_similarity": round(
                        self._retrieval_v2_unit_float(
                            mmr.get("maximum_selected_similarity")
                        ),
                        8,
                    ),
                    "diversity_penalty": round(
                        max(
                            0.0,
                            self._retrieval_v2_finite_float(
                                mmr.get("diversity_penalty")
                            ),
                        ),
                        8,
                    ),
                    "selection_score": round(
                        self._retrieval_v2_finite_float(mmr.get("selection_score")),
                        8,
                    ),
                },
            },
            "confidence": {
                "calibrated": False,
                "probability": None,
                "signal": "uncalibrated-ranking-score",
                "score": round(relevance_score, 8),
                "warning": "Do not interpret this value as truth probability.",
            },
            "match_reasons": reasons,
            "scope_provenance": self._retrieval_v2_public_scope_provenance(
                scope_record,
                origin_context=str(scope_record.get("origin_context_id") or ""),
            ),
            "graph_provenance": graph_provenance,
            "source_provenance": source_provenance,
            "ranker_id": RETRIEVAL_V2_RANKER_ID,
            "ranker_version": RETRIEVAL_V2_RANKER_VERSION,
            "content_duplicate_count": int(candidate.get("content_duplicate_count", 0)),
            "output_redaction_count": int(display["output_redaction_count"]),
            "raw_source_included": False,
        }

    @staticmethod
    def _retrieval_v2_finite_float(value: Any, default: float = 0.0) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return float(default)
        return parsed if math.isfinite(parsed) else float(default)

    @classmethod
    def _retrieval_v2_unit_float(cls, value: Any) -> float:
        parsed = cls._retrieval_v2_finite_float(value)
        return min(max(parsed, 0.0), 1.0)

    def run_snn_cycle(self, sensory_spikes: Any, *, steps: int = 12):
        """Run recurrent LIF propagation with immutable state updates."""
        self._require_neural_substrate()
        native_mx = self._mx
        spikes_in = self._coerce_embedding(sensory_spikes)
        self._ensure_projection_shape(int(spikes_in.shape[0]))

        input_current = native_mx.matmul(spikes_in, self.W_syn) * self.W_syn_decay_multiplier
        mem = self.state["mem"]
        prev_spikes = self.state["spk"]
        accumulated = native_mx.zeros((self.num_neurons,))
        W_lateral = self.W_lateral

        for _ in range(max(1, int(steps))):
            lateral_current = (
                native_mx.matmul(prev_spikes, W_lateral)
                * self.W_lateral_decay_multiplier
            )
            total_current = input_current + lateral_current
            spk, mem = self._lif_update(mem, total_current)
            accumulated = accumulated + spk
            W_lateral = self._apply_stdp(W_lateral, prev_spikes, spk)
            prev_spikes = spk

        self.W_lateral = W_lateral
        self.state = {
            "mem": mem,
            "spk": prev_spikes,
        }
        self.active_traces = self.trace_decay * self.active_traces + accumulated
        self._eval_if_available(accumulated, self.state["mem"], self.state["spk"], self.active_traces)
        return accumulated

    def _apply_stdp(self, W_lateral: Any, previous_spikes: Any, current_spikes: Any):
        native_mx = self._mx
        if self.stdp_active_limit == 0:
            return W_lateral

        active_count = int(native_mx.sum(previous_spikes + current_spikes).item())
        if active_count <= 0 or active_count > self.stdp_active_limit:
            return W_lateral

        positive_decay = math.exp(-1.0 / self.stdp_tau_plus)
        negative_decay = math.exp(-1.0 / self.stdp_tau_minus)
        potentiation = (
            previous_spikes[:, None]
            * current_spikes[None, :]
            * (self.stdp_a_plus * positive_decay)
        )
        depression = (
            current_spikes[:, None]
            * previous_spikes[None, :]
            * (self.stdp_a_minus * negative_decay)
        )
        next_weights = W_lateral + potentiation - depression
        return native_mx.clip(next_weights, -self.stdp_clip, self.stdp_clip)

    def register_trace(
        self,
        *,
        tag: str,
        embedding: Any,
        context_id: str = "default",
        metadata: dict[str, Any] | None = None,
        source_text: str = "",
    ) -> dict[str, Any]:
        self._require_neural_substrate()
        context = sanitize_context_id(context_id)
        clean_tag = sanitize_tag(tag)
        safe_source_text, source_redactions = redact_capture_text(
            str(source_text or "")
        )
        safe_metadata = self._json_safe_metadata(metadata)
        if source_redactions:
            safe_metadata = {
                **safe_metadata,
                "redaction_count": int(
                    source_redactions
                    + int(safe_metadata.get("redaction_count", 0) or 0)
                ),
                "raw_text_stored": False,
            }
        try:
            self._auto_quick_prune_if_due(trigger="register-trace")
            arr = self._coerce_embedding(embedding)
            self._ensure_projection_shape(int(arr.shape[0]))
            sensory_spikes = self.encode_to_spikes_top_k(arr)
            spike_indices = self._active_indices_from_spikes(sensory_spikes)
            neuron_indices = self._project_sensory_indices(spike_indices)
            registered_at = time.time()
            trace = {
                "tag": clean_tag,
                "context_id": context,
                "embedding_dimensions": int(arr.shape[0]),
                "spike_indices": spike_indices,
                "neuron_indices": neuron_indices,
                "metadata": safe_metadata,
                "registered_at": registered_at,
                "source_text": safe_source_text,
            }

            persisted = self.memory_store.upsert_entry(
                tag=trace["tag"],
                context_id=trace["context_id"],
                source_text=trace["source_text"],
                metadata=trace["metadata"],
                embedding_dimensions=trace["embedding_dimensions"],
                spike_indices=trace["spike_indices"],
                neuron_indices=trace["neuron_indices"],
                registered_at=registered_at,
            )
            self._refresh_registered_traces()
            self._surface_recall_cache.clear()
            self._persist_runtime_state()
            self._mark_activity()
            embedding_provider = trace["metadata"].get("embedding_provider")
            return {
                "tag": clean_tag,
                "context_id": context,
                "memory_id": persisted["memory_id"],
                "spike_count": len(spike_indices),
                "neuron_count": len(neuron_indices),
                "registered_trace_count": len(self.registered_traces),
                "state_path": str(self.state_path),
                "memory_db_path": str(self.memory_store.db_path),
                "persisted": True,
                "embedding_provider": embedding_provider,
            }
        except Exception:
            LOGGER.exception("trace registration failed for context_id=%s tag=%s", context, clean_tag)
            raise

    def query_text(
        self,
        prompt: str,
        *,
        context_id: str = "default",
        steps: int = 12,
        recall_scope: str = "local",
    ) -> str:
        prompt_text, _ = redact_capture_text(str(prompt or "").strip())
        if not prompt_text:
            raise ValueError("prompt must not be empty")
        return self.query(
            self.embed_text(prompt_text),
            context_id=context_id,
            steps=steps,
            prompt_text=prompt_text,
            recall_scope=recall_scope,
        )

    def query(
        self,
        embedding: Any,
        *,
        context_id: str = "default",
        steps: int = 12,
        prompt_text: str = "",
        recall_scope: str = "local",
    ) -> str:
        context = sanitize_context_id(context_id)
        normalized_scope = sanitize_recall_scope(recall_scope)
        if not self.is_enabled(context):
            self._mark_activity()
            return (
                f"SYNAPSE-S2 disabled for context {context}. "
                "Toggle it with set_spiking_attention_enabled(true)."
            )
        try:
            self._auto_quick_prune_if_due(trigger="query")
            sensory_spikes = self.encode_to_spikes_top_k(embedding)
            firing_signature = self.run_snn_cycle(sensory_spikes, steps=steps)
            registered = self._recall_registered_traces(
                context=context,
                sensory_spikes=sensory_spikes,
                firing_signature=firing_signature,
                prompt_text=prompt_text,
                recall_scope=normalized_scope,
            )
            if registered:
                return " / ".join(registered)
            active_indices = self._recall_indices(firing_signature, sensory_spikes)
            tags = self._tags_for_indices(
                active_indices,
                context,
                recall_scope=normalized_scope,
            )
            if not tags:
                return self._raw_activation_summary(active_indices)
            return " / ".join(tags)
        except Exception:
            LOGGER.exception("query failed for context_id=%s", context)
            raise
        finally:
            self._mark_activity()

    def _active_indices_from_spikes(self, spikes: Any) -> list[int]:
        return [
            idx
            for idx, value in enumerate(spikes.tolist())
            if float(value) > 0.0
        ]

    def _project_sensory_indices(self, sensory_indices: list[int]) -> list[int]:
        if not sensory_indices:
            return []
        projected = {
            min(self.num_neurons - 1, int(idx * self.num_neurons / max(1, self.dimension)))
            for idx in sensory_indices
        }
        return sorted(projected)

    def _recall_registered_traces(
        self,
        *,
        context: str,
        sensory_spikes: Any,
        firing_signature: Any,
        prompt_text: str = "",
        recall_scope: str = "local",
    ) -> list[str]:
        query_spikes = set(self._active_indices_from_spikes(sensory_spikes))
        if not query_spikes:
            return []
        firing_values = firing_signature.tolist()
        scope_records = self.bridge_governance.resolve_recall_contexts(
            context_id=context,
            scope=recall_scope,
        )
        candidates = self.memory_store.recall_candidates(
            context_id=context,
            query_spikes=query_spikes,
            firing_values=firing_values,
            limit=self.recall_count,
            recall_scope=recall_scope,
            recall_contexts=scope_records,
        )
        candidates = self._merge_surface_text_recall_candidates(
            context=context,
            prompt_text=prompt_text,
            candidates=candidates,
            recall_scope=recall_scope,
            recall_contexts=scope_records,
        )
        rendered = [
            self._format_recall_entry(candidate, score=float(candidate["score"]))
            for candidate in candidates
        ]
        rendered.extend(
                self._related_trace_contexts(
                    context=context,
                    candidates=candidates,
                    recall_scope=recall_scope,
                )
        )
        return rendered

    def _related_trace_contexts(
        self,
        *,
        context: str,
        candidates: list[dict[str, Any]],
        recall_scope: str = "local",
    ) -> list[str]:
        seen_ids = {str(candidate["memory_id"]) for candidate in candidates}
        related: list[str] = []
        for candidate in candidates:
            memory_id = str(candidate["memory_id"])
            candidate_context = sanitize_context_id(
                str(candidate.get("context_id") or context)
            )
            relationships = (
                self.memory_store.list_relationships(
                    context_id=candidate_context,
                    source_memory_id=memory_id,
                    limit=max(1, self.recall_count),
                )
                + self.memory_store.list_relationships(
                    context_id=candidate_context,
                    target_memory_id=memory_id,
                    limit=max(1, self.recall_count),
                )
            )
            relationships.sort(
                key=lambda item: (float(item["weight"]), float(item["updated_at"])),
                reverse=True,
            )
            for relationship in relationships[: max(1, self.recall_count)]:
                neighbor_id = (
                    relationship["target_memory_id"]
                    if relationship["source_memory_id"] == memory_id
                    else relationship["source_memory_id"]
                )
                if neighbor_id in seen_ids:
                    continue
                entry = self.memory_store.get_entry(str(neighbor_id))
                if entry is None:
                    continue
                entry_context = sanitize_context_id(
                    str(entry.get("context_id") or "")
                )
                if entry_context != candidate_context:
                    continue
                seen_ids.add(neighbor_id)
                entry = dict(entry)
                for key in (
                    "recall_scope",
                    "recall_provenance",
                    "via_context_link_id",
                    "via_relation_type",
                    "via_direction",
                ):
                    if key in candidate:
                        entry[key] = candidate[key]
                entry.setdefault("recall_scope", recall_scope)
                related.append(
                    self._format_recall_entry(
                        entry,
                        linked=str(relationship["relation_type"]),
                        weight=float(relationship["weight"]),
                    )
                )
        return related

    def _format_recall_entry(
        self,
        entry: dict[str, Any],
        *,
        score: float | None = None,
        linked: str = "",
        weight: float | None = None,
    ) -> str:
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        tag = str(entry.get("tag") or "untagged")
        label = self._surface_label_for_entry(entry)
        facets = metadata.get("semantic_facets")
        facet_text = ""
        if isinstance(facets, (list, tuple)):
            facet_text = " | ".join(str(facet) for facet in facets[:4] if str(facet).strip())
        summary = str(metadata.get("display_summary") or "").strip()
        details: list[str] = []
        def clean_value(value: str, limit: int) -> str:
            return self._compact_text(value, limit).replace(",", ";")

        if score is not None:
            details.append(f"score={float(score):.3f}")
        if linked:
            details.append(f"linked={linked}")
        if weight is not None:
            details.append(f"weight={float(weight):.3f}")
        if label and label != tag:
            details.append(f"label={clean_value(label, 72)}")
        if facet_text:
            details.append(f"facets={clean_value(facet_text, 96)}")
        if summary and summary != label:
            details.append(f"summary={clean_value(summary, 96)}")
        overlap_terms = metadata.get("surface_text_overlap")
        if isinstance(overlap_terms, (list, tuple)):
            matched = " ".join(
                str(term)
                for term in overlap_terms[:8]
                if str(term).strip()
            )
            if matched:
                details.append(f"matched={clean_value(matched, 96)}")
        details.append(f"context={entry.get('context_id', '')}")
        recall_scope = str(entry.get("recall_scope") or "local")
        provenance = str(entry.get("recall_provenance") or "local")
        details.append(f"scope={recall_scope}")
        details.append(f"provenance={provenance}")
        via_context_link_id = str(entry.get("via_context_link_id") or "")
        if via_context_link_id:
            details.append(f"via_context_link={via_context_link_id}")
        via_relation_type = str(entry.get("via_relation_type") or "")
        if via_relation_type:
            details.append(f"via_relation={via_relation_type}")
        details.append(f"id={entry.get('memory_id', '')}")
        return f"{tag} ({', '.join(details)})"

    def _merge_surface_text_recall_candidates(
        self,
        *,
        context: str,
        prompt_text: str,
        candidates: list[dict[str, Any]],
        recall_scope: str = "local",
        recall_contexts: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {
            str(candidate["memory_id"]): {
                **dict(candidate),
                "spike_recall_score": float(candidate.get("score", 0.0) or 0.0),
            }
            for candidate in candidates
        }
        for candidate in self._surface_text_recall_candidates(
            context=context,
            prompt_text=prompt_text,
            recall_scope=recall_scope,
            recall_contexts=recall_contexts,
        ):
            memory_id = str(candidate["memory_id"])
            surface_score = float(candidate.get("score", 0.0) or 0.0)
            current = merged.get(memory_id)
            if current is None:
                merged[memory_id] = {
                    **dict(candidate),
                    "surface_recall_score": surface_score,
                }
                continue
            previous_surface_score = float(current.get("surface_recall_score", 0.0) or 0.0)
            current["surface_recall_score"] = max(previous_surface_score, surface_score)
            if surface_score >= previous_surface_score:
                current["metadata"] = candidate.get("metadata", current.get("metadata", {}))
                current["surface_overlap_count"] = candidate.get("surface_overlap_count")
                current["surface_term_weight"] = candidate.get("surface_term_weight")
        rescored: list[dict[str, Any]] = []
        for candidate in merged.values():
            ranked_candidate = dict(candidate)
            ranked_score = self._merged_recall_candidate_score(ranked_candidate)
            metadata = ranked_candidate.get("metadata")
            metadata = dict(metadata) if isinstance(metadata, dict) else {}
            spike_score = float(ranked_candidate.get("spike_recall_score", 0.0) or 0.0)
            surface_score = float(ranked_candidate.get("surface_recall_score", 0.0) or 0.0)
            if spike_score > 0.0:
                metadata["spike_recall_score"] = round(spike_score, 6)
            if surface_score > 0.0:
                metadata["surface_recall_score"] = round(surface_score, 6)
            metadata["recall_rank_score"] = round(ranked_score, 6)
            ranked_candidate["metadata"] = self._json_safe_metadata(metadata)
            ranked_candidate["score"] = round(ranked_score, 6)
            rescored.append(ranked_candidate)
        ranked = sorted(
            rescored,
            key=lambda item: (float(item.get("score", 0.0)), float(item.get("updated_at", 0.0))),
            reverse=True,
        )
        return ranked[: max(1, self.recall_count)]

    def _merged_recall_candidate_score(self, candidate: dict[str, Any]) -> float:
        metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
        spike_score = float(candidate.get("spike_recall_score", 0.0) or 0.0)
        surface_score = float(candidate.get("surface_recall_score", 0.0) or 0.0)
        if surface_score <= 0.0:
            return min(0.995, 0.6 * spike_score)
        overlap_terms = metadata.get("surface_text_overlap")
        concrete_terms = metadata.get("surface_text_concrete_overlap")
        overlap_count = len(overlap_terms) if isinstance(overlap_terms, (list, tuple)) else 0
        concrete_count = len(concrete_terms) if isinstance(concrete_terms, (list, tuple)) else 0
        concrete_bonus = min(0.12, 0.03 * concrete_count)
        breadth_bonus = min(0.04, 0.005 * overlap_count)
        spike_bonus = min(0.1, 0.12 * spike_score)
        return min(0.995, surface_score + concrete_bonus + breadth_bonus + spike_bonus)

    def _surface_text_recall_candidates(
        self,
        *,
        context: str,
        prompt_text: str,
        recall_scope: str = "local",
        recall_contexts: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        query_terms = set(self._surface_recall_terms(prompt_text))
        if not query_terms:
            return []
        scope_records = list(
            recall_contexts
            if recall_contexts is not None
            else self.bridge_governance.resolve_recall_contexts(
                context_id=context,
                scope=recall_scope,
            )
        )
        scope_context_ids = [
            str(record.get("context_id") or "")
            for record in scope_records
            if str(record.get("context_id") or "")
        ]
        revision = self.memory_store.entries_revision(
            context_ids=scope_context_ids,
        )
        query_hash = hashlib.sha256(
            "\x1f".join(sorted(query_terms)).encode("utf-8")
        ).hexdigest()[:16]
        scope_key = ",".join(scope_context_ids)
        cache_key = f"{context}|{recall_scope}|{scope_key}|surface-query|{query_hash}"
        cached = self._surface_recall_cache.get(cache_key)
        if cached and cached.get("revision") == revision["revision"]:
            return [dict(candidate) for candidate in cached.get("candidates", [])]

        prompt_lower = " ".join(str(prompt_text or "").lower().split())
        candidates: list[dict[str, Any]] = []
        indexed_entries = self.memory_store.surface_recall_candidates(
            context_id=context,
            query_terms=query_terms,
            limit=max(self.recall_count * 8, 64),
            recall_scope=recall_scope,
            recall_contexts=scope_records,
        )
        for entry in indexed_entries:
            metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
            facets = self._surface_facets_for_entry(entry)
            corpus = " ".join(
                [
                    self._surface_label_for_entry(entry),
                    self._surface_summary_for_entry(entry),
                    str(entry.get("tag") or ""),
                    str(entry.get("source_text") or "")[:MAX_SURFACE_RECALL_SOURCE_CHARS],
                    " ".join(facets),
                ]
            )
            corpus_terms = set(self._surface_recall_terms(corpus))
            overlap = query_terms & corpus_terms
            phrase_hits = 0
            facet_phrases = tuple(
                " ".join(str(facet or "").lower().split())
                for facet in facets
                if str(facet or "").strip()
            )
            for facet_text in facet_phrases:
                if facet_text and (facet_text in prompt_lower or prompt_lower in facet_text):
                    phrase_hits += 1
            if len(overlap) < 2 and phrase_hits == 0:
                continue
            term_weight = float(entry.get("surface_term_weight", 0.0) or 0.0)
            concrete_query_terms = {
                term
                for term in query_terms
                if self._is_concrete_surface_recall_term(term)
            }
            concrete_overlap = overlap & concrete_query_terms
            coverage = len(overlap) / max(1, len(query_terms))
            density = len(overlap) / max(1, len(corpus_terms))
            concrete_coverage = len(concrete_overlap) / max(1, len(concrete_query_terms))
            score = min(
                0.995,
                0.24
                + (0.42 * coverage)
                + (0.16 * density)
                + (0.12 * concrete_coverage)
                + min(0.05, term_weight / 100.0)
                + min(0.08, 0.04 * phrase_hits),
            )
            candidate = dict(entry)
            candidate["score"] = round(score, 6)
            metadata = dict(metadata)
            metadata["surface_text_recall"] = True
            metadata["surface_text_overlap"] = sorted(overlap)
            metadata["surface_text_concrete_overlap"] = sorted(concrete_overlap)
            candidate["metadata"] = self._json_safe_metadata(metadata)
            candidates.append(candidate)
        candidates.sort(
            key=lambda item: (float(item["score"]), float(item["updated_at"])),
            reverse=True,
        )
        bounded = candidates[: max(self.recall_count * 3, 12)]
        self._surface_recall_cache[cache_key] = {
            "revision": revision["revision"],
            "revision_info": revision,
            "candidates": [dict(candidate) for candidate in bounded],
            "built_at": time.time(),
        }
        if len(self._surface_recall_cache) > 32:
            oldest_key = min(
                self._surface_recall_cache,
                key=lambda key: float(self._surface_recall_cache[key].get("built_at", 0.0)),
            )
            self._surface_recall_cache.pop(oldest_key, None)
        return bounded

    def _recall_indices(self, firing_signature: Any, sensory_spikes: Any) -> list[int]:
        native_mx = self._mx
        total_activity = float(native_mx.sum(firing_signature).item())
        if total_activity > 0.0:
            ordered = native_mx.argsort(firing_signature)[-self.recall_count :]
            return list(reversed(_array_to_int_list(ordered)))

        sensory_indices = [
            idx for idx, value in enumerate(sensory_spikes.tolist()) if float(value) > 0.0
        ]
        projected = {
            min(self.num_neurons - 1, int(idx * self.num_neurons / max(1, self.dimension)))
            for idx in sensory_indices
        }
        return sorted(projected, reverse=True)[: self.recall_count]

    def _tags_for_indices(
        self,
        active_indices: list[int],
        context: str,
        *,
        recall_scope: str = "local",
    ) -> list[str]:
        scope_records = self.bridge_governance.resolve_recall_contexts(
            context_id=context,
            scope=recall_scope,
        )
        scope_by_context = {
            str(record["context_id"]): record
            for record in scope_records
        }
        tags: list[str] = []
        seen_memory_ids: set[str] = set()
        for idx in active_indices[: self.recall_count]:
            for trace in self.registered_traces:
                trace_context = str(trace.get("context_id") or "")
                if trace_context not in scope_by_context:
                    continue
                if int(idx) not in trace.get("neuron_indices", []):
                    continue
                memory_id = str(trace.get("memory_id") or "")
                if memory_id in seen_memory_ids:
                    continue
                seen_memory_ids.add(memory_id)
                rendered_trace = dict(trace)
                rendered_trace.update(scope_by_context[trace_context])
                tags.append(self._format_recall_entry(rendered_trace))
                if len(tags) >= self.recall_count:
                    return tags
        return tags

    def _raw_activation_summary(self, active_indices: list[int]) -> str:
        if not active_indices:
            return "No registered historical context matched. raw_activation_top_neurons=[]"
        raw = ",".join(f"{idx:06d}" for idx in active_indices[: self.recall_count])
        return (
            "No registered historical context matched. "
            f"raw_activation_top_neurons=[{raw}]"
        )

    def is_enabled(self, context_id: str = "default") -> bool:
        context = sanitize_context_id(context_id)
        if context in self.context_overrides:
            return bool(self.context_overrides[context])
        return bool(self.global_enabled)

    def set_enabled(
        self,
        enabled: bool,
        *,
        context_id: str | None = None,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id) if context_id is not None else None
        if context is None or context in {"global", "all"}:
            self.global_enabled = bool(enabled)
            self._global_enabled_dirty = True
        else:
            self.context_overrides[context] = bool(enabled)
            self._dirty_context_overrides.add(context)
        self._persist_runtime_state()
        return self.status(context_id=context_id or "default")

    def status(self, *, context_id: str = "default") -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        total_stats = self.memory_store.stats()
        context_stats = self.memory_store.stats(context_id=context)
        return {
            "runtime": "ready" if self.is_enabled(context) else "disabled",
            "runtime_mode": (
                "control-plane" if self.control_plane_only else "neural"
            ),
            "neural_state": (
                "deferred" if self.control_plane_only else "materialized"
            ),
            "context_id": context,
            "global_enabled": bool(self.global_enabled),
            "effective_enabled": self.is_enabled(context),
            "context_overrides": dict(sorted(self.context_overrides.items())),
            "runtime_state_repair": dict(self.runtime_state_repair),
            "dimension": int(self.dimension),
            "num_neurons": int(self.num_neurons),
            "default_top_k": int(self.default_top_k),
            "recall_count": int(self.recall_count),
            "beta": float(self.beta),
            "threshold": float(self.threshold),
            "registered_trace_count": int(total_stats["entry_count"]),
            "registered_trace_cache_count": len(self.registered_traces),
            "memory_mapping_count": len(self.memory_mapping),
            "memory_entry_count": int(total_stats["entry_count"]),
            "memory_context_entry_count": int(context_stats["entry_count"]),
            "memory_event_count": int(total_stats["event_count"]),
            "memory_relationship_count": int(total_stats["relationship_count"]),
            "memory_context_relationship_count": int(context_stats["relationship_count"]),
            "memory_context_link_count": int(total_stats["context_link_count"]),
            "memory_selected_context_link_count": int(context_stats["context_link_count"]),
            "memory_contexts": total_stats["contexts"],
            "active_cortex_session_count": len(
                [
                    session
                    for session in self.cortex_sessions.values()
                    if session.get("status") == "active"
                    and session.get("context_id") == context
                ]
            ),
            "cortex_policy": self._cortex_policy("strict"),
            "context_bus_event_count": int(total_stats["context_bus_event_count"]),
            "context_bus_context_event_count": int(context_stats["context_bus_event_count"]),
            "context_bus_latest_event_id": int(context_stats["context_bus_latest_event_id"]),
            "context_bus_ack_cursor_count": int(
                context_stats["context_bus_ack_cursor_count"]
            ),
            "context_bus_verified_cursor_count": int(
                context_stats.get("context_bus_verified_cursor_count", 0)
            ),
            "context_bus_legacy_unverified_cursor_count": int(
                context_stats.get("context_bus_legacy_unverified_cursor_count", 0)
            ),
            "context_bus_delivery_count": int(
                context_stats.get("context_bus_delivery_count", 0)
            ),
            "context_bus_active_lease_count": int(
                context_stats.get("context_bus_active_lease_count", 0)
            ),
            "context_bus_expired_retryable_lease_count": int(
                context_stats.get(
                    "context_bus_expired_retryable_lease_count",
                    0,
                )
            ),
            "context_bus_ack_receipt_count": int(
                context_stats.get("context_bus_ack_receipt_count", 0)
            ),
            "context_bus_ack_tombstone_count": int(
                context_stats.get("context_bus_ack_tombstone_count", 0)
            ),
            "context_bus_retry_exhausted_count": int(
                context_stats.get("context_bus_retry_exhausted_count", 0)
            ),
            "context_bus_dead_letter_count": int(
                context_stats.get("context_bus_dead_letter_count", 0)
            ),
            "context_bus_max_delivery_attempts": int(
                context_stats.get("context_bus_max_delivery_attempts", 5)
            ),
            "context_bus_delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "context_bus_protocol_version": CONTEXT_BUS_PROTOCOL_VERSION,
            "context_bus_agent_targets": list(DEFAULT_AGENT_TARGETS),
            "semantic_group_count": len(self.semantic_hierarchy),
            "mlx_available": mx is not None,
            "mlxsnn_available": self._mlxsnn_available,
            "mlxsnn_lif_execution_path": self._mlxsnn_lif_layer is not None,
            "mlx_device": os.getenv("MLX_DEVICE", "default"),
            "embedding_provider": self.embedding_provider_info(),
            "state_path": str(self.state_path),
            "memory_db_path": str(self.memory_store.db_path),
            "quick_pruning_interval_seconds": self.quick_pruning_interval_seconds,
            "idle_deep_sleep_seconds": self.idle_deep_sleep_seconds,
            "last_pruning_age_seconds": round(time.monotonic() - self.last_pruning_monotonic, 3),
            "last_activity_age_seconds": round(time.monotonic() - self.last_activity_monotonic, 3),
            "quick_pruning_count": self.quick_pruning_count,
            "deep_sleep_count": self.deep_sleep_count,
            "W_syn_decay_multiplier": round(float(self.W_syn_decay_multiplier), 9),
            "W_lateral_decay_multiplier": round(float(self.W_lateral_decay_multiplier), 9),
            "quick_pruning_eager_decay_elements": self.quick_pruning_eager_decay_elements,
            "last_maintenance": self.last_maintenance,
            "consolidation_phase_names": list(CONSOLIDATION_PHASES),
        }

    def audit_semantic_indexes(
        self,
        *,
        context_id: str | None = None,
        sample_limit: int = 20,
    ) -> dict[str, Any]:
        """Return the public semantic-index integrity report."""
        context = (
            sanitize_context_id(context_id)
            if context_id is not None
            else None
        )
        return self.memory_store.audit_semantic_indexes(
            context_id=context,
            sample_limit=sample_limit,
        )

    def repair_semantic_indexes(
        self,
        *,
        context_id: str | None = None,
        confirm: bool = False,
        expected_revision: str | None = None,
        sample_limit: int = 20,
    ) -> dict[str, Any]:
        """Repair reviewed semantic-index drift through the authoritative lane."""
        context = (
            sanitize_context_id(context_id)
            if context_id is not None
            else None
        )
        return self.memory_store.repair_semantic_indexes(
            context_id=context,
            confirm=confirm,
            expected_revision=expected_revision,
            sample_limit=sample_limit,
        )

    def resolve_recall_contexts(
        self,
        *,
        context_id: str = "default",
        recall_scope: str = "local",
    ) -> list[dict[str, Any]]:
        """Resolve the backend's bounded recall scope with provenance."""
        context = sanitize_context_id(context_id)
        scope = sanitize_recall_scope(recall_scope)
        return self.bridge_governance.resolve_recall_contexts(
            context_id=context,
            scope=scope,
        )

    def memory_entries_revision(
        self,
        *,
        context_id: str | None = None,
        include_global: bool = False,
        context_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Return the public cache identity for a bounded entry selection."""
        context = (
            sanitize_context_id(context_id)
            if context_id is not None
            else None
        )
        clean_context_ids = None
        if context_ids is not None:
            if isinstance(context_ids, (str, bytes)):
                raise ValueError("context_ids must be an iterable of identifiers")
            clean_context_ids = list(
                dict.fromkeys(
                    sanitize_context_id(str(value))
                    for value in context_ids
                    if str(value).strip()
                )
            )
        return self.memory_store.entries_revision(
            context_id=context,
            include_global=bool(include_global),
            context_ids=clean_context_ids,
        )

    def get_memory_entry(
        self,
        memory_id: str,
        *,
        include_vectors: bool = False,
    ) -> dict[str, Any] | None:
        """Return one durable memory through the backend's safe renderer."""
        clean_memory_id = reject_sensitive_identifier(
            memory_id,
            field="memory_id",
        ).strip()
        if not clean_memory_id:
            raise ValueError("memory_id is required")
        entry = self.memory_store.get_entry(clean_memory_id)
        if entry is None:
            return None
        return self._render_memory_entry(
            entry,
            include_vectors=bool(include_vectors),
        )

    def _get_retrieval_cursor_codec(self) -> RetrievalCursorCodec:
        codec = self._retrieval_cursor_codec
        if codec is not None:
            return codec
        with self._retrieval_cursor_lock:
            codec = self._retrieval_cursor_codec
            if codec is None:
                codec = RetrievalCursorCodec.from_key_path(
                    self.state_path.parent / "retrieval_cursor.key"
                )
                self._retrieval_cursor_codec = codec
        return codec

    @staticmethod
    def _retrieval_response_mode(value: Any) -> str:
        normalized = str(value or "legacy").strip().casefold()
        if normalized not in {"legacy", "compact", "full"}:
            raise ValueError("response_mode must be legacy, compact, or full")
        return normalized

    @staticmethod
    def _retrieval_filter_digest(filters: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(
                filters,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    def _cortex_retrieval_runtime_snapshot(
        self,
        *,
        context: str,
        agent: str,
    ) -> tuple[list[dict[str, Any]], str]:
        """Freeze and fingerprint the live Cortex fields returned by Retrieval v2.

        Durable Cortex memories are snapshot-fenced by SQLite. Active governor
        sessions live in the runtime-state plane, so they need an independent
        revision that is authenticated alongside the durable page cursor. The
        caller performs an optimistic before/after check and only renders the
        frozen copy returned here.
        """

        active_sessions = [
            self._json_safe_metadata(dict(session))
            for session in self.cortex_sessions.values()
            if session.get("context_id") == context
            and session.get("status") == "active"
            and (not agent or session.get("agent_id") == agent)
        ]
        active_sessions.sort(
            key=lambda item: (
                float(item.get("updated_at", 0.0)),
                str(item.get("session_id", "")),
            ),
            reverse=True,
        )
        revision = self._retrieval_filter_digest(
            {
                "schema": "synapse-s2.cortex-runtime-snapshot.v1",
                "context_id": context,
                "agent_id": agent,
                "active_sessions": active_sessions,
            }
        )
        return active_sessions, revision

    @classmethod
    def _cortex_retrieval_snapshot_revision(
        cls,
        *,
        durable_revision: str,
        runtime_revision: str,
    ) -> str:
        return cls._retrieval_filter_digest(
            {
                "schema": "synapse-s2.cortex-composite-snapshot.v1",
                "durable_revision": durable_revision,
                "runtime_revision": runtime_revision,
            }
        )

    def _retrieval_scope_binding(
        self,
        *,
        context: str,
        recall_scope: str,
        include_global: bool,
    ) -> dict[str, Any]:
        records = self.bridge_governance.resolve_recall_contexts(
            context_id=context,
            scope=recall_scope,
        )
        if not include_global:
            records = [
                record
                for record in records
                if str(record.get("context_id") or "") != "global"
            ]
        normalized_records = sorted(
            (
                {
                    "context_id": sanitize_context_id(
                        str(record.get("context_id") or "")
                    ),
                    "recall_scope": recall_scope,
                    "recall_provenance": str(
                        record.get("recall_provenance") or "local"
                    ),
                    "via_context_link_id": str(
                        record.get("via_context_link_id") or ""
                    ),
                    "via_relation_type": str(
                        record.get("via_relation_type") or ""
                    ),
                    "via_direction": str(record.get("via_direction") or ""),
                }
                for record in records
            ),
            key=lambda record: (
                0 if record["context_id"] == context else 1,
                record["context_id"],
                record["via_context_link_id"],
            ),
        )
        if not normalized_records:
            raise RuntimeError("retrieval scope resolved no namespaces")
        if len(normalized_records) > 64:
            raise RuntimeError(
                "retrieval scope exceeds the 64-namespace snapshot ceiling"
            )
        context_ids = [record["context_id"] for record in normalized_records]
        if len(context_ids) != len(set(context_ids)):
            raise RuntimeError("retrieval scope contains duplicate namespaces")
        revision = self._retrieval_filter_digest(
            {
                "schema": "synapse-s2.retrieval-scope-binding.v2",
                "origin_context_id": context,
                "recall_scope": recall_scope,
                "include_global": bool(include_global),
                "records": normalized_records,
            }
        )
        return {
            "records": normalized_records,
            "context_ids": context_ids,
            "revision": revision,
        }

    @staticmethod
    def _retrieval_page_metadata(
        *,
        surface: str,
        response_mode: str,
        snapshot_revision: str,
        filters: dict[str, Any],
        ordering: str,
        total: dict[str, int],
        returned: dict[str, int],
        has_more: bool,
        next_cursor: str | None,
        expires_at: int | None,
        origin_node: str,
    ) -> dict[str, Any]:
        return {
            "schema": RETRIEVAL_PAGE_SCHEMA,
            "surface": surface,
            "response_mode": response_mode,
            "snapshot_revision": snapshot_revision,
            "filters_sha256": SpikingAttentionBackend._retrieval_filter_digest(
                filters
            ),
            "ordering": ordering,
            "total": {key: int(value) for key, value in total.items()},
            "returned": {key: int(value) for key, value in returned.items()},
            "has_more": bool(has_more),
            "next_cursor": next_cursor,
            "expires_at": int(expires_at or 0),
            "origin_node": origin_node,
        }

    @staticmethod
    def _graph_cursor_position_from_store(
        *,
        entry_position: dict[str, Any],
        relationship_position: dict[str, Any],
    ) -> dict[str, Any]:
        entry_done = entry_position.get("done") is True
        relationship_done = relationship_position.get("done") is True
        return {
            "entry_updated_at": (
                None if entry_done else float(entry_position["updated_at"])
            ),
            "entry_memory_id": (
                "" if entry_done else str(entry_position["memory_id"])
            ),
            "relationship_updated_at": (
                None
                if relationship_done
                else float(relationship_position["updated_at"])
            ),
            "relationship_id": (
                "" if relationship_done else str(relationship_position["relationship_id"])
            ),
        }

    @staticmethod
    def _graph_cursor_position_to_store(
        position: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        entry_updated_at = position.get("entry_updated_at")
        entry_memory_id = position.get("entry_memory_id")
        relationship_updated_at = position.get("relationship_updated_at")
        relationship_id = position.get("relationship_id")
        if (entry_updated_at is None) != (entry_memory_id == ""):
            raise ValueError("graph cursor entry position is invalid")
        if (relationship_updated_at is None) != (relationship_id == ""):
            raise ValueError("graph cursor relationship position is invalid")
        entry_position = (
            {"done": True}
            if entry_updated_at is None
            else {
                "updated_at": float(entry_updated_at),
                "memory_id": str(entry_memory_id),
            }
        )
        relationship_position = (
            {"done": True}
            if relationship_updated_at is None
            else {
                "updated_at": float(relationship_updated_at),
                "relationship_id": str(relationship_id),
            }
        )
        return entry_position, relationship_position

    def list_memory(
        self,
        *,
        context_id: str = "default",
        limit: int = 50,
        include_global: bool = True,
        include_vectors: bool = False,
        recall_scope: str = "local",
        cursor: str = "",
        response_mode: str = "legacy",
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        normalized_scope = sanitize_recall_scope(recall_scope)
        mode = self._retrieval_response_mode(response_mode)
        continuation = str(cursor or "").strip()
        if mode == "legacy":
            if continuation:
                raise ValueError("legacy memory listing does not support cursors")
            return self._list_memory_legacy(
                context=context,
                limit=limit,
                include_global=include_global,
                include_vectors=include_vectors,
                recall_scope=normalized_scope,
            )

        if type(include_global) is not bool or type(include_vectors) is not bool:
            raise ValueError("include_global and include_vectors must be booleans")
        if type(limit) is not int or limit < 1 or limit > 500:
            raise ValueError("limit must be an integer between 1 and 500")
        bounded_limit = limit
        scope_binding = self._retrieval_scope_binding(
            context=context,
            recall_scope=normalized_scope,
            include_global=include_global,
        )
        filters = {
            "include_global": include_global,
            "include_vectors": include_vectors,
            "scope_revision": scope_binding["revision"],
        }
        ordering = canonical_ordering(
            (
                {"field": "updated_at", "direction": "desc"},
                {"field": "memory_id", "direction": "desc"},
            ),
            unique_tie_breaker="memory_id",
        )
        position = None
        expected_revision = None
        codec = self._get_retrieval_cursor_codec()
        if continuation:
            decoded = codec.decode(
                continuation,
                expected_surface="memory-list",
                expected_response_mode=mode,
                expected_context_id=context,
                expected_recall_scope=normalized_scope,
                expected_filters=filters,
                expected_ordering=ordering,
                expected_snapshot_revision=None,
            )
            position = decoded.position
            expected_revision = str(decoded.snapshot_revision)

        try:
            page = self.memory_store.retrieval_memory_page(
                context_ids=scope_binding["context_ids"],
                limit=bounded_limit,
                position=position,
                expected_revision=expected_revision,
            )
        except RetrievalSnapshotStaleError as exc:
            if continuation:
                raise RetrievalCursorSnapshotMismatchError() from exc
            raise
        scope_after = self._retrieval_scope_binding(
            context=context,
            recall_scope=normalized_scope,
            include_global=include_global,
        )
        if scope_after["revision"] != scope_binding["revision"]:
            raise RetrievalSnapshotStaleError(
                expected_revision=scope_binding["revision"],
                actual_revision=scope_after["revision"],
            )

        record_by_context = {
            str(record["context_id"]): record for record in scope_binding["records"]
        }
        rendered_entries: list[dict[str, Any]] = []
        for entry in page["entries"]:
            annotated = dict(entry)
            annotated.update(record_by_context[str(entry["context_id"])])
            rendered_entries.append(
                self._render_memory_entry(
                    annotated,
                    include_vectors=include_vectors,
                )
            )

        next_cursor = None
        expires_at = None
        if page["has_more"]:
            next_cursor = codec.encode(
                surface="memory-list",
                response_mode=mode,
                context_id=context,
                recall_scope=normalized_scope,
                filters=filters,
                ordering=ordering,
                position=page["next_position"],
                snapshot_revision=page["snapshot_revision"],
                ttl_seconds=DEFAULT_RETRIEVAL_CURSOR_TTL_SECONDS,
            )
            expires_at = codec.decode(
                next_cursor,
                expected_surface="memory-list",
                expected_response_mode=mode,
                expected_context_id=context,
                expected_recall_scope=normalized_scope,
                expected_filters=filters,
                expected_ordering=ordering,
                expected_snapshot_revision=page["snapshot_revision"],
            ).expires_at
        return {
            "context_id": context,
            "memory_db_path": str(self.memory_store.db_path),
            "entry_count": len(rendered_entries),
            "entries": rendered_entries,
            "include_vectors": include_vectors,
            "recall_scope": normalized_scope,
            "recall_contexts": scope_binding["records"],
            "one_hop_only": normalized_scope == "connected",
            "_retrieval_page": self._retrieval_page_metadata(
                surface="memory-list",
                response_mode=mode,
                snapshot_revision=page["snapshot_revision"],
                filters=filters,
                ordering="updated_at-desc,memory_id-desc",
                total={"entries": page["total"]},
                returned={"entries": page["returned"]},
                has_more=page["has_more"],
                next_cursor=next_cursor,
                expires_at=expires_at,
                origin_node=codec.origin_node,
            ),
        }

    def _list_memory_legacy(
        self,
        *,
        context: str,
        limit: int,
        include_global: bool,
        include_vectors: bool,
        recall_scope: str,
    ) -> dict[str, Any]:
        bounded_limit = min(max(int(limit), 1), 10_000)
        scope_records = self.bridge_governance.resolve_recall_contexts(
            context_id=context,
            scope=recall_scope,
        )
        if not include_global:
            scope_records = [
                record
                for record in scope_records
                if str(record.get("context_id") or "") != "global"
            ]
        entries: list[dict[str, Any]] = []
        for record in scope_records:
            context_entries = self.memory_store.list_entries(
                context_id=str(record["context_id"]),
                limit=bounded_limit,
                include_global=False,
            )
            for entry in context_entries:
                annotated = dict(entry)
                annotated.update(record)
                entries.append(annotated)
        entries.sort(
            key=lambda entry: (
                float(entry.get("updated_at", 0.0)),
                float(entry.get("created_at", 0.0)),
            ),
            reverse=True,
        )
        entries = entries[:bounded_limit]
        rendered_entries = [
            self._render_memory_entry(entry, include_vectors=include_vectors)
            for entry in entries
        ]
        return {
            "context_id": context,
            "memory_db_path": str(self.memory_store.db_path),
            "entry_count": len(rendered_entries),
            "entries": rendered_entries,
            "include_vectors": bool(include_vectors),
            "recall_scope": recall_scope,
            "recall_contexts": scope_records,
            "one_hop_only": recall_scope == "connected",
        }

    def publish_context_event(
        self,
        *,
        context_id: str = "default",
        source_surface: str,
        event_type: str,
        summary: str,
        payload: dict[str, Any] | None = None,
        agent_targets: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        targets = list(agent_targets or DEFAULT_AGENT_TARGETS)
        safe_summary, _summary_redactions = redact_capture_text(str(summary or ""))
        safe_payload, payload_redactions = redact_sensitive_value(payload or {})
        if payload_redactions:
            if isinstance(safe_payload, dict):
                safe_payload = {
                    **safe_payload,
                    "context_bus_redaction_count": int(
                        payload_redactions
                        + int(safe_payload.get("context_bus_redaction_count", 0) or 0)
                    ),
                    "raw_payload_stored": False,
                }
        try:
            event = self.memory_store.publish_context_event(
                context_id=context,
                source_surface=str(source_surface or "unknown"),
                event_type=str(event_type or "context-update"),
                summary=safe_summary,
                payload=self._json_safe_metadata(safe_payload if isinstance(safe_payload, dict) else {}),
                agent_targets=targets,
            )
            self._mark_activity()
            return self._decorate_context_event(event)
        except Exception:
            LOGGER.exception(
                "context event publish failed for context_id=%s event_type=%s",
                context,
                event_type,
            )
            raise

    def list_context_events(
        self,
        *,
        context_id: str = "default",
        since_event_id: int = 0,
        before_event_id: int | None = None,
        agent_id: str | None = None,
        order: str = "asc",
        limit: int = 100,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        bounded_limit = min(max(int(limit), 1), 500)
        agent = sanitize_agent_id(agent_id) if agent_id is not None else None
        normalized_order = str(order or "asc").strip().lower()
        if normalized_order not in {"asc", "desc"}:
            raise ValueError("context event order must be asc or desc")
        bounded_before_event_id = (
            None
            if before_event_id is None
            else max(1, int(before_event_id))
        )
        rows = self.memory_store.list_context_events(
            context_id=context,
            since_event_id=max(0, int(since_event_id)),
            before_event_id=bounded_before_event_id,
            agent_id=agent,
            consumer_groups=(context_consumer_groups(agent) if agent else None),
            order=normalized_order,
            limit=bounded_limit + 1,
        )
        has_more = len(rows) > bounded_limit
        events = rows[:bounded_limit]
        return {
            "protocol_version": CONTEXT_BUS_PROTOCOL_VERSION,
            "context_id": context,
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "observation_only": True,
            "inspection_scope": "agent-eligible" if agent is not None else "admin-ledger",
            "agent_id": agent,
            "since_event_id": max(0, int(since_event_id)),
            "order": normalized_order,
            "event_count": len(events),
            "has_more": has_more,
            "next_event_id": (
                int(events[-1]["event_id"])
                if events and normalized_order == "asc"
                else max(0, int(since_event_id))
            ),
            "before_event_id": bounded_before_event_id,
            "next_before_event_id": (
                int(events[-1]["event_id"])
                if events and normalized_order == "desc"
                else None
            ),
            "events": [self._decorate_context_event(event) for event in events],
            "memory_db_path": str(self.memory_store.db_path),
        }

    def lease_context_events(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        consumer_instance_id: str = "",
        limit: int = 20,
        lease_seconds: float = 60.0,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        instance = sanitize_agent_id(
            consumer_instance_id or self.delivery_instance_id
        )
        leased = self.memory_store.lease_context_events(
            context_id=context,
            agent_id=agent,
            consumer_instance_id=instance,
            consumer_groups=context_consumer_groups(agent),
            limit=min(max(int(limit), 1), 500),
            lease_seconds=lease_seconds,
        )
        try:
            leased["events"] = [
                self._decorate_context_event(event)
                for event in leased.get("events", [])
            ]
            for delivery in leased.get("deliveries", []):
                if isinstance(delivery, dict) and isinstance(delivery.get("event"), dict):
                    delivery["event"] = self._decorate_context_event(delivery["event"])
        except Exception:
            receipt_ids = [
                str(delivery.get("receipt_id") or "")
                for delivery in leased.get("deliveries", [])
                if isinstance(delivery, dict) and str(delivery.get("receipt_id") or "")
            ]
            if receipt_ids:
                try:
                    self.memory_store.release_context_deliveries(
                        context_id=context,
                        agent_id=agent,
                        consumer_instance_id=instance,
                        receipt_ids=receipt_ids,
                    )
                except Exception as release_exc:
                    LOGGER.exception(
                        "context lease decoration failed and receipts could not be released"
                    )
                    raise RuntimeError(
                        "context lease construction failed and receipts could not be released; "
                        "wait for lease expiry before retrying"
                    ) from release_exc
            raise
        self._mark_activity()
        return leased

    def ack_context_events(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        acknowledgements: list[dict[str, Any]] | None = None,
        receipt_id: str = "",
        last_event_id: int | None = None,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        try:
            requested = list(acknowledgements or [])
            if str(receipt_id or "").strip():
                requested.append({"receipt_id": str(receipt_id).strip()})
            if requested:
                result = self.memory_store.acknowledge_context_deliveries(
                    context_id=context,
                    agent_id=agent,
                    acknowledgements=requested,
                )
                result["cursor"] = self._decorate_context_cursor(result["cursor"])
            else:
                result = self.memory_store.ack_context_events(
                    context_id=context,
                    agent_id=agent,
                    last_event_id=max(0, int(last_event_id or 0)),
                )
                result = self._decorate_context_cursor(result)
            self._mark_activity()
            return result
        except ValueError:
            LOGGER.warning(
                "context event ack refused for context_id=%s agent_id=%s",
                context,
                agent,
            )
            raise
        except Exception:
            LOGGER.exception(
                "context event ack failed for context_id=%s agent_id=%s",
                context,
                agent,
            )
            raise

    def release_context_events(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        consumer_instance_id: str = "",
        receipt_ids: list[str] | tuple[str, ...],
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        instance = sanitize_agent_id(
            consumer_instance_id or self.delivery_instance_id
        )
        result = self.memory_store.release_context_deliveries(
            context_id=context,
            agent_id=agent,
            consumer_instance_id=instance,
            receipt_ids=receipt_ids,
        )
        self._mark_activity()
        return result

    def dead_letter_context_delivery(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        delivery_id: str,
        reason: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id).casefold()
        result = self.memory_store.dead_letter_context_delivery(
            context_id=context,
            agent_id=agent,
            delivery_id=str(delivery_id),
            reason=reason,
            confirm=bool(confirm),
        )
        self._mark_activity()
        return result

    def list_context_cursors(
        self,
        *,
        context_id: str = "default",
        limit: int = 100,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        bounded_limit = min(max(int(limit), 1), 500)
        cursors = self.memory_store.list_context_cursors(
            context_id=context,
            limit=bounded_limit,
        )
        latest_event_id = int(self.memory_store.stats(context_id=context)[
            "context_bus_latest_event_id"
        ])
        return {
            "context_id": context,
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "latest_event_id": latest_event_id,
            "cursor_count": len(cursors),
            "cursors": [self._decorate_context_cursor(cursor) for cursor in cursors],
            "memory_db_path": str(self.memory_store.db_path),
        }

    def context_delivery_health(
        self,
        *,
        context_id: str | None = None,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id) if context_id is not None else None
        return self.memory_store.context_delivery_health(context_id=context)

    def enter_spiking_cortex(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        task: str,
        mode: str = "strict",
        recall_mode: str = "neural",
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        task_text, task_redactions = redact_capture_text(str(task or "").strip())
        if not task_text:
            raise ValueError("task must not be empty")
        clean_mode = str(mode or "strict").strip().lower()
        if clean_mode not in CORTEX_MODES:
            clean_mode = "strict"
        normalized_recall_mode = self._normalize_agent_recall_mode(recall_mode)
        if self.control_plane_only and normalized_recall_mode == "neural":
            raise BackendUnavailable(
                "neural recall is unavailable in the control-plane backend"
            )
        now = time.time()
        seed = f"{context}\x1f{agent}\x1f{task_text}\x1f{now:.6f}".encode("utf-8")
        session_id = "ctx_" + hashlib.sha256(seed).hexdigest()[:18]
        session = self._normalize_cortex_session(
            {
                "session_id": session_id,
                "context_id": context,
                "agent_id": agent,
                "task": task_text,
                "mode": clean_mode,
                "status": "active",
                "started_at": now,
                "updated_at": now,
                "tick_count": 0,
                "last_decision": "entered",
            }
        )
        self.cortex_sessions[session_id] = session
        self._persist_runtime_state()
        if normalized_recall_mode == "neural":
            _retrieval, recall_items = self._retrieval_v2_briefing_recall(
                prompt_text=task_text,
                context=context,
            )
            recall_result = " / ".join(recall_items)
        elif normalized_recall_mode == "surface":
            recall_items = self._surface_bootstrap_recall(
                context=context,
                prompt_text=task_text,
            )
            recall_result = " / ".join(recall_items)
        else:
            recall_result = ""
            recall_items = []
        policy = self._cortex_policy(clean_mode)
        state = self.get_cortex_state(context_id=context, agent_id=agent)
        deployment = self.publish_context_event(
            context_id=context,
            source_surface="cortex-governor",
            event_type="cortex-entered",
            summary=f"{agent} entered Cortex Governor for {self._compact_text(task_text, 120)}",
            payload={
                "session_id": session_id,
                "agent_id": agent,
                "task": task_text,
                "mode": clean_mode,
                "governance_contract": policy["contract"],
                "recall_items": recall_items[:8],
                "recall_mode": normalized_recall_mode,
            },
        )
        return {
            "action": "enter-spiking-cortex",
            "context_id": context,
            "agent_id": agent,
            "session_id": session_id,
            "task": task_text,
            "input_redaction_count": int(task_redactions),
            "raw_input_stored": False,
            "mode": clean_mode,
            "governance_contract": policy["contract"],
            "policy": policy,
            "recall_result": recall_result,
            "recall_items": recall_items,
            "recall_mode": normalized_recall_mode,
            "recall_provenance": (
                "retrieval-v2-hybrid-read-only"
                if normalized_recall_mode == "neural"
                else "sqlite-surface-bootstrap"
                if normalized_recall_mode == "surface"
                else "disabled"
            ),
            "cortex_state": state,
            "agent_deployment": deployment,
        }

    def attach_client_cortex_session(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        session_id: str,
        client_bridge_session_id: str,
        owner_pid: int,
        owner_ppid: int = 0,
        owner_started_at: float | None = None,
    ) -> dict[str, Any]:
        """Attach explicit process ownership to an active MCP Cortex session."""
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        clean_session_id = reject_sensitive_identifier(
            session_id,
            field="cortex session_id",
        ).strip()
        clean_bridge_session_id = reject_sensitive_identifier(
            client_bridge_session_id,
            field="client bridge session_id",
        ).strip()
        if not clean_bridge_session_id:
            raise ValueError("client_bridge_session_id is required")
        clean_owner_pid = int(owner_pid)
        clean_owner_ppid = int(owner_ppid)
        if clean_owner_pid <= 0:
            raise ValueError("owner_pid must be positive")
        if clean_owner_ppid < 0:
            raise ValueError("owner_ppid must be non-negative")
        started_at = (
            time.time()
            if owner_started_at is None
            else float(owner_started_at)
        )
        if not math.isfinite(started_at) or started_at <= 0.0:
            raise ValueError("owner_started_at must be a positive finite timestamp")

        session = self._active_cortex_session(
            context=context,
            agent_id=agent,
            session_id=clean_session_id,
        )
        session.update(
            {
                "client_bridge_session_id": clean_bridge_session_id,
                "lease_kind": "mcp-client",
                "owner_pid": clean_owner_pid,
                "owner_ppid": clean_owner_ppid,
                "owner_started_at": started_at,
                "updated_at": time.time(),
            }
        )
        self.cortex_sessions[clean_session_id] = self._normalize_cortex_session(
            session
        )
        self._persist_runtime_state()
        return dict(self.cortex_sessions[clean_session_id])

    def finish_client_cortex_session(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        session_id: str,
        client_bridge_session_id: str,
        reason: str = "client-session-finish",
        finished_at: float | None = None,
    ) -> dict[str, Any]:
        """Mark an MCP-owned Cortex session finished without publishing twice."""
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        clean_session_id = reject_sensitive_identifier(
            session_id,
            field="cortex session_id",
        ).strip()
        if not clean_session_id:
            raise ValueError("session_id is required")
        session = self.cortex_sessions.get(clean_session_id)
        if not isinstance(session, dict):
            raise ValueError(f"cortex session not found: {clean_session_id}")
        if session.get("context_id") != context:
            raise ValueError("cortex session context mismatch")
        if session.get("agent_id") != agent:
            raise ValueError("cortex session agent mismatch")
        clean_bridge_session_id = reject_sensitive_identifier(
            client_bridge_session_id,
            field="client bridge session_id",
        ).strip()
        if not clean_bridge_session_id:
            raise ValueError("client_bridge_session_id is required")
        if session.get("lease_kind") != "mcp-client":
            raise ValueError("cortex session is not owned by an MCP client")
        if session.get("client_bridge_session_id") != clean_bridge_session_id:
            raise ValueError("cortex session client bridge mismatch")
        clean_reason, _ = redact_capture_text(
            str(reason or "client-session-finish").strip()
        )
        ended_at = time.time() if finished_at is None else float(finished_at)
        if not math.isfinite(ended_at) or ended_at <= 0.0:
            raise ValueError("finished_at must be a positive finite timestamp")
        finished_session = dict(session)
        finished_session.update(
            {
                "status": "finished",
                "finished_at": ended_at,
                "finish_reason": clean_reason[:240] or "client-session-finish",
                "updated_at": ended_at,
            }
        )
        self.cortex_sessions[clean_session_id] = self._normalize_cortex_session(
            finished_session
        )
        self._persist_runtime_state()
        return dict(self.cortex_sessions[clean_session_id])

    def cortex_tick(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        session_id: str,
        observation: str = "",
        proposed_action: str = "",
        intended_files: Any = None,
        intended_tools: Any = None,
        mutation_intent: bool = False,
        confidence: float = 0.5,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        clean_session_id = reject_sensitive_identifier(
            session_id,
            field="cortex session_id",
        ).strip()
        session = self._active_cortex_session(
            context=context,
            agent_id=agent,
            session_id=clean_session_id,
        )
        observation_text, observation_redactions = redact_capture_text(
            str(observation or "").strip()
        )
        proposed_text, proposed_redactions = redact_capture_text(
            str(proposed_action or "").strip()
        )
        scoped_files = self._normalize_cortex_intent_list(intended_files)
        scoped_tools = self._normalize_cortex_intent_list(intended_tools)
        bounded_confidence = min(max(float(confidence), 0.0), 1.0)
        state = self.get_cortex_state(context_id=context, agent_id=agent)
        recall_prompt = " ".join(part for part in (observation_text, proposed_text) if part)
        if recall_prompt:
            _retrieval, recall_items = self._retrieval_v2_briefing_recall(
                prompt_text=recall_prompt,
                context=context,
            )
            recall_result = " / ".join(recall_items)
        else:
            recall_result = ""
            recall_items = []
        warnings = self._cortex_warnings(
            mutation_intent=bool(mutation_intent),
            confidence=bounded_confidence,
            observation=observation_text,
            proposed_action=proposed_text,
            intended_files=scoped_files,
            intended_tools=scoped_tools,
            cortex_state=state,
        )
        decision = self._cortex_decision(warnings=warnings, confidence=bounded_confidence)
        capture_recommendation = self._cortex_capture_recommendation(
            observation_text,
            proposed_text,
            decision,
            intended_files=scoped_files,
            intended_tools=scoped_tools,
        )
        now = time.time()
        session.update(
            {
                "updated_at": now,
                "tick_count": int(session.get("tick_count", 0)) + 1,
                "last_decision": decision,
                "last_confidence": bounded_confidence,
                "last_observation": observation_text[:2000],
                "last_proposed_action": proposed_text[:2000],
                "last_warnings": warnings,
                "last_intended_files": scoped_files,
                "last_intended_tools": scoped_tools,
                "last_recall_items": recall_items[:12],
                "last_capture_recommendation": capture_recommendation,
            }
        )
        session = self._normalize_cortex_session(session)
        self.cortex_sessions[clean_session_id] = session
        self._persist_runtime_state()
        deployment = self.publish_context_event(
            context_id=context,
            source_surface="cortex-governor",
            event_type="cortex-tick",
            summary=f"{agent} cortex tick: {decision}",
            payload={
                "session_id": clean_session_id,
                "agent_id": agent,
                "decision": decision,
                "confidence": bounded_confidence,
                "mutation_intent": bool(mutation_intent),
                "intended_files": scoped_files,
                "intended_tools": scoped_tools,
                "warning_codes": [warning["code"] for warning in warnings],
            },
        )
        return {
            "action": "cortex-tick",
            "context_id": context,
            "agent_id": agent,
            "session_id": clean_session_id,
            "decision": decision,
            "confidence": bounded_confidence,
            "input_redaction_count": int(
                observation_redactions + proposed_redactions
            ),
            "raw_input_stored": False,
            "intended_files": scoped_files,
            "intended_tools": scoped_tools,
            "warnings": warnings,
            "recalled_constraints": state["constraints"][:8],
            "recalled_risks": state["risks"][:8],
            "recall_result": recall_result,
            "recall_items": recall_items,
            "capture_recommendation": capture_recommendation,
            "cortex_state": self.get_cortex_state(context_id=context, agent_id=agent),
            "agent_deployment": deployment,
        }

    def close_spiking_cortex(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        session_id: str,
        reason: str = "operator-complete",
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        clean_session_id = reject_sensitive_identifier(
            session_id,
            field="cortex session_id",
        ).strip()
        clean_reason, _ = redact_capture_text(
            str(reason or "operator-complete").strip()
        )
        clean_reason = clean_reason[:240] or "operator-complete"
        session = self._active_cortex_session(
            context=context,
            agent_id=agent,
            session_id=clean_session_id,
        )
        now = time.time()
        closed_session = dict(session)
        closed_session.update(
            {
                "status": "closed",
                "finished_at": now,
                "updated_at": now,
                "finish_reason": clean_reason,
            }
        )
        self.cortex_sessions[clean_session_id] = self._normalize_cortex_session(closed_session)
        self._persist_runtime_state()
        deployment = self.publish_context_event(
            context_id=context,
            source_surface="cortex-governor",
            event_type="cortex-closed",
            summary=f"{agent} closed Cortex Governor session {clean_session_id}",
            payload={
                "session_id": clean_session_id,
                "agent_id": agent,
                "reason": clean_reason,
                "task": str(session.get("task", "")),
                "tick_count": int(session.get("tick_count", 0) or 0),
                "last_decision": str(session.get("last_decision", "")),
            },
        )
        return {
            "action": "close-spiking-cortex",
            "context_id": context,
            "agent_id": agent,
            "session_id": clean_session_id,
            "status": "closed",
            "reason": clean_reason,
            "closed_session": self._normalize_cortex_session(closed_session),
            "cortex_state": self.get_cortex_state(context_id=context, agent_id=agent),
            "agent_deployment": deployment,
        }

    def commit_cortical_trace(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        session_id: str = "",
        trace_type: str = "",
        truth_posture: str = "observed",
        text: str,
        evidence: dict[str, Any] | None = None,
        confidence: float | None = None,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        clean_text, text_redactions = redact_capture_text(str(text or "").strip())
        if not clean_text:
            raise ValueError("text must not be empty")
        clean_session_id = reject_sensitive_identifier(
            session_id or "direct-cortex-commit",
            field="cortex session_id",
        ).strip() or "direct-cortex-commit"
        clean_trace_type = self._normalize_cortex_trace_type(trace_type, clean_text)
        clean_truth_posture = self._normalize_truth_posture(truth_posture)
        safe_evidence = self._json_safe_metadata(evidence or {})
        if (
            clean_truth_posture == "test-validated"
            and not self._has_concrete_validation_evidence(safe_evidence)
        ):
            raise ValueError(
                "test-validated truth posture requires concrete validation evidence"
            )
        scored_confidence = self._score_cortex_confidence(
            trace_type=clean_trace_type,
            truth_posture=clean_truth_posture,
            evidence=safe_evidence,
            confidence=confidence,
            text=clean_text,
        )
        session = self.cortex_sessions.get(clean_session_id, {})
        stamp = time.strftime("%Y%m%d-%H%M%S")
        digest = hashlib.sha256(
            f"{context}\x1f{agent}\x1f{clean_session_id}\x1f{clean_trace_type}\x1f{clean_text}".encode("utf-8")
        ).hexdigest()[:8]
        tag = sanitize_tag(f"cortex-{agent}-{clean_trace_type}-{stamp}-{digest}")
        metadata = self._json_safe_metadata(
            {
                "source": "cortex-governor",
                "cortex_governor": True,
                "cortex_session_id": clean_session_id,
                "agent_id": agent,
                "trace_type": clean_trace_type,
                "truth_posture": clean_truth_posture,
                "confidence": scored_confidence,
                "evidence": safe_evidence,
                "redaction_count": int(text_redactions),
                "raw_text_stored": False,
                "governance_mode": session.get("mode", "direct"),
                "task": session.get("task", ""),
            }
        )
        registration = self.register_text_trace(
            tag=tag,
            context_id=context,
            text=clean_text,
            metadata=metadata,
        )
        if clean_session_id in self.cortex_sessions:
            updated_session = dict(self.cortex_sessions[clean_session_id])
            updated_session.update(
                {
                    "updated_at": time.time(),
                    "last_capture_recommendation": {
                        "recommended": False,
                        "trace_type": clean_trace_type,
                        "truth_posture": clean_truth_posture,
                        "reason": "Committed cortical trace resolved the pending capture recommendation.",
                        "memory_id": registration["memory_id"],
                        "tag": registration["tag"],
                    },
                }
            )
            self.cortex_sessions[clean_session_id] = self._normalize_cortex_session(
                updated_session
            )
            self._persist_runtime_state()
        deployment = self.publish_context_event(
            context_id=context,
            source_surface="cortex-governor",
            event_type="cortex-trace-committed",
            summary=f"{agent} committed {clean_trace_type} trace at {scored_confidence:.2f} confidence",
            payload={
                "session_id": clean_session_id,
                "agent_id": agent,
                "trace_type": clean_trace_type,
                "truth_posture": clean_truth_posture,
                "confidence": scored_confidence,
                "memory_id": registration["memory_id"],
                "tag": registration["tag"],
                "evidence": safe_evidence,
            },
        )
        return {
            "action": "commit-cortical-trace",
            "context_id": context,
            "agent_id": agent,
            "session_id": clean_session_id,
            "trace_type": clean_trace_type,
            "truth_posture": clean_truth_posture,
            "confidence": scored_confidence,
            "memory_id": registration["memory_id"],
            "tag": registration["tag"],
            "metadata": metadata,
            "agent_deployment": deployment,
        }

    def get_cortex_state(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "",
        limit: int = 50,
        cursor: str = "",
        response_mode: str = "legacy",
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id) if agent_id else ""
        mode = self._retrieval_response_mode(response_mode)
        continuation = str(cursor or "").strip()
        if mode != "legacy":
            return self._get_cortex_state_retrieval(
                context=context,
                agent=agent,
                limit=limit,
                cursor=continuation,
                response_mode=mode,
            )
        if continuation:
            raise ValueError("legacy Cortex state does not support cursors")
        visible_limit = max(1, min(int(limit), 500))
        scan_limit = max(100, visible_limit * 5)
        scan_limit = min(scan_limit, 500)
        active_sessions = [
            dict(session)
            for session in self.cortex_sessions.values()
            if session.get("context_id") == context
            and session.get("status") == "active"
            and (not agent or session.get("agent_id") == agent)
        ]
        active_sessions.sort(key=lambda item: float(item.get("updated_at", 0.0)), reverse=True)
        entries = self.memory_store.list_entries(
            context_id=context,
            include_global=True,
            limit=scan_limit,
        )
        cortical_entries = [
            self._summarize_cortex_memory(entry)
            for entry in entries
            if isinstance(entry.get("metadata"), dict)
            and entry["metadata"].get("cortex_governor") is True
        ]
        typed_counts: dict[str, int] = {}
        for entry in cortical_entries:
            trace_type = str(entry.get("trace_type") or "unknown")
            typed_counts[trace_type] = typed_counts.get(trace_type, 0) + 1
        high_confidence = [
            entry for entry in cortical_entries if float(entry.get("confidence", 0.0)) >= 0.8
        ][:10]
        constraints = [
            entry for entry in cortical_entries if entry.get("trace_type") == "constraint"
        ][:10]
        risks = [
            entry for entry in cortical_entries if entry.get("trace_type") in {"risk", "blocker", "assumption"}
        ][:10]
        decisions = [
            entry for entry in cortical_entries if entry.get("trace_type") == "decision"
        ][:10]
        assumptions = [
            entry
            for entry in cortical_entries
            if entry.get("trace_type") == "assumption"
            or entry.get("truth_posture") == "inferred"
            or float(entry.get("confidence", 0.0) or 0.0) < 0.6
        ][:10]
        stale_or_uncertain = [
            entry
            for entry in cortical_entries
            if entry.get("truth_posture") == "stale"
            or entry.get("trace_type") in {"assumption", "blocker"}
            or any(
                token in str(entry.get("excerpt", "")).lower()
                for token in ("assume", "maybe", "might", "uncertain")
            )
        ][:10]
        goals = self._goal_ledger_from_cortical_summaries(cortical_entries, limit=10)
        active_goal = (
            str(active_sessions[0].get("task", ""))
            if active_sessions
            else next(
                (
                    str(goal.get("title", ""))
                    for goal in goals
                    if goal.get("state") not in {"done", "stale"}
                ),
                "",
            )
        )
        contradictions = self._cortex_contradictions(cortical_entries)[:10]
        capture_queue = self._cortex_capture_queue(active_sessions)[:10]
        suggested_next_move = self._cortex_suggested_next_move(
            active_sessions=active_sessions,
            assumptions=assumptions,
            stale_or_uncertain=stale_or_uncertain,
            contradictions=contradictions,
            risks=risks,
            capture_queue=capture_queue,
        )
        return {
            "action": "cortex-state",
            "context_id": context,
            "agent_id": agent,
            "active_goal": active_goal,
            "current_goal": active_goal,
            "active_session_count": len(active_sessions),
            "active_sessions": active_sessions[:10],
            "goals": goals,
            "goal_count": len(goals),
            "typed_memory_counts": dict(sorted(typed_counts.items())),
            "high_confidence_truths": high_confidence,
            "constraints": constraints,
            "governing_constraints": constraints,
            "risks": risks,
            "decisions": decisions,
            "recent_decisions": decisions,
            "unverified_assumptions": assumptions,
            "stale_or_uncertain_memories": stale_or_uncertain,
            "contradictions": contradictions,
            "suggested_next_move": suggested_next_move,
            "capture_queue": capture_queue,
            "working_memory": cortical_entries[:visible_limit],
            "policy": self._cortex_policy(
                str(active_sessions[0].get("mode", "strict")) if active_sessions else "strict"
            ),
            "memory_db_path": str(self.memory_store.db_path),
        }

    def _get_cortex_state_retrieval(
        self,
        *,
        context: str,
        agent: str,
        limit: int,
        cursor: str,
        response_mode: str,
    ) -> dict[str, Any]:
        if type(limit) is not int or limit < 1 or limit > 500:
            raise ValueError("limit must be an integer between 1 and 500")
        bounded_limit = limit
        include_global = True
        base_filters = {
            "agent_id": agent,
            "include_global": include_global,
            "memory_filter": "metadata.cortex_governor=true",
        }
        ordering = canonical_ordering(
            (
                {"field": "updated_at", "direction": "desc"},
                {"field": "memory_id", "direction": "desc"},
            ),
            unique_tie_breaker="memory_id",
        )
        position = None
        expected_revision = None
        codec = self._get_retrieval_cursor_codec()
        active_sessions, runtime_revision = self._cortex_retrieval_runtime_snapshot(
            context=context,
            agent=agent,
        )
        decoded = None
        if cursor:
            decoded = codec.decode(
                cursor,
                expected_surface="cortex-state",
                expected_response_mode=response_mode,
                expected_context_id=context,
                expected_recall_scope="local",
                expected_filters=None,
                expected_ordering=ordering,
                expected_snapshot_revision=None,
            )
            decoded_filters = decoded.filters
            if (
                set(decoded_filters)
                != {
                    *base_filters,
                    "durable_snapshot_revision",
                    "runtime_snapshot_revision",
                }
                or any(
                    decoded_filters.get(key) != value
                    for key, value in base_filters.items()
                )
            ):
                raise RetrievalCursorFilterMismatchError()
            durable_revision = decoded_filters.get("durable_snapshot_revision")
            cursor_runtime_revision = decoded_filters.get(
                "runtime_snapshot_revision"
            )
            if (
                not isinstance(durable_revision, str)
                or re.fullmatch(r"[0-9a-f]{64}", durable_revision) is None
                or not isinstance(cursor_runtime_revision, str)
                or re.fullmatch(r"[0-9a-f]{64}", cursor_runtime_revision) is None
            ):
                raise RetrievalCursorFilterMismatchError()
            if not secrets.compare_digest(
                cursor_runtime_revision,
                runtime_revision,
            ):
                raise RetrievalCursorSnapshotMismatchError()
            position = decoded.position
            expected_revision = durable_revision
        try:
            page = self.memory_store.retrieval_cortex_page(
                context_id=context,
                include_global=include_global,
                limit=bounded_limit,
                position=position,
                expected_revision=expected_revision,
            )
        except RetrievalSnapshotStaleError as exc:
            if cursor:
                raise RetrievalCursorSnapshotMismatchError() from exc
            raise
        _active_sessions_after, runtime_revision_after = (
            self._cortex_retrieval_runtime_snapshot(
                context=context,
                agent=agent,
            )
        )
        if not secrets.compare_digest(runtime_revision, runtime_revision_after):
            raise RetrievalSnapshotStaleError(
                expected_revision=runtime_revision,
                actual_revision=runtime_revision_after,
            )
        snapshot_revision = self._cortex_retrieval_snapshot_revision(
            durable_revision=page["snapshot_revision"],
            runtime_revision=runtime_revision,
        )
        if decoded is not None and not secrets.compare_digest(
            str(decoded.snapshot_revision),
            snapshot_revision,
        ):
            raise RetrievalCursorSnapshotMismatchError()
        filters = {
            **base_filters,
            "durable_snapshot_revision": page["snapshot_revision"],
            "runtime_snapshot_revision": runtime_revision,
        }
        cortical_entries = [
            self._summarize_cortex_memory(entry) for entry in page["entries"]
        ]
        typed_counts: dict[str, int] = {}
        for entry in cortical_entries:
            trace_type = str(entry.get("trace_type") or "unknown")
            typed_counts[trace_type] = typed_counts.get(trace_type, 0) + 1
        high_confidence = [
            entry
            for entry in cortical_entries
            if float(entry.get("confidence", 0.0)) >= 0.8
        ][:10]
        constraints = [
            entry
            for entry in cortical_entries
            if entry.get("trace_type") == "constraint"
        ][:10]
        risks = [
            entry
            for entry in cortical_entries
            if entry.get("trace_type") in {"risk", "blocker", "assumption"}
        ][:10]
        decisions = [
            entry
            for entry in cortical_entries
            if entry.get("trace_type") == "decision"
        ][:10]
        assumptions = [
            entry
            for entry in cortical_entries
            if entry.get("trace_type") == "assumption"
            or entry.get("truth_posture") == "inferred"
            or float(entry.get("confidence", 0.0) or 0.0) < 0.6
        ][:10]
        stale_or_uncertain = [
            entry
            for entry in cortical_entries
            if entry.get("truth_posture") == "stale"
            or entry.get("trace_type") in {"assumption", "blocker"}
            or any(
                token in str(entry.get("excerpt", "")).lower()
                for token in ("assume", "maybe", "might", "uncertain")
            )
        ][:10]
        goals = self._goal_ledger_from_cortical_summaries(
            cortical_entries,
            limit=10,
        )
        active_goal = (
            str(active_sessions[0].get("task", ""))
            if active_sessions
            else next(
                (
                    str(goal.get("title", ""))
                    for goal in goals
                    if goal.get("state") not in {"done", "stale"}
                ),
                "",
            )
        )
        contradictions = self._cortex_contradictions(cortical_entries)[:10]
        capture_queue = self._cortex_capture_queue(active_sessions)[:10]
        suggested_next_move = self._cortex_suggested_next_move(
            active_sessions=active_sessions,
            assumptions=assumptions,
            stale_or_uncertain=stale_or_uncertain,
            contradictions=contradictions,
            risks=risks,
            capture_queue=capture_queue,
        )

        next_cursor = None
        expires_at = None
        if page["has_more"]:
            next_cursor = codec.encode(
                surface="cortex-state",
                response_mode=response_mode,
                context_id=context,
                recall_scope="local",
                filters=filters,
                ordering=ordering,
                position=page["next_position"],
                snapshot_revision=snapshot_revision,
                ttl_seconds=DEFAULT_RETRIEVAL_CURSOR_TTL_SECONDS,
            )
            expires_at = codec.decode(
                next_cursor,
                expected_surface="cortex-state",
                expected_response_mode=response_mode,
                expected_context_id=context,
                expected_recall_scope="local",
                expected_filters=filters,
                expected_ordering=ordering,
                expected_snapshot_revision=snapshot_revision,
            ).expires_at
        return {
            "action": "cortex-state",
            "context_id": context,
            "agent_id": agent,
            "active_goal": active_goal,
            "current_goal": active_goal,
            "active_session_count": len(active_sessions),
            "active_sessions": active_sessions[:10],
            "goals": goals,
            "goal_count": len(goals),
            "typed_memory_counts": dict(sorted(typed_counts.items())),
            "typed_memory_counts_scope": "returned-page",
            "high_confidence_truths": high_confidence,
            "constraints": constraints,
            "governing_constraints": constraints,
            "risks": risks,
            "decisions": decisions,
            "recent_decisions": decisions,
            "unverified_assumptions": assumptions,
            "stale_or_uncertain_memories": stale_or_uncertain,
            "contradictions": contradictions,
            "suggested_next_move": suggested_next_move,
            "capture_queue": capture_queue,
            "working_memory": cortical_entries,
            "policy": self._cortex_policy(
                str(active_sessions[0].get("mode", "strict"))
                if active_sessions
                else "strict"
            ),
            "memory_db_path": str(self.memory_store.db_path),
            "_retrieval_page": self._retrieval_page_metadata(
                surface="cortex-state",
                response_mode=response_mode,
                snapshot_revision=snapshot_revision,
                filters=filters,
                ordering="updated_at-desc,memory_id-desc",
                total={"working_memory": page["total"]},
                returned={"working_memory": page["returned"]},
                has_more=page["has_more"],
                next_cursor=next_cursor,
                expires_at=expires_at,
                origin_node=codec.origin_node,
            ),
        }

    def reap_orphaned_cortex_sessions(
        self,
        *,
        context_id: str = "",
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Persist orphaned client-session transitions as explicit maintenance."""

        context = sanitize_context_id(context_id) if context_id else ""
        agent = sanitize_agent_id(agent_id) if agent_id else ""
        session_ids = self._reap_orphaned_cortex_sessions(
            context_id=context,
            agent_id=agent,
        )
        return {
            "action": "reap-orphaned-cortex-sessions",
            "context_id": context,
            "agent_id": agent,
            "reaped_count": len(session_ids),
            "session_ids": session_ids,
            "mutation_performed": bool(session_ids),
        }

    def create_goal(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "operator",
        title: str,
        owner: str = "",
        state: str = "planned",
        next_action: str = "",
        evidence: str = "",
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        clean_title, _ = redact_capture_text(" ".join(str(title or "").split()))
        if not clean_title:
            raise ValueError("title is required")
        clean_state = self._normalize_goal_state(state or "planned")
        clean_owner, _ = redact_capture_text(" ".join(str(owner or agent).split()))
        clean_next_action, _ = redact_capture_text(
            " ".join(str(next_action or "").split())
        )
        clean_evidence, _ = redact_capture_text(
            " ".join(str(evidence or "").split())
        )
        evidence_payload = {
            "source": "goal-ledger",
            "title": clean_title,
            "owner": clean_owner,
            "goal_state": clean_state,
            "next_action": clean_next_action,
            "last_verified_evidence": clean_evidence,
        }
        text = self._format_goal_trace_text(
            title=clean_title,
            owner=clean_owner,
            state=clean_state,
            next_action=clean_next_action,
            evidence=clean_evidence,
        )
        commit = self.commit_cortical_trace(
            context_id=context,
            agent_id=agent,
            session_id="goal-ledger",
            trace_type="goal",
            truth_posture="observed",
            text=text,
            evidence=evidence_payload,
            confidence=0.82,
        )
        goal = self._goal_from_cortex_summary(
            {
                "memory_id": commit.get("memory_id", ""),
                "tag": commit.get("tag", ""),
                "context_id": context,
                "trace_type": "goal",
                "truth_posture": "observed",
                "confidence": commit.get("confidence", 0.82),
                "agent_id": agent,
                "session_id": "goal-ledger",
                "excerpt": text,
                "evidence": evidence_payload,
                "updated_at": time.time(),
            }
        )
        return {
            "action": "goal-create",
            "context_id": context,
            "agent_id": agent,
            "memory_id": commit.get("memory_id", ""),
            "tag": commit.get("tag", ""),
            "goal": goal,
            "receipt": self._simple_operation_receipt(
                action="goal-create",
                status="ready",
                title="Goal recorded",
                summary=f"{clean_title} is {clean_state}.",
                context_id=context,
                memory_id=str(commit.get("memory_id", "")),
                next_action=clean_next_action or "Run Start Work to surface this goal in the operator brief.",
            ),
            "agent_deployment": commit.get("agent_deployment"),
            "memory_db_path": str(self.memory_store.db_path),
        }

    def update_goal(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "operator",
        goal_id: str = "",
        title: str = "",
        owner: str = "",
        state: str = "",
        next_action: str = "",
        evidence: str = "",
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        clean_goal_id = reject_sensitive_identifier(
            goal_id,
            field="goal_id",
        ).strip()
        existing: dict[str, Any] | None = None
        if clean_goal_id:
            entry = self.memory_store.get_entry(clean_goal_id)
            if entry and entry.get("context_id") == context:
                metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
                if metadata.get("cortex_governor") is True and metadata.get("trace_type") == "goal":
                    existing = self._goal_from_cortex_summary(self._summarize_cortex_memory(entry))
        clean_title, _ = redact_capture_text(
            " ".join(str(title or (existing or {}).get("title", "")).split())
        )
        if not clean_title:
            raise ValueError("title is required when goal_id does not point to an existing goal")
        clean_state = self._normalize_goal_state(state or str((existing or {}).get("state", "in_progress")))
        clean_owner, _ = redact_capture_text(
            " ".join(
                str(owner or (existing or {}).get("owner", "") or agent).split()
            )
        )
        clean_next_action, _ = redact_capture_text(
            " ".join(
                str(next_action or (existing or {}).get("next_action", "")).split()
            )
        )
        clean_evidence, _ = redact_capture_text(
            " ".join(str(evidence or "").split())
        )
        root_goal_id = clean_goal_id or str((existing or {}).get("goal_id", ""))
        if not root_goal_id:
            root_goal_id = hashlib.sha256(f"{context}\x1f{clean_title}".encode("utf-8")).hexdigest()[:16]
        evidence_payload = {
            "source": "goal-ledger",
            "goal_id": root_goal_id,
            "title": clean_title,
            "owner": clean_owner,
            "goal_state": clean_state,
            "next_action": clean_next_action,
            "last_verified_evidence": clean_evidence,
            "previous_memory_id": clean_goal_id,
        }
        text = self._format_goal_trace_text(
            title=clean_title,
            owner=clean_owner,
            state=clean_state,
            next_action=clean_next_action,
            evidence=clean_evidence,
            prefix="Goal update",
        )
        commit = self.commit_cortical_trace(
            context_id=context,
            agent_id=agent,
            session_id="goal-ledger",
            trace_type="goal",
            truth_posture="observed",
            text=text,
            evidence=evidence_payload,
            confidence=0.84,
        )
        goal = self._goal_from_cortex_summary(
            {
                "memory_id": commit.get("memory_id", ""),
                "tag": commit.get("tag", ""),
                "context_id": context,
                "trace_type": "goal",
                "truth_posture": "observed",
                "confidence": commit.get("confidence", 0.84),
                "agent_id": agent,
                "session_id": "goal-ledger",
                "excerpt": text,
                "evidence": evidence_payload,
                "updated_at": time.time(),
            }
        )
        return {
            "action": "goal-update",
            "context_id": context,
            "agent_id": agent,
            "goal_id": root_goal_id,
            "memory_id": commit.get("memory_id", ""),
            "tag": commit.get("tag", ""),
            "goal": goal,
            "receipt": self._simple_operation_receipt(
                action="goal-update",
                status="ready",
                title="Goal updated",
                summary=f"{clean_title} is now {clean_state}.",
                context_id=context,
                memory_id=str(commit.get("memory_id", "")),
                next_action=clean_next_action or "Run goal.list or Start Work to confirm current state.",
            ),
            "agent_deployment": commit.get("agent_deployment"),
            "memory_db_path": str(self.memory_store.db_path),
        }

    def list_goals(
        self,
        *,
        context_id: str = "default",
        limit: int = 20,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        bounded_limit = max(1, min(int(limit), 100))
        entries = self.memory_store.list_entries(
            context_id=context,
            include_global=True,
            limit=max(100, bounded_limit * 10),
        )
        summaries = [
            self._summarize_cortex_memory(entry)
            for entry in entries
            if isinstance(entry.get("metadata"), dict)
            and entry["metadata"].get("cortex_governor") is True
            and entry["metadata"].get("trace_type") == "goal"
        ]
        goals = self._goal_ledger_from_cortical_summaries(summaries, limit=bounded_limit)
        active_goal = next(
            (goal for goal in goals if goal.get("state") not in {"done", "stale"}),
            goals[0] if goals else None,
        )
        return {
            "action": "goal-list",
            "context_id": context,
            "goal_count": len(goals),
            "goals": goals,
            "active_goal": active_goal,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def moderate_cortex_trace(
        self,
        *,
        context_id: str = "default",
        memory_id: str,
        action: str,
        reason: str = "",
        source_surface: str = "operator",
        confirm: bool = False,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        clean_memory_id = reject_sensitive_identifier(
            memory_id,
            field="memory_id",
        ).strip()
        if not clean_memory_id:
            raise ValueError("memory_id is required")
        clean_reason, _ = redact_capture_text(str(reason or ""))
        clean_source_surface = reject_sensitive_identifier(
            source_surface or "operator",
            field="source_surface",
        ).strip() or "operator"
        clean_action = str(action or "").strip().lower().replace("-", "_")
        if clean_action not in {"promote", "demote", "prune"}:
            raise ValueError("action must be promote, demote, or prune")
        entry = self.memory_store.get_entry(clean_memory_id)
        if not entry or entry.get("context_id") != context:
            raise ValueError("cortical trace was not found in the selected context")
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        if metadata.get("cortex_governor") is not True:
            raise ValueError("memory_id is not a Cortex Governor trace")

        if clean_action == "prune":
            if confirm is not True:
                raise ValueError("confirm must be true before pruning a Cortex trace")
            prune = self.prune_memory(
                context_id=context,
                target_type="memory",
                memory_id=clean_memory_id,
                reason=clean_reason,
                source_surface=clean_source_surface,
                publish_audit=True,
                confirm=True,
            )
            return {
                "action": "moderate-cortex-trace",
                "context_id": context,
                "memory_id": clean_memory_id,
                "moderation_action": clean_action,
                "reason": clean_reason,
                "trace": self._summarize_cortex_memory(entry),
                "prune": prune,
            }

        next_metadata = self._json_safe_metadata(dict(metadata))
        current_confidence = float(next_metadata.get("confidence", 0.0) or 0.0)
        now = time.time()
        if clean_action == "promote":
            next_metadata["confidence"] = round(max(current_confidence, 0.9), 3)
            if next_metadata.get("truth_posture") not in {
                "operator-confirmed",
                "test-validated",
            }:
                next_metadata["truth_posture"] = "operator-confirmed"
        else:
            next_metadata["confidence"] = round(min(current_confidence, 0.35), 3)
            next_metadata["truth_posture"] = "stale"
        history = next_metadata.get("moderation_history")
        if not isinstance(history, list):
            history = []
        history.append(
            {
                "action": clean_action,
                "reason": clean_reason,
                "source_surface": clean_source_surface,
                "moderated_at": now,
            }
        )
        next_metadata["moderation_history"] = history[-20:]
        updated = self.memory_store.upsert_entry(
            tag=str(entry["tag"]),
            context_id=context,
            source_text=str(entry.get("source_text", "")),
            metadata=next_metadata,
            embedding_dimensions=int(entry.get("embedding_dimensions", 0) or 0),
            spike_indices=entry.get("spike_indices", []),
            neuron_indices=entry.get("neuron_indices", []),
            registered_at=float(entry.get("created_at", now) or now),
        )
        self._refresh_registered_traces()
        trace = self._summarize_cortex_memory(updated)
        audit = self.publish_context_event(
            context_id=context,
            source_surface=clean_source_surface,
            event_type="cortex-trace-moderated",
            summary=f"cortex trace {clean_action}: {trace.get('tag', clean_memory_id)}",
            payload={
                "memory_id": clean_memory_id,
                "tag": trace.get("tag", ""),
                "moderation_action": clean_action,
                "reason": clean_reason,
                "trace_type": trace.get("trace_type", ""),
                "truth_posture": trace.get("truth_posture", ""),
                "confidence": trace.get("confidence", 0.0),
            },
        )
        return {
            "action": "moderate-cortex-trace",
            "context_id": context,
            "memory_id": clean_memory_id,
            "moderation_action": clean_action,
            "reason": clean_reason,
            "trace": trace,
            "agent_deployment": audit,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def _normalize_goal_state(self, state: str) -> str:
        clean_state = str(state or "planned").strip().lower().replace("-", "_").replace(" ", "_")
        if clean_state not in GOAL_LEDGER_STATES:
            raise ValueError(
                "goal state must be one of " + ", ".join(sorted(GOAL_LEDGER_STATES))
            )
        return clean_state

    def _format_goal_trace_text(
        self,
        *,
        title: str,
        owner: str,
        state: str,
        next_action: str = "",
        evidence: str = "",
        prefix: str = "Goal",
    ) -> str:
        return "\n".join(
            [
                f"{prefix}: {title}",
                f"Owner: {owner or 'operator'}",
                f"State: {state}",
                f"Next action: {next_action or 'none recorded'}",
                f"Last verified evidence: {evidence or 'none recorded'}",
            ]
        ).strip()

    def _goal_ledger_from_cortical_summaries(
        self,
        summaries: list[dict[str, Any]],
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        goal_summaries = [
            summary
            for summary in summaries
            if str(summary.get("trace_type", "")) == "goal"
        ]
        goal_summaries.sort(
            key=lambda item: float(item.get("updated_at", 0.0) or 0.0),
            reverse=True,
        )
        goals: list[dict[str, Any]] = []
        seen: set[str] = set()
        for summary in goal_summaries:
            goal = self._goal_from_cortex_summary(summary)
            goal_id = str(goal.get("goal_id", "") or goal.get("memory_id", ""))
            if not goal_id or goal_id in seen:
                continue
            seen.add(goal_id)
            goals.append(goal)
            if len(goals) >= max(1, int(limit)):
                break
        return goals

    def _goal_from_cortex_summary(self, summary: dict[str, Any]) -> dict[str, Any]:
        evidence = summary.get("evidence") if isinstance(summary.get("evidence"), dict) else {}
        excerpt = str(summary.get("excerpt", "") or "")
        title = (
            str(evidence.get("title") or "").strip()
            or self._extract_labeled_line(excerpt, {"goal", "goal update", "objective"})
            or self._compact_text(excerpt, 140)
        )
        state = str(evidence.get("goal_state") or evidence.get("state") or "planned")
        try:
            normalized_state = self._normalize_goal_state(state)
        except ValueError:
            normalized_state = "planned"
        memory_id = str(summary.get("memory_id", "") or "")
        goal_id = str(evidence.get("goal_id") or memory_id)
        owner = str(evidence.get("owner") or summary.get("agent_id") or "operator")
        next_action = str(
            evidence.get("next_action")
            or self._extract_labeled_line(excerpt, {"next action"})
            or ""
        )
        last_evidence = str(
            evidence.get("last_verified_evidence")
            or self._extract_labeled_line(excerpt, {"last verified evidence", "evidence"})
            or ""
        )
        return {
            "goal_id": goal_id,
            "memory_id": memory_id,
            "tag": summary.get("tag", ""),
            "context_id": summary.get("context_id", ""),
            "title": title or "Untitled goal",
            "owner": owner,
            "state": normalized_state,
            "next_action": next_action,
            "last_verified_evidence": last_evidence,
            "confidence": summary.get("confidence", 0.0),
            "truth_posture": summary.get("truth_posture", "observed"),
            "updated_at": summary.get("updated_at", 0.0),
            "related_memory_id": memory_id,
        }

    def _extract_labeled_line(self, text: str, labels: set[str]) -> str:
        wanted = {label.strip().lower() for label in labels if label.strip()}
        for line in str(text or "").splitlines():
            if ":" not in line:
                continue
            label, value = line.split(":", 1)
            if label.strip().lower() in wanted:
                return " ".join(value.split())
        return ""

    def _simple_operation_receipt(
        self,
        *,
        action: str,
        status: str,
        title: str,
        summary: str,
        context_id: str,
        memory_id: str = "",
        next_action: str = "",
    ) -> dict[str, Any]:
        return {
            "action": action,
            "status": status,
            "title": title,
            "summary": summary,
            "context_id": sanitize_context_id(context_id),
            "memory_id": str(memory_id or ""),
            "event_count": 1 if memory_id else 0,
            "quality": "operator-confirmed" if memory_id else "pending",
            "next_action": next_action,
            "generated_at": time.time(),
        }

    def _reap_orphaned_cortex_sessions(
        self,
        *,
        context_id: str = "",
        agent_id: str = "",
    ) -> list[str]:
        now = time.time()
        changed = False
        reaped_session_ids: list[str] = []
        for session_id, session in list(self.cortex_sessions.items()):
            if session.get("status") != "active":
                continue
            if context_id and session.get("context_id") != context_id:
                continue
            if agent_id and session.get("agent_id") != agent_id:
                continue
            if session.get("lease_kind") != "mcp-client":
                continue
            owner_pid = int(session.get("owner_pid", 0) or 0)
            if self._process_is_alive(owner_pid):
                continue
            orphaned = dict(session)
            orphaned.update(
                {
                    "status": "orphaned",
                    "finished_at": now,
                    "updated_at": now,
                    "finish_reason": "owner-process-missing",
                    "orphan_reason": f"owner pid {owner_pid} is not running",
                }
            )
            self.cortex_sessions[session_id] = self._normalize_cortex_session(orphaned)
            changed = True
            reaped_session_ids.append(str(session_id))
        if changed:
            self._persist_runtime_state()
        return sorted(reaped_session_ids)

    @staticmethod
    def _process_is_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    def _active_cortex_session(
        self,
        *,
        context: str,
        agent_id: str,
        session_id: str,
    ) -> dict[str, Any]:
        if not session_id:
            raise ValueError("session_id is required")
        session = self.cortex_sessions.get(session_id)
        if not session:
            raise ValueError(f"cortex session not found: {session_id}")
        if session.get("context_id") != context:
            raise ValueError("cortex session context mismatch")
        if session.get("agent_id") != agent_id:
            raise ValueError("cortex session agent mismatch")
        if session.get("status") != "active":
            raise ValueError("cortex session is not active")
        return dict(session)

    def _cortex_policy(self, mode: str) -> dict[str, Any]:
        clean_mode = str(mode or "strict").strip().lower()
        if clean_mode not in CORTEX_MODES:
            clean_mode = "strict"
        base_contract = [
            "hydrate-before-action",
            "verify-before-mutation",
            "capture-validated-traces",
            "surface-conflicts",
            "prune-sensitive-or-wrong-memory",
        ]
        if clean_mode == "creative":
            base_contract.append("allow-low-confidence-exploration")
        elif clean_mode == "security":
            base_contract.extend(["fail-closed-on-secret-risk", "require-provenance"])
        elif clean_mode == "demo":
            base_contract.append("prefer-readable-evidence")
        return {
            "policy_id": f"cognitive_governance:{clean_mode}",
            "cognitive_governance": True,
            "mode": clean_mode,
            "contract": base_contract,
            "decision_thresholds": {
                "verify_first_below_confidence": 0.7,
                "high_confidence_truth": 0.8,
                "mutation_requires_warning": True,
            },
            "memory_rules": [
                "user corrections outrank generated inference",
                "test-validated traces outrank unverified summaries",
                "stale or sensitive traces should be pruned before reuse",
            ],
        }

    def _normalize_cortex_trace_type(self, trace_type: str, text: str) -> str:
        requested = str(trace_type or "").strip().lower().replace("-", "_")
        if requested in CORTEX_TRACE_TYPES:
            return requested
        lowered = str(text or "").lower()
        keyword_map = {
            "validation": ("test", "passed", "verified", "validated", "certified"),
            "decision": ("decided", "decision", "choose", "selected", "approved"),
            "constraint": ("must", "requires", "do not", "never", "constraint"),
            "risk": ("risk", "danger", "sensitive", "unsafe", "warning"),
            "blocker": ("blocked", "blocker", "cannot", "missing"),
            "correction": ("correction", "actually", "wrong", "fix"),
            "implementation": ("implemented", "changed", "added", "patched"),
            "goal": ("goal", "objective", "target"),
            "follow_up": ("follow up", "next", "todo"),
        }
        for candidate, keywords in keyword_map.items():
            if any(keyword in lowered for keyword in keywords):
                return candidate
        return "evidence"

    def _normalize_truth_posture(self, truth_posture: str) -> str:
        posture = str(truth_posture or "observed").strip().lower().replace("_", "-")
        return posture if posture in CORTEX_TRUTH_POSTURES else "observed"

    def _score_cortex_confidence(
        self,
        *,
        trace_type: str,
        truth_posture: str,
        evidence: dict[str, Any],
        confidence: float | None,
        text: str,
    ) -> float:
        if confidence is not None:
            return round(min(max(float(confidence), 0.0), 1.0), 3)
        base_by_posture = {
            "test-validated": 0.88,
            "operator-confirmed": 0.86,
            "observed": 0.74,
            "inferred": 0.58,
            "stale": 0.3,
        }
        score = base_by_posture.get(truth_posture, 0.7)
        if evidence:
            score += 0.05
        if trace_type in {"validation", "constraint", "decision"}:
            score += 0.03
        lowered = str(text or "").lower()
        if any(token in lowered for token in ("passed", "verified", "confirmed")):
            score += 0.03
        if any(token in lowered for token in ("maybe", "might", "assume", "guess")):
            score -= 0.12
        return round(min(max(score, 0.05), 0.99), 3)

    def _has_concrete_validation_evidence(self, evidence: dict[str, Any]) -> bool:
        if not evidence:
            return False
        concrete_keys = {
            "artifact",
            "artifact_path",
            "artifacts",
            "check",
            "checks",
            "command",
            "commands",
            "commit",
            "output",
            "output_summary",
            "proof",
            "report",
            "test_command",
            "test_output",
            "tests",
            "validated_by",
            "validation",
            "verification",
        }
        for key, value in evidence.items():
            normalized_key = str(key or "").strip().lower().replace("-", "_")
            if normalized_key not in concrete_keys:
                continue
            if isinstance(value, (list, tuple, set, dict)):
                if len(value) > 0:
                    return True
            elif str(value or "").strip():
                return True
        return False

    def _summarize_cortex_memory(self, entry: dict[str, Any]) -> dict[str, Any]:
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        source_text = str(entry.get("source_text") or "")
        return {
            "memory_id": entry.get("memory_id", ""),
            "tag": entry.get("tag", ""),
            "context_id": entry.get("context_id", ""),
            "trace_type": str(metadata.get("trace_type", "evidence")),
            "truth_posture": str(metadata.get("truth_posture", "observed")),
            "confidence": round(float(metadata.get("confidence", 0.0) or 0.0), 3),
            "agent_id": str(metadata.get("agent_id", "")),
            "session_id": str(metadata.get("cortex_session_id", "")),
            "excerpt": self._compact_text(source_text, 180),
            "evidence": metadata.get("evidence", {}),
            "updated_at": float(entry.get("updated_at", 0.0) or 0.0),
        }

    def _normalize_cortex_intent_list(self, values: Any) -> list[str]:
        if values is None:
            return []
        raw_items: list[Any]
        if isinstance(values, str):
            stripped = values.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError:
                    parsed = None
                raw_items = parsed if isinstance(parsed, list) else [stripped]
            else:
                raw_items = re.split(r"[\n,]", stripped)
        elif isinstance(values, (list, tuple, set)):
            raw_items = list(values)
        else:
            raw_items = [values]

        normalized: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            text, _ = redact_capture_text(" ".join(str(item or "").split()))
            if not text:
                continue
            text = text[:260]
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            normalized.append(text)
            if len(normalized) >= 24:
                break
        return normalized

    def _cortex_contradictions(self, cortical_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        contradictions: list[dict[str, Any]] = []
        for entry in cortical_entries:
            excerpt = str(entry.get("excerpt", ""))
            lowered = excerpt.lower()
            if entry.get("trace_type") == "correction" or any(
                token in lowered
                for token in (
                    "correction",
                    "actually",
                    "wrong",
                    "not true",
                    "contradicts earlier",
                    "conflicts with",
                    "supersede",
                )
            ):
                item = dict(entry)
                item["conflict_reason"] = (
                    "Correction or contradiction trace should override older inferred memory."
                )
                contradictions.append(item)
        return contradictions

    def _cortex_capture_queue(
        self,
        active_sessions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        queue: list[dict[str, Any]] = []
        for session in active_sessions:
            recommendation = session.get("last_capture_recommendation")
            if not isinstance(recommendation, dict) or not recommendation:
                continue
            if not bool(recommendation.get("recommended", False)):
                continue
            queue.append(
                {
                    "session_id": session.get("session_id", ""),
                    "agent_id": session.get("agent_id", ""),
                    "trace_type": recommendation.get("trace_type", "evidence"),
                    "truth_posture": recommendation.get("truth_posture", "observed"),
                    "reason": recommendation.get("reason", ""),
                    "observation": self._compact_text(
                        str(session.get("last_observation", "")),
                        180,
                    ),
                    "proposed_action": self._compact_text(
                        str(session.get("last_proposed_action", "")),
                        180,
                    ),
                    "intended_files": session.get("last_intended_files", []),
                    "intended_tools": session.get("last_intended_tools", []),
                    "decision": session.get("last_decision", ""),
                }
            )
        return queue

    def _cortex_suggested_next_move(
        self,
        *,
        active_sessions: list[dict[str, Any]],
        assumptions: list[dict[str, Any]],
        stale_or_uncertain: list[dict[str, Any]],
        contradictions: list[dict[str, Any]],
        risks: list[dict[str, Any]],
        capture_queue: list[dict[str, Any]],
    ) -> str:
        if not active_sessions:
            return "Enter Cortex Governor before substantial work so recall, constraints, and validation capture are tied to a session."
        active = active_sessions[0]
        warning_codes = {
            str(warning.get("code", ""))
            for warning in active.get("last_warnings", [])
            if isinstance(warning, dict)
        }
        decision = str(active.get("last_decision", "entered"))
        if "sensitive-data-risk" in warning_codes or "sensitive-intent-scope" in warning_codes:
            return "Stop, sanitize the scoped data, and prune any sensitive trace before continuing."
        if contradictions:
            return "Resolve the surfaced correction or contradiction before relying on older memory."
        if decision in {"verify-first", "proceed-with-verification"}:
            return "Run the missing verification, then commit a validation trace with evidence."
        if capture_queue:
            return "Complete the proposed action, then commit the queued cortical trace with concrete evidence."
        if stale_or_uncertain or assumptions:
            return "Verify or demote stale assumptions before using them as working facts."
        if risks:
            return "Review active risk traces and keep mutation scope explicit before acting."
        return "Proceed, keep file/tool scope declared on each tick, and capture only validated outcomes."

    def _cortex_warnings(
        self,
        *,
        mutation_intent: bool,
        confidence: float,
        observation: str,
        proposed_action: str,
        intended_files: list[str],
        intended_tools: list[str],
        cortex_state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        warnings: list[dict[str, Any]] = []
        if mutation_intent:
            warnings.append(
                {
                    "code": "mutation-verification-required",
                    "severity": "high" if confidence < 0.7 else "medium",
                    "message": "Mutation intent requires verification evidence before completion.",
                }
            )
            if not intended_files and not intended_tools:
                warnings.append(
                    {
                        "code": "missing-intent-scope",
                        "severity": "medium",
                        "message": "Mutation intent should declare intended files or tools before acting.",
                    }
                )
        if confidence < 0.5:
            warnings.append(
                {
                    "code": "low-confidence-action",
                    "severity": "medium",
                    "message": "Agent confidence is below the Cortex Governor verification threshold.",
                }
            )
        combined = f"{observation} {proposed_action}".lower()
        if any(token in combined for token in ("secret", "token", "password", "private key", "credential")):
            warnings.append(
                {
                    "code": "sensitive-data-risk",
                    "severity": "critical",
                    "message": "Potential sensitive data path detected; avoid capture and verify redaction.",
                }
            )
        scoped_text = " ".join([*intended_files, *intended_tools]).lower()
        if any(
            token in scoped_text
            for token in (
                ".env",
                ".ssh",
                "id_rsa",
                "private key",
                "secret",
                "token",
                "credential",
                "password",
            )
        ):
            warnings.append(
                {
                    "code": "sensitive-intent-scope",
                    "severity": "critical",
                    "message": "Declared file/tool scope appears to include sensitive material; sanitize before capture.",
                }
            )
        if any(
            token in scoped_text
            for token in (
                "git push",
                "deploy",
                "launchctl",
                "sudo",
                "rm ",
                "rm -",
                "chmod",
                "chown",
                "prune",
                "delete",
            )
        ):
            warnings.append(
                {
                    "code": "high-impact-tool-scope",
                    "severity": "medium",
                    "message": "Declared tools include a high-impact operation; verify target and rollback path.",
                }
            )
        if any(token in combined for token in ("assume", "maybe", "might", "uncertain")):
            warnings.append(
                {
                    "code": "unverified-assumption",
                    "severity": "medium",
                    "message": "Observation or proposed action contains uncertainty language.",
                }
            )
        if cortex_state.get("risks"):
            warnings.append(
                {
                    "code": "related-risk-memory",
                    "severity": "medium",
                    "message": "Related risk or blocker memories are active in this context.",
                }
            )
        return warnings

    def _cortex_decision(
        self,
        *,
        warnings: list[dict[str, Any]],
        confidence: float,
    ) -> str:
        warning_codes = {str(warning.get("code", "")) for warning in warnings}
        if "sensitive-data-risk" in warning_codes or "sensitive-intent-scope" in warning_codes:
            return "stop-and-sanitize"
        if "mutation-verification-required" in warning_codes and confidence < 0.7:
            return "verify-first"
        if warnings:
            return "proceed-with-verification"
        return "proceed"

    def _cortex_capture_recommendation(
        self,
        observation: str,
        proposed_action: str,
        decision: str,
        *,
        intended_files: list[str] | None = None,
        intended_tools: list[str] | None = None,
    ) -> dict[str, Any]:
        combined = f"{observation} {proposed_action}".lower()
        if "test" in combined or "verify" in combined:
            trace_type = "validation"
        elif "decid" in combined or "choose" in combined:
            trace_type = "decision"
        elif "risk" in combined or "secret" in combined:
            trace_type = "risk"
        else:
            trace_type = "evidence"
        return {
            "recommended": decision in {"verify-first", "proceed-with-verification"},
            "trace_type": trace_type,
            "truth_posture": "observed",
            "reason": "Capture the outcome after verification, not before.",
            "intended_files": list(intended_files or []),
            "intended_tools": list(intended_tools or []),
        }

    def hydrate_agent_context(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        prompt: str = "",
        since_event_id: int | None = None,
        event_limit: int = 20,
        graph_limit: int = 30,
        acknowledge: bool = False,
        claim_events: bool = True,
        consumer_instance_id: str = "",
        lease_seconds: float = 60.0,
        recall_mode: str = "neural",
    ) -> dict[str, Any]:
        """Compose the durable S2 context bus into an agent-ready briefing."""
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        if acknowledge:
            raise ValueError(
                "inline acknowledgement is disabled; consume the returned events, then acknowledge their receipt_id values"
            )
        if claim_events and since_event_id is not None:
            raise ValueError(
                "since_event_id is observation-only and cannot be combined with leased delivery"
            )
        bounded_event_limit = min(max(int(event_limit), 1), 100)
        bounded_graph_limit = min(max(int(graph_limit), 1), 200)
        normalized_recall_mode = self._normalize_agent_recall_mode(recall_mode)
        if self.control_plane_only and normalized_recall_mode == "neural":
            raise BackendUnavailable(
                "neural recall is unavailable in the control-plane backend"
            )
        start_event_id = (
            self._agent_cursor_event_id(context=context, agent_id=agent)
            if since_event_id is None
            else max(0, int(since_event_id))
        )
        graph = self.list_memory_graph(context_id=context, limit=bounded_graph_limit)

        prompt_text, prompt_redactions = redact_capture_text(
            str(prompt or "").strip()
        )
        recall_result = ""
        recall_items: list[str] = []
        if prompt_text:
            if normalized_recall_mode == "neural":
                _retrieval, recall_items = self._retrieval_v2_briefing_recall(
                    prompt_text=prompt_text,
                    context=context,
                )
                recall_result = " / ".join(recall_items)
            elif normalized_recall_mode == "surface":
                recall_items = self._surface_bootstrap_recall(
                    context=context,
                    prompt_text=prompt_text,
                )
                recall_result = " / ".join(recall_items)

        graph_entries = [
            self._summarize_agent_graph_entry(entry)
            for entry in graph["entries"][: min(10, bounded_graph_limit)]
        ]
        graph_relationships = [
            self._summarize_agent_graph_relationship(relationship)
            for relationship in graph["relationships"][: min(10, bounded_graph_limit)]
        ]
        graph_summary = {
            "entry_count": int(graph["entry_count"]),
            "relationship_count": int(graph["relationship_count"]),
            "relationship_modes": graph["relationship_summary"],
        }
        cortex_state = self.get_cortex_state(
            context_id=context,
            agent_id=agent,
            limit=bounded_graph_limit,
        )
        instance = consumer_instance_id or self.delivery_instance_id
        if claim_events:
            deployments = self.lease_context_events(
                context_id=context,
                agent_id=agent,
                consumer_instance_id=instance,
                limit=bounded_event_limit,
                lease_seconds=lease_seconds,
            )
            start_event_id = int(
                deployments.get("cursor", {}).get("last_event_id", start_event_id)
            )
        else:
            deployments = {
                "protocol_version": CONTEXT_BUS_PROTOCOL_VERSION,
                "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
                "events": [],
                "deliveries": [],
                "has_more": False,
                "ack_required": False,
                "observation_only": True,
            }
        try:
            return self._compose_agent_hydration_payload(
                context=context,
                agent=agent,
                start_event_id=start_event_id,
                deployments=deployments,
                claim_events=claim_events,
                prompt_text=prompt_text,
                prompt_redactions=prompt_redactions,
                recall_result=recall_result,
                recall_items=recall_items,
                normalized_recall_mode=normalized_recall_mode,
                graph_summary=graph_summary,
                graph_entries=graph_entries,
                graph_relationships=graph_relationships,
                cortex_state=cortex_state,
            )
        except Exception:
            receipt_ids = [
                str(delivery.get("receipt_id") or "")
                for delivery in deployments.get("deliveries", [])
                if isinstance(delivery, dict) and str(delivery.get("receipt_id") or "")
            ]
            if receipt_ids:
                try:
                    self.release_context_events(
                        context_id=context,
                        agent_id=agent,
                        consumer_instance_id=instance,
                        receipt_ids=receipt_ids,
                    )
                except Exception as release_exc:
                    LOGGER.exception(
                        "agent hydration failed and leased receipts could not be released"
                    )
                    raise RuntimeError(
                        "agent hydration failed and leased receipts could not be released; "
                        "wait for lease expiry before retrying"
                    ) from release_exc
            raise

    def _compose_agent_hydration_payload(
        self,
        *,
        context: str,
        agent: str,
        start_event_id: int,
        deployments: dict[str, Any],
        claim_events: bool,
        prompt_text: str,
        prompt_redactions: int,
        recall_result: str,
        recall_items: list[str],
        normalized_recall_mode: str,
        graph_summary: dict[str, Any],
        graph_entries: list[dict[str, Any]],
        graph_relationships: list[dict[str, Any]],
        cortex_state: dict[str, Any],
    ) -> dict[str, Any]:
        raw_events = deployments["events"]
        events = [self._summarize_agent_context_event(event) for event in raw_events]
        latest_event_id = max(
            [start_event_id] + [int(event["event_id"]) for event in raw_events]
        )
        raw_blocking = deployments.get("blocking_delivery")
        blocking_delivery = None
        if isinstance(raw_blocking, dict):
            blocking_delivery = {
                key: raw_blocking.get(key)
                for key in (
                    "delivery_id",
                    "event_id",
                    "attempt_count",
                    "max_delivery_attempts",
                    "reason",
                    "requires_governed_dead_letter",
                    "lease_expires_at",
                )
                if key in raw_blocking
            }
            if not blocking_delivery.get("reason") and "lease_expires_at" in raw_blocking:
                blocking_delivery["reason"] = "active-lease"
        payload = {
            "action": "agent-context-hydrate",
            "context_id": context,
            "agent_id": agent,
            "since_event_id": start_event_id,
            "latest_event_id": latest_event_id,
            "new_event_count": len(events),
            "events": events,
            "deliveries": [
                {
                    key: value
                    for key, value in delivery.items()
                    if key != "event"
                }
                for delivery in deployments.get("deliveries", [])
            ],
            "ack": None,
            "acknowledged": False,
            "ack_required": bool(deployments.get("ack_required", False)),
            "acknowledgement_instruction": (
                "After successfully consuming this briefing, acknowledge every receipt_id."
                if deployments.get("ack_required")
                else "No delivery acknowledgement is required."
            ),
            "has_more_events": bool(deployments.get("has_more", False)),
            "remaining_pending_count": int(
                deployments.get("remaining_pending_count", 0) or 0
            ),
            "blocking_delivery": blocking_delivery,
            "max_delivery_attempts": int(
                deployments.get("max_delivery_attempts", 0) or 0
            ),
            "claim_events": bool(claim_events),
            "recall_prompt": prompt_text,
            "input_redaction_count": int(prompt_redactions),
            "raw_input_stored": False,
            "recall_result": recall_result,
            "recall_items": recall_items,
            "recall_mode": normalized_recall_mode,
            "recall_provenance": (
                "retrieval-v2-hybrid-read-only"
                if normalized_recall_mode == "neural"
                else "sqlite-surface-bootstrap"
                if normalized_recall_mode == "surface"
                else "disabled"
            ),
            "graph_summary": graph_summary,
            "graph_entries": graph_entries,
            "graph_relationships": graph_relationships,
            "cortex_state": cortex_state,
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "protocol_version": CONTEXT_BUS_PROTOCOL_VERSION,
            "memory_db_path": str(self.memory_store.db_path),
        }
        payload["briefing_markdown"] = self._render_agent_context_briefing(payload)
        return payload

    @staticmethod
    def _normalize_agent_recall_mode(recall_mode: str) -> str:
        normalized = str(recall_mode or "neural").strip().lower().replace("_", "-")
        aliases = {
            "full": "neural",
            "spiking": "neural",
            "surface-bootstrap": "surface",
            "lexical": "surface",
            "off": "none",
            "disabled": "none",
        }
        normalized = aliases.get(normalized, normalized)
        if normalized not in {"neural", "surface", "none"}:
            raise ValueError("recall_mode must be neural, surface, or none")
        return normalized

    def _retrieval_v2_briefing_recall(
        self,
        *,
        prompt_text: str,
        context: str,
        recall_scope: str = "local",
    ) -> tuple[dict[str, Any], list[str]]:
        """Adapt structured Retrieval v2 hits to existing briefing text fields.

        The compatibility strings are rendered from typed result fields; they
        are never parsed back into authority-bearing identities or provenance.
        """

        result_limit = min(
            max(int(self.recall_count), 1),
            RETRIEVAL_V2_MAX_RESULT_LIMIT,
        )
        candidate_limit = min(
            max(result_limit * 4, 16),
            RETRIEVAL_V2_MAX_CANDIDATE_LIMIT,
        )
        retrieval = self.retrieve_text_v2(
            prompt_text,
            context_id=context,
            recall_scope=recall_scope,
            result_limit=result_limit,
            candidate_limit=candidate_limit,
            include_graph_neighbors=True,
        )
        rendered: list[str] = []
        for item in retrieval.get("items", []):
            if not isinstance(item, dict):
                continue
            scope = (
                item.get("scope_provenance")
                if isinstance(item.get("scope_provenance"), dict)
                else {}
            )
            context_link = (
                scope.get("context_link")
                if isinstance(scope.get("context_link"), dict)
                else {}
            )
            entry = {
                "memory_id": item.get("memory_id", ""),
                "tag": item.get("tag", ""),
                "context_id": item.get("context_id", ""),
                "recall_scope": scope.get("requested_scope", recall_scope),
                "recall_provenance": scope.get("provenance", "local"),
                "via_context_link_id": context_link.get("context_link_id", ""),
                "via_relation_type": context_link.get("relation_type", ""),
                "via_direction": context_link.get("direction", ""),
                "metadata": {
                    "display_label": item.get("label", ""),
                    "display_summary": item.get("summary", ""),
                    "semantic_facets": item.get("facets", []),
                },
            }
            rendered.append(
                self._format_recall_entry(
                    entry,
                    score=float(item.get("score", 0.0) or 0.0),
                )
            )
        return retrieval, rendered

    def _surface_bootstrap_recall(
        self,
        *,
        context: str,
        prompt_text: str,
    ) -> list[str]:
        candidates = self._surface_text_recall_candidates(
            context=context,
            prompt_text=prompt_text,
            recall_scope="local",
        )
        return [
            self._format_recall_entry(
                candidate,
                score=float(candidate.get("score", 0.0) or 0.0),
            )
            for candidate in candidates[: max(1, self.recall_count)]
        ]

    def _agent_cursor_event_id(self, *, context: str, agent_id: str) -> int:
        cursors = self.memory_store.list_context_cursors(
            context_id=context,
            agent_id=agent_id,
            limit=1,
        )
        if not cursors:
            return 0
        return max(0, int(cursors[0].get("last_event_id", 0)))

    def _split_recall_result(self, recall_result: str) -> list[str]:
        if not recall_result:
            return []
        if "No registered historical context matched" in recall_result:
            return []
        if "disabled" in recall_result.lower():
            return []
        return [
            item.strip()
            for item in recall_result.split(" / ")
            if item.strip()
        ]

    def _summarize_agent_context_event(self, event: dict[str, Any]) -> dict[str, Any]:
        summary = {
            "event_id": event.get("event_id", 0),
            "context_id": event.get("context_id", ""),
            "source_surface": event.get("source_surface", ""),
            "event_type": event.get("event_type", ""),
            "summary": event.get("summary", ""),
            "agent_targets": event.get("agent_targets", []),
            "target_count": event.get("target_count", 0),
            "delivery_mode": event.get("delivery_mode", CONTEXT_BUS_DELIVERY_MODE),
            "published": bool(event.get("published", True)),
            "created_at": event.get("created_at", 0.0),
            "payload_summary": self._summarize_agent_event_payload(
                event.get("payload", {})
            ),
        }
        delivery = event.get("delivery")
        if isinstance(delivery, dict):
            summary["delivery"] = {
                key: delivery.get(key)
                for key in (
                    "delivery_id",
                    "receipt_id",
                    "lease_token",
                    "consumer_instance_id",
                    "attempt_count",
                    "lease_expires_at",
                    "redelivered",
                    "ack_required",
                )
                if key in delivery
            }
        return summary

    def _summarize_agent_event_payload(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return {"payload_type": type(payload).__name__}
        summary: dict[str, Any] = {
            "payload_keys": sorted(str(key) for key in payload.keys()),
        }
        scalar_keys = (
            "tag",
            "memory_id",
            "source_tag",
            "sequence_id",
            "speaker",
            "target_type",
            "reason",
            "event_count",
            "relationship_count",
            "spike_count",
            "neuron_count",
        )
        for key in scalar_keys:
            if key not in payload:
                continue
            value = payload[key]
            if isinstance(value, str):
                summary[key] = self._compact_text(value, 180)
            elif isinstance(value, (int, float, bool)) or value is None:
                summary[key] = value
        if isinstance(payload.get("source_text"), str):
            summary["source_text_bytes"] = len(
                payload["source_text"].encode("utf-8")
            )
        if isinstance(payload.get("text"), str):
            summary["text_bytes"] = len(payload["text"].encode("utf-8"))
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            summary["metadata_keys"] = sorted(str(key) for key in metadata.keys())
        nested_events = payload.get("events")
        if isinstance(nested_events, list):
            summary["nested_event_count"] = len(nested_events)
            summary["nested_event_tags"] = [
                str(item.get("tag", ""))
                for item in nested_events[:5]
                if isinstance(item, dict) and item.get("tag")
            ]
        nested_relationships = payload.get("relationships")
        if isinstance(nested_relationships, list):
            summary["nested_relationship_count"] = len(nested_relationships)
        result = payload.get("result")
        if isinstance(result, dict):
            summary["result"] = {
                key: result.get(key)
                for key in (
                    "deleted",
                    "deleted_memory_id",
                    "deleted_relationship_count",
                    "deleted_memory_event_count",
                    "deleted_relationship_ids",
                )
                if key in result
            }
        return summary

    def _summarize_agent_graph_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        source_text = str(entry.get("source_text") or "").strip()
        excerpt = source_text[:220] + ("..." if len(source_text) > 220 else "")
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        return {
            "memory_id": entry.get("memory_id", ""),
            "tag": entry.get("tag", ""),
            "context_id": entry.get("context_id", ""),
            "excerpt": excerpt,
            "metadata_keys": sorted(str(key) for key in metadata.keys()),
            "updated_at": entry.get("updated_at", 0.0),
        }

    def _summarize_agent_graph_relationship(
        self,
        relationship: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "relationship_id": relationship.get("relationship_id", ""),
            "relation_type": relationship.get("relation_type", ""),
            "weight": relationship.get("weight", 0.0),
            "source_memory_id": relationship.get("source_memory_id", ""),
            "source_tag": relationship.get("source_tag", ""),
            "source_label": relationship.get("source_label", ""),
            "target_memory_id": relationship.get("target_memory_id", ""),
            "target_tag": relationship.get("target_tag", ""),
            "target_label": relationship.get("target_label", ""),
            "updated_at": relationship.get("updated_at", 0.0),
        }

    def _render_agent_context_briefing(self, payload: dict[str, Any]) -> str:
        lines = [
            "# SYNAPSE-S2 Agent Context",
            (
                f"- Context: {payload['context_id']} | Agent: {payload['agent_id']} | "
                f"Events: {payload['new_event_count']} new since "
                f"{payload['since_event_id']} -> {payload['latest_event_id']}"
            ),
            (
                f"- Delivery: {payload['delivery_mode']} | Ack: "
                f"{'required after consumption' if payload.get('ack_required') else 'none'}"
            ),
        ]
        events = payload.get("events", [])
        if events:
            lines.append("## New Context Deployments")
            for event in events[:10]:
                lines.append(
                    (
                        f"- #{event['event_id']} {event['event_type']} from "
                        f"{event['source_surface']}: {self._compact_text(event['summary'], 180)}"
                    )
                )
        else:
            lines.append("## New Context Deployments")
            lines.append("- No new context deployments for this agent cursor.")

        recall_prompt = str(payload.get("recall_prompt") or "")
        if recall_prompt:
            lines.append("## Prompt Recall")
            if payload.get("recall_items"):
                for item in payload["recall_items"][:8]:
                    lines.append(f"- {self._compact_text(item, 220)}")
            else:
                lines.append(f"- {self._compact_text(payload.get('recall_result', ''), 220)}")

        graph_summary = payload.get("graph_summary", {})
        relationship_modes = graph_summary.get("relationship_modes", {})
        lines.append("## Memory Graph")
        lines.append(
            (
                f"- Entries: {graph_summary.get('entry_count', 0)} | "
                f"Relationships: {graph_summary.get('relationship_count', 0)} | "
                f"Temporal: {relationship_modes.get('temporal', 0)} | "
                f"Associative: {relationship_modes.get('associative', 0)}"
            )
        )
        for entry in payload.get("graph_entries", [])[:5]:
            excerpt = entry.get("excerpt") or "no source text"
            lines.append(
                f"- {entry.get('tag', '')}: {self._compact_text(str(excerpt), 180)}"
            )
        cortex_state = payload.get("cortex_state", {})
        if cortex_state:
            policy = cortex_state.get("policy", {})
            lines.append("## Cortex Governor")
            lines.append(
                (
                    f"- Active Sessions: {cortex_state.get('active_session_count', 0)} | "
                    f"Policy: {policy.get('policy_id', 'cognitive_governance:strict')}"
                )
            )
            typed_counts = cortex_state.get("typed_memory_counts", {})
            if typed_counts:
                counts_text = ", ".join(
                    f"{key}={value}" for key, value in sorted(typed_counts.items())
                )
                lines.append(f"- Typed Memory: {counts_text}")
            for item in cortex_state.get("high_confidence_truths", [])[:3]:
                lines.append(
                    (
                        f"- {item.get('trace_type', 'evidence')} "
                        f"({item.get('truth_posture', 'observed')}, "
                        f"{item.get('confidence', 0.0)}): "
                        f"{self._compact_text(str(item.get('excerpt', '')), 150)}"
                    )
                )
        lines.append("## Operator Safety")
        lines.append(
            "- Treat this as local working memory. Prune sensitive, wrong, or partial data before it influences future recall."
        )
        return "\n".join(lines)

    def _compact_text(self, value: str, limit: int) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 3)].rstrip() + "..."

    def ingest_text_events(
        self,
        *,
        text: str,
        context_id: str = "default",
        source_tag: str = "memory",
        surprise_threshold: float = 0.62,
        min_segment_sentences: int = 2,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        source = sanitize_tag(source_tag).replace(" ", "-")
        safe_text, input_redactions = redact_capture_text(str(text or ""))
        safe_metadata = self._json_safe_metadata(metadata)
        if input_redactions:
            safe_metadata = {
                **safe_metadata,
                "redaction_count": int(
                    input_redactions
                    + int(safe_metadata.get("redaction_count", 0) or 0)
                ),
                "raw_text_stored": False,
            }
        surprise_model = self._surprise_model_info()
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=surprise_threshold,
            min_segment_sentences=min_segment_sentences,
            embedding_fn=self._embed_sentence_for_surprise,
        )
        segments = segmenter.segment(
            safe_text,
            context_id=context,
            source_tag=source,
        )
        registrations: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []
        try:
            for segment in segments:
                safe_segment = dict(segment)
                safe_segment_text, segment_redactions = redact_capture_text(
                    str(segment.get("text") or "")
                )
                safe_segment["text"] = safe_segment_text
                safe_segment["keywords"] = self._surface_words(safe_segment_text)[:10]
                if segment_redactions:
                    safe_segment["redaction_count"] = int(segment_redactions)
                    safe_segment["raw_text_stored"] = False
                event_metadata = self._json_safe_metadata(
                    {
                        **safe_metadata,
                        "event_segment": True,
                        "segment_id": safe_segment["segment_id"],
                        "sequence_id": safe_segment["sequence_id"],
                        "segment_index": safe_segment["segment_index"],
                        "sentence_count": safe_segment["sentence_count"],
                        "surprise_score": safe_segment["surprise_score"],
                        "surprise_mode": safe_segment.get("surprise_mode", "lexical"),
                        "lexical_surprise_score": segment.get(
                            "lexical_surprise_score",
                            safe_segment["surprise_score"],
                        ),
                        "semantic_surprise_score": segment.get(
                            "semantic_surprise_score",
                            0.0,
                        ),
                        "surprise_model": surprise_model,
                        "keywords": safe_segment["keywords"],
                        "source_tag": safe_segment["source_tag"],
                    }
                )
                registration = self.register_text_trace(
                    tag=self._event_memory_tag(segment=safe_segment),
                    context_id=context,
                    metadata=event_metadata,
                    text=safe_segment_text,
                )
                registration["segment"] = safe_segment
                registrations.append(registration)

            for index in range(1, len(registrations)):
                previous = registrations[index - 1]
                current = registrations[index]
                current_segment = current["segment"]
                relationships.append(
                    self.memory_store.upsert_relationship(
                        context_id=context,
                        source_memory_id=previous["memory_id"],
                        target_memory_id=current["memory_id"],
                        relation_type="temporal_next",
                        weight=max(0.5, float(current_segment["surprise_score"])),
                        evidence={
                            "sequence_id": current_segment["sequence_id"],
                            "source_tag": source,
                            "surprise_score": current_segment["surprise_score"],
                            "surprise_mode": current_segment.get(
                                "surprise_mode",
                                "lexical",
                            ),
                            "lexical_surprise_score": current_segment.get(
                                "lexical_surprise_score",
                                current_segment["surprise_score"],
                            ),
                            "semantic_surprise_score": current_segment.get(
                                "semantic_surprise_score",
                                0.0,
                            ),
                            "surprise_model": surprise_model,
                        },
                    )
                )

            relationships.extend(
                self._link_semantic_event_overlaps(
                    context=context,
                    registrations=registrations,
                    source_tag=source,
                )
            )
            self._refresh_registered_traces()
            return {
                "context_id": context,
                "source_tag": source,
                "sequence_id": segments[0]["sequence_id"] if segments else "",
                "event_count": len(registrations),
                "relationship_count": len(relationships),
                "surprise_model": surprise_model,
                "events": [
                    {
                        "tag": item["tag"],
                        "memory_id": item["memory_id"],
                        "segment": item["segment"],
                    }
                    for item in registrations
                ],
                "relationships": relationships,
                "memory_db_path": str(self.memory_store.db_path),
            }
        except Exception:
            LOGGER.exception("event ingestion failed for context_id=%s source_tag=%s", context, source)
            raise

    def _embed_sentence_for_surprise(self, sentence: str) -> list[float]:
        payload = self.embed_text_payload(str(sentence or ""), dimensions=self.dimension)
        embedding = payload["embedding"]
        try:
            return [float(value) for value in embedding.tolist()]
        except AttributeError:
            return [float(value) for value in embedding]

    def _event_memory_tag(self, *, segment: dict[str, Any]) -> str:
        base_tag = sanitize_tag(str(segment.get("tag") or "event")).replace(" ", "-")
        sequence_id = str(segment.get("sequence_id") or "")
        digest = hashlib.sha256(sequence_id.encode("utf-8")).hexdigest()[:8]
        return sanitize_tag(f"{base_tag}-{digest}").replace(" ", "-")

    def _surprise_model_info(self) -> dict[str, Any]:
        provider_info = self.embedding_provider_info()
        provider_id = str(
            provider_info.get("provider")
            or getattr(self.embedding_provider, "provider_id", "")
            or self.embedding_provider_name
            or "unknown"
        )
        return self._json_safe_metadata(
            {
                "mode": "embedding-cosine",
                "fallback": "lexical-jaccard",
                "embedding_provider": provider_id,
                "provider_type": provider_info.get("provider_type", "unknown"),
                "semantic": bool(provider_info.get("semantic", False)),
                "local_only": bool(provider_info.get("local_only", True)),
                "dimensions": int(self.dimension),
            }
        )

    def _surface_node_details(
        self,
        *,
        tag: str,
        text: str,
        metadata: dict[str, Any] | None,
    ) -> dict[str, Any]:
        source_text, _ = redact_capture_text(str(text or ""))
        metadata = metadata if isinstance(metadata, dict) else {}
        label = self._surface_label_from_fields(
            tag=tag,
            text=source_text,
            metadata=metadata,
        )
        summary = str(metadata.get("display_summary") or "").strip()
        if not summary:
            summary = self._compact_text(
                self._extract_first_sentence(source_text) or source_text or label,
                180,
            )
        facets = self._surface_facets(
            label=label,
            text=source_text,
            metadata=metadata,
        )
        detail_badges = self._surface_detail_badges(metadata)
        return self._json_safe_metadata(
            {
                "display_label": label,
                "display_summary": summary,
                "semantic_facets": facets,
                "detail_badges": detail_badges,
            }
        )

    def _surface_label_from_fields(
        self,
        *,
        tag: str,
        text: str,
        metadata: dict[str, Any],
    ) -> str:
        existing = str(metadata.get("display_label") or "").strip()
        if existing:
            return self._compact_text(self._clean_context_label(existing), 72)
        context_memory_type = str(metadata.get("context_memory_type") or "").strip().lower()
        namespace_title = self._clean_context_label(
            str(metadata.get("context_namespace_title") or "")
        )
        context_label = self._clean_context_label(str(metadata.get("context_label") or ""))
        if context_memory_type == "namespace" and namespace_title:
            return self._compact_text(namespace_title, 72)
        if context_memory_type and context_label:
            return self._compact_text(f"{context_memory_type.title()}: {context_label}", 72)
        prefixed = self._extract_context_label_with_prefix(text)
        if prefixed:
            return self._compact_text(prefixed, 72)
        first_sentence = self._extract_first_sentence(text)
        if first_sentence:
            return self._compact_text(first_sentence, 72)
        clean_tag = sanitize_tag(tag)
        return self._compact_text(clean_tag, 72)

    def _extract_context_label_with_prefix(self, text: str) -> str:
        for prefix in ("thread", "feature", "topic", "namespace", "goal", "objective", "event"):
            value = self._extract_prefixed_context_value(text, prefixes=(prefix,))
            if value:
                label = self._clean_context_label(value)
                if not label:
                    continue
                display_prefix = "Topic" if prefix in {"thread", "feature", "namespace"} else prefix.title()
                return f"{display_prefix}: {label}"
        return ""

    def _surface_facets(
        self,
        *,
        label: str,
        text: str,
        metadata: dict[str, Any],
        limit: int = 8,
    ) -> list[str]:
        facets: list[str] = []

        def add_facet(value: Any) -> None:
            clean = self._clean_context_label(str(value or "")).lower()
            if not clean:
                return
            clean = re.sub(r"\s+", " ", clean)
            if len(clean) < 3 or clean in SURFACE_DETAIL_STOP_WORDS:
                return
            if clean not in facets:
                facets.append(clean)

        context_memory_type = metadata.get("context_memory_type")
        if context_memory_type:
            add_facet(context_memory_type)
        for phrase_key in ("context_namespace_title", "context_label", "source_tag", "speaker"):
            phrase = metadata.get(phrase_key)
            if phrase and phrase_key != "speaker":
                add_facet(phrase)
        keywords = metadata.get("keywords")
        if isinstance(keywords, (list, tuple)):
            for keyword in keywords[:12]:
                add_facet(keyword)
        for word in self._surface_words(" ".join([label, text])):
            add_facet(word)
            if len(facets) >= limit:
                break
        return facets[:limit]

    def _surface_words(self, value: str) -> list[str]:
        words: list[str] = []
        seen: set[str] = set()
        for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", str(value or "").lower()):
            if word in SURFACE_DETAIL_STOP_WORDS or word in seen:
                continue
            seen.add(word)
            words.append(word)
        return words

    def _surface_recall_terms(self, value: str) -> list[str]:
        terms: list[str] = []
        seen: set[str] = set()
        for match in SURFACE_RECALL_TERM_RE.finditer(str(value or "").lower()):
            term = match.group(0).strip("._/:-")
            if len(term) < 2 or term in SURFACE_DETAIL_STOP_WORDS or term in seen:
                continue
            seen.add(term)
            terms.append(term)
        return terms

    def _is_concrete_surface_recall_term(self, term: str) -> bool:
        return any(char.isdigit() for char in term) or any(
            char in term for char in ("_", "-", "/", ":")
        )

    def _surface_detail_badges(self, metadata: dict[str, Any]) -> list[str]:
        badges: list[str] = []
        for key in ("context_memory_type", "source_tag", "source", "speaker"):
            value = self._clean_context_label(str(metadata.get(key) or ""))
            if value and value not in badges:
                badges.append(value)
        return badges[:4]

    def _canonical_capture_id(self, capture_id: str | None) -> str:
        if capture_id is None:
            return f"s2cap_{uuid.uuid4().hex}"
        if type(capture_id) is not str or CAPTURE_ID_RE.fullmatch(capture_id) is None:
            raise ValueError(
                "capture_id must use canonical s2cap_<32 lowercase hex> format"
            )
        return capture_id

    def _capture_safe_metadata(
        self,
        metadata: dict[str, Any] | None,
    ) -> tuple[dict[str, Any], int]:
        """Return canonical, key-aware redacted metadata for a capture plan.

        Capture producers historically supplied ``input_sha256`` over raw text.
        Persisting that value would retain a stable digest of secrets even after
        the text itself was redacted, so capture.v2 deliberately discards those
        untrusted raw-input digest fields.
        """

        source = metadata if isinstance(metadata, dict) else {}
        redacted_value, value_redactions = redact_sensitive_value(source)
        try:
            serialized = json.dumps(
                redacted_value,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("capture metadata must be finite JSON-safe data") from exc
        decoded = json.loads(serialized)
        stripped, _removed_digest_count = strip_untrusted_raw_digest_fields(decoded)
        if not isinstance(stripped, dict):  # pragma: no cover - source is a dict
            stripped = {}
        return (
            self._json_safe_metadata(stripped),
            int(value_redactions),
        )

    def _capture_request_fingerprint(
        self,
        *,
        text: str,
        context_id: str,
        source_tag: str,
        speaker: str,
        surprise_threshold: float,
        min_segment_sentences: int,
        metadata: dict[str, Any],
    ) -> str:
        return capture_request_fingerprint(
            text=text,
            context_id=context_id,
            source_tag=source_tag,
            speaker=speaker,
            surprise_threshold=surprise_threshold,
            min_segment_sentences=min_segment_sentences,
            metadata=metadata,
        )

    def _capture_operation_matches(
        self,
        operation: dict[str, Any],
        *,
        request_fingerprint: str,
        context_id: str,
        source_tag: str,
        speaker: str,
    ) -> bool:
        return bool(
            operation.get("protocol") == CAPTURE_PROTOCOL_VERSION
            and operation.get("request_fingerprint") == request_fingerprint
            and operation.get("context_id") == context_id
            and operation.get("source_tag") == source_tag
            and operation.get("speaker") == speaker
        )

    def _capture_response_from_operation(
        self,
        operation: dict[str, Any],
        *,
        idempotent_replay: bool,
    ) -> dict[str, Any]:
        raw_result = operation.get("result")
        if not isinstance(raw_result, dict):
            raise RuntimeError("capture receipt is missing its committed result")
        deployment = operation.get("deployment_event")
        if not isinstance(deployment, dict):
            raise RuntimeError("capture receipt is missing its deployment event")
        response = {
            "action": "capture-conversation",
            "status": str(raw_result.get("status") or "committed"),
            "context_id": str(operation.get("context_id") or ""),
            "source_tag": str(operation.get("source_tag") or ""),
            "speaker": str(operation.get("speaker") or ""),
            "event_count": int(raw_result.get("event_count") or 0),
            "entry_count": int(raw_result.get("entry_count") or 0),
            "relationship_count": int(
                raw_result.get("relationship_count") or 0
            ),
            "capture_id": str(operation.get("capture_id") or ""),
            "protocol": CAPTURE_PROTOCOL_VERSION,
            "capture_protocol": CAPTURE_PROTOCOL_VERSION,
            "idempotent_replay": bool(idempotent_replay),
            "receipt_compact": True,
            "agent_deployment": self._decorate_context_event(deployment),
        }
        # The request fingerprint is durable conflict-detection state, not a
        # public content digest.  Never copy it into capture responses.
        response.pop("request_fingerprint", None)
        return response

    def _capture_first_commit_response(
        self,
        *,
        operation: dict[str, Any],
        result: dict[str, Any],
        deployment: dict[str, Any],
    ) -> dict[str, Any]:
        """Render the rich first response without duplicating it in SQLite."""

        deployment_receipt = operation.get("deployment_event")
        if not isinstance(deployment_receipt, dict):
            raise RuntimeError("capture receipt is missing its deployment event")
        response = dict(result)
        response.update(
            {
                "capture_id": str(operation.get("capture_id") or ""),
                "protocol": CAPTURE_PROTOCOL_VERSION,
                "capture_protocol": CAPTURE_PROTOCOL_VERSION,
                "idempotent_replay": False,
                "receipt_compact": False,
                "agent_deployment": self._decorate_context_event(
                    {
                        **deployment,
                        **deployment_receipt,
                    }
                ),
            }
        )
        response.pop("request_fingerprint", None)
        return response

    def replay_capture_operation(
        self,
        capture_id: str,
        *,
        context_id: str | None = None,
        source_tag: str | None = None,
        speaker: str | None = None,
    ) -> dict[str, Any] | None:
        """Return an existing durable receipt without re-reading live input.

        Dynamic producers such as clipboard and Accessibility adapters cannot
        safely reconstruct a request after a successful response is lost: the
        external surface may already have changed.  They call this lookup
        before observing that surface again.  Optional producer identities are
        checked against the committed operation so an ID cannot cross a
        context/source/speaker boundary.
        """

        canonical_capture_id = self._canonical_capture_id(capture_id)
        operation = self.memory_store.get_capture_operation(canonical_capture_id)
        if operation is None:
            return None
        expected = {
            "context_id": (
                sanitize_context_id(context_id) if context_id is not None else None
            ),
            "source_tag": (
                sanitize_tag(source_tag).replace(" ", "-")
                if source_tag is not None
                else None
            ),
            "speaker": sanitize_agent_id(speaker) if speaker is not None else None,
        }
        mismatched = [
            key
            for key, value in expected.items()
            if value is not None and operation.get(key) != value
        ]
        if mismatched:
            raise ValueError(
                "capture_id is already committed for a different capture producer"
            )
        response = self._capture_response_from_operation(
            operation,
            idempotent_replay=True,
        )
        self._refresh_after_capture(committed_new_operation=False)
        return response

    def _refresh_after_capture(self, *, committed_new_operation: bool) -> None:
        refreshes = [
            self._refresh_registered_traces,
            self._surface_recall_cache.clear,
        ]
        if committed_new_operation:
            refreshes.append(self._persist_runtime_state)
        refreshes.append(self._mark_activity)
        for refresh in refreshes:
            try:
                refresh()
            except Exception:
                # The SQLite receipt is authoritative. A cache or JSON runtime
                # refresh is repairable and must never revoke committed success.
                LOGGER.exception("post-commit capture runtime refresh failed")

    def _prepare_capture_entry(
        self,
        *,
        tag: str,
        text: str,
        context_id: str,
        metadata: dict[str, Any],
        registered_at: float,
    ) -> dict[str, Any]:
        redacted_text, text_redactions = redact_capture_text(str(text or ""))
        safe_metadata, metadata_redactions = self._capture_safe_metadata(metadata)
        total_redactions = int(text_redactions + metadata_redactions)
        if total_redactions:
            safe_metadata = {
                **safe_metadata,
                "redaction_count": int(
                    total_redactions + int(safe_metadata.get("redaction_count", 0) or 0)
                ),
                "raw_text_stored": False,
            }
        payload = self.embed_text_payload(redacted_text)
        base_metadata = {
            **safe_metadata,
            "embedding_provider": payload["provenance"],
        }
        merged_metadata = self._json_safe_metadata(
            {
                **base_metadata,
                **self._surface_node_details(
                    tag=tag,
                    text=redacted_text,
                    metadata=base_metadata,
                ),
            }
        )
        clean_tag = sanitize_tag(tag)
        embedding = self._coerce_embedding(payload["embedding"])
        self._ensure_projection_shape(int(embedding.shape[0]))
        sensory_spikes = self.encode_to_spikes_top_k(embedding)
        spike_indices = self._active_indices_from_spikes(sensory_spikes)
        neuron_indices = self._project_sensory_indices(spike_indices)
        memory_id = self.memory_store.stable_memory_id(
            context_id=context_id,
            tag=clean_tag,
        )
        return {
            "memory_id": memory_id,
            "tag": clean_tag,
            "context_id": context_id,
            "source_text": redacted_text,
            "metadata": merged_metadata,
            "embedding_dimensions": int(embedding.shape[0]),
            "spike_indices": spike_indices,
            "neuron_indices": neuron_indices,
            "registered_at": float(registered_at),
        }

    def _prepare_capture_relationship(
        self,
        *,
        context_id: str,
        source_memory_id: str,
        target_memory_id: str,
        relation_type: str,
        weight: float,
        evidence: dict[str, Any],
        entries_by_id: dict[str, dict[str, Any]],
        created_at: float,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        numeric_weight = float(weight)
        if not math.isfinite(numeric_weight):
            raise ValueError("capture relationship weight must be finite")
        bounded_weight = min(max(numeric_weight, 0.0), 1.0)
        safe_evidence, _redactions = self._capture_safe_metadata(evidence)
        relationship_id = self.memory_store.stable_relationship_id(
            context_id=context_id,
            source_memory_id=source_memory_id,
            target_memory_id=target_memory_id,
            relation_type=relation_type,
        )
        spec = {
            "relationship_id": relationship_id,
            "context_id": context_id,
            "source_memory_id": source_memory_id,
            "target_memory_id": target_memory_id,
            "relation_type": relation_type,
            "weight": bounded_weight,
            "evidence": safe_evidence,
            "created_at": float(created_at),
        }
        source_entry = entries_by_id[source_memory_id]
        target_entry = entries_by_id[target_memory_id]
        rendered = {
            **spec,
            "source_tag": source_entry["tag"],
            "target_tag": target_entry["tag"],
            "weight": round(bounded_weight, 6),
            "updated_at": float(created_at),
        }
        return spec, rendered

    def _capture_event_memory_tag(
        self,
        *,
        segment: dict[str, Any],
        capture_id: str,
    ) -> str:
        base_tag = sanitize_tag(str(segment.get("tag") or "event")).replace(" ", "-")
        return sanitize_tag(f"{base_tag}-{capture_id[6:]}").replace(" ", "-")

    def _build_capture_plan(
        self,
        *,
        capture_id: str,
        text: str,
        context_id: str,
        source_tag: str,
        speaker: str,
        surprise_threshold: float,
        min_segment_sentences: int,
        metadata: dict[str, Any],
        namespace_profile: dict[str, Any],
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
        dict[str, Any],
        dict[str, Any],
    ]:
        planned_at = time.time()
        surprise_model = self._surprise_model_info()
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=surprise_threshold,
            min_segment_sentences=min_segment_sentences,
            embedding_fn=self._embed_sentence_for_surprise,
        )
        segments = segmenter.segment(
            text,
            context_id=context_id,
            source_tag=source_tag,
        )
        entries: list[dict[str, Any]] = []
        entries_by_id: dict[str, dict[str, Any]] = {}
        relationship_specs: list[dict[str, Any]] = []
        relationship_results: list[dict[str, Any]] = []
        relationship_ids: set[str] = set()

        def add_entry(*, tag: str, source_text: str, entry_metadata: dict[str, Any]) -> dict[str, Any]:
            entry = self._prepare_capture_entry(
                tag=tag,
                text=source_text,
                context_id=context_id,
                metadata=entry_metadata,
                registered_at=planned_at,
            )
            existing = entries_by_id.get(str(entry["memory_id"]))
            if existing is None:
                entries.append(entry)
                entries_by_id[str(entry["memory_id"])] = entry
                return entry
            if existing != entry:
                raise ValueError("capture plan produced conflicting stable memory entries")
            return existing

        def add_relationship(
            *,
            source_memory_id: str,
            target_memory_id: str,
            relation_type: str,
            weight: float,
            evidence: dict[str, Any],
        ) -> dict[str, Any]:
            spec, rendered = self._prepare_capture_relationship(
                context_id=context_id,
                source_memory_id=source_memory_id,
                target_memory_id=target_memory_id,
                relation_type=relation_type,
                weight=weight,
                evidence=evidence,
                entries_by_id=entries_by_id,
                created_at=planned_at,
            )
            relationship_id = str(spec["relationship_id"])
            if relationship_id not in relationship_ids:
                relationship_ids.add(relationship_id)
                relationship_specs.append(spec)
                relationship_results.append(rendered)
                return rendered
            return next(
                item
                for item in relationship_results
                if item["relationship_id"] == relationship_id
            )

        event_records: list[dict[str, Any]] = []
        capture_metadata = self._json_safe_metadata(
            {
                **metadata,
                "source": "conversation-capture",
                "conversation_capture": True,
                "speaker": speaker,
                "temporal": True,
                "capture_id": capture_id,
                "capture_protocol": CAPTURE_PROTOCOL_VERSION,
                "context_namespace": namespace_profile["namespace_id"],
                "context_namespace_title": namespace_profile["namespace_title"],
                "context_namespace_source": namespace_profile["namespace_source"],
            }
        )
        for segment in segments:
            safe_segment = dict(segment)
            safe_segment_text, segment_redactions = redact_capture_text(
                str(segment.get("text") or "")
            )
            safe_segment["text"] = safe_segment_text
            safe_segment["keywords"] = self._surface_words(safe_segment_text)[:10]
            if segment_redactions:
                safe_segment["redaction_count"] = int(segment_redactions)
                safe_segment["raw_text_stored"] = False
            event_metadata = self._json_safe_metadata(
                {
                    **capture_metadata,
                    "event_segment": True,
                    "segment_id": safe_segment["segment_id"],
                    "sequence_id": safe_segment["sequence_id"],
                    "segment_index": safe_segment["segment_index"],
                    "sentence_count": safe_segment["sentence_count"],
                    "surprise_score": safe_segment["surprise_score"],
                    "surprise_mode": safe_segment.get("surprise_mode", "lexical"),
                    "lexical_surprise_score": safe_segment.get(
                        "lexical_surprise_score",
                        safe_segment["surprise_score"],
                    ),
                    "semantic_surprise_score": safe_segment.get(
                        "semantic_surprise_score",
                        0.0,
                    ),
                    "surprise_model": surprise_model,
                    "keywords": safe_segment["keywords"],
                    "source_tag": safe_segment["source_tag"],
                }
            )
            entry = add_entry(
                tag=self._capture_event_memory_tag(
                    segment=safe_segment,
                    capture_id=capture_id,
                ),
                source_text=safe_segment_text,
                entry_metadata=event_metadata,
            )
            event_records.append(
                {
                    "tag": entry["tag"],
                    "memory_id": entry["memory_id"],
                    "segment": safe_segment,
                }
            )

        for previous, current in zip(event_records, event_records[1:]):
            current_segment = current["segment"]
            add_relationship(
                source_memory_id=str(previous["memory_id"]),
                target_memory_id=str(current["memory_id"]),
                relation_type="temporal_next",
                weight=max(0.5, float(current_segment["surprise_score"])),
                evidence={
                    "capture_id": capture_id,
                    "sequence_id": current_segment["sequence_id"],
                    "source_tag": source_tag,
                    "surprise_score": current_segment["surprise_score"],
                    "surprise_mode": current_segment.get("surprise_mode", "lexical"),
                    "lexical_surprise_score": current_segment.get(
                        "lexical_surprise_score",
                        current_segment["surprise_score"],
                    ),
                    "semantic_surprise_score": current_segment.get(
                        "semantic_surprise_score",
                        0.0,
                    ),
                    "surprise_model": surprise_model,
                },
            )

        for left_index, left in enumerate(event_records):
            left_keywords = set(left["segment"]["keywords"])
            if not left_keywords:
                continue
            for right in event_records[left_index + 1 :]:
                right_keywords = set(right["segment"]["keywords"])
                if not right_keywords:
                    continue
                overlap = left_keywords & right_keywords
                if not overlap:
                    continue
                weight = len(overlap) / max(1, len(left_keywords | right_keywords))
                if weight < 0.12:
                    continue
                add_relationship(
                    source_memory_id=str(left["memory_id"]),
                    target_memory_id=str(right["memory_id"]),
                    relation_type="semantic_overlap",
                    weight=weight,
                    evidence={
                        "capture_id": capture_id,
                        "source_tag": source_tag,
                        "keywords": sorted(overlap),
                    },
                )

        namespace_id = str(namespace_profile.get("namespace_id") or "default")
        namespace_title, _namespace_redactions = redact_capture_text(
            str(namespace_profile.get("namespace_title") or namespace_id)
        )
        sequence_id = str(segments[0]["sequence_id"] if segments else "")
        namespace_metadata = {
            "source": "context-namespace-automation",
            "context_automation": True,
            "context_namespace": namespace_id,
            "context_namespace_title": namespace_title,
            "context_namespace_source": namespace_profile.get("namespace_source", ""),
            "source_tag": source_tag,
            "speaker": speaker,
            "sequence_id": sequence_id,
            "capture_id": capture_id,
            "capture_protocol": CAPTURE_PROTOCOL_VERSION,
        }
        namespace_entry = add_entry(
            tag=f"namespace-{namespace_id}",
            source_text=f"Namespace: {namespace_title}",
            entry_metadata={
                **namespace_metadata,
                "context_namespace_anchor": True,
                "context_memory_type": "namespace",
            },
        )
        namespace_nodes: list[dict[str, Any]] = [
            {
                "memory_id": namespace_entry["memory_id"],
                "tag": namespace_entry["tag"],
                "context_memory_type": "namespace",
                "text": namespace_entry["source_text"],
            }
        ]
        typed_nodes: list[dict[str, Any]] = []
        labels = (
            namespace_profile.get("labels")
            if isinstance(namespace_profile.get("labels"), dict)
            else {}
        )
        for memory_type in ("topic", "goal", "objective", "event"):
            values = labels.get(memory_type, [])
            if not isinstance(values, list):
                continue
            for index, label in enumerate(values, start=1):
                clean_label, _label_redactions = redact_capture_text(
                    self._clean_context_label(str(label or ""))
                )
                clean_label = self._clean_context_label(clean_label)
                if not clean_label:
                    continue
                identity_parts = [namespace_id, memory_type, str(index), clean_label]
                digest = hashlib.sha256(
                    "\x1f".join(identity_parts).encode("utf-8")
                ).hexdigest()[:8]
                if memory_type == "event":
                    # Event nodes are temporal occurrences. Use the complete
                    # capture identity instead of a collision-prone short hash.
                    digest = capture_id[6:]
                entry = add_entry(
                    tag=f"namespace-{namespace_id}-{memory_type}-{index}-{digest}",
                    source_text=f"{memory_type.title()}: {clean_label}",
                    entry_metadata={
                        **namespace_metadata,
                        "context_memory_type": memory_type,
                        "context_label": clean_label,
                        "context_label_index": index,
                    },
                )
                node = {
                    "memory_id": entry["memory_id"],
                    "tag": entry["tag"],
                    "context_memory_type": memory_type,
                    "text": entry["source_text"],
                }
                typed_nodes.append(node)
                namespace_nodes.append(node)

        namespace_relationships: list[dict[str, Any]] = []
        for node in typed_nodes:
            namespace_relationships.append(
                add_relationship(
                    source_memory_id=str(namespace_entry["memory_id"]),
                    target_memory_id=str(node["memory_id"]),
                    relation_type="namespace_contains",
                    weight=0.95,
                    evidence={
                        "capture_id": capture_id,
                        "namespace_id": namespace_id,
                        "target_type": node["context_memory_type"],
                        "source_tag": source_tag,
                    },
                )
            )
        for event in event_records:
            namespace_relationships.append(
                add_relationship(
                    source_memory_id=str(namespace_entry["memory_id"]),
                    target_memory_id=str(event["memory_id"]),
                    relation_type="namespace_contains",
                    weight=0.88,
                    evidence={
                        "capture_id": capture_id,
                        "namespace_id": namespace_id,
                        "target_type": "conversation_event",
                        "source_tag": source_tag,
                    },
                )
            )
        for previous, current in zip(typed_nodes, typed_nodes[1:]):
            namespace_relationships.append(
                add_relationship(
                    source_memory_id=str(previous["memory_id"]),
                    target_memory_id=str(current["memory_id"]),
                    relation_type="typed_context_sequence",
                    weight=0.74,
                    evidence={
                        "capture_id": capture_id,
                        "namespace_id": namespace_id,
                        "source_type": previous["context_memory_type"],
                        "target_type": current["context_memory_type"],
                        "source_tag": source_tag,
                    },
                )
            )

        context_namespace = {
            "namespace_id": namespace_id,
            "namespace_title": namespace_title,
            "namespace_source": namespace_profile.get("namespace_source", ""),
            "context_id": context_id,
            "source_tag": source_tag,
            "speaker": speaker,
            "node_count": len(namespace_nodes),
            "source_event_count": len(event_records),
            "relationship_count": len(namespace_relationships),
            "nodes": namespace_nodes,
            "relationships": namespace_relationships,
            "automated": True,
        }
        result = {
            "context_id": context_id,
            "source_tag": source_tag,
            "sequence_id": sequence_id,
            "event_count": len(event_records),
            "relationship_count": len(relationship_results),
            "surprise_model": surprise_model,
            "events": event_records,
            "relationships": relationship_results,
            "memory_db_path": str(self.memory_store.db_path),
            "action": "capture-conversation",
            "speaker": speaker,
            "context_namespace": context_namespace,
        }
        deployment = {
            "context_id": context_id,
            "source_surface": "conversation-capture",
            "event_type": "conversation-capture",
            "summary": f"{source_tag} captured {len(event_records)} conversation events",
            "payload": {
                "capture_id": capture_id,
                "protocol": CAPTURE_PROTOCOL_VERSION,
                "source_tag": source_tag,
                "sequence_id": sequence_id,
                "speaker": speaker,
                "event_count": len(event_records),
                "relationship_count": len(relationship_results),
                "context_namespace": context_namespace,
                "events": event_records,
                "relationships": relationship_results,
            },
            "agent_targets": list(DEFAULT_AGENT_TARGETS),
            "created_at": planned_at,
        }
        return entries, relationship_specs, deployment, result

    def capture_conversation(
        self,
        *,
        text: str,
        context_id: str = "default",
        source_tag: str = "codex-session",
        speaker: str = "operator",
        surprise_threshold: float = 0.5,
        min_segment_sentences: int = 1,
        metadata: dict[str, Any] | None = None,
        capture_id: str | None = None,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        source = sanitize_tag(source_tag).replace(" ", "-")
        raw_text = str(text or "").strip()
        if not raw_text:
            raise ValueError("conversation text must not be empty")
        clean_speaker = sanitize_agent_id(speaker)
        canonical_capture_id = self._canonical_capture_id(capture_id)
        clean_text, text_redactions = redact_capture_text(raw_text)
        safe_metadata, metadata_redactions = self._capture_safe_metadata(metadata)
        total_redactions = int(text_redactions + metadata_redactions)
        if total_redactions:
            safe_metadata = {
                **safe_metadata,
                "redaction_count": int(
                    total_redactions + int(safe_metadata.get("redaction_count", 0) or 0)
                ),
                "raw_text_stored": False,
            }
        try:
            normalized_threshold = float(surprise_threshold)
        except (TypeError, ValueError) as exc:
            raise ValueError("surprise_threshold must be a finite number") from exc
        if not math.isfinite(normalized_threshold):
            raise ValueError("surprise_threshold must be a finite number")
        normalized_threshold = min(max(normalized_threshold, 0.0), 1.0)
        if normalized_threshold == 0.0:
            normalized_threshold = 0.0  # canonicalize negative zero for hashing
        if isinstance(min_segment_sentences, bool):
            raise ValueError("min_segment_sentences must be an integer")
        try:
            normalized_min_sentences = max(1, int(min_segment_sentences))
        except (TypeError, ValueError) as exc:
            raise ValueError("min_segment_sentences must be an integer") from exc
        request_fingerprint = self._capture_request_fingerprint(
            text=clean_text,
            context_id=context,
            source_tag=source,
            speaker=clean_speaker,
            surprise_threshold=normalized_threshold,
            min_segment_sentences=normalized_min_sentences,
            metadata=safe_metadata,
        )

        committed = self.memory_store.get_capture_operation(canonical_capture_id)
        if committed is not None:
            if not self._capture_operation_matches(
                committed,
                request_fingerprint=request_fingerprint,
                context_id=context,
                source_tag=source,
                speaker=clean_speaker,
            ):
                raise ValueError(
                    "capture_id is already committed for a different capture request"
                )
            response = self._capture_response_from_operation(
                committed,
                idempotent_replay=True,
            )
            # A prior caller may have lost the response after SQLite committed
            # but before this process refreshed its in-memory trace view.
            self._refresh_after_capture(committed_new_operation=False)
            return response

        namespace_profile = self._infer_context_namespace(
            text=clean_text,
            context_id=context,
            source_tag=source,
            speaker=clean_speaker,
            metadata=safe_metadata,
        )
        try:
            entries, relationships, deployment, result = self._build_capture_plan(
                capture_id=canonical_capture_id,
                text=clean_text,
                context_id=context,
                source_tag=source,
                speaker=clean_speaker,
                surprise_threshold=normalized_threshold,
                min_segment_sentences=normalized_min_sentences,
                metadata=safe_metadata,
                namespace_profile=namespace_profile,
            )
            operation = self.memory_store.commit_capture_plan(
                capture_id=canonical_capture_id,
                request_fingerprint=request_fingerprint,
                context_id=context,
                source_tag=source,
                speaker=clean_speaker,
                entries=entries,
                relationships=relationships,
                deployment=deployment,
                result=result,
            )
            idempotent_replay = bool(operation.get("idempotent_replay", False))
            response = (
                self._capture_response_from_operation(
                    operation,
                    idempotent_replay=True,
                )
                if idempotent_replay
                else self._capture_first_commit_response(
                    operation=operation,
                    result=result,
                    deployment=deployment,
                )
            )
            self._refresh_after_capture(
                committed_new_operation=not idempotent_replay
            )
            return response
        except Exception:
            LOGGER.exception(
                "conversation capture failed for context_id=%s source_tag=%s",
                context,
                source,
            )
            raise

    def _infer_context_namespace(
        self,
        *,
        text: str,
        context_id: str,
        source_tag: str,
        speaker: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        explicit = metadata.get("context_namespace") or metadata.get("namespace")
        if isinstance(explicit, dict):
            title = str(
                explicit.get("title")
                or explicit.get("namespace_title")
                or explicit.get("namespace_id")
                or ""
            )
        else:
            title = str(explicit or "")
        namespace_source = "metadata" if title.strip() else "text"
        if not title.strip():
            title = self._extract_prefixed_context_value(
                text,
                prefixes=("thread", "feature", "topic", "namespace"),
            )
        if not title.strip():
            namespace_source = "source-tag"
            title = source_tag
        title = self._clean_context_label(title)
        namespace_id = self._slugify_context_namespace(title)
        labels = self._extract_context_memory_labels(text, namespace_title=title)
        return {
            "namespace_id": namespace_id,
            "namespace_title": title,
            "namespace_source": namespace_source,
            "context_id": context_id,
            "source_tag": source_tag,
            "speaker": speaker,
            "labels": labels,
        }

    def _materialize_context_namespace(
        self,
        *,
        context_id: str,
        source_tag: str,
        speaker: str,
        namespace_profile: dict[str, Any],
        ingestion: dict[str, Any],
    ) -> dict[str, Any]:
        namespace_id = str(namespace_profile.get("namespace_id") or "default")
        namespace_title, _namespace_redactions = redact_capture_text(
            str(namespace_profile.get("namespace_title") or namespace_id)
        )
        sequence_id = str(ingestion.get("sequence_id") or "")
        base_metadata = {
            "source": "context-namespace-automation",
            "context_automation": True,
            "context_namespace": namespace_id,
            "context_namespace_title": namespace_title,
            "context_namespace_source": namespace_profile.get("namespace_source", ""),
            "source_tag": source_tag,
            "speaker": speaker,
            "sequence_id": sequence_id,
        }
        nodes: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        namespace_node = self.register_text_trace(
            tag=f"namespace-{namespace_id}",
            context_id=context_id,
            text=f"Namespace: {namespace_title}",
            metadata={
                **base_metadata,
                "context_namespace_anchor": True,
                "context_memory_type": "namespace",
            },
        )
        namespace_entry = self.memory_store.get_entry(str(namespace_node["memory_id"]))
        nodes.append(
            {
                "memory_id": namespace_node["memory_id"],
                "tag": namespace_node["tag"],
                "context_memory_type": "namespace",
                "text": str(
                    (namespace_entry or {}).get("source_text")
                    or f"Namespace: {namespace_title}"
                ),
            }
        )

        typed_nodes: list[dict[str, Any]] = []
        labels = namespace_profile.get("labels") if isinstance(namespace_profile.get("labels"), dict) else {}
        for memory_type in ("topic", "goal", "objective", "event"):
            values = labels.get(memory_type, [])
            if not isinstance(values, list):
                continue
            for index, label in enumerate(values, start=1):
                clean_label = self._clean_context_label(str(label or ""))
                clean_label, _label_redactions = redact_capture_text(clean_label)
                clean_label = self._clean_context_label(clean_label)
                if not clean_label:
                    continue
                digest = hashlib.sha256(
                    f"{namespace_id}\x1f{memory_type}\x1f{index}\x1f{clean_label}".encode(
                        "utf-8"
                    )
                ).hexdigest()[:8]
                tag = f"namespace-{namespace_id}-{memory_type}-{index}-{digest}"
                text = f"{memory_type.title()}: {clean_label}"
                node = self.register_text_trace(
                    tag=tag,
                    context_id=context_id,
                    text=text,
                    metadata={
                        **base_metadata,
                        "context_memory_type": memory_type,
                        "context_label": clean_label,
                        "context_label_index": index,
                    },
                )
                stored_entry = self.memory_store.get_entry(str(node["memory_id"]))
                typed_node = {
                    "memory_id": node["memory_id"],
                    "tag": node["tag"],
                    "context_memory_type": memory_type,
                    "text": str((stored_entry or {}).get("source_text") or text),
                }
                typed_nodes.append(typed_node)
                nodes.append(typed_node)

        for node in typed_nodes:
            relationships.append(
                self.memory_store.upsert_relationship(
                    context_id=context_id,
                    source_memory_id=namespace_node["memory_id"],
                    target_memory_id=node["memory_id"],
                    relation_type="namespace_contains",
                    weight=0.95,
                    evidence={
                        "namespace_id": namespace_id,
                        "target_type": node["context_memory_type"],
                        "source_tag": source_tag,
                    },
                )
            )

        source_events = ingestion.get("events") if isinstance(ingestion.get("events"), list) else []
        for item in source_events:
            memory_id = str(item.get("memory_id") or "")
            if not memory_id:
                continue
            relationships.append(
                self.memory_store.upsert_relationship(
                    context_id=context_id,
                    source_memory_id=namespace_node["memory_id"],
                    target_memory_id=memory_id,
                    relation_type="namespace_contains",
                    weight=0.88,
                    evidence={
                        "namespace_id": namespace_id,
                        "target_type": "conversation_event",
                        "source_tag": source_tag,
                    },
                )
            )

        for previous, current in zip(typed_nodes, typed_nodes[1:]):
            relationships.append(
                self.memory_store.upsert_relationship(
                    context_id=context_id,
                    source_memory_id=previous["memory_id"],
                    target_memory_id=current["memory_id"],
                    relation_type="typed_context_sequence",
                    weight=0.74,
                    evidence={
                        "namespace_id": namespace_id,
                        "source_type": previous["context_memory_type"],
                        "target_type": current["context_memory_type"],
                        "source_tag": source_tag,
                    },
                )
            )

        self._refresh_registered_traces()
        return {
            "namespace_id": namespace_id,
            "namespace_title": namespace_title,
            "namespace_source": namespace_profile.get("namespace_source", ""),
            "context_id": context_id,
            "source_tag": source_tag,
            "speaker": speaker,
            "node_count": len(nodes),
            "source_event_count": len(source_events),
            "relationship_count": len(relationships),
            "nodes": nodes,
            "relationships": relationships,
            "automated": True,
        }

    def _extract_context_memory_labels(
        self,
        text: str,
        *,
        namespace_title: str,
    ) -> dict[str, list[str]]:
        labels: dict[str, list[str]] = {
            "topic": [self._clean_context_label(namespace_title)],
            "goal": [],
            "objective": [],
            "event": [],
        }
        prefix_map = {
            "thread": "topic",
            "feature": "topic",
            "topic": "topic",
            "namespace": "topic",
            "goal": "goal",
            "goals": "goal",
            "objective": "objective",
            "objectives": "objective",
            "event": "event",
            "events": "event",
        }
        pattern = re.compile(
            r"\b(thread|feature|topic|namespace|goals?|objectives?|events?)\s*:\s*([^.\n;]+)",
            re.IGNORECASE,
        )
        for match in pattern.finditer(str(text or "")):
            target = prefix_map.get(match.group(1).lower(), "")
            label = self._clean_context_label(match.group(2))
            if target and label:
                labels.setdefault(target, []).append(label)
        lowered = str(text or "").lower()
        if not labels["event"] and any(token in lowered for token in ("began", "started", "opened")):
            labels["event"].append(
                self._clean_context_label(
                    self._extract_first_sentence(text) or f"{namespace_title} started"
                )
            )
        return {
            key: self._dedupe_context_labels(values)
            for key, values in labels.items()
            if self._dedupe_context_labels(values)
        }

    def _extract_prefixed_context_value(
        self,
        text: str,
        *,
        prefixes: tuple[str, ...],
    ) -> str:
        joined = "|".join(re.escape(prefix) for prefix in prefixes)
        match = re.search(rf"\b({joined})\s*:\s*([^.\n;]+)", str(text or ""), re.IGNORECASE)
        if match:
            return match.group(2)
        return ""

    def _extract_first_sentence(self, text: str) -> str:
        match = re.search(r"[^.!?\n]+", str(text or "").strip())
        return self._clean_context_label(match.group(0)) if match else ""

    def _clean_context_label(self, value: str) -> str:
        cleaned = " ".join(str(value or "").replace("\n", " ").split()).strip(" .:-")
        return cleaned[:160]

    def _dedupe_context_labels(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            cleaned = self._clean_context_label(value)
            key = cleaned.lower()
            if not cleaned or key in seen:
                continue
            seen.add(key)
            deduped.append(cleaned)
        return deduped

    def _slugify_context_namespace(self, value: str) -> str:
        words = re.findall(r"[A-Za-z0-9]+", str(value or "").lower())
        slug = "-".join(words[:8]).strip("-")
        return sanitize_context_id(slug or "default")

    def prune_memory(
        self,
        *,
        context_id: str = "default",
        target_type: str,
        memory_id: str = "",
        tag: str = "",
        relationship_id: str = "",
        event_id: int = 0,
        reason: str = "",
        source_surface: str = "operator",
        publish_audit: bool = True,
        confirm: bool,
    ) -> dict[str, Any]:
        if confirm is not True:
            raise ValueError("confirm must be true before pruning memory graph data")
        context = sanitize_context_id(context_id)
        clean_reason, _ = redact_capture_text(str(reason or ""))
        clean_source_surface = reject_sensitive_identifier(
            source_surface or "operator",
            field="source_surface",
        ).strip() or "operator"
        normalized_target = str(target_type or "").strip().lower().replace("-", "_")
        if normalized_target in {"node", "memory", "trace", "event"}:
            result = self.memory_store.delete_entry(
                context_id=context,
                memory_id=(
                    reject_sensitive_identifier(memory_id, field="memory_id").strip()
                    or None
                ),
                tag=sanitize_tag(tag) if str(tag or "").strip() else None,
            )
            self._refresh_registered_traces()
            self._persist_runtime_state()
        elif normalized_target in {"relationship", "edge"}:
            clean_relationship_id = reject_sensitive_identifier(
                relationship_id,
                field="relationship_id",
            ).strip()
            if not clean_relationship_id:
                raise ValueError("relationship_id is required for relationship pruning")
            result = self.memory_store.delete_relationship(
                context_id=context,
                relationship_id=clean_relationship_id,
            )
        elif normalized_target in {"temporal", "associative"}:
            result = self.memory_store.delete_relationships_by_mode(
                context_id=context,
                mode=normalized_target,
            )
        elif normalized_target in {"context_event", "deployment", "context_deployment"}:
            if int(event_id or 0) <= 0:
                raise ValueError("event_id is required for context_event pruning")
            result = self.memory_store.delete_context_event(
                context_id=context,
                event_id=int(event_id),
            )
            normalized_target = "context_event"
        else:
            raise ValueError(
                "target_type must be memory, node, event, relationship, edge, "
                "temporal, associative, or context_event"
            )

        safe_result = self._redact_prune_result(result)
        payload = {
            "context_id": context,
            "target_type": normalized_target,
            "reason": clean_reason,
            "result": safe_result,
        }
        audit_event = None
        if publish_audit:
            audit_event = self.publish_context_event(
                context_id=context,
                source_surface=clean_source_surface,
                event_type="prune-memory",
                summary=(
                    f"{normalized_target} prune "
                    f"{'removed data' if safe_result.get('deleted') else 'found no match'}"
                ),
                payload=payload,
            )
        self._mark_activity()
        return {
            "action": "prune-memory",
            "context_id": context,
            "target_type": normalized_target,
            "reason": clean_reason,
            "result": safe_result,
            "agent_deployment": audit_event,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def _redact_prune_result(self, result: dict[str, Any]) -> dict[str, Any]:
        safe = dict(result)
        entry = safe.get("entry")
        if isinstance(entry, dict):
            safe["entry"] = {
                "memory_id": entry.get("memory_id"),
                "tag": entry.get("tag"),
                "context_id": entry.get("context_id"),
                "source_text_bytes": len(str(entry.get("source_text") or "").encode("utf-8")),
            }
        relationship = safe.get("relationship")
        if isinstance(relationship, dict):
            safe["relationship"] = {
                "relationship_id": relationship.get("relationship_id"),
                "context_id": relationship.get("context_id"),
                "source_memory_id": relationship.get("source_memory_id"),
                "target_memory_id": relationship.get("target_memory_id"),
                "relation_type": relationship.get("relation_type"),
                "weight": relationship.get("weight"),
            }
        event = safe.get("event")
        if isinstance(event, dict):
            safe_summary, summary_redactions = redact_capture_text(str(event.get("summary") or ""))
            safe["event"] = {
                "event_id": event.get("event_id"),
                "context_id": event.get("context_id"),
                "event_type": event.get("event_type"),
                "source_surface": event.get("source_surface"),
                "summary": safe_summary,
                "summary_redaction_count": int(summary_redactions),
            }
        return safe

    def _link_semantic_event_overlaps(
        self,
        *,
        context: str,
        registrations: list[dict[str, Any]],
        source_tag: str,
    ) -> list[dict[str, Any]]:
        relationships: list[dict[str, Any]] = []
        for left_index, left in enumerate(registrations):
            left_keywords = set(left["segment"]["keywords"])
            if not left_keywords:
                continue
            for right in registrations[left_index + 1 :]:
                right_keywords = set(right["segment"]["keywords"])
                if not right_keywords:
                    continue
                overlap = left_keywords & right_keywords
                if not overlap:
                    continue
                union = left_keywords | right_keywords
                weight = len(overlap) / max(1, len(union))
                if weight < 0.12:
                    continue
                relationships.append(
                    self.memory_store.upsert_relationship(
                        context_id=context,
                        source_memory_id=left["memory_id"],
                        target_memory_id=right["memory_id"],
                        relation_type="semantic_overlap",
                        weight=weight,
                        evidence={
                            "source_tag": source_tag,
                            "keywords": sorted(overlap),
                        },
                    )
                )
        return relationships

    def approve_namespace_link(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        relation_type: str = "related",
        weight: float = 1.0,
        evidence: dict[str, Any] | None = None,
        direction: str = "bidirectional",
        approved_by: str = "operator",
        enabled: bool = True,
        reason: str = "explicit operator approval",
        link_expires_at: float | None = None,
        governance_request_id: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Compatibility approval that still records the full governed lifecycle."""
        if confirm is not True:
            raise ValueError("confirm=true is required to approve a namespace link")
        if enabled is not True:
            raise ValueError(
                "direct approval must be enabled; approve then explicitly disable it"
            )
        source = sanitize_context_id(source_context_id)
        target = sanitize_context_id(target_context_id)
        if source == target:
            raise ValueError("source and target namespaces must be distinct")
        relation = sanitize_tag(relation_type or "related").lower().replace(" ", "_")
        similarity = self.memory_store.context_similarity(
            source_context_id=source,
            target_context_id=target,
            max_phase_delay_ticks=4,
        )
        supplied_evidence = evidence if isinstance(evidence, dict) else {}
        safe_supplied, _redaction_count = redact_sensitive_value(supplied_evidence)
        safe_supplied = safe_supplied if isinstance(safe_supplied, dict) else {}
        approval_evidence = {
            **safe_supplied,
            **dict(similarity["evidence"]),
            "approval_source": "explicit-operator-confirmation",
            "automatic_cross_namespace_write": False,
            "connected_recall_only": True,
        }
        governed = self.bridge_governance.approve_namespace_link_compat(
            source_context_id=source,
            target_context_id=target,
            relation_type=relation,
            weight=weight,
            evidence=self._json_safe_metadata(approval_evidence),
            direction=direction,
            approved_by=sanitize_agent_id(approved_by),
            reason=reason,
            link_expires_at=link_expires_at,
            governance_request_id=governance_request_id,
            confirm=confirm,
        )
        link = self._decorate_namespace_link(dict(governed["link"]))
        self._surface_recall_cache.clear()
        self._mark_activity()
        return {
            "action": "approve-namespace-link",
            "approved": bool(governed.get("authorization_active")),
            "confirmed": True,
            "link": link,
            "proposal": governed["proposal"],
            "governance_state": governed["state"],
            "authorization_active": bool(governed.get("authorization_active")),
            "idempotent_replay": bool(governed.get("idempotent_replay")),
            "compatibility_mode": True,
            "automatic_cross_namespace_write": False,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def propose_namespace_link(
        self,
        *,
        source_context_id: str,
        target_context_id: str,
        relation_type: str = "related",
        weight: float = 1.0,
        evidence: dict[str, Any] | None = None,
        direction: str = "bidirectional",
        proposed_by: str = "operator",
        reason: str,
        proposal_expires_at: float | None = None,
        link_expires_at: float | None = None,
        governance_request_id: str | None = None,
    ) -> dict[str, Any]:
        source = sanitize_context_id(source_context_id)
        target = sanitize_context_id(target_context_id)
        if source == target:
            raise ValueError("source and target namespaces must be distinct")
        similarity = self.memory_store.context_similarity(
            source_context_id=source,
            target_context_id=target,
            max_phase_delay_ticks=4,
        )
        supplied = evidence if isinstance(evidence, dict) else {}
        safe_supplied, _redaction_count = redact_sensitive_value(supplied)
        safe_supplied = safe_supplied if isinstance(safe_supplied, dict) else {}
        basis_revision = self.memory_store.entries_revision(
            context_ids=sorted({source, target})
        )
        result = self.bridge_governance.propose_namespace_link(
            source_context_id=source,
            target_context_id=target,
            relation_type=sanitize_tag(relation_type or "related")
            .lower()
            .replace(" ", "_"),
            weight=weight,
            evidence=self._json_safe_metadata(
                {
                    **safe_supplied,
                    **dict(similarity["evidence"]),
                    "basis_entries_revision": basis_revision["revision"],
                    "basis_context_ids": basis_revision["context_ids"],
                    "proposal_source": "explicit-operator-request",
                    "connected_recall_only": True,
                    "automatic_cross_namespace_write": False,
                }
            ),
            direction=direction,
            proposed_by=sanitize_agent_id(proposed_by),
            reason=reason,
            proposal_expires_at=proposal_expires_at,
            link_expires_at=link_expires_at,
            governance_request_id=governance_request_id,
        )
        self._mark_activity()
        return {**result, "memory_db_path": str(self.memory_store.db_path)}

    def review_namespace_link(
        self,
        *,
        proposal_id: str,
        decision: str,
        expected_revision: str,
        reviewed_by: str = "operator",
        reason: str,
        governance_request_id: str | None = None,
    ) -> dict[str, Any]:
        current_proposal = self.bridge_governance.get_namespace_link_proposal(
            proposal_id=proposal_id
        )
        if str(decision or "").strip().lower() == "approve":
            proposal_evidence = current_proposal.get("evidence")
            proposal_evidence = (
                proposal_evidence if isinstance(proposal_evidence, dict) else {}
            )
            basis_revision = str(
                proposal_evidence.get("basis_entries_revision") or ""
            )
            if basis_revision:
                observed_revision = self.memory_store.entries_revision(
                    context_ids=sorted(
                        {
                            str(current_proposal["source_context_id"]),
                            str(current_proposal["target_context_id"]),
                        }
                    )
                )["revision"]
                if observed_revision != basis_revision:
                    raise BridgeGovernanceStaleRevision(
                        "bridge proposal evidence is stale; create a new proposal"
                    )
        result = self.bridge_governance.review_namespace_link(
            proposal_id=proposal_id,
            decision=decision,
            expected_revision=expected_revision,
            reviewed_by=sanitize_agent_id(reviewed_by),
            reason=reason,
            governance_request_id=governance_request_id,
        )
        if isinstance(result.get("link"), dict):
            result["link"] = self._decorate_namespace_link(dict(result["link"]))
        self._surface_recall_cache.clear()
        self._mark_activity()
        return {**result, "memory_db_path": str(self.memory_store.db_path)}

    def disable_namespace_link(
        self,
        *,
        context_link_id: str,
        expected_revision: str,
        disabled_by: str = "operator",
        reason: str,
        governance_request_id: str | None = None,
        confirm: bool,
    ) -> dict[str, Any]:
        result = self.bridge_governance.disable_namespace_link(
            context_link_id=context_link_id,
            expected_revision=expected_revision,
            disabled_by=sanitize_agent_id(disabled_by),
            reason=reason,
            governance_request_id=governance_request_id,
            confirm=confirm,
        )
        if isinstance(result.get("link"), dict):
            result["link"] = self._decorate_namespace_link(dict(result["link"]))
        self._surface_recall_cache.clear()
        self._mark_activity()
        return {**result, "memory_db_path": str(self.memory_store.db_path)}

    def revoke_namespace_link(
        self,
        *,
        context_link_id: str,
        expected_revision: str,
        revoked_by: str = "operator",
        reason: str,
        governance_request_id: str | None = None,
        confirm: bool,
    ) -> dict[str, Any]:
        result = self.bridge_governance.revoke_namespace_link(
            context_link_id=context_link_id,
            expected_revision=expected_revision,
            revoked_by=sanitize_agent_id(revoked_by),
            reason=reason,
            governance_request_id=governance_request_id,
            confirm=confirm,
        )
        if isinstance(result.get("link"), dict):
            result["link"] = self._decorate_namespace_link(dict(result["link"]))
        self._surface_recall_cache.clear()
        self._mark_activity()
        return {**result, "memory_db_path": str(self.memory_store.db_path)}

    def list_namespace_link_proposals(
        self,
        *,
        context_id: str = "",
        state: str = "",
        limit: int = 500,
    ) -> dict[str, Any]:
        return self.bridge_governance.list_namespace_link_proposals(
            context_id=sanitize_context_id(context_id) if str(context_id).strip() else None,
            state=state or None,
            limit=limit,
        )

    def list_namespace_link_history(
        self,
        *,
        proposal_id: str = "",
        context_link_id: str = "",
        limit: int = 500,
    ) -> dict[str, Any]:
        return self.bridge_governance.list_namespace_link_history(
            proposal_id=proposal_id or None,
            context_link_id=context_link_id or None,
            limit=limit,
        )

    def audit_namespace_link_governance(self) -> dict[str, Any]:
        return self.bridge_governance.audit_integrity()

    def expire_namespace_links(self) -> dict[str, Any]:
        result = self.bridge_governance.expire_due()
        if int(result.get("expired_count", 0)):
            self._surface_recall_cache.clear()
            self._mark_activity()
        return result

    def delete_namespace_link(
        self,
        *,
        context_link_id: str,
        expected_revision: str,
        revoked_by: str = "operator",
        reason: str = "legacy delete request converted to governed revocation",
        governance_request_id: str | None = None,
        confirm: bool,
    ) -> dict[str, Any]:
        if not confirm:
            raise ValueError("confirm=true is required to delete a namespace link")
        result = self.revoke_namespace_link(
            context_link_id=context_link_id,
            expected_revision=expected_revision,
            revoked_by=revoked_by,
            reason=reason,
            governance_request_id=governance_request_id,
            confirm=True,
        )
        return {
            "action": "revoke-namespace-link",
            "deleted": False,
            "revoked": True,
            "result": result,
            "automatic_cross_namespace_write": False,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def suggest_namespace_links(
        self,
        *,
        context_id: str = "",
        limit: int = 50,
        min_score: float = 0.05,
        include_linked: bool = False,
        max_visual_phase_delay_ticks: int = 4,
    ) -> dict[str, Any]:
        selected_context = (
            sanitize_context_id(context_id)
            if str(context_id or "").strip()
            else ""
        )
        suggestions = self.memory_store.suggest_context_links(
            context_id=selected_context or None,
            limit=limit,
            min_score=min_score,
            include_linked=include_linked,
            max_phase_delay_ticks=max_visual_phase_delay_ticks,
        )
        return {
            "action": "suggest-namespace-links",
            "selected_context_id": selected_context,
            "suggestion_count": len(suggestions),
            "suggestions": suggestions,
            "method": "density-normalized-dice-v1",
            "read_only": True,
            "requires_approval": True,
            "automatic_cross_namespace_write": False,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def list_namespace_map(
        self,
        *,
        context_id: str = "",
        limit: int = 500,
        include_suggestions: bool = True,
        suggestion_limit: int = 50,
        min_suggestion_score: float = 0.05,
        max_visual_phase_delay_ticks: int = 4,
    ) -> dict[str, Any]:
        """Build a graph across every durable context id and approved link."""
        selected_context = (
            sanitize_context_id(context_id)
            if str(context_id or "").strip()
            else ""
        )
        bounded_limit = min(max(int(limit), 1), 10_000)
        raw_nodes = self.memory_store.list_context_summaries(limit=bounded_limit)
        raw_links = self.bridge_governance.list_active_namespace_links(
            limit=min(max(bounded_limit * 8, 1000), 2_000)
        )
        links = [self._decorate_namespace_link(link) for link in raw_links]
        adjacency: dict[str, set[str]] = {
            str(node["context_id"]): set()
            for node in raw_nodes
        }
        for link in links:
            if not bool(link.get("enabled")):
                continue
            source = str(link["source_context_id"])
            target = str(link["target_context_id"])
            adjacency.setdefault(source, set()).add(target)
            if str(link.get("direction") or "bidirectional") == "bidirectional":
                adjacency.setdefault(target, set()).add(source)
        nodes: list[dict[str, Any]] = []
        for raw_node in raw_nodes:
            node = dict(raw_node)
            node_context = str(node["context_id"])
            connected_context_ids = sorted(adjacency.get(node_context, set()))
            node.update(
                {
                    "selected": node_context == selected_context,
                    "connected_to_selected": bool(
                        selected_context
                        and node_context in adjacency.get(selected_context, set())
                    ),
                    "connected_context_ids": connected_context_ids,
                    "connected_context_count": len(connected_context_ids),
                    "visual_size": round(1.0 + math.log1p(int(node["entry_count"])), 6),
                }
            )
            nodes.append(node)
        nodes.sort(
            key=lambda node: (
                bool(node.get("selected")),
                int(node.get("entry_count", 0)),
                float(node.get("last_activity_at", 0.0)),
            ),
            reverse=True,
        )
        suggestions_payload = (
            self.suggest_namespace_links(
                context_id=selected_context,
                limit=suggestion_limit,
                min_score=min_suggestion_score,
                include_linked=False,
                max_visual_phase_delay_ticks=max_visual_phase_delay_ticks,
            )
            if include_suggestions
            else {"suggestions": []}
        )
        suggestions = list(suggestions_payload.get("suggestions", []))
        proposal_payload = self.bridge_governance.list_namespace_link_proposals(
            limit=min(max(bounded_limit * 4, 500), 2_000)
        )
        proposals = list(proposal_payload.get("proposals", []))
        return {
            "action": "list-namespace-map",
            "scope": "all",
            "selected_context_id": selected_context,
            "node_count": len(nodes),
            "link_count": len(links),
            "proposal_count": len(proposals),
            "suggestion_count": len(suggestions),
            "nodes": nodes,
            "links": links,
            "proposals": proposals,
            "suggestions": suggestions,
            "bridge_governance": {
                "schema": "synapse-s2.bridge-governance-map.v1",
                "mode": "proposal-review-cas",
                "actor_assurance": "os-verified-local-owner-v1",
                "review_separation": "two-step-single-local-owner",
                "distinct_human_review_claimed": False,
                "active_link_count": len(links),
                "proposal_count": len(proposals),
                "audit_available": True,
                "automatic_cross_namespace_write": False,
            },
            "recall_scopes": ["local", "connected", "all"],
            "default_recall_scope": "local",
            "connected_scope_hops": 1,
            "automatic_cross_namespace_write": False,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def list_namespace_detail(
        self,
        *,
        context_id: str = "default",
        level: str = "cortex",
        cluster_id: str = "",
        limit: int = 100,
    ) -> dict[str, Any]:
        """Return a bounded, deterministic projection of one stored namespace."""
        context = sanitize_context_id(context_id)
        normalized_level = str(level or "cortex").strip().lower()
        if normalized_level not in NAMESPACE_DETAIL_LEVELS:
            raise ValueError("level must be cortex, ganglion, or neurons")
        selected_cluster_id = str(cluster_id or "").strip()
        if normalized_level == "cortex" and selected_cluster_id:
            raise ValueError("cluster_id is only valid for ganglion or neurons level")
        bounded_limit = min(
            max(int(limit), 1),
            NAMESPACE_DETAIL_MAX_RETURNED_NODES,
        )
        snapshot = self.memory_store.namespace_graph_snapshot(
            context_id=context,
            entry_scan_limit=NAMESPACE_DETAIL_ENTRY_SCAN_LIMIT,
            relationship_scan_limit=NAMESPACE_DETAIL_RELATIONSHIP_SCAN_LIMIT,
        )
        entries = sorted(
            (dict(entry) for entry in snapshot["entries"]),
            key=lambda entry: str(entry["memory_id"]),
        )
        relationships = sorted(
            (dict(relationship) for relationship in snapshot["relationships"]),
            key=lambda relationship: str(relationship["relationship_id"]),
        )
        clusters, cluster_by_memory_id = self._namespace_detail_clusters(
            context=context,
            entries=entries,
            relationships=relationships,
            entry_scan_truncated=bool(snapshot["entry_scan_truncated"]),
        )
        clusters_by_id = {
            str(cluster["cluster_id"]): cluster
            for cluster in clusters
        }
        if selected_cluster_id and selected_cluster_id not in clusters_by_id:
            raise ValueError(
                f"unknown cluster_id for context {context}: {selected_cluster_id}"
            )

        namespace_node_id = self._stable_namespace_detail_id(
            prefix="s2ctx",
            values=(context,),
        )
        namespace = {
            "node_id": namespace_node_id,
            "entity_kind": "namespace",
            "node_type": "context",
            "context_id": context,
            "display_label": self._namespace_detail_safe_text(context, 128),
            "stored": int(snapshot["entry_total"]) > 0,
            "entry_total": int(snapshot["entry_total"]),
            "relationship_total": int(snapshot["relationship_total"]),
            "cluster_total": len(clusters),
            "cluster_total_exact": not bool(snapshot["entry_scan_truncated"]),
            "first_created_at": float(snapshot["first_created_at"]),
            "last_updated_at": float(snapshot["last_updated_at"]),
            "provenance": {
                "source": "memory_entries.context_id",
                "storage_table": "memory_entries",
                "context_isolation": True,
            },
        }

        returned_clusters: list[dict[str, Any]] = []
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        eligible_node_total = 0
        eligible_edge_total = 0
        eligible_cluster_total = 0
        raw_relationships_supporting_edges = 0

        if normalized_level == "cortex":
            eligible_node_total = 1 if namespace["stored"] else 0
            nodes = [dict(namespace)] if namespace["stored"] else []
        elif normalized_level == "ganglion":
            eligible_clusters = (
                [clusters_by_id[selected_cluster_id]]
                if selected_cluster_id
                else clusters
            )
            eligible_cluster_total = len(eligible_clusters)
            returned_clusters = [
                dict(cluster)
                for cluster in eligible_clusters[:bounded_limit]
            ]
            nodes = [dict(cluster) for cluster in returned_clusters]
            eligible_cluster_ids = {
                str(cluster["cluster_id"])
                for cluster in eligible_clusters
            }
            returned_cluster_ids = {
                str(cluster["cluster_id"])
                for cluster in returned_clusters
            }
            aggregate_edges = self._namespace_detail_ganglion_edges(
                context=context,
                relationships=relationships,
                cluster_by_memory_id=cluster_by_memory_id,
                eligible_cluster_ids=eligible_cluster_ids,
            )
            eligible_edge_total = len(aggregate_edges)
            returned_edge_candidates = [
                edge
                for edge in aggregate_edges
                if str(edge["source_id"]) in returned_cluster_ids
                and str(edge["target_id"]) in returned_cluster_ids
            ]
            edge_limit = min(
                max(bounded_limit * 4, bounded_limit),
                NAMESPACE_DETAIL_MAX_RETURNED_EDGES,
            )
            edges = returned_edge_candidates[:edge_limit]
            raw_relationships_supporting_edges = sum(
                int(edge["stored_relationship_count"])
                for edge in edges
            )
            eligible_node_total = eligible_cluster_total
        else:
            eligible_entries = [
                entry
                for entry in entries
                if not selected_cluster_id
                or cluster_by_memory_id.get(str(entry["memory_id"]))
                == selected_cluster_id
            ]
            eligible_node_total = (
                len(eligible_entries)
                if selected_cluster_id
                else int(snapshot["entry_total"])
            )
            returned_entries = eligible_entries[:bounded_limit]
            returned_memory_ids = {
                str(entry["memory_id"])
                for entry in returned_entries
            }
            eligible_memory_ids = {
                str(entry["memory_id"])
                for entry in eligible_entries
            }
            nodes = [
                self._namespace_detail_memory_node(
                    entry,
                    cluster_id=str(cluster_by_memory_id[str(entry["memory_id"])]),
                )
                for entry in returned_entries
            ]
            # At the neuron level the ganglion map describes the namespace as a
            # whole.  Do not hide clusters merely because their first neuron is
            # outside the bounded node sample.
            eligible_clusters = (
                [clusters_by_id[selected_cluster_id]]
                if selected_cluster_id
                else clusters
            )
            eligible_cluster_total = len(eligible_clusters)
            returned_clusters = [
                dict(cluster)
                for cluster in eligible_clusters[:NAMESPACE_DETAIL_MAX_RETURNED_CLUSTERS]
            ]
            eligible_relationships = [
                relationship
                for relationship in relationships
                if str(relationship["source_memory_id"]) in eligible_memory_ids
                and str(relationship["target_memory_id"]) in eligible_memory_ids
            ]
            # The unfiltered stored total is exact even if the bounded entry
            # sample cannot render every edge. A selected cluster is a bounded
            # projection and is explicitly labelled as a lower bound below.
            eligible_edge_total = (
                len(eligible_relationships)
                if selected_cluster_id
                else int(snapshot["relationship_total"])
            )
            returned_relationships = [
                relationship
                for relationship in eligible_relationships
                if str(relationship["source_memory_id"]) in returned_memory_ids
                and str(relationship["target_memory_id"]) in returned_memory_ids
            ]
            edge_limit = min(
                max(bounded_limit * 4, bounded_limit),
                NAMESPACE_DETAIL_MAX_RETURNED_EDGES,
            )
            edges = [
                self._namespace_detail_memory_edge(relationship)
                for relationship in returned_relationships[:edge_limit]
            ]
            raw_relationships_supporting_edges = len(edges)

        counts = {
            "memory_total": int(snapshot["entry_total"]),
            "relationship_total": int(snapshot["relationship_total"]),
            "cluster_total": len(clusters),
            "cluster_total_exact": not bool(snapshot["entry_scan_truncated"]),
            "eligible_nodes": eligible_node_total,
            "returned_nodes": len(nodes),
            "eligible_edges": eligible_edge_total,
            "returned_edges": len(edges),
            "eligible_clusters": eligible_cluster_total,
            "returned_clusters": len(returned_clusters),
            "raw_relationships_supporting_returned_edges": (
                raw_relationships_supporting_edges
            ),
            "eligible_nodes_is_lower_bound": bool(
                snapshot["entry_scan_truncated"]
                and normalized_level == "neurons"
                and bool(selected_cluster_id)
            ),
            "eligible_edges_is_lower_bound": bool(
                snapshot["relationship_scan_truncated"]
                and (normalized_level == "ganglion" or bool(selected_cluster_id))
            ),
            "eligible_clusters_is_lower_bound": bool(
                snapshot["entry_scan_truncated"]
            ),
        }
        truncation = {
            "truncated": bool(
                snapshot["entry_scan_truncated"]
                or snapshot["relationship_scan_truncated"]
                or eligible_node_total > len(nodes)
                or eligible_edge_total > len(edges)
                or eligible_cluster_total > len(returned_clusters)
            ),
            "limit": bounded_limit,
            "sampling": "deterministic",
            "scan_limits": {
                "entries": int(snapshot["entry_scan_limit"]),
                "relationships": int(snapshot["relationship_scan_limit"]),
            },
            "source_scan": {
                "entries_truncated": bool(snapshot["entry_scan_truncated"]),
                "relationships_truncated": bool(
                    snapshot["relationship_scan_truncated"]
                ),
            },
            "nodes": {
                "total": eligible_node_total,
                "returned": len(nodes),
                "truncated": eligible_node_total > len(nodes),
            },
            "edges": {
                "total": eligible_edge_total,
                "returned": len(edges),
                "truncated": eligible_edge_total > len(edges),
            },
            "clusters": {
                "total": eligible_cluster_total,
                "returned": len(returned_clusters),
                "truncated": eligible_cluster_total > len(returned_clusters),
                "limit": NAMESPACE_DETAIL_MAX_RETURNED_CLUSTERS,
            },
            "selection_order": {
                **dict(snapshot["selection_order"]),
                "clusters": "cluster_id ascending",
                "rendered_edges": "edge_id ascending",
            },
        }
        return {
            "action": "namespace-detail",
            "read_only": True,
            "automatic_cross_namespace_write": False,
            "context_id": context,
            "level": normalized_level,
            "selected_cluster_id": selected_cluster_id,
            "empty": int(snapshot["entry_total"]) == 0,
            "namespace": namespace,
            "counts": counts,
            "truncation": truncation,
            "pagination": {
                "supported": False,
                "strategy": "bounded-deterministic-sample",
                "limit": bounded_limit,
                "next_cursor": None,
            },
            "clusters": returned_clusters,
            "nodes": nodes,
            "edges": edges,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def _namespace_detail_clusters(
        self,
        *,
        context: str,
        entries: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
        entry_scan_truncated: bool,
    ) -> tuple[list[dict[str, Any]], dict[str, str]]:
        entries_by_id = {
            str(entry["memory_id"]): entry
            for entry in entries
        }
        node_types = {
            memory_id: self._namespace_detail_node_type(entry)
            for memory_id, entry in entries_by_id.items()
        }
        namespace_anchor_ids = {
            memory_id
            for memory_id, node_type in node_types.items()
            if node_type == "namespace"
        }
        anchors_by_namespace_token: dict[str, str] = {}
        for memory_id in sorted(namespace_anchor_ids):
            metadata = entries_by_id[memory_id].get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            token = str(metadata.get("context_namespace") or "").strip()
            if token:
                anchors_by_namespace_token.setdefault(token, memory_id)

        containment_by_target: dict[str, list[dict[str, Any]]] = {}
        for relationship in relationships:
            if str(relationship.get("relation_type") or "") != "namespace_contains":
                continue
            source_id = str(relationship.get("source_memory_id") or "")
            target_id = str(relationship.get("target_memory_id") or "")
            if source_id not in namespace_anchor_ids or target_id not in entries_by_id:
                continue
            containment_by_target.setdefault(target_id, []).append(relationship)
        for candidates in containment_by_target.values():
            candidates.sort(
                key=lambda relationship: (
                    -float(relationship.get("weight", 0.0)),
                    str(relationship.get("relationship_id") or ""),
                )
            )

        cluster_builders: dict[str, dict[str, Any]] = {}
        cluster_by_memory_id: dict[str, str] = {}
        for memory_id, entry in sorted(entries_by_id.items()):
            metadata = entry.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            node_type = node_types[memory_id]
            relationship_ids: list[str] = []
            anchor_memory_id = ""
            if memory_id in namespace_anchor_ids:
                anchor_memory_id = memory_id
                cluster_key = f"namespace:{memory_id}"
                basis = "namespace_contains"
                label = self._namespace_detail_entry_label(entry)
                provenance_source = "memory_entries.metadata.context_memory_type"
            elif containment_by_target.get(memory_id):
                membership_relationship = containment_by_target[memory_id][0]
                anchor_memory_id = str(membership_relationship["source_memory_id"])
                cluster_key = f"namespace:{anchor_memory_id}"
                basis = "namespace_contains"
                label = self._namespace_detail_entry_label(
                    entries_by_id[anchor_memory_id]
                )
                relationship_ids = [
                    str(membership_relationship["relationship_id"])
                ]
                provenance_source = "memory_relationships.namespace_contains"
            else:
                namespace_token = str(metadata.get("context_namespace") or "").strip()
                if namespace_token:
                    anchor_memory_id = anchors_by_namespace_token.get(namespace_token, "")
                    cluster_key = (
                        f"namespace:{anchor_memory_id}"
                        if anchor_memory_id
                        else f"metadata-namespace:{namespace_token}"
                    )
                    basis = "metadata_context_namespace"
                    label = self._namespace_detail_safe_text(
                        str(metadata.get("context_namespace_title") or namespace_token),
                        96,
                    )
                    provenance_source = "memory_entries.metadata.context_namespace"
                elif node_type != "memory":
                    cluster_key = f"stored-type:{node_type}"
                    basis = "stored_type"
                    label = self._namespace_detail_safe_text(
                        f"Stored type: {node_type}",
                        96,
                    )
                    provenance_source = "memory_entries.metadata.context_memory_type"
                else:
                    cluster_key = "fallback:untyped"
                    basis = "fallback_untyped"
                    label = "Stored memories without a typed namespace"
                    provenance_source = "memory_entries fallback for untyped rows"

            cluster_id = self._stable_namespace_detail_id(
                prefix="s2g",
                values=(context, cluster_key),
            )
            cluster_by_memory_id[memory_id] = cluster_id
            builder = cluster_builders.setdefault(
                cluster_id,
                {
                    "cluster_id": cluster_id,
                    "node_id": cluster_id,
                    "entity_kind": "ganglion",
                    "node_type": "semantic_cluster",
                    "context_id": context,
                    "display_label": label,
                    "basis": basis,
                    "anchor_memory_id": anchor_memory_id,
                    "member_memory_ids": [],
                    "node_type_counts": {},
                    "first_created_at": float(entry.get("created_at", 0.0)),
                    "last_updated_at": float(entry.get("updated_at", 0.0)),
                    "semantic_facets": set(),
                    "membership_relationship_ids": [],
                    "provenance": {
                        "source": provenance_source,
                        "stored_data_only": True,
                    },
                },
            )
            builder["member_memory_ids"].append(memory_id)
            builder["node_type_counts"][node_type] = (
                int(builder["node_type_counts"].get(node_type, 0)) + 1
            )
            builder["first_created_at"] = min(
                float(builder["first_created_at"]),
                float(entry.get("created_at", 0.0)),
            )
            builder["last_updated_at"] = max(
                float(builder["last_updated_at"]),
                float(entry.get("updated_at", 0.0)),
            )
            builder["membership_relationship_ids"].extend(relationship_ids)
            for facet in self._namespace_detail_stored_strings(
                metadata.get("semantic_facets"),
                limit=12,
                item_limit=72,
            ):
                builder["semantic_facets"].add(facet)

        clusters: list[dict[str, Any]] = []
        for cluster_id, builder in sorted(cluster_builders.items()):
            member_ids = sorted(set(builder.pop("member_memory_ids")))
            relationship_ids = sorted(
                set(builder.pop("membership_relationship_ids"))
            )
            semantic_facets = sorted(builder.pop("semantic_facets"))[:12]
            clusters.append(
                {
                    **builder,
                    "cluster_id": cluster_id,
                    "node_id": cluster_id,
                    "memory_total": len(member_ids),
                    "memory_total_is_lower_bound": bool(entry_scan_truncated),
                    "member_memory_id_sample": member_ids[:16],
                    "member_sample_truncated": len(member_ids) > 16,
                    "node_type_counts": dict(
                        sorted(builder["node_type_counts"].items())
                    ),
                    "semantic_facets": semantic_facets,
                    "membership_relationship_id_sample": relationship_ids[:16],
                    "provenance": {
                        **dict(builder["provenance"]),
                        "relationship_ids": relationship_ids[:16],
                    },
                }
            )
        return clusters, cluster_by_memory_id

    def _namespace_detail_ganglion_edges(
        self,
        *,
        context: str,
        relationships: list[dict[str, Any]],
        cluster_by_memory_id: dict[str, str],
        eligible_cluster_ids: set[str],
    ) -> list[dict[str, Any]]:
        aggregates: dict[tuple[str, str, str], dict[str, Any]] = {}
        for relationship in relationships:
            source_cluster_id = cluster_by_memory_id.get(
                str(relationship.get("source_memory_id") or "")
            )
            target_cluster_id = cluster_by_memory_id.get(
                str(relationship.get("target_memory_id") or "")
            )
            if (
                not source_cluster_id
                or not target_cluster_id
                or source_cluster_id == target_cluster_id
                or source_cluster_id not in eligible_cluster_ids
                or target_cluster_id not in eligible_cluster_ids
            ):
                continue
            edge_type = str(relationship.get("relation_type") or "unknown")
            key = (source_cluster_id, target_cluster_id, edge_type)
            aggregate = aggregates.setdefault(
                key,
                {
                    "weights": [],
                    "relationship_ids": [],
                    "first_created_at": float(relationship.get("created_at", 0.0)),
                    "last_updated_at": float(relationship.get("updated_at", 0.0)),
                },
            )
            aggregate["weights"].append(float(relationship.get("weight", 0.0)))
            aggregate["relationship_ids"].append(
                str(relationship.get("relationship_id") or "")
            )
            aggregate["first_created_at"] = min(
                float(aggregate["first_created_at"]),
                float(relationship.get("created_at", 0.0)),
            )
            aggregate["last_updated_at"] = max(
                float(aggregate["last_updated_at"]),
                float(relationship.get("updated_at", 0.0)),
            )

        edges: list[dict[str, Any]] = []
        for (source_id, target_id, edge_type), aggregate in sorted(aggregates.items()):
            relationship_ids = sorted(set(aggregate["relationship_ids"]))
            weights = [float(weight) for weight in aggregate["weights"]]
            edge_id = self._stable_namespace_detail_id(
                prefix="s2ge",
                values=(context, source_id, target_id, edge_type),
            )
            edges.append(
                {
                    "edge_id": edge_id,
                    "entity_kind": "relationship_aggregate",
                    "source_id": source_id,
                    "target_id": target_id,
                    "edge_type": edge_type,
                    "direction": "directed",
                    "weight": round(max(weights), 6) if weights else 0.0,
                    "average_weight": round(
                        sum(weights) / max(1, len(weights)),
                        6,
                    ),
                    "stored_relationship_count": len(relationship_ids),
                    "relationship_id_sample": relationship_ids[:16],
                    "first_created_at": float(aggregate["first_created_at"]),
                    "last_updated_at": float(aggregate["last_updated_at"]),
                    "provenance": {
                        "source": "memory_relationships",
                        "relationship_ids": relationship_ids[:16],
                        "stored_relationship_count": len(relationship_ids),
                        "aggregation": "same directed cluster pair and edge type",
                    },
                }
            )
        return sorted(edges, key=lambda edge: str(edge["edge_id"]))

    def _namespace_detail_memory_node(
        self,
        entry: dict[str, Any],
        *,
        cluster_id: str,
    ) -> dict[str, Any]:
        metadata = entry.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        provenance = self._namespace_detail_entry_provenance(entry)
        return {
            "node_id": str(entry["memory_id"]),
            "memory_id": str(entry["memory_id"]),
            "entity_kind": "memory",
            "node_type": self._namespace_detail_node_type(entry),
            "cluster_id": cluster_id,
            "context_id": str(entry["context_id"]),
            "tag": self._namespace_detail_safe_text(str(entry["tag"]), 200),
            "display_label": self._namespace_detail_entry_label(entry),
            "excerpt": self._namespace_detail_entry_excerpt(entry),
            "created_at": float(entry.get("created_at", 0.0)),
            "updated_at": float(entry.get("updated_at", 0.0)),
            "source": str(provenance.get("source") or "memory_entries"),
            "provenance": provenance,
            "semantic_facets": self._namespace_detail_stored_strings(
                metadata.get("semantic_facets"),
                limit=12,
                item_limit=72,
            ),
            "detail_badges": self._namespace_detail_stored_strings(
                metadata.get("detail_badges"),
                limit=12,
                item_limit=72,
            ),
        }

    def _namespace_detail_memory_edge(
        self,
        relationship: dict[str, Any],
    ) -> dict[str, Any]:
        evidence = relationship.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        provenance: dict[str, Any] = {
            "source": "memory_relationships",
            "relationship_id": str(relationship["relationship_id"]),
            "evidence_keys": sorted(
                self._namespace_detail_safe_text(str(key), 96)
                for key in evidence
            )[:24],
        }
        for key in (
            "namespace_id",
            "source_tag",
            "source_type",
            "target_type",
            "sequence_id",
            "surprise_mode",
        ):
            if key in evidence:
                provenance[key] = self._namespace_detail_safe_text(
                    str(evidence[key]),
                    128,
                )
        return {
            "edge_id": str(relationship["relationship_id"]),
            "entity_kind": "relationship",
            "source_id": str(relationship["source_memory_id"]),
            "target_id": str(relationship["target_memory_id"]),
            "edge_type": self._namespace_detail_safe_text(
                str(relationship.get("relation_type") or "unknown"),
                96,
            ),
            "direction": "directed",
            "weight": round(float(relationship.get("weight", 0.0)), 6),
            "created_at": float(relationship.get("created_at", 0.0)),
            "updated_at": float(relationship.get("updated_at", 0.0)),
            "provenance": provenance,
        }

    def _namespace_detail_node_type(self, entry: dict[str, Any]) -> str:
        metadata = entry.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        raw_type = self._namespace_detail_safe_text(
            str(metadata.get("context_memory_type") or ""),
            64,
        ).strip().lower()
        if not raw_type and metadata.get("event_segment"):
            raw_type = "event"
        if not raw_type and str(metadata.get("cortex_trace_type") or "").strip():
            raw_type = "cortex_trace"
        cleaned = re.sub(r"[^a-z0-9_.:-]+", "_", raw_type).strip("._-:")
        return (cleaned or "memory")[:64]

    def _namespace_detail_entry_label(self, entry: dict[str, Any]) -> str:
        metadata = entry.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        stored_label = str(
            metadata.get("display_label")
            or metadata.get("context_label")
            or entry.get("tag")
            or entry.get("source_text")
            or entry.get("memory_id")
        )
        return self._namespace_detail_safe_text(stored_label, 96)

    def _namespace_detail_entry_excerpt(self, entry: dict[str, Any]) -> str:
        metadata = entry.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        stored_excerpt = str(
            metadata.get("display_summary")
            or entry.get("source_text")
            or entry.get("tag")
            or ""
        )
        return self._namespace_detail_safe_text(stored_excerpt, 240)

    def _namespace_detail_entry_provenance(
        self,
        entry: dict[str, Any],
    ) -> dict[str, Any]:
        metadata = entry.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        provenance: dict[str, Any] = {
            "source": self._namespace_detail_safe_text(
                str(metadata.get("source") or metadata.get("source_tag") or "memory_entries"),
                128,
            ),
            "storage_table": "memory_entries",
            "memory_id": str(entry.get("memory_id") or ""),
        }
        for key in (
            "source_tag",
            "speaker",
            "sequence_id",
            "context_namespace",
            "context_namespace_source",
            "truth_posture",
            "trace_type",
        ):
            value = str(metadata.get(key) or "").strip()
            if value:
                provenance[key] = self._namespace_detail_safe_text(value, 128)
        embedding_provider = metadata.get("embedding_provider")
        if isinstance(embedding_provider, dict):
            provider_summary = {
                key: embedding_provider.get(key)
                for key in (
                    "provider",
                    "provider_type",
                    "model_id",
                    "local_only",
                    "semantic",
                )
                if key in embedding_provider
            }
            if provider_summary:
                provenance["embedding_provider"] = {
                    str(key): self._namespace_detail_safe_value(value, 128)
                    for key, value in sorted(provider_summary.items())
                }
        return provenance

    def _namespace_detail_stored_strings(
        self,
        values: Any,
        *,
        limit: int,
        item_limit: int,
    ) -> list[str]:
        raw_values = values if isinstance(values, (list, tuple, set)) else []
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw_value in raw_values:
            value = self._namespace_detail_safe_text(str(raw_value), item_limit)
            if not value or value in seen:
                continue
            seen.add(value)
            cleaned.append(value)
            if len(cleaned) >= max(0, int(limit)):
                break
        return sorted(cleaned)[: max(0, int(limit))]

    def _namespace_detail_safe_text(self, value: str, limit: int) -> str:
        redacted, _redaction_count = redact_capture_text(str(value or ""))
        return self._compact_text(redacted, max(1, int(limit)))

    def _namespace_detail_safe_value(self, value: Any, limit: int) -> Any:
        """Render scalar provenance without leaking legacy secret-bearing text."""
        if isinstance(value, str):
            return self._namespace_detail_safe_text(value, limit)
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return value
        return self._namespace_detail_safe_text(str(value), limit)

    def _stable_namespace_detail_id(
        self,
        *,
        prefix: str,
        values: tuple[str, ...],
    ) -> str:
        seed = "\x1f".join(str(value) for value in values).encode("utf-8")
        return f"{prefix}_" + hashlib.sha256(seed).hexdigest()[:32]

    def _decorate_namespace_link(self, link: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(link)
        evidence = (
            dict(enriched.get("evidence"))
            if isinstance(enriched.get("evidence"), dict)
            else {}
        )
        if "dice_score" not in evidence:
            similarity = self.memory_store.context_similarity(
                source_context_id=str(enriched["source_context_id"]),
                target_context_id=str(enriched["target_context_id"]),
                max_phase_delay_ticks=4,
            )
            evidence = {**dict(similarity["evidence"]), **evidence}
        enriched["evidence"] = evidence
        enriched["dice_score"] = round(float(evidence.get("dice_score", 0.0) or 0.0), 6)
        enriched["suggested_phase_delay_ticks"] = int(
            evidence.get("suggested_phase_delay_ticks", 0) or 0
        )
        enriched["delay_semantics"] = "visualization-only"
        enriched["recall_hops"] = 1
        enriched["automatic_cross_namespace_write"] = False
        return self._json_safe_metadata(enriched)

    def list_memory_graph(
        self,
        *,
        context_id: str = "default",
        limit: int = 100,
        cursor: str = "",
        response_mode: str = "legacy",
        include_global: bool = True,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        mode = self._retrieval_response_mode(response_mode)
        continuation = str(cursor or "").strip()
        if mode == "legacy":
            if continuation:
                raise ValueError("legacy memory graph does not support cursors")
            return self._list_memory_graph_legacy(context=context, limit=limit)
        if type(include_global) is not bool:
            raise ValueError("include_global must be a boolean")
        if type(limit) is not int or limit < 1 or limit > 500:
            raise ValueError("limit must be an integer between 1 and 500")
        bounded_limit = limit
        filters = {"include_global": include_global}
        ordering = canonical_ordering(
            (
                {"field": "entry_updated_at", "direction": "desc"},
                {"field": "entry_memory_id", "direction": "desc"},
                {"field": "relationship_updated_at", "direction": "desc"},
                {"field": "relationship_id", "direction": "desc"},
            ),
            unique_tie_breaker="relationship_id",
        )
        entry_position = None
        relationship_position = None
        expected_revision = None
        codec = self._get_retrieval_cursor_codec()
        if continuation:
            decoded = codec.decode(
                continuation,
                expected_surface="memory-graph",
                expected_response_mode=mode,
                expected_context_id=context,
                expected_recall_scope="local",
                expected_filters=filters,
                expected_ordering=ordering,
                expected_snapshot_revision=None,
            )
            entry_position, relationship_position = (
                self._graph_cursor_position_to_store(decoded.position)
            )
            expected_revision = str(decoded.snapshot_revision)

        try:
            page = self.memory_store.retrieval_graph_page(
                context_id=context,
                include_global=include_global,
                entry_limit=bounded_limit,
                relationship_limit=bounded_limit,
                entry_position=entry_position,
                relationship_position=relationship_position,
                expected_revision=expected_revision,
            )
        except RetrievalSnapshotStaleError as exc:
            if continuation:
                raise RetrievalCursorSnapshotMismatchError() from exc
            raise
        roles_by_memory_id: dict[str, set[str]] = {}
        raw_by_memory_id: dict[str, dict[str, Any]] = {}
        for entry in page["entries"]:
            memory_id = str(entry["memory_id"])
            raw_by_memory_id[memory_id] = entry
            roles_by_memory_id.setdefault(memory_id, set()).add("primary")
        for entry in page["endpoint_entries"]:
            memory_id = str(entry["memory_id"])
            raw_by_memory_id.setdefault(memory_id, entry)
            roles_by_memory_id.setdefault(memory_id, set()).add("edge-endpoint")
        primary_ids = [str(entry["memory_id"]) for entry in page["entries"]]
        supplemental_ids = sorted(
            (memory_id for memory_id in raw_by_memory_id if memory_id not in primary_ids),
            key=lambda memory_id: (
                float(raw_by_memory_id[memory_id].get("updated_at", 0.0)),
                memory_id,
            ),
            reverse=True,
        )
        ordered_raw_entries = [
            raw_by_memory_id[memory_id]
            for memory_id in [*primary_ids, *supplemental_ids]
        ]
        entries: list[dict[str, Any]] = []
        for entry in ordered_raw_entries:
            rendered = self._render_memory_entry(entry, include_vectors=False)
            rendered["graph_page_roles"] = sorted(
                roles_by_memory_id[str(entry["memory_id"])]
            )
            entries.append(rendered)
        relationship_entries = {str(entry["memory_id"]): entry for entry in entries}
        enriched_relationships = [
            self._decorate_memory_relationship(relationship, relationship_entries)
            for relationship in page["relationships"]
        ]

        has_more = bool(page["entry_has_more"] or page["relationship_has_more"])
        next_cursor = None
        expires_at = None
        if has_more:
            next_position = self._graph_cursor_position_from_store(
                entry_position=page["entry_next_position"],
                relationship_position=page["relationship_next_position"],
            )
            next_cursor = codec.encode(
                surface="memory-graph",
                response_mode=mode,
                context_id=context,
                recall_scope="local",
                filters=filters,
                ordering=ordering,
                position=next_position,
                snapshot_revision=page["snapshot_revision"],
                ttl_seconds=DEFAULT_RETRIEVAL_CURSOR_TTL_SECONDS,
            )
            expires_at = codec.decode(
                next_cursor,
                expected_surface="memory-graph",
                expected_response_mode=mode,
                expected_context_id=context,
                expected_recall_scope="local",
                expected_filters=filters,
                expected_ordering=ordering,
                expected_snapshot_revision=page["snapshot_revision"],
            ).expires_at
        return {
            "context_id": context,
            "memory_db_path": str(self.memory_store.db_path),
            "entry_count": len(entries),
            "primary_entry_count": page["entry_returned"],
            "relationship_endpoint_count": len(page["endpoint_entries"]),
            "graph_entry_strategy": "cursor-primary-plus-edge-endpoints",
            "relationship_count": len(enriched_relationships),
            "relationship_summary": self._summarize_relationship_modes(
                enriched_relationships
            ),
            "entries": entries,
            "relationships": enriched_relationships,
            "_retrieval_page": self._retrieval_page_metadata(
                surface="memory-graph",
                response_mode=mode,
                snapshot_revision=page["snapshot_revision"],
                filters=filters,
                ordering=(
                    "entries:updated_at-desc,memory_id-desc;"
                    "relationships:updated_at-desc,relationship_id-desc"
                ),
                total={
                    "nodes": page["entry_total"],
                    "relationships": page["relationship_total"],
                },
                returned={
                    "nodes": page["entry_returned"],
                    "relationships": page["relationship_returned"],
                },
                has_more=has_more,
                next_cursor=next_cursor,
                expires_at=expires_at,
                origin_node=codec.origin_node,
            ),
        }

    def _list_memory_graph_legacy(
        self,
        *,
        context: str,
        limit: int,
    ) -> dict[str, Any]:
        bounded_limit = min(max(int(limit), 1), 500)
        relationships = self.memory_store.list_relationships(
            context_id=context,
            limit=bounded_limit,
        )
        endpoint_ids: list[str] = []
        for relationship in relationships:
            endpoint_ids.append(str(relationship.get("source_memory_id") or ""))
            endpoint_ids.append(str(relationship.get("target_memory_id") or ""))
        max_graph_entries = min(max(bounded_limit * 2, bounded_limit), 1000)
        endpoint_entries = self.memory_store.list_entries_by_ids(
            endpoint_ids,
            context_id=context,
            limit=max_graph_entries,
        )
        recent_entries = self.memory_store.list_entries(
            context_id=context,
            include_global=True,
            limit=bounded_limit,
        )
        ordered_raw_entries: list[dict[str, Any]] = []
        seen_entry_ids: set[str] = set()
        endpoint_entry_ids: set[str] = set()
        for entry in endpoint_entries:
            memory_id = str(entry.get("memory_id") or "")
            if not memory_id or memory_id in seen_entry_ids:
                continue
            ordered_raw_entries.append(entry)
            seen_entry_ids.add(memory_id)
            endpoint_entry_ids.add(memory_id)
        for entry in recent_entries:
            if len(ordered_raw_entries) >= max_graph_entries:
                break
            memory_id = str(entry.get("memory_id") or "")
            if not memory_id or memory_id in seen_entry_ids:
                continue
            ordered_raw_entries.append(entry)
            seen_entry_ids.add(memory_id)
        entries = [
            self._render_memory_entry(entry, include_vectors=False)
            for entry in ordered_raw_entries
        ]
        relationship_entries = {str(entry["memory_id"]): entry for entry in entries}
        enriched_relationships = [
            self._decorate_memory_relationship(relationship, relationship_entries)
            for relationship in relationships
        ]
        return {
            "context_id": context,
            "memory_db_path": str(self.memory_store.db_path),
            "entry_count": len(entries),
            "recent_entry_count": len(recent_entries),
            "relationship_endpoint_count": len(endpoint_entry_ids),
            "graph_entry_strategy": "relationship_endpoints_first",
            "relationship_count": len(enriched_relationships),
            "relationship_summary": self._summarize_relationship_modes(enriched_relationships),
            "entries": entries,
            "relationships": enriched_relationships,
        }

    def _decorate_memory_relationship(
        self,
        relationship: dict[str, Any],
        entries_by_id: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        source_id = str(relationship.get("source_memory_id") or "")
        target_id = str(relationship.get("target_memory_id") or "")
        source_entry = self._relationship_entry(source_id, entries_by_id)
        target_entry = self._relationship_entry(target_id, entries_by_id)
        enriched = dict(relationship)
        if source_entry:
            enriched["source_label"] = self._surface_label_for_entry(source_entry)
            enriched["source_summary"] = self._surface_summary_for_entry(source_entry)
            enriched["source_facets"] = self._surface_facets_for_entry(source_entry)
        else:
            enriched["source_label"] = relationship.get("source_tag") or source_id
            enriched["source_summary"] = ""
            enriched["source_facets"] = []
        if target_entry:
            enriched["target_label"] = self._surface_label_for_entry(target_entry)
            enriched["target_summary"] = self._surface_summary_for_entry(target_entry)
            enriched["target_facets"] = self._surface_facets_for_entry(target_entry)
        else:
            enriched["target_label"] = relationship.get("target_tag") or target_id
            enriched["target_summary"] = ""
            enriched["target_facets"] = []
        return self._json_safe_metadata(enriched)

    def _relationship_entry(
        self,
        memory_id: str,
        entries_by_id: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        if memory_id in entries_by_id:
            return entries_by_id[memory_id]
        entry = self.memory_store.get_entry(memory_id)
        if entry is None:
            return None
        return self._render_memory_entry(entry, include_vectors=False)

    def _surface_label_for_entry(self, entry: dict[str, Any]) -> str:
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        label = str(metadata.get("display_label") or "").strip()
        if label:
            return self._compact_text(label, 96)
        return self._surface_label_from_fields(
            tag=str(entry.get("tag") or ""),
            text=str(entry.get("source_text") or ""),
            metadata=metadata,
        )

    def _surface_summary_for_entry(self, entry: dict[str, Any]) -> str:
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        summary = str(metadata.get("display_summary") or "").strip()
        if summary:
            return self._compact_text(summary, 180)
        return self._compact_text(str(entry.get("source_text") or ""), 180)

    def _surface_facets_for_entry(self, entry: dict[str, Any]) -> list[str]:
        metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        facets = metadata.get("semantic_facets")
        if isinstance(facets, (list, tuple)):
            return [str(facet) for facet in facets[:8] if str(facet).strip()]
        return self._surface_facets(
            label=self._surface_label_for_entry(entry),
            text=str(entry.get("source_text") or ""),
            metadata=metadata,
        )

    def _summarize_relationship_modes(
        self,
        relationships: list[dict[str, Any]],
    ) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        temporal = 0
        associative = 0
        for relationship in relationships:
            relation_type = str(relationship.get("relation_type") or "unknown")
            by_type[relation_type] = by_type.get(relation_type, 0) + 1
            if relation_type.startswith("temporal") or relation_type == "typed_context_sequence":
                temporal += 1
            elif relation_type.startswith("semantic") or relation_type.startswith("associative"):
                associative += 1
        total = len(relationships)
        return {
            "total": total,
            "temporal": temporal,
            "associative": associative,
            "other": max(0, total - temporal - associative),
            "by_type": dict(sorted(by_type.items())),
        }

    def resource_profile(
        self,
        *,
        benchmark_quick_prune: bool = False,
        target_min_mb: float = DEFAULT_RESOURCE_TARGET_MIN_MB,
        target_max_mb: float = DEFAULT_RESOURCE_TARGET_MAX_MB,
    ) -> dict[str, Any]:
        self._require_neural_substrate()
        arrays = {
            "W_syn": self._array_profile(self.W_syn),
            "W_lateral": self._array_profile(self.W_lateral),
            "mem": self._array_profile(self.state["mem"]),
            "spk": self._array_profile(self.state["spk"]),
            "active_traces": self._array_profile(self.active_traces),
        }
        estimated_total_bytes = sum(
            int(profile["estimated_bytes"])
            for profile in arrays.values()
        )
        estimated_total_mb = round(estimated_total_bytes / (1024.0 * 1024.0), 6)
        quick_profile = (
            self._benchmark_quick_pruning(trigger="resource-profile")
            if benchmark_quick_prune
            else None
        )
        profile = {
            "dimension": int(self.dimension),
            "num_neurons": int(self.num_neurons),
            "default_top_k": int(self.default_top_k),
            "recall_count": int(self.recall_count),
            "estimated_total_bytes": int(estimated_total_bytes),
            "estimated_total_mb": estimated_total_mb,
            "target_envelope_mb": {
                "min": float(target_min_mb),
                "max": float(target_max_mb),
            },
            "within_target_envelope": bool(
                float(target_min_mb) <= estimated_total_mb <= float(target_max_mb)
            ),
            "arrays": arrays,
            "mlx_device": os.getenv("MLX_DEVICE", "default"),
            "mlxsnn_lif_execution_path": self._mlxsnn_lif_layer is not None,
        }
        if quick_profile is not None:
            profile["quick_pruning"] = quick_profile
        return profile

    def certify_runtime(
        self,
        *,
        strict_native: bool = False,
        require_gpu: bool = False,
        benchmark_quick_prune: bool = False,
        require_resource_envelope: bool = False,
        target_min_mb: float = DEFAULT_RESOURCE_TARGET_MIN_MB,
        target_max_mb: float = DEFAULT_RESOURCE_TARGET_MAX_MB,
        output_path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        profile = self.resource_profile(
            benchmark_quick_prune=benchmark_quick_prune,
            target_min_mb=target_min_mb,
            target_max_mb=target_max_mb,
        )
        status = self.status(context_id="default")
        mlx_device = str(status.get("mlx_device") or "default").lower()
        provider_status = status["embedding_provider"]
        provider_type = str(provider_status.get("provider_type", ""))
        checks = {
            "mlx_available": self._cert_check(
                passed=mx is not None,
                required=True,
                detail="mlx.core import is available",
            ),
            "mx_compile_available": self._cert_check(
                passed=hasattr(self._mx, "compile"),
                required=bool(strict_native),
                detail="mlx.core exposes mx.compile",
            ),
            "mlxsnn_available": self._cert_check(
                passed=self._mlxsnn_available,
                required=bool(strict_native),
                detail="mlxsnn import is available",
            ),
            "mlxsnn_lif_execution_path": self._cert_check(
                passed=self._mlxsnn_lif_layer is not None,
                required=bool(strict_native),
                detail="mlxsnn.Leaky initialized and remains active",
            ),
            "mlx_device_gpu": self._cert_check(
                passed=mlx_device == "gpu",
                required=bool(require_gpu),
                detail=f"MLX_DEVICE={status.get('mlx_device')}",
            ),
            "resource_envelope": self._cert_check(
                passed=bool(profile["within_target_envelope"]),
                required=bool(require_resource_envelope),
                detail=(
                    f"{profile['estimated_total_mb']} MB inside "
                    f"{target_min_mb}-{target_max_mb} MB target"
                ),
            ),
            "quick_pruning_budget": self._cert_check(
                passed=(
                    not benchmark_quick_prune
                    or bool(profile.get("quick_pruning", {}).get("within_60ms_budget"))
                ),
                required=bool(benchmark_quick_prune),
                detail=(
                    "quick-prune benchmark disabled"
                    if not benchmark_quick_prune
                    else f"{profile['quick_pruning']['elapsed_ms']} ms"
                ),
            ),
            "embedding_provider_local": self._cert_check(
                passed=bool(provider_status.get("local_only", True)),
                required=True,
                detail=str(provider_status.get("provider", "")),
            ),
            "embedding_provider_native_mlx": self._cert_check(
                passed=(
                    provider_type != "mlx-neural"
                    or bool(provider_status.get("native_mlx", False))
                ),
                required=provider_type == "mlx-neural",
                detail=(
                    f"{provider_status.get('provider', '')} "
                    f"native_mlx={provider_status.get('native_mlx', False)}"
                ),
            ),
        }
        failed_checks = [
            name
            for name, check in checks.items()
            if check["required"] and not check["passed"]
        ]
        evidence_path = ""
        payload = {
            "action": "certify-runtime",
            "generated_at": time.time(),
            "ready": not failed_checks,
            "strict_native": bool(strict_native),
            "require_gpu": bool(require_gpu),
            "require_resource_envelope": bool(require_resource_envelope),
            "failed_checks": failed_checks,
            "checks": checks,
            "python": sys.version.split()[0],
            "executable": sys.executable,
            "platform": platform.platform(),
            "environment": {
                "MLX_DEVICE": os.getenv("MLX_DEVICE", ""),
                "SYNAPSE_S2_EMBEDDING_PROVIDER": os.getenv(
                    "SYNAPSE_S2_EMBEDDING_PROVIDER",
                    "",
                ),
                "SYNAPSE_S2_REQUIRE_NATIVE": os.getenv(
                    "SYNAPSE_S2_REQUIRE_NATIVE",
                    "",
                ),
            },
            "status": status,
            "resource_profile": profile,
            "embedding_provider": status["embedding_provider"],
        }
        if output_path:
            reject_sensitive_identifier(output_path, field="output_path")
            path = Path(output_path).expanduser().resolve()
            evidence_path = str(path)
            payload["evidence_path"] = evidence_path
            _atomic_write_private_json(path, payload)
        else:
            payload["evidence_path"] = evidence_path
        return payload

    def _cert_check(self, *, passed: bool, required: bool, detail: str) -> dict[str, Any]:
        return {
            "passed": bool(passed),
            "required": bool(required),
            "detail": str(detail),
        }

    def _array_profile(self, array: Any) -> dict[str, Any]:
        elements = self._array_element_count(array)
        dtype = str(getattr(array, "dtype", "float32"))
        dtype_bytes = 8 if "float64" in dtype else 4
        estimated_bytes = int(elements * dtype_bytes)
        return {
            "shape": [int(dimension) for dimension in getattr(array, "shape", ())],
            "dtype": dtype,
            "elements": int(elements),
            "estimated_bytes": estimated_bytes,
            "estimated_mb": round(estimated_bytes / (1024.0 * 1024.0), 6),
        }

    def _render_memory_entry(
        self,
        entry: dict[str, Any],
        *,
        include_vectors: bool,
    ) -> dict[str, Any]:
        if include_vectors:
            return dict(entry)
        spike_indices = [int(value) for value in entry.get("spike_indices", [])]
        neuron_indices = [int(value) for value in entry.get("neuron_indices", [])]
        rendered = {
            "memory_id": entry["memory_id"],
            "tag": entry["tag"],
            "context_id": entry["context_id"],
            "source_text": entry["source_text"],
            "metadata": entry["metadata"],
            "embedding_dimensions": entry["embedding_dimensions"],
            "spike_count": len(spike_indices),
            "neuron_count": len(neuron_indices),
            "spike_coordinate_sample": spike_indices[:12],
            "neuron_index_sample": neuron_indices[:12],
            "created_at": entry["created_at"],
            "updated_at": entry["updated_at"],
        }
        for key in (
            "recall_scope",
            "recall_provenance",
            "via_context_link_id",
            "via_relation_type",
            "via_direction",
        ):
            if key in entry:
                rendered[key] = entry[key]
        return rendered

    def _decorate_context_event(self, event: dict[str, Any]) -> dict[str, Any]:
        targets = [
            str(target)
            for target in event.get("agent_targets", [])
            if str(target).strip()
        ]
        return {
            **event,
            "agent_targets": targets,
            "target_count": len(targets),
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "protocol_version": CONTEXT_BUS_PROTOCOL_VERSION,
            "published": True,
        }

    def _decorate_context_cursor(self, cursor: dict[str, Any]) -> dict[str, Any]:
        return {
            **cursor,
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "protocol_version": CONTEXT_BUS_PROTOCOL_VERSION,
        }

    def export_memory(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        context_id: str | None = None,
        limit: int = 10_000,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id) if context_id is not None else None
        return self.memory_store.export_json(path, context_id=context, limit=limit)

    def backup_memory(
        self,
        path: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        return self.memory_store.backup(path)

    def backup_recovery_bundle(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        capture_root: str | os.PathLike[str] | None = None,
        purpose: str = "operator",
        pinned: bool = False,
        allow_noncanonical_capture_root: bool = False,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        return VerifiedRecoveryManager(
            self.memory_store,
            capture_root=capture_root,
            allow_noncanonical_capture_root=allow_noncanonical_capture_root,
        ).create_bundle(path, purpose=purpose, pinned=pinned)

    def audit_capture_ledger(
        self,
        *,
        capture_root: str | os.PathLike[str] | None = None,
        sample_limit: int = 20,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        authoritative_capture_root = (
            self.memory_store.db_path.parent
            if capture_root is None
            else capture_root
        )
        return VerifiedRecoveryManager(
            self.memory_store,
            capture_root=authoritative_capture_root,
        ).audit_capture_ledger(sample_limit=sample_limit)

    def repair_capture_ledger(
        self,
        *,
        capture_root: str | os.PathLike[str] | None = None,
        confirm: bool = False,
        expected_revision: str | None = None,
        sample_limit: int = 20,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        authoritative_capture_root = (
            self.memory_store.db_path.parent
            if capture_root is None
            else capture_root
        )
        return VerifiedRecoveryManager(
            self.memory_store,
            capture_root=authoritative_capture_root,
        ).repair_capture_ledger(
            confirm=confirm,
            expected_revision=expected_revision,
            sample_limit=sample_limit,
        )

    def verify_recovery_bundle(
        self,
        receipt_path: str | os.PathLike[str],
        *,
        capture_root: str | os.PathLike[str] | None = None,
        expected_database_sha256: str | None = None,
        expected_capture_sha256: str | None = None,
        expected_request_journal_sha256: str | None = None,
        expected_runtime_state_sha256: str | None = None,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        return VerifiedRecoveryManager(
            self.memory_store,
            capture_root=capture_root,
        ).verify_bundle(
            receipt_path,
            expected_database_sha256=expected_database_sha256,
            expected_capture_sha256=expected_capture_sha256,
            expected_request_journal_sha256=expected_request_journal_sha256,
            expected_runtime_state_sha256=expected_runtime_state_sha256,
        )

    def restore_recovery_bundle_isolated(
        self,
        receipt_path: str | os.PathLike[str],
        output_root: str | os.PathLike[str],
        *,
        capture_root: str | os.PathLike[str] | None = None,
        expected_database_sha256: str | None = None,
        expected_capture_sha256: str | None = None,
        expected_request_journal_sha256: str | None = None,
        expected_runtime_state_sha256: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        return VerifiedRecoveryManager(
            self.memory_store,
            capture_root=capture_root,
        ).restore_bundle_isolated(
            receipt_path,
            output_root,
            expected_database_sha256=expected_database_sha256,
            expected_capture_sha256=expected_capture_sha256,
            expected_request_journal_sha256=expected_request_journal_sha256,
            expected_runtime_state_sha256=expected_runtime_state_sha256,
            confirm=confirm,
        )

    def plan_recovery_retention(
        self,
        *,
        directory: str | os.PathLike[str] | None = None,
        keep_latest: int = 7,
        max_age_days: float = 30.0,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        return VerifiedRecoveryManager(self.memory_store).plan_retention(
            directory,
            keep_latest=keep_latest,
            max_age_days=max_age_days,
        )

    def apply_recovery_retention(
        self,
        *,
        plan_token: str,
        cutoff_created_at: float,
        directory: str | os.PathLike[str] | None = None,
        keep_latest: int = 7,
        max_age_days: float = 30.0,
        confirm: bool = False,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        return VerifiedRecoveryManager(self.memory_store).apply_retention(
            plan_token=plan_token,
            cutoff_created_at=cutoff_created_at,
            directory=directory,
            keep_latest=keep_latest,
            max_age_days=max_age_days,
            confirm=confirm,
        )

    def restore_retired_recovery(
        self,
        *,
        plan_token: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        from recovery_manager import VerifiedRecoveryManager

        return VerifiedRecoveryManager(self.memory_store).restore_retired(
            plan_token=plan_token,
            confirm=confirm,
        )

    def _mark_activity(self) -> None:
        self.last_activity_monotonic = time.monotonic()

    def _auto_quick_prune_if_due(self, *, trigger: str) -> dict[str, Any] | None:
        elapsed = time.monotonic() - self.last_pruning_monotonic
        if elapsed < self.quick_pruning_interval_seconds:
            return None
        return self.run_quick_pruning(trigger=f"auto:{trigger}")

    def run_quick_pruning(self, *, trigger: str = "manual") -> dict[str, Any]:
        """Run non-LLM synaptic decay and transient membrane flushing."""
        native_mx = self._mx
        timing = ConsolidationTiming(time.perf_counter())
        try:
            elapsed_min = max(1.0, (time.monotonic() - self.last_pruning_monotonic) / 60.0)
            syn_decay = self.quick_decay_syn**elapsed_min
            lateral_decay = self.quick_decay_lateral**elapsed_min
            decay_strategy = self._apply_weight_decay(
                syn_decay=syn_decay,
                lateral_decay=lateral_decay,
            )
            self.active_traces = self.active_traces * self.trace_decay
            self.state = {
                "mem": native_mx.zeros_like(self.state["mem"]),
                "spk": native_mx.zeros_like(self.state["spk"]),
            }
            self._eval_if_available(
                self.active_traces,
                self.state["mem"],
                self.state["spk"],
            )
            self.last_pruning_monotonic = time.monotonic()
            self.quick_pruning_count += 1
            elapsed_ms = timing.elapsed_ms()
            status = {
                "mode": "quick-pruning",
                "trigger": str(trigger),
                "elapsed_ms": elapsed_ms,
                "target_interval_seconds": self.quick_pruning_interval_seconds,
                "within_60ms_budget": elapsed_ms <= 60.0,
                "gpu_non_llm": True,
                "decay_strategy": decay_strategy,
                "syn_decay": round(float(syn_decay), 6),
                "lateral_decay": round(float(lateral_decay), 6),
                "W_syn_decay_multiplier": round(float(self.W_syn_decay_multiplier), 9),
                "W_lateral_decay_multiplier": round(float(self.W_lateral_decay_multiplier), 9),
                "membrane_reset": True,
                "quick_pruning_count": self.quick_pruning_count,
            }
            self.last_maintenance = status
            return status
        except Exception:
            LOGGER.exception("quick pruning failed")
            raise

    def _benchmark_quick_pruning(
        self,
        *,
        trigger: str,
        budget_ms: float = 60.0,
        max_samples: int = 2,
    ) -> dict[str, Any]:
        samples: list[dict[str, Any]] = []
        best: dict[str, Any] | None = None
        sample_count = max(1, int(max_samples))
        for index in range(sample_count):
            sample_trigger = trigger if index == 0 else f"{trigger}:warm-retry-{index + 1}"
            checkpoint = self._quick_prune_checkpoint() if index > 0 else None
            sample = dict(self.run_quick_pruning(trigger=sample_trigger))
            if checkpoint is not None:
                self._restore_quick_prune_checkpoint(checkpoint)
            sample["sample_index"] = index + 1
            sample["within_60ms_budget"] = (
                float(sample.get("elapsed_ms", 999999.0)) <= budget_ms
            )
            samples.append(sample)
            if best is None or float(sample["elapsed_ms"]) < float(best["elapsed_ms"]):
                best = sample
            if sample["within_60ms_budget"]:
                break
        if best is None:
            raise RuntimeError("quick-prune benchmark produced no samples")
        profile = dict(best)
        profile["trigger"] = trigger
        profile["best_sample_trigger"] = best.get("trigger", trigger)
        profile["budget_ms"] = float(budget_ms)
        profile["sample_count"] = len(samples)
        profile["samples"] = [
            {
                "sample_index": sample.get("sample_index"),
                "trigger": sample.get("trigger"),
                "elapsed_ms": sample.get("elapsed_ms"),
                "within_60ms_budget": sample.get("within_60ms_budget"),
                "decay_strategy": sample.get("decay_strategy"),
            }
            for sample in samples
        ]
        profile["cold_start_retry_used"] = (
            len(samples) > 1 and not bool(samples[0].get("within_60ms_budget"))
        )
        profile["cold_start_elapsed_ms"] = samples[0].get("elapsed_ms")
        profile["worst_elapsed_ms"] = max(float(sample["elapsed_ms"]) for sample in samples)
        profile["within_60ms_budget"] = float(profile["elapsed_ms"]) <= budget_ms
        self.last_maintenance = profile
        return profile

    def _quick_prune_checkpoint(self) -> dict[str, Any]:
        return {
            "W_syn": self.W_syn,
            "W_lateral": self.W_lateral,
            "active_traces": self.active_traces,
            "state": dict(self.state),
            "W_syn_decay_multiplier": self.W_syn_decay_multiplier,
            "W_lateral_decay_multiplier": self.W_lateral_decay_multiplier,
            "last_pruning_monotonic": self.last_pruning_monotonic,
        }

    def _restore_quick_prune_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        self.W_syn = checkpoint["W_syn"]
        self.W_lateral = checkpoint["W_lateral"]
        self.active_traces = checkpoint["active_traces"]
        self.state = dict(checkpoint["state"])
        self.W_syn_decay_multiplier = float(checkpoint["W_syn_decay_multiplier"])
        self.W_lateral_decay_multiplier = float(
            checkpoint["W_lateral_decay_multiplier"]
        )
        self.last_pruning_monotonic = float(checkpoint["last_pruning_monotonic"])

    def _apply_weight_decay(self, *, syn_decay: float, lateral_decay: float) -> str:
        total_elements = self._array_element_count(self.W_syn) + self._array_element_count(
            self.W_lateral
        )
        if total_elements <= self.quick_pruning_eager_decay_elements:
            self.W_syn = self.W_syn * syn_decay
            self.W_lateral = self.W_lateral * lateral_decay
            self.W_syn_decay_multiplier = 1.0
            self.W_lateral_decay_multiplier = 1.0
            self._eval_if_available(self.W_syn, self.W_lateral)
            return "eager-matrix"

        self.W_syn_decay_multiplier *= float(syn_decay)
        self.W_lateral_decay_multiplier *= float(lateral_decay)
        return "lazy-scalar"

    def _array_element_count(self, array: Any) -> int:
        count = 1
        for dimension in getattr(array, "shape", ()):
            count *= int(dimension)
        return int(count)

    def run_idle_maintenance(self, *, force_deep_sleep: bool = False) -> dict[str, Any]:
        """Run maintenance appropriate for the current idle window."""
        try:
            idle_seconds = time.monotonic() - self.last_activity_monotonic
            if force_deep_sleep or idle_seconds >= self.idle_deep_sleep_seconds:
                status = self.run_deep_sleep_consolidation(
                    trigger="idle-force" if force_deep_sleep else "idle-threshold"
                )
                status["idle_seconds"] = round(idle_seconds, 3)
                status["deep_sleep_threshold_seconds"] = self.idle_deep_sleep_seconds
                status["maintenance_run"] = True
                self.last_maintenance = status
                return status

            quick_status = self._auto_quick_prune_if_due(trigger="idle-maintenance")
            return {
                "mode": "idle-maintenance",
                "maintenance_run": quick_status is not None,
                "idle_seconds": round(idle_seconds, 3),
                "deep_sleep_threshold_seconds": self.idle_deep_sleep_seconds,
                "quick_pruning": quick_status,
            }
        except Exception:
            LOGGER.exception("idle maintenance failed")
            raise

    def run_deep_sleep_consolidation(self, *, trigger: str = "manual") -> dict[str, Any]:
        """Distill active traces into context-keyed semantic hierarchy groups."""
        timing = ConsolidationTiming(time.perf_counter())
        try:
            quick_status = self.run_quick_pruning(trigger=f"{trigger}:deep-sleep-prepass")
            ranked = self._rank_active_trace_indices(limit=max(self.recall_count, 32))
            grouped: dict[str, list[str]] = {}
            for idx in ranked:
                tag = self.memory_mapping.get(idx)
                if tag is None:
                    continue
                context = tag.split("::", 1)[0]
                grouped.setdefault(context, []).append(tag)
            memory_entries = self.memory_store.list_entries(limit=10_000)
            for entry in memory_entries:
                context = sanitize_context_id(str(entry["context_id"]))
                tag = sanitize_tag(str(entry["tag"]))
                members = grouped.setdefault(context, [])
                if tag not in members:
                    members.append(tag)

            threshold_before = self.threshold
            self._rescore_threshold(active_rank_count=len(ranked))
            relationships_by_context = {
                context: self.memory_store.list_relationships(
                    context_id=context,
                    limit=1_000,
                )
                for context in grouped
            }
            self.semantic_hierarchy = {
                context: {
                    "members": members,
                    "member_count": len(members),
                    "relationships": relationships_by_context.get(context, []),
                    "relationship_count": len(
                        relationships_by_context.get(context, [])
                    ),
                    "distillation": "hebbian-memory-store",
                }
                for context, members in grouped.items()
            }
            self.active_traces = self.active_traces * 0.5
            self._eval_if_available(self.active_traces)
            phases = self._build_consolidation_phases(
                grouped=grouped,
                memory_entries=memory_entries,
                ranked=ranked,
                quick_status=quick_status,
                threshold_before=threshold_before,
                relationship_count=sum(
                    len(relationships)
                    for relationships in relationships_by_context.values()
                ),
            )
            self.consolidation_phase_history = phases
            self.deep_sleep_count += 1
            elapsed_ms = timing.elapsed_ms()
            status = {
                "mode": "deep-sleep",
                "trigger": str(trigger),
                "elapsed_ms": elapsed_ms,
                "contexts": sorted(self.semantic_hierarchy),
                "semantic_groups": len(self.semantic_hierarchy),
                "memory_entry_count": len(memory_entries),
                "phase_count": len(phases),
                "phases": phases,
                "quick_pruning": quick_status,
                "deep_sleep_count": self.deep_sleep_count,
            }
            self.last_maintenance = status
            return status
        except Exception:
            LOGGER.exception("deep sleep consolidation failed")
            raise

    def _rescore_threshold(self, *, active_rank_count: int) -> None:
        active_fraction = active_rank_count / max(1, self.num_neurons)
        if active_fraction > 0.08:
            self.threshold = min(self.threshold * 1.02, 10.0)
        elif active_fraction < 0.005:
            self.threshold = max(self.threshold * 0.99, 0.05)

    def _build_consolidation_phases(
        self,
        *,
        grouped: dict[str, list[str]],
        memory_entries: list[dict[str, Any]],
        ranked: list[int],
        quick_status: dict[str, Any],
        threshold_before: float,
        relationship_count: int = 0,
    ) -> list[dict[str, Any]]:
        semantic_member_count = sum(len(members) for members in grouped.values())
        inactive_pool = max(0, self.num_neurons - len(set(ranked)))
        return [
            {
                "phase": 1,
                "name": "connection-weight-decay",
                "operation": "exponential GPU weight decay",
                "syn_decay": quick_status["syn_decay"],
                "lateral_decay": quick_status["lateral_decay"],
            },
            {
                "phase": 2,
                "name": "synaptic-clustering",
                "operation": "active trace density grouping",
                "active_trace_count": len(ranked),
            },
            {
                "phase": 3,
                "name": "semantic-merging",
                "operation": "context-keyed node pooling",
                "semantic_groups": len(grouped),
                "semantic_member_count": semantic_member_count,
            },
            {
                "phase": 4,
                "name": "threshold-rescoring",
                "operation": "bounded adaptive V_thr rescore",
                "threshold_before": round(float(threshold_before), 6),
                "threshold_after": round(float(self.threshold), 6),
            },
            {
                "phase": 5,
                "name": "trace-promotion",
                "operation": "durable SQLite memory substrate retention",
                "promoted_trace_count": len(memory_entries),
            },
            {
                "phase": 6,
                "name": "relationship-extraction",
                "operation": "Hebbian Distillation semantic graph build",
                "contexts": sorted(grouped),
                "relationship_count": int(relationship_count),
            },
            {
                "phase": 7,
                "name": "neurogenesis",
                "operation": "inactive transient state reset for reuse",
                "available_neuron_pool": inactive_pool,
            },
        ]

    def _rank_active_trace_indices(self, *, limit: int) -> list[int]:
        scored = [
            (int(idx), float(value))
            for idx, value in enumerate(self.active_traces.tolist())
            if float(value) > 0.0
        ]
        scored.sort(key=lambda item: item[1], reverse=True)
        return [idx for idx, _ in scored[:limit]]


_ENGINE_INSTANCE: Any | None = None
_CONTROL_PLANE_INSTANCE: Any | None = None
_ENGINE_INSTANCE_LOCK = threading.RLock()


def get_backend() -> Any:
    global _CONTROL_PLANE_INSTANCE, _ENGINE_INSTANCE
    if _ENGINE_INSTANCE is None:
        with _ENGINE_INSTANCE_LOCK:
            if _ENGINE_INSTANCE is None:
                _ENGINE_INSTANCE = _build_environment_backend(control_plane_only=False)
                if _is_authoritative_core_client(_ENGINE_INSTANCE):
                    _CONTROL_PLANE_INSTANCE = _ENGINE_INSTANCE
    return _ENGINE_INSTANCE


def get_control_plane_backend() -> Any:
    """Return the lightweight durable control plane without neural matrices.

    Short-lived MCP discovery/status clients use this lane so protocol
    availability does not depend on dense MLX initialization. Neural tools keep
    using :func:`get_backend` and therefore retain the full runtime contract.
    """

    global _CONTROL_PLANE_INSTANCE, _ENGINE_INSTANCE
    if _CONTROL_PLANE_INSTANCE is None:
        with _ENGINE_INSTANCE_LOCK:
            if _CONTROL_PLANE_INSTANCE is None:
                if _is_authoritative_core_client(_ENGINE_INSTANCE):
                    _CONTROL_PLANE_INSTANCE = _ENGINE_INSTANCE
                else:
                    _CONTROL_PLANE_INSTANCE = _build_environment_backend(
                        control_plane_only=True
                    )
                    if _is_authoritative_core_client(_CONTROL_PLANE_INSTANCE):
                        _ENGINE_INSTANCE = _CONTROL_PLANE_INSTANCE
    return _CONTROL_PLANE_INSTANCE


def _is_authoritative_core_client(value: Any) -> bool:
    if value is None:
        return False
    from core_client import CoreClient

    return isinstance(value, CoreClient)


def _build_environment_backend(*, control_plane_only: bool) -> Any:
    # Import lazily so the explicit backend class remains usable by tests,
    # recovery candidates, and the authoritative core without a cycle.
    from backend_router import build_environment_backend

    return build_environment_backend(control_plane_only=control_plane_only)


def simulate_spiking_retrieval(
    embedding: Any,
    context_id: str = "default",
    recall_scope: str = "local",
) -> str:
    return get_backend().query(
        embedding,
        context_id=context_id,
        recall_scope=recall_scope,
    )


def simulate_spiking_text_retrieval(
    prompt: str,
    context_id: str = "default",
    recall_scope: str = "local",
) -> str:
    return get_backend().query_text(
        prompt,
        context_id=context_id,
        recall_scope=recall_scope,
    )


def register_trace(
    *,
    tag: str,
    embedding: Any,
    context_id: str = "default",
    metadata: dict[str, Any] | None = None,
    source_text: str = "",
) -> dict[str, Any]:
    return get_backend().register_trace(
        tag=tag,
        embedding=embedding,
        context_id=context_id,
        metadata=metadata,
        source_text=source_text,
    )


def register_text_trace(
    *,
    tag: str,
    text: str,
    context_id: str = "default",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return get_backend().register_text_trace(
        tag=tag,
        text=text,
        context_id=context_id,
        metadata=metadata,
    )


def set_enabled(enabled: bool, context_id: str | None = None) -> dict[str, Any]:
    return get_backend().set_enabled(enabled, context_id=context_id)


def get_status(context_id: str = "default") -> dict[str, Any]:
    backend = _ENGINE_INSTANCE or get_control_plane_backend()
    return backend.status(context_id=context_id)


def list_memory(
    context_id: str = "default",
    limit: int = 50,
    include_global: bool = True,
    include_vectors: bool = False,
    recall_scope: str = "local",
    cursor: str = "",
    response_mode: str = "legacy",
) -> dict[str, Any]:
    return get_backend().list_memory(
        context_id=context_id,
        limit=limit,
        include_global=include_global,
        include_vectors=include_vectors,
        recall_scope=recall_scope,
        cursor=cursor,
        response_mode=response_mode,
    )


def retrieve_text_v2(
    prompt: str,
    *,
    context_id: str = "default",
    recall_scope: str = "local",
    result_limit: int = 10,
    candidate_limit: int = 128,
    include_graph_neighbors: bool = True,
) -> dict[str, Any]:
    return get_backend().retrieve_text_v2(
        prompt,
        context_id=context_id,
        recall_scope=recall_scope,
        result_limit=result_limit,
        candidate_limit=candidate_limit,
        include_graph_neighbors=include_graph_neighbors,
    )


def publish_context_event(
    *,
    context_id: str = "default",
    source_surface: str,
    event_type: str,
    summary: str,
    payload: dict[str, Any] | None = None,
    agent_targets: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    return get_backend().publish_context_event(
        context_id=context_id,
        source_surface=source_surface,
        event_type=event_type,
        summary=summary,
        payload=payload,
        agent_targets=agent_targets,
    )


def list_context_events(
    context_id: str = "default",
    since_event_id: int = 0,
    before_event_id: int | None = None,
    agent_id: str | None = None,
    order: str = "asc",
    limit: int = 100,
) -> dict[str, Any]:
    return get_backend().list_context_events(
        context_id=context_id,
        since_event_id=since_event_id,
        before_event_id=before_event_id,
        agent_id=agent_id,
        order=order,
        limit=limit,
    )


def lease_context_events(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    consumer_instance_id: str = "",
    limit: int = 20,
    lease_seconds: float = 60.0,
) -> dict[str, Any]:
    return get_backend().lease_context_events(
        context_id=context_id,
        agent_id=agent_id,
        consumer_instance_id=consumer_instance_id,
        limit=limit,
        lease_seconds=lease_seconds,
    )


def ack_context_events(
    context_id: str = "default",
    agent_id: str = "mcp-client",
    receipt_id: str = "",
    acknowledgements: list[dict[str, Any]] | None = None,
    last_event_id: int | None = None,
) -> dict[str, Any]:
    return get_backend().ack_context_events(
        context_id=context_id,
        agent_id=agent_id,
        receipt_id=receipt_id,
        acknowledgements=acknowledgements,
        last_event_id=last_event_id,
    )


def release_context_events(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    consumer_instance_id: str = "",
    receipt_ids: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    return get_backend().release_context_events(
        context_id=context_id,
        agent_id=agent_id,
        consumer_instance_id=consumer_instance_id,
        receipt_ids=receipt_ids,
    )


def dead_letter_context_delivery(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    delivery_id: str,
    reason: str,
    confirm: bool = False,
) -> dict[str, Any]:
    return get_backend().dead_letter_context_delivery(
        context_id=context_id,
        agent_id=agent_id,
        delivery_id=delivery_id,
        reason=reason,
        confirm=confirm,
    )


def list_context_cursors(
    context_id: str = "default",
    limit: int = 100,
) -> dict[str, Any]:
    return get_backend().list_context_cursors(
        context_id=context_id,
        limit=limit,
    )


def hydrate_agent_context(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    prompt: str = "",
    since_event_id: int | None = None,
    event_limit: int = 20,
    graph_limit: int = 30,
    acknowledge: bool = False,
    claim_events: bool = True,
    consumer_instance_id: str = "",
    lease_seconds: float = 60.0,
) -> dict[str, Any]:
    return get_backend().hydrate_agent_context(
        context_id=context_id,
        agent_id=agent_id,
        prompt=prompt,
        since_event_id=since_event_id,
        event_limit=event_limit,
        graph_limit=graph_limit,
        acknowledge=acknowledge,
        claim_events=claim_events,
        consumer_instance_id=consumer_instance_id,
        lease_seconds=lease_seconds,
    )


def enter_spiking_cortex(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    task: str,
    mode: str = "strict",
) -> dict[str, Any]:
    return get_backend().enter_spiking_cortex(
        context_id=context_id,
        agent_id=agent_id,
        task=task,
        mode=mode,
    )


def cortex_tick(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    session_id: str,
    observation: str = "",
    proposed_action: str = "",
    intended_files: Any = None,
    intended_tools: Any = None,
    mutation_intent: bool = False,
    confidence: float = 0.5,
) -> dict[str, Any]:
    return get_backend().cortex_tick(
        context_id=context_id,
        agent_id=agent_id,
        session_id=session_id,
        observation=observation,
        proposed_action=proposed_action,
        intended_files=intended_files,
        intended_tools=intended_tools,
        mutation_intent=mutation_intent,
        confidence=confidence,
    )


def close_spiking_cortex(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    session_id: str,
    reason: str = "operator-complete",
) -> dict[str, Any]:
    return get_backend().close_spiking_cortex(
        context_id=context_id,
        agent_id=agent_id,
        session_id=session_id,
        reason=reason,
    )


def commit_cortical_trace(
    *,
    context_id: str = "default",
    agent_id: str = "mcp-client",
    session_id: str = "",
    trace_type: str = "",
    truth_posture: str = "observed",
    text: str,
    evidence: dict[str, Any] | None = None,
    confidence: float | None = None,
) -> dict[str, Any]:
    return get_backend().commit_cortical_trace(
        context_id=context_id,
        agent_id=agent_id,
        session_id=session_id,
        trace_type=trace_type,
        truth_posture=truth_posture,
        text=text,
        evidence=evidence,
        confidence=confidence,
    )


def get_cortex_state(
    *,
    context_id: str = "default",
    agent_id: str = "",
    limit: int = 50,
    cursor: str = "",
    response_mode: str = "legacy",
) -> dict[str, Any]:
    return get_backend().get_cortex_state(
        context_id=context_id,
        agent_id=agent_id,
        limit=limit,
        cursor=cursor,
        response_mode=response_mode,
    )


def create_goal(
    *,
    context_id: str = "default",
    agent_id: str = "operator",
    title: str,
    owner: str = "",
    state: str = "planned",
    next_action: str = "",
    evidence: str = "",
) -> dict[str, Any]:
    return get_backend().create_goal(
        context_id=context_id,
        agent_id=agent_id,
        title=title,
        owner=owner,
        state=state,
        next_action=next_action,
        evidence=evidence,
    )


def update_goal(
    *,
    context_id: str = "default",
    agent_id: str = "operator",
    goal_id: str = "",
    title: str = "",
    owner: str = "",
    state: str = "",
    next_action: str = "",
    evidence: str = "",
) -> dict[str, Any]:
    return get_backend().update_goal(
        context_id=context_id,
        agent_id=agent_id,
        goal_id=goal_id,
        title=title,
        owner=owner,
        state=state,
        next_action=next_action,
        evidence=evidence,
    )


def list_goals(
    *,
    context_id: str = "default",
    limit: int = 20,
) -> dict[str, Any]:
    return get_backend().list_goals(context_id=context_id, limit=limit)


def moderate_cortex_trace(
    *,
    context_id: str = "default",
    memory_id: str,
    action: str,
    reason: str = "",
    source_surface: str = "operator",
    confirm: bool = False,
) -> dict[str, Any]:
    return get_backend().moderate_cortex_trace(
        context_id=context_id,
        memory_id=memory_id,
        action=action,
        reason=reason,
        source_surface=source_surface,
        confirm=confirm,
    )


def ingest_text_events(
    *,
    text: str,
    context_id: str = "default",
    source_tag: str = "memory",
    surprise_threshold: float = 0.62,
    min_segment_sentences: int = 2,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return get_backend().ingest_text_events(
        text=text,
        context_id=context_id,
        source_tag=source_tag,
        surprise_threshold=surprise_threshold,
        min_segment_sentences=min_segment_sentences,
        metadata=metadata,
    )


def capture_conversation(
    *,
    text: str,
    context_id: str = "default",
    source_tag: str = "codex-session",
    speaker: str = "operator",
    surprise_threshold: float = 0.5,
    min_segment_sentences: int = 1,
    metadata: dict[str, Any] | None = None,
    capture_id: str | None = None,
) -> dict[str, Any]:
    return get_backend().capture_conversation(
        text=text,
        context_id=context_id,
        source_tag=source_tag,
        speaker=speaker,
        surprise_threshold=surprise_threshold,
        min_segment_sentences=min_segment_sentences,
        metadata=metadata,
        capture_id=capture_id,
    )


def prune_memory(
    *,
    context_id: str = "default",
    target_type: str,
    memory_id: str = "",
    tag: str = "",
    relationship_id: str = "",
    event_id: int = 0,
    reason: str = "",
    source_surface: str = "operator",
    publish_audit: bool = True,
    confirm: bool,
) -> dict[str, Any]:
    return get_backend().prune_memory(
        context_id=context_id,
        target_type=target_type,
        memory_id=memory_id,
        tag=tag,
        relationship_id=relationship_id,
        event_id=event_id,
        reason=reason,
        source_surface=source_surface,
        publish_audit=publish_audit,
        confirm=confirm,
    )


def list_memory_graph(
    context_id: str = "default",
    limit: int = 100,
    cursor: str = "",
    response_mode: str = "legacy",
    include_global: bool = True,
) -> dict[str, Any]:
    return get_backend().list_memory_graph(
        context_id=context_id,
        limit=limit,
        cursor=cursor,
        response_mode=response_mode,
        include_global=include_global,
    )


def approve_namespace_link(
    *,
    source_context_id: str,
    target_context_id: str,
    relation_type: str = "related",
    weight: float = 1.0,
    evidence: dict[str, Any] | None = None,
    direction: str = "bidirectional",
    approved_by: str = "operator",
    enabled: bool = True,
    reason: str = "explicit operator approval",
    link_expires_at: float | None = None,
    governance_request_id: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    return get_backend().approve_namespace_link(
        source_context_id=source_context_id,
        target_context_id=target_context_id,
        relation_type=relation_type,
        weight=weight,
        evidence=evidence,
        direction=direction,
        approved_by=approved_by,
        enabled=enabled,
        reason=reason,
        link_expires_at=link_expires_at,
        governance_request_id=governance_request_id,
        confirm=confirm,
    )


def propose_namespace_link(**arguments: Any) -> dict[str, Any]:
    return get_backend().propose_namespace_link(**arguments)


def review_namespace_link(**arguments: Any) -> dict[str, Any]:
    return get_backend().review_namespace_link(**arguments)


def disable_namespace_link(**arguments: Any) -> dict[str, Any]:
    return get_backend().disable_namespace_link(**arguments)


def revoke_namespace_link(**arguments: Any) -> dict[str, Any]:
    return get_backend().revoke_namespace_link(**arguments)


def list_namespace_link_proposals(**arguments: Any) -> dict[str, Any]:
    return get_backend().list_namespace_link_proposals(**arguments)


def list_namespace_link_history(**arguments: Any) -> dict[str, Any]:
    return get_backend().list_namespace_link_history(**arguments)


def audit_namespace_link_governance() -> dict[str, Any]:
    return get_backend().audit_namespace_link_governance()


def expire_namespace_links() -> dict[str, Any]:
    return get_backend().expire_namespace_links()


def delete_namespace_link(
    *,
    context_link_id: str,
    expected_revision: str,
    revoked_by: str = "operator",
    reason: str = "legacy delete request converted to governed revocation",
    governance_request_id: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    return get_backend().delete_namespace_link(
        context_link_id=context_link_id,
        expected_revision=expected_revision,
        revoked_by=revoked_by,
        reason=reason,
        governance_request_id=governance_request_id,
        confirm=confirm,
    )


def suggest_namespace_links(
    *,
    context_id: str = "",
    limit: int = 50,
    min_score: float = 0.05,
    include_linked: bool = False,
    max_visual_phase_delay_ticks: int = 4,
) -> dict[str, Any]:
    return get_backend().suggest_namespace_links(
        context_id=context_id,
        limit=limit,
        min_score=min_score,
        include_linked=include_linked,
        max_visual_phase_delay_ticks=max_visual_phase_delay_ticks,
    )


def list_namespace_map(
    *,
    context_id: str = "",
    limit: int = 500,
    include_suggestions: bool = True,
    suggestion_limit: int = 50,
    min_suggestion_score: float = 0.05,
    max_visual_phase_delay_ticks: int = 4,
) -> dict[str, Any]:
    return get_backend().list_namespace_map(
        context_id=context_id,
        limit=limit,
        include_suggestions=include_suggestions,
        suggestion_limit=suggestion_limit,
        min_suggestion_score=min_suggestion_score,
        max_visual_phase_delay_ticks=max_visual_phase_delay_ticks,
    )


def resource_profile(
    *,
    benchmark_quick_prune: bool = False,
    target_min_mb: float = DEFAULT_RESOURCE_TARGET_MIN_MB,
    target_max_mb: float = DEFAULT_RESOURCE_TARGET_MAX_MB,
) -> dict[str, Any]:
    return get_backend().resource_profile(
        benchmark_quick_prune=benchmark_quick_prune,
        target_min_mb=target_min_mb,
        target_max_mb=target_max_mb,
    )


def benchmark_embedding_provider(
    *,
    text: str,
    runs: int = 1,
    dimensions: int | None = None,
) -> dict[str, Any]:
    return get_backend().benchmark_embedding_provider(
        text=text,
        runs=runs,
        dimensions=dimensions,
    )


def certify_runtime(
    *,
    strict_native: bool = False,
    require_gpu: bool = False,
    benchmark_quick_prune: bool = False,
    require_resource_envelope: bool = False,
    target_min_mb: float = DEFAULT_RESOURCE_TARGET_MIN_MB,
    target_max_mb: float = DEFAULT_RESOURCE_TARGET_MAX_MB,
    output_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    return get_backend().certify_runtime(
        strict_native=strict_native,
        require_gpu=require_gpu,
        benchmark_quick_prune=benchmark_quick_prune,
        require_resource_envelope=require_resource_envelope,
        target_min_mb=target_min_mb,
        target_max_mb=target_max_mb,
        output_path=output_path,
    )


def export_memory(
    path: str | os.PathLike[str] | None = None,
    context_id: str | None = None,
) -> dict[str, Any]:
    return get_backend().export_memory(path=path, context_id=context_id)


def backup_memory(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    return get_backend().backup_memory(path=path)


def backup_recovery_bundle(
    path: str | os.PathLike[str] | None = None,
    *,
    capture_root: str | os.PathLike[str] | None = None,
    purpose: str = "operator",
    pinned: bool = False,
    allow_noncanonical_capture_root: bool = False,
) -> dict[str, Any]:
    backend = get_backend()
    if _is_authoritative_core_client(backend):
        if capture_root is not None or allow_noncanonical_capture_root:
            raise ValueError(
                "capture root overrides are unavailable on the authoritative core lane"
            )
        return backend.backup_recovery_bundle(
            path=path,
            purpose=purpose,
            pinned=pinned,
        )
    return backend.backup_recovery_bundle(
        path=path,
        capture_root=capture_root,
        purpose=purpose,
        pinned=pinned,
        allow_noncanonical_capture_root=allow_noncanonical_capture_root,
    )


def audit_capture_ledger(
    *,
    capture_root: str | os.PathLike[str] | None = None,
    sample_limit: int = 20,
) -> dict[str, Any]:
    backend = get_control_plane_backend()
    if _is_authoritative_core_client(backend):
        if capture_root is not None:
            raise ValueError(
                "capture root overrides are unavailable on the authoritative core lane"
            )
        return backend.audit_capture_ledger(sample_limit=sample_limit)
    return backend.audit_capture_ledger(
        capture_root=capture_root,
        sample_limit=sample_limit,
    )


def repair_capture_ledger(
    *,
    capture_root: str | os.PathLike[str] | None = None,
    confirm: bool = False,
    expected_revision: str | None = None,
    sample_limit: int = 20,
) -> dict[str, Any]:
    backend = get_control_plane_backend()
    if _is_authoritative_core_client(backend):
        if capture_root is not None:
            raise ValueError(
                "capture root overrides are unavailable on the authoritative core lane"
            )
        return backend.repair_capture_ledger(
            confirm=confirm,
            expected_revision=expected_revision,
            sample_limit=sample_limit,
        )
    return backend.repair_capture_ledger(
        capture_root=capture_root,
        confirm=confirm,
        expected_revision=expected_revision,
        sample_limit=sample_limit,
    )


def verify_recovery_bundle(
    receipt_path: str | os.PathLike[str],
    *,
    capture_root: str | os.PathLike[str] | None = None,
    expected_database_sha256: str | None = None,
    expected_capture_sha256: str | None = None,
    expected_request_journal_sha256: str | None = None,
    expected_runtime_state_sha256: str | None = None,
) -> dict[str, Any]:
    backend = get_backend()
    if _is_authoritative_core_client(backend):
        if capture_root is not None:
            raise ValueError(
                "capture root overrides are unavailable on the authoritative core lane"
            )
        return backend.verify_recovery_bundle(
            receipt_path,
            expected_database_sha256=expected_database_sha256,
            expected_capture_sha256=expected_capture_sha256,
            expected_request_journal_sha256=expected_request_journal_sha256,
            expected_runtime_state_sha256=expected_runtime_state_sha256,
        )
    return backend.verify_recovery_bundle(
        receipt_path,
        capture_root=capture_root,
        expected_database_sha256=expected_database_sha256,
        expected_capture_sha256=expected_capture_sha256,
        expected_request_journal_sha256=expected_request_journal_sha256,
        expected_runtime_state_sha256=expected_runtime_state_sha256,
    )


def restore_recovery_bundle_isolated(
    receipt_path: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    *,
    capture_root: str | os.PathLike[str] | None = None,
    expected_database_sha256: str | None = None,
    expected_capture_sha256: str | None = None,
    expected_request_journal_sha256: str | None = None,
    expected_runtime_state_sha256: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    backend = get_backend()
    if _is_authoritative_core_client(backend):
        if capture_root is not None:
            raise ValueError(
                "capture root overrides are unavailable on the authoritative core lane"
            )
        return backend.restore_recovery_bundle_isolated(
            receipt_path,
            output_root,
            expected_database_sha256=expected_database_sha256,
            expected_capture_sha256=expected_capture_sha256,
            expected_request_journal_sha256=expected_request_journal_sha256,
            expected_runtime_state_sha256=expected_runtime_state_sha256,
            confirm=confirm,
        )
    return backend.restore_recovery_bundle_isolated(
        receipt_path,
        output_root,
        capture_root=capture_root,
        expected_database_sha256=expected_database_sha256,
        expected_capture_sha256=expected_capture_sha256,
        expected_request_journal_sha256=expected_request_journal_sha256,
        expected_runtime_state_sha256=expected_runtime_state_sha256,
        confirm=confirm,
    )


def plan_recovery_retention(
    *,
    directory: str | os.PathLike[str] | None = None,
    keep_latest: int = 7,
    max_age_days: float = 30.0,
) -> dict[str, Any]:
    backend = get_backend()
    if _is_authoritative_core_client(backend):
        if directory is not None:
            raise ValueError(
                "retention directory overrides are unavailable on the authoritative core lane"
            )
        return backend.plan_recovery_retention(
            keep_latest=keep_latest,
            max_age_days=max_age_days,
        )
    return backend.plan_recovery_retention(
        directory=directory,
        keep_latest=keep_latest,
        max_age_days=max_age_days,
    )


def apply_recovery_retention(
    *,
    plan_token: str,
    cutoff_created_at: float,
    directory: str | os.PathLike[str] | None = None,
    keep_latest: int = 7,
    max_age_days: float = 30.0,
    confirm: bool = False,
) -> dict[str, Any]:
    backend = get_backend()
    if _is_authoritative_core_client(backend):
        if directory is not None:
            raise ValueError(
                "retention directory overrides are unavailable on the authoritative core lane"
            )
        return backend.apply_recovery_retention(
            plan_token=plan_token,
            cutoff_created_at=cutoff_created_at,
            keep_latest=keep_latest,
            max_age_days=max_age_days,
            confirm=confirm,
        )
    return backend.apply_recovery_retention(
        plan_token=plan_token,
        cutoff_created_at=cutoff_created_at,
        directory=directory,
        keep_latest=keep_latest,
        max_age_days=max_age_days,
        confirm=confirm,
    )


def restore_retired_recovery(
    *,
    plan_token: str,
    confirm: bool = False,
) -> dict[str, Any]:
    return get_backend().restore_retired_recovery(
        plan_token=plan_token,
        confirm=confirm,
    )


def run_quick_pruning() -> dict[str, Any]:
    return get_backend().run_quick_pruning()


def run_idle_maintenance(*, force_deep_sleep: bool = False) -> dict[str, Any]:
    return get_backend().run_idle_maintenance(force_deep_sleep=force_deep_sleep)


def run_offline_consolidation() -> dict[str, Any]:
    return get_backend().run_deep_sleep_consolidation()


def run_deep_sleep_consolidation() -> dict[str, Any]:
    return get_backend().run_deep_sleep_consolidation()

from __future__ import annotations

import hashlib
import logging
import json
import math
import os
import platform
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from embedding_providers import EmbeddingProviderError, resolve_embedding_provider
from event_segmenter import BayesianSurpriseEventSegmenter
from memory_store import DurableMemoryStore
from redaction import redact_capture_text, redact_sensitive_value

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
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

MAX_EMBEDDING_DIMS = 32_768
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
DEFAULT_AGENT_TARGETS = ("mcp-clients", "codex-desktop", "local-ide-adapters")
CONTEXT_BUS_DELIVERY_MODE = "durable-mcp-pull"
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


class BackendUnavailable(RuntimeError):
    """Raised when the native MLX runtime is unavailable."""


@dataclass(frozen=True)
class ConsolidationTiming:
    started_at: float

    def elapsed_ms(self) -> float:
        return round((time.perf_counter() - self.started_at) * 1000.0, 3)


def _require_mx() -> Any:
    if mx is None:
        raise BackendUnavailable(f"mlx.core import failed: {_MLX_IMPORT_ERROR}")
    return mx


def sanitize_context_id(context_id: str) -> str:
    raw = str(context_id or "default").strip()
    cleaned = CONTEXT_ID_RE.sub("_", raw).strip("._-:")
    return (cleaned or "default")[:128]


def sanitize_tag(tag: str) -> str:
    raw = str(tag or "").strip()
    cleaned = TAG_RE.sub("_", raw).strip()
    return (cleaned or "untagged-trace")[:200]


def sanitize_agent_id(agent_id: str) -> str:
    raw = str(agent_id or "").strip()
    cleaned = AGENT_ID_RE.sub("_", raw).strip("._-:@")
    return (cleaned or "unknown-agent")[:128]


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
        num_neurons: int = 5400,
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
        require_native: bool = False,
    ) -> None:
        native_mx = _require_mx()
        if dimension <= 0:
            raise ValueError("dimension must be positive")
        if num_neurons <= 0:
            raise ValueError("num_neurons must be positive")
        if not 0.0 < beta < 1.0:
            raise ValueError("beta must be in the open interval (0, 1)")
        if threshold <= 0.0:
            raise ValueError("threshold must be positive")
        if quick_pruning_interval_seconds < 0.0:
            raise ValueError("quick_pruning_interval_seconds must be non-negative")
        if idle_deep_sleep_seconds < 0.0:
            raise ValueError("idle_deep_sleep_seconds must be non-negative")

        self.dimension = int(dimension)
        self.num_neurons = int(num_neurons)
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
        self._mx = native_mx
        self._lif_step = self._build_lif_step(compile_graph)
        self._mlxsnn_available = mlxsnn is not None
        self._mlxsnn_lif_layer = self._build_mlxsnn_lif_layer()
        self.embedding_provider_name = embedding_provider_name or os.getenv(
            "SYNAPSE_S2_EMBEDDING_PROVIDER",
            "auto",
        )
        self.embedding_provider = resolve_embedding_provider(self.embedding_provider_name)
        self.state_path = self._resolve_state_path(state_path)
        if memory_path is None and state_path is not None:
            resolved_memory_path = self.state_path.parent / "memory.sqlite3"
        else:
            resolved_memory_path = self._resolve_memory_path(memory_path)
        self.memory_store = DurableMemoryStore(resolved_memory_path)
        self.global_enabled = True
        self.context_overrides: dict[str, bool] = {}
        self.cortex_sessions: dict[str, dict[str, Any]] = {}
        self.registered_traces: list[dict[str, Any]] = []
        self._surface_recall_cache: dict[str, dict[str, Any]] = {}

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
        self.state: dict[str, Any] = {
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
        self._load_runtime_state()
        self._refresh_registered_traces()

        if not self._mlxsnn_available:
            LOGGER.warning(
                "mlxsnn import failed; using explicit MLX LIF math until installed: %s",
                _MLXSNN_IMPORT_ERROR,
            )
        if require_native:
            certification = self.certify_runtime(strict_native=True)
            if not certification["ready"]:
                raise BackendUnavailable(
                    "SYNAPSE-S2 native certification failed: "
                    + ", ".join(certification["failed_checks"])
                )

    def _resolve_state_path(self, state_path: str | os.PathLike[str] | None) -> Path:
        if state_path is not None:
            return Path(state_path)
        configured = os.getenv("SYNAPSE_S2_STATE_PATH")
        if configured:
            return Path(configured)
        project_dir = os.getenv("CLAUDE_PROJECT_DIR") or os.getenv("CODEX_PROJECT_DIR")
        if project_dir:
            return Path(project_dir).expanduser() / ".synapse_s2" / "runtime_state.json"
        return Path.cwd() / ".synapse_s2" / "runtime_state.json"

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
        if not self.state_path.exists():
            return
        try:
            migrated_trace_count = 0
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("runtime state root must be an object")
            self.global_enabled = bool(payload.get("global_enabled", True))
            overrides = payload.get("context_overrides", {})
            if isinstance(overrides, dict):
                self.context_overrides = {
                    sanitize_context_id(key): bool(value)
                    for key, value in overrides.items()
                }
            cortex_sessions = payload.get("cortex_sessions", {})
            if isinstance(cortex_sessions, dict):
                self.cortex_sessions = {
                    str(session_id): self._normalize_cortex_session(raw_session)
                    for session_id, raw_session in cortex_sessions.items()
                    if isinstance(raw_session, dict)
                }
            traces = payload.get("registered_traces", [])
            if isinstance(traces, list):
                for raw_trace in traces:
                    if not isinstance(raw_trace, dict):
                        continue
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
            if migrated_trace_count:
                LOGGER.info(
                    "migrated %s legacy runtime traces into SQLite memory store",
                    migrated_trace_count,
                )
                self._persist_runtime_state()
        except Exception as exc:
            LOGGER.error("failed to load runtime state from %s: %s", self.state_path, exc)

    def _persist_runtime_state(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 2,
                "global_enabled": self.global_enabled,
                "context_overrides": self.context_overrides,
                "cortex_sessions": self.cortex_sessions,
                "memory_db_path": str(self.memory_store.db_path),
                "updated_at": time.time(),
            }
            temp_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            temp_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            temp_path.replace(self.state_path)
        except Exception:
            LOGGER.exception("failed to persist runtime state to %s", self.state_path)
            raise

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
            "source_text": str(entry.get("source_text", "")),
        }

    def _normalize_trace_payload(self, trace: dict[str, Any]) -> dict[str, Any]:
        metadata = trace.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {"value": str(metadata)}
        return {
            "tag": sanitize_tag(str(trace.get("tag", "untagged-trace"))),
            "context_id": sanitize_context_id(str(trace.get("context_id", "default"))),
            "embedding_dimensions": int(trace.get("embedding_dimensions", self.dimension)),
            "spike_indices": [int(idx) for idx in trace.get("spike_indices", [])],
            "neuron_indices": [int(idx) for idx in trace.get("neuron_indices", [])],
            "metadata": self._json_safe_metadata(metadata),
            "registered_at": float(trace.get("registered_at", time.time())),
            "source_text": str(trace.get("source_text", "")),
        }

    def _json_safe_metadata(self, metadata: dict[str, Any] | None) -> dict[str, Any]:
        if not metadata:
            return {}
        try:
            return json.loads(json.dumps(metadata, default=str))
        except Exception:
            return {str(key): str(value) for key, value in metadata.items()}

    def _normalize_cortex_session(self, session: dict[str, Any]) -> dict[str, Any]:
        now = time.time()
        session_id = str(session.get("session_id") or "").strip()
        if not session_id:
            seed = json.dumps(session, sort_keys=True, default=str).encode("utf-8")
            session_id = "ctx_" + hashlib.sha256(seed).hexdigest()[:16]
        mode = str(session.get("mode") or "strict").strip().lower()
        if mode not in CORTEX_MODES:
            mode = "strict"
        status = str(session.get("status") or "active").strip().lower()
        if status not in {"active", "closed", "finished", "orphaned"}:
            status = "active"
        normalized = {
            "session_id": session_id,
            "context_id": sanitize_context_id(str(session.get("context_id", "default"))),
            "agent_id": sanitize_agent_id(str(session.get("agent_id", "unknown-agent"))),
            "task": str(session.get("task", "")).strip()[:2000],
            "mode": mode,
            "status": status,
            "started_at": float(session.get("started_at", now) or now),
            "updated_at": float(session.get("updated_at", now) or now),
            "tick_count": int(max(0, int(session.get("tick_count", 0) or 0))),
            "last_decision": str(session.get("last_decision", "enter")),
            "last_confidence": float(session.get("last_confidence", 0.0) or 0.0),
            "last_observation": str(session.get("last_observation", ""))[:2000],
            "last_proposed_action": str(session.get("last_proposed_action", ""))[:2000],
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
                normalized[key] = str(session.get(key, ""))[:500]
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

    def _coerce_embedding(self, embedding: Any):
        native_mx = self._mx
        arr = native_mx.array(embedding, dtype=native_mx.float32)
        if len(arr.shape) != 1:
            raise ValueError("prompt_embedding must be a one-dimensional coordinate list")
        if arr.shape[0] == 0:
            raise ValueError("prompt_embedding must not be empty")
        if arr.shape[0] > MAX_EMBEDDING_DIMS:
            raise ValueError(f"prompt_embedding exceeds {MAX_EMBEDDING_DIMS} dimensions")
        finite_mask = native_mx.isfinite(arr)
        if int(native_mx.sum(finite_mask).item()) != int(arr.shape[0]):
            raise ValueError("prompt_embedding must contain only finite float values")
        return arr

    def _ensure_projection_shape(self, embedding_size: int) -> None:
        if int(embedding_size) == self.dimension:
            return
        self.dimension = int(embedding_size)
        self.W_syn = self._balanced_matrix(
            (self.dimension, self.num_neurons),
            scale=0.01,
            excitatory_ratio=0.8,
        )
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
        dims = int(dimensions or self.dimension)
        if dims <= 0 or dims > MAX_EMBEDDING_DIMS:
            raise ValueError(f"dimensions must be between 1 and {MAX_EMBEDDING_DIMS}")
        try:
            result = self.embedding_provider.embed(str(text or ""), dimensions=dims)
        except EmbeddingProviderError:
            raise
        except Exception as exc:
            raise EmbeddingProviderError(
                f"embedding provider {self.embedding_provider_name} failed: {exc}"
            ) from exc
        return {
            "embedding": self._mx.array(result.vector, dtype=self._mx.float32),
            "provenance": self._json_safe_metadata(result.provenance),
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
                "error": str(exc),
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
        prompt = str(text or "")
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
            "input_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "input_chars": len(prompt),
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
                "input_sha256": hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
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

    def run_snn_cycle(self, sensory_spikes: Any, *, steps: int = 12):
        """Run recurrent LIF propagation with immutable state updates."""
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
        context = sanitize_context_id(context_id)
        clean_tag = sanitize_tag(tag)
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
                "metadata": self._json_safe_metadata(metadata),
                "registered_at": registered_at,
                "source_text": str(source_text or ""),
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
    ) -> str:
        prompt_text = str(prompt or "").strip()
        if not prompt_text:
            raise ValueError("prompt must not be empty")
        return self.query(
            self.embed_text(prompt_text),
            context_id=context_id,
            steps=steps,
            prompt_text=prompt_text,
        )

    def query(
        self,
        embedding: Any,
        *,
        context_id: str = "default",
        steps: int = 12,
        prompt_text: str = "",
    ) -> str:
        context = sanitize_context_id(context_id)
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
            )
            if registered:
                return " / ".join(registered)
            active_indices = self._recall_indices(firing_signature, sensory_spikes)
            tags = self._tags_for_indices(active_indices, context)
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
    ) -> list[str]:
        query_spikes = set(self._active_indices_from_spikes(sensory_spikes))
        if not query_spikes:
            return []
        firing_values = firing_signature.tolist()
        candidates = self.memory_store.recall_candidates(
            context_id=context,
            query_spikes=query_spikes,
            firing_values=firing_values,
            limit=self.recall_count,
        )
        candidates = self._merge_surface_text_recall_candidates(
            context=context,
            prompt_text=prompt_text,
            candidates=candidates,
        )
        rendered = [
            self._format_recall_entry(candidate, score=float(candidate["score"]))
            for candidate in candidates
        ]
        rendered.extend(
            self._related_trace_contexts(
                context=context,
                candidates=candidates,
            )
        )
        return rendered

    def _related_trace_contexts(
        self,
        *,
        context: str,
        candidates: list[dict[str, Any]],
    ) -> list[str]:
        seen_ids = {str(candidate["memory_id"]) for candidate in candidates}
        related: list[str] = []
        for candidate in candidates:
            memory_id = str(candidate["memory_id"])
            relationships = (
                self.memory_store.list_relationships(
                    context_id=context,
                    source_memory_id=memory_id,
                    limit=max(1, self.recall_count),
                )
                + self.memory_store.list_relationships(
                    context_id=context,
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
                seen_ids.add(neighbor_id)
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
        details.append(f"context={entry.get('context_id', '')}")
        details.append(f"id={entry.get('memory_id', '')}")
        return f"{tag} ({', '.join(details)})"

    def _merge_surface_text_recall_candidates(
        self,
        *,
        context: str,
        prompt_text: str,
        candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {
            str(candidate["memory_id"]): dict(candidate)
            for candidate in candidates
        }
        for candidate in self._surface_text_recall_candidates(
            context=context,
            prompt_text=prompt_text,
        ):
            memory_id = str(candidate["memory_id"])
            current = merged.get(memory_id)
            if current is None or float(candidate["score"]) > float(current.get("score", 0.0)):
                merged[memory_id] = candidate
        ranked = sorted(
            merged.values(),
            key=lambda item: (float(item.get("score", 0.0)), float(item.get("updated_at", 0.0))),
            reverse=True,
        )
        return ranked[: max(1, self.recall_count)]

    def _surface_text_recall_candidates(
        self,
        *,
        context: str,
        prompt_text: str,
    ) -> list[dict[str, Any]]:
        query_terms = set(self._surface_words(prompt_text))
        if not query_terms:
            return []
        revision = self.memory_store.entries_revision(
            context_id=context,
            include_global=True,
        )
        query_hash = hashlib.sha256(
            "\x1f".join(sorted(query_terms)).encode("utf-8")
        ).hexdigest()[:16]
        cache_key = f"{context}|surface-query|{query_hash}"
        cached = self._surface_recall_cache.get(cache_key)
        if cached and cached.get("revision") == revision["revision"]:
            return [dict(candidate) for candidate in cached.get("candidates", [])]

        prompt_lower = " ".join(str(prompt_text or "").lower().split())
        candidates: list[dict[str, Any]] = []
        indexed_entries = self.memory_store.surface_recall_candidates(
            context_id=context,
            query_terms=query_terms,
            limit=max(self.recall_count * 8, 64),
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
            corpus_terms = set(self._surface_words(corpus))
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
            score = min(
                0.99,
                0.35
                + (0.5 * len(overlap) / max(1, len(query_terms)))
                + min(0.08, term_weight / 80.0)
                + min(0.14, 0.07 * phrase_hits),
            )
            candidate = dict(entry)
            candidate["score"] = round(score, 6)
            metadata = dict(metadata)
            metadata["surface_text_recall"] = True
            metadata["surface_text_overlap"] = sorted(overlap)
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

    def _tags_for_indices(self, active_indices: list[int], context: str) -> list[str]:
        tags: list[str] = []
        for idx in active_indices[: self.recall_count]:
            tag = self.memory_mapping.get(idx)
            if tag is not None:
                tags.append(tag)
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
        if context_id is None or sanitize_context_id(context_id) in {"global", "all"}:
            self.global_enabled = bool(enabled)
        else:
            self.context_overrides[sanitize_context_id(context_id)] = bool(enabled)
        self._persist_runtime_state()
        return self.status(context_id=context_id or "default")

    def status(self, *, context_id: str = "default") -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        total_stats = self.memory_store.stats()
        context_stats = self.memory_store.stats(context_id=context)
        return {
            "runtime": "ready" if self.is_enabled(context) else "disabled",
            "context_id": context,
            "global_enabled": bool(self.global_enabled),
            "effective_enabled": self.is_enabled(context),
            "context_overrides": dict(sorted(self.context_overrides.items())),
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
            "context_bus_delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
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

    def list_memory(
        self,
        *,
        context_id: str = "default",
        limit: int = 50,
        include_global: bool = True,
        include_vectors: bool = False,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        entries = self.memory_store.list_entries(
            context_id=context,
            limit=limit,
            include_global=include_global,
        )
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
        limit: int = 100,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        bounded_limit = min(max(int(limit), 1), 500)
        events = self.memory_store.list_context_events(
            context_id=context,
            since_event_id=max(0, int(since_event_id)),
            limit=bounded_limit,
        )
        return {
            "context_id": context,
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "agent_targets": list(DEFAULT_AGENT_TARGETS),
            "since_event_id": max(0, int(since_event_id)),
            "event_count": len(events),
            "events": [self._decorate_context_event(event) for event in events],
            "memory_db_path": str(self.memory_store.db_path),
        }

    def ack_context_events(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        last_event_id: int = 0,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        try:
            cursor = self.memory_store.ack_context_events(
                context_id=context,
                agent_id=agent,
                last_event_id=max(0, int(last_event_id)),
            )
            self._mark_activity()
            return self._decorate_context_cursor(cursor)
        except Exception:
            LOGGER.exception(
                "context event ack failed for context_id=%s agent_id=%s",
                context,
                agent,
            )
            raise

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

    def enter_spiking_cortex(
        self,
        *,
        context_id: str = "default",
        agent_id: str = "mcp-client",
        task: str,
        mode: str = "strict",
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        task_text = str(task or "").strip()
        if not task_text:
            raise ValueError("task must not be empty")
        clean_mode = str(mode or "strict").strip().lower()
        if clean_mode not in CORTEX_MODES:
            clean_mode = "strict"
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
        recall_result = self.query_text(task_text, context_id=context)
        recall_items = self._split_recall_result(recall_result)
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
            },
        )
        return {
            "action": "enter-spiking-cortex",
            "context_id": context,
            "agent_id": agent,
            "session_id": session_id,
            "task": task_text,
            "mode": clean_mode,
            "governance_contract": policy["contract"],
            "policy": policy,
            "recall_result": recall_result,
            "recall_items": recall_items,
            "cortex_state": state,
            "agent_deployment": deployment,
        }

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
        clean_session_id = str(session_id or "").strip()
        session = self._active_cortex_session(
            context=context,
            agent_id=agent,
            session_id=clean_session_id,
        )
        observation_text = str(observation or "").strip()
        proposed_text = str(proposed_action or "").strip()
        scoped_files = self._normalize_cortex_intent_list(intended_files)
        scoped_tools = self._normalize_cortex_intent_list(intended_tools)
        bounded_confidence = min(max(float(confidence), 0.0), 1.0)
        state = self.get_cortex_state(context_id=context, agent_id=agent)
        recall_prompt = " ".join(part for part in (observation_text, proposed_text) if part)
        recall_result = (
            self.query_text(recall_prompt, context_id=context)
            if recall_prompt
            else ""
        )
        recall_items = self._split_recall_result(recall_result)
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
        clean_text = str(text or "").strip()
        if not clean_text:
            raise ValueError("text must not be empty")
        clean_session_id = str(session_id or "").strip() or "direct-cortex-commit"
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
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id) if agent_id else ""
        self._reap_orphaned_cortex_sessions(context_id=context, agent_id=agent)
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
        active_goal = (
            str(active_sessions[0].get("task", ""))
            if active_sessions
            else next(
                (
                    str(entry.get("excerpt", ""))
                    for entry in cortical_entries
                    if entry.get("trace_type") == "goal"
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
        clean_memory_id = str(memory_id or "").strip()
        if not clean_memory_id:
            raise ValueError("memory_id is required")
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
                reason=reason,
                source_surface=source_surface,
                publish_audit=True,
            )
            return {
                "action": "moderate-cortex-trace",
                "context_id": context,
                "memory_id": clean_memory_id,
                "moderation_action": clean_action,
                "reason": str(reason or ""),
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
                "reason": str(reason or ""),
                "source_surface": str(source_surface or "operator"),
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
            source_surface=str(source_surface or "operator"),
            event_type="cortex-trace-moderated",
            summary=f"cortex trace {clean_action}: {trace.get('tag', clean_memory_id)}",
            payload={
                "memory_id": clean_memory_id,
                "tag": trace.get("tag", ""),
                "moderation_action": clean_action,
                "reason": str(reason or ""),
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
            "reason": str(reason or ""),
            "trace": trace,
            "agent_deployment": audit,
            "memory_db_path": str(self.memory_store.db_path),
        }

    def _reap_orphaned_cortex_sessions(
        self,
        *,
        context_id: str = "",
        agent_id: str = "",
    ) -> None:
        now = time.time()
        changed = False
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
        if changed:
            self._persist_runtime_state()

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
            text = " ".join(str(item or "").split())
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
        acknowledge: bool = True,
    ) -> dict[str, Any]:
        """Compose the durable S2 context bus into an agent-ready briefing."""
        context = sanitize_context_id(context_id)
        agent = sanitize_agent_id(agent_id)
        bounded_event_limit = min(max(int(event_limit), 1), 100)
        bounded_graph_limit = min(max(int(graph_limit), 1), 200)
        start_event_id = (
            self._agent_cursor_event_id(context=context, agent_id=agent)
            if since_event_id is None
            else max(0, int(since_event_id))
        )

        deployments = self.list_context_events(
            context_id=context,
            since_event_id=start_event_id,
            limit=bounded_event_limit,
        )
        raw_events = deployments["events"]
        events = [
            self._summarize_agent_context_event(event)
            for event in raw_events
        ]
        latest_event_id = max(
            [start_event_id] + [int(event["event_id"]) for event in raw_events]
        )
        graph = self.list_memory_graph(context_id=context, limit=bounded_graph_limit)

        prompt_text = str(prompt or "").strip()
        recall_result = ""
        recall_items: list[str] = []
        if prompt_text:
            recall_result = self.query(
                self.embed_text(prompt_text),
                context_id=context,
            )
            recall_items = self._split_recall_result(recall_result)

        ack_payload = None
        if acknowledge:
            ack_payload = self.ack_context_events(
                context_id=context,
                agent_id=agent,
                last_event_id=latest_event_id,
            )

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
        payload = {
            "action": "agent-context-hydrate",
            "context_id": context,
            "agent_id": agent,
            "since_event_id": start_event_id,
            "latest_event_id": latest_event_id,
            "new_event_count": len(events),
            "events": events,
            "ack": ack_payload,
            "acknowledged": bool(ack_payload),
            "recall_prompt": prompt_text,
            "recall_result": recall_result,
            "recall_items": recall_items,
            "graph_summary": graph_summary,
            "graph_entries": graph_entries,
            "graph_relationships": graph_relationships,
            "cortex_state": cortex_state,
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "memory_db_path": str(self.memory_store.db_path),
        }
        payload["briefing_markdown"] = self._render_agent_context_briefing(payload)
        return payload

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
        return {
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
            f"- Delivery: {payload['delivery_mode']} | Ack: {'yes' if payload['acknowledged'] else 'no'}",
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
        surprise_model = self._surprise_model_info()
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=surprise_threshold,
            min_segment_sentences=min_segment_sentences,
            embedding_fn=self._embed_sentence_for_surprise,
        )
        segments = segmenter.segment(text, context_id=context, source_tag=source)
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
                        **(metadata or {}),
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
        source_text = str(text or "")
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

    def _surface_detail_badges(self, metadata: dict[str, Any]) -> list[str]:
        badges: list[str] = []
        for key in ("context_memory_type", "source_tag", "source", "speaker"):
            value = self._clean_context_label(str(metadata.get(key) or ""))
            if value and value not in badges:
                badges.append(value)
        return badges[:4]

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
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        source = sanitize_tag(source_tag).replace(" ", "-")
        clean_text = str(text or "").strip()
        if not clean_text:
            raise ValueError("conversation text must not be empty")
        clean_speaker = sanitize_agent_id(speaker)
        namespace_profile = self._infer_context_namespace(
            text=clean_text,
            context_id=context,
            source_tag=source,
            speaker=clean_speaker,
            metadata=metadata or {},
        )
        capture_metadata = self._json_safe_metadata(
            {
                **(metadata or {}),
                "source": "conversation-capture",
                "conversation_capture": True,
                "speaker": clean_speaker,
                "temporal": True,
                "context_namespace": namespace_profile["namespace_id"],
                "context_namespace_title": namespace_profile["namespace_title"],
                "context_namespace_source": namespace_profile["namespace_source"],
            }
        )
        try:
            ingestion = self.ingest_text_events(
                text=clean_text,
                context_id=context,
                source_tag=source,
                surprise_threshold=surprise_threshold,
                min_segment_sentences=min_segment_sentences,
                metadata=capture_metadata,
            )
            context_namespace = self._materialize_context_namespace(
                context_id=context,
                source_tag=source,
                speaker=clean_speaker,
                namespace_profile=namespace_profile,
                ingestion=ingestion,
            )
            ingestion["action"] = "capture-conversation"
            ingestion["speaker"] = clean_speaker
            ingestion["context_namespace"] = context_namespace
            ingestion["relationship_count"] = int(ingestion.get("relationship_count") or 0) + int(
                context_namespace.get("relationship_count") or 0
            )
            ingestion["relationships"].extend(context_namespace.get("relationships", []))
            ingestion["agent_deployment"] = self.publish_context_event(
                context_id=context,
                source_surface="conversation-capture",
                event_type="conversation-capture",
                summary=(
                    f"{source} captured {ingestion['event_count']} conversation events"
                ),
                payload={
                    "source_tag": ingestion["source_tag"],
                    "sequence_id": ingestion["sequence_id"],
                    "speaker": clean_speaker,
                    "event_count": ingestion["event_count"],
                    "relationship_count": ingestion["relationship_count"],
                    "context_namespace": context_namespace,
                    "events": ingestion["events"],
                    "relationships": ingestion["relationships"],
                },
            )
            return ingestion
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
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
        normalized_target = str(target_type or "").strip().lower().replace("-", "_")
        if normalized_target in {"node", "memory", "trace", "event"}:
            result = self.memory_store.delete_entry(
                context_id=context,
                memory_id=str(memory_id or "").strip() or None,
                tag=sanitize_tag(tag) if str(tag or "").strip() else None,
            )
            self._refresh_registered_traces()
            self._persist_runtime_state()
        elif normalized_target in {"relationship", "edge"}:
            clean_relationship_id = str(relationship_id or "").strip()
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
            "reason": str(reason or ""),
            "result": safe_result,
        }
        audit_event = None
        if publish_audit:
            audit_event = self.publish_context_event(
                context_id=context,
                source_surface=str(source_surface or "operator"),
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
            "reason": str(reason or ""),
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

    def list_memory_graph(
        self,
        *,
        context_id: str = "default",
        limit: int = 100,
    ) -> dict[str, Any]:
        context = sanitize_context_id(context_id)
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
        target_min_mb: float = 61.0,
        target_max_mb: float = 138.0,
    ) -> dict[str, Any]:
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
        return {
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
            "quick_pruning": quick_profile,
            "mlx_device": os.getenv("MLX_DEVICE", "default"),
            "mlxsnn_lif_execution_path": self._mlxsnn_lif_layer is not None,
        }

    def certify_runtime(
        self,
        *,
        strict_native: bool = False,
        require_gpu: bool = False,
        benchmark_quick_prune: bool = False,
        require_resource_envelope: bool = False,
        target_min_mb: float = 61.0,
        target_max_mb: float = 138.0,
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
            path = Path(output_path).expanduser().resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path = str(path)
            payload["evidence_path"] = evidence_path
            path.write_text(
                json.dumps(payload, indent=2, sort_keys=True, default=str),
                encoding="utf-8",
            )
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
        return {
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

    def _decorate_context_event(self, event: dict[str, Any]) -> dict[str, Any]:
        targets = [
            str(target)
            for target in event.get("agent_targets", [])
            if str(target).strip()
        ] or list(DEFAULT_AGENT_TARGETS)
        return {
            **event,
            "agent_targets": targets,
            "target_count": len(targets),
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "published": True,
        }

    def _decorate_context_cursor(self, cursor: dict[str, Any]) -> dict[str, Any]:
        return {
            **cursor,
            "delivery_mode": CONTEXT_BUS_DELIVERY_MODE,
            "acknowledged": True,
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


_ENGINE_INSTANCE: SpikingAttentionBackend | None = None


def get_backend() -> SpikingAttentionBackend:
    global _ENGINE_INSTANCE
    if _ENGINE_INSTANCE is None:
        _ENGINE_INSTANCE = SpikingAttentionBackend(
            dimension=int(os.getenv("SYNAPSE_S2_DIMENSION", "1024")),
            num_neurons=int(os.getenv("SYNAPSE_S2_NEURONS", "5400")),
            default_top_k=int(os.getenv("SYNAPSE_S2_TOP_K", "256")),
            recall_count=int(os.getenv("SYNAPSE_S2_RECALL_COUNT", "10")),
            quick_pruning_interval_seconds=float(
                os.getenv("SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS", "300")
            ),
            idle_deep_sleep_seconds=float(
                os.getenv("SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS", "1800")
            ),
            embedding_provider_name=os.getenv("SYNAPSE_S2_EMBEDDING_PROVIDER", "auto"),
            require_native=os.getenv("SYNAPSE_S2_REQUIRE_NATIVE", "").lower()
            in {"1", "true", "yes", "on"},
        )
    return _ENGINE_INSTANCE


def simulate_spiking_retrieval(embedding: Any, context_id: str = "default") -> str:
    return get_backend().query(embedding, context_id=context_id)


def simulate_spiking_text_retrieval(prompt: str, context_id: str = "default") -> str:
    return get_backend().query_text(prompt, context_id=context_id)


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
    return get_backend().status(context_id=context_id)


def list_memory(
    context_id: str = "default",
    limit: int = 50,
    include_vectors: bool = False,
) -> dict[str, Any]:
    return get_backend().list_memory(
        context_id=context_id,
        limit=limit,
        include_vectors=include_vectors,
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
    limit: int = 100,
) -> dict[str, Any]:
    return get_backend().list_context_events(
        context_id=context_id,
        since_event_id=since_event_id,
        limit=limit,
    )


def ack_context_events(
    context_id: str = "default",
    agent_id: str = "mcp-client",
    last_event_id: int = 0,
) -> dict[str, Any]:
    return get_backend().ack_context_events(
        context_id=context_id,
        agent_id=agent_id,
        last_event_id=last_event_id,
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
    acknowledge: bool = True,
) -> dict[str, Any]:
    return get_backend().hydrate_agent_context(
        context_id=context_id,
        agent_id=agent_id,
        prompt=prompt,
        since_event_id=since_event_id,
        event_limit=event_limit,
        graph_limit=graph_limit,
        acknowledge=acknowledge,
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
) -> dict[str, Any]:
    return get_backend().get_cortex_state(
        context_id=context_id,
        agent_id=agent_id,
        limit=limit,
    )


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
) -> dict[str, Any]:
    return get_backend().capture_conversation(
        text=text,
        context_id=context_id,
        source_tag=source_tag,
        speaker=speaker,
        surprise_threshold=surprise_threshold,
        min_segment_sentences=min_segment_sentences,
        metadata=metadata,
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
    )


def list_memory_graph(
    context_id: str = "default",
    limit: int = 100,
) -> dict[str, Any]:
    return get_backend().list_memory_graph(context_id=context_id, limit=limit)


def resource_profile(
    *,
    benchmark_quick_prune: bool = False,
    target_min_mb: float = 61.0,
    target_max_mb: float = 138.0,
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
    target_min_mb: float = 61.0,
    target_max_mb: float = 138.0,
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


def run_quick_pruning() -> dict[str, Any]:
    return get_backend().run_quick_pruning()


def run_idle_maintenance(*, force_deep_sleep: bool = False) -> dict[str, Any]:
    return get_backend().run_idle_maintenance(force_deep_sleep=force_deep_sleep)


def run_offline_consolidation() -> dict[str, Any]:
    return get_backend().run_deep_sleep_consolidation()


def run_deep_sleep_consolidation() -> dict[str, Any]:
    return get_backend().run_deep_sleep_consolidation()

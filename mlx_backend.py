from __future__ import annotations

import logging
import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from event_segmenter import BayesianSurpriseEventSegmenter
from memory_store import DurableMemoryStore

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
        num_neurons: int = 5000,
        default_top_k: int = 150,
        recall_count: int = 5,
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
        self.state_path = self._resolve_state_path(state_path)
        if memory_path is None and state_path is not None:
            resolved_memory_path = self.state_path.parent / "memory.sqlite3"
        else:
            resolved_memory_path = self._resolve_memory_path(memory_path)
        self.memory_store = DurableMemoryStore(resolved_memory_path)
        self.global_enabled = True
        self.context_overrides: dict[str, bool] = {}
        self.registered_traces: list[dict[str, Any]] = []

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
        """Map text to a deterministic local embedding for offline MCP use.

        This is not a semantic embedding model. It is a stable sparse projection
        that lets SYNAPSE-S2 operate without calling an LLM or external API when
        a client only has text available.
        """
        native_mx = self._mx
        dims = int(dimensions or self.dimension)
        if dims <= 0 or dims > MAX_EMBEDDING_DIMS:
            raise ValueError(f"dimensions must be between 1 and {MAX_EMBEDDING_DIMS}")
        vector = [0.0] * dims
        normalized = str(text or "").strip().lower()
        tokens = re.findall(r"[a-z0-9_.:/#-]+", normalized)
        if not tokens:
            tokens = ["empty"]
        features = tokens + [
            f"{tokens[index]}::{tokens[index + 1]}"
            for index in range(max(0, len(tokens) - 1))
        ]
        for feature in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=16).digest()
            index = int.from_bytes(digest[:4], "big") % dims
            magnitude = 0.5 + (int.from_bytes(digest[4:8], "big") % 1000) / 1000.0
            sign = 1.0 if digest[8] % 2 == 0 else -1.0
            vector[index] += sign * magnitude
        return native_mx.array(vector, dtype=native_mx.float32)

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
            self._persist_runtime_state()
            self._mark_activity()
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
            }
        except Exception:
            LOGGER.exception("trace registration failed for context_id=%s tag=%s", context, clean_tag)
            raise

    def query(self, embedding: Any, *, context_id: str = "default", steps: int = 12) -> str:
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
        rendered = [
            (
                f"{candidate['tag']} "
                f"(score={float(candidate['score']):.3f}, "
                f"context={candidate['context_id']}, "
                f"id={candidate['memory_id']})"
            )
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
                    (
                        f"{entry['tag']} "
                        f"(linked={relationship['relation_type']}, "
                        f"weight={float(relationship['weight']):.3f}, "
                        f"context={entry['context_id']}, "
                        f"id={entry['memory_id']})"
                    )
                )
        return related

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
            "registered_trace_count": int(total_stats["entry_count"]),
            "registered_trace_cache_count": len(self.registered_traces),
            "memory_mapping_count": len(self.memory_mapping),
            "memory_entry_count": int(total_stats["entry_count"]),
            "memory_context_entry_count": int(context_stats["entry_count"]),
            "memory_event_count": int(total_stats["event_count"]),
            "memory_relationship_count": int(total_stats["relationship_count"]),
            "memory_context_relationship_count": int(context_stats["relationship_count"]),
            "memory_contexts": total_stats["contexts"],
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
        try:
            event = self.memory_store.publish_context_event(
                context_id=context,
                source_surface=str(source_surface or "unknown"),
                event_type=str(event_type or "context-update"),
                summary=str(summary or ""),
                payload=self._json_safe_metadata(payload or {}),
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
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=surprise_threshold,
            min_segment_sentences=min_segment_sentences,
        )
        segments = segmenter.segment(text, context_id=context, source_tag=source)
        registrations: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []
        try:
            for segment in segments:
                event_metadata = self._json_safe_metadata(
                    {
                        **(metadata or {}),
                        "event_segment": True,
                        "segment_id": segment["segment_id"],
                        "sequence_id": segment["sequence_id"],
                        "segment_index": segment["segment_index"],
                        "sentence_count": segment["sentence_count"],
                        "surprise_score": segment["surprise_score"],
                        "keywords": segment["keywords"],
                        "source_tag": segment["source_tag"],
                    }
                )
                registration = self.register_trace(
                    tag=segment["tag"],
                    embedding=self.embed_text(segment["text"]),
                    context_id=context,
                    metadata=event_metadata,
                    source_text=segment["text"],
                )
                registration["segment"] = segment
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
        entries = self.list_memory(context_id=context, limit=limit)["entries"]
        relationships = self.memory_store.list_relationships(
            context_id=context,
            limit=limit,
        )
        return {
            "context_id": context,
            "memory_db_path": str(self.memory_store.db_path),
            "entry_count": len(entries),
            "relationship_count": len(relationships),
            "relationship_summary": self._summarize_relationship_modes(relationships),
            "entries": entries,
            "relationships": relationships,
        }

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
            if relation_type.startswith("temporal"):
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
            self.run_quick_pruning(trigger="resource-profile")
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
        return {
            "memory_id": entry["memory_id"],
            "tag": entry["tag"],
            "context_id": entry["context_id"],
            "source_text": entry["source_text"],
            "metadata": entry["metadata"],
            "embedding_dimensions": entry["embedding_dimensions"],
            "spike_count": len(entry.get("spike_indices", [])),
            "neuron_count": len(entry.get("neuron_indices", [])),
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
            num_neurons=int(os.getenv("SYNAPSE_S2_NEURONS", "5000")),
            default_top_k=int(os.getenv("SYNAPSE_S2_TOP_K", "150")),
            recall_count=int(os.getenv("SYNAPSE_S2_RECALL_COUNT", "5")),
            quick_pruning_interval_seconds=float(
                os.getenv("SYNAPSE_S2_QUICK_PRUNING_INTERVAL_SECONDS", "300")
            ),
            idle_deep_sleep_seconds=float(
                os.getenv("SYNAPSE_S2_IDLE_DEEP_SLEEP_SECONDS", "1800")
            ),
        )
    return _ENGINE_INSTANCE


def simulate_spiking_retrieval(embedding: Any, context_id: str = "default") -> str:
    return get_backend().query(embedding, context_id=context_id)


def simulate_spiking_text_retrieval(prompt: str, context_id: str = "default") -> str:
    backend = get_backend()
    return backend.query(backend.embed_text(prompt), context_id=context_id)


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
    backend = get_backend()
    return backend.register_trace(
        tag=tag,
        embedding=backend.embed_text(text),
        context_id=context_id,
        metadata=metadata,
        source_text=text,
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

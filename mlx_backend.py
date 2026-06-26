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
        compile_graph: bool = True,
        state_path: str | os.PathLike[str] | None = None,
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
        self._mx = native_mx
        self._lif_step = self._build_lif_step(compile_graph)
        self._mlxsnn_available = mlxsnn is not None
        self.state_path = self._resolve_state_path(state_path)
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
        self._load_runtime_state()

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
        return Path.cwd() / ".synapse_s2" / "runtime_state.json"

    def _load_runtime_state(self) -> None:
        if not self.state_path.exists():
            return
        try:
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
                self.registered_traces = [
                    self._normalize_trace_payload(trace)
                    for trace in traces
                    if isinstance(trace, dict)
                ]
            for trace in self.registered_traces:
                for neuron_idx in trace["neuron_indices"]:
                    self.memory_mapping.setdefault(int(neuron_idx), trace["tag"])
        except Exception as exc:
            LOGGER.error("failed to load runtime state from %s: %s", self.state_path, exc)

    def _persist_runtime_state(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "global_enabled": self.global_enabled,
                "context_overrides": self.context_overrides,
                "registered_traces": self.registered_traces,
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
            "source_text": str(trace.get("source_text", ""))[:1000],
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
        threshold_value = native_mx.sort(z_scores)[-top_k]
        return native_mx.where(z_scores >= threshold_value, 1.0, 0.0)

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

        input_current = native_mx.matmul(spikes_in, self.W_syn)
        mem = self.state["mem"]
        prev_spikes = self.state["spk"]
        accumulated = native_mx.zeros((self.num_neurons,))
        W_lateral = self.W_lateral

        for _ in range(max(1, int(steps))):
            lateral_current = native_mx.matmul(prev_spikes, W_lateral)
            total_current = input_current + lateral_current
            spk, mem = self._lif_step(mem, total_current, self.beta, self.threshold)
            accumulated = accumulated + spk
            W_lateral = self._apply_stdp(W_lateral, prev_spikes, spk)
            prev_spikes = spk

        self.W_lateral = W_lateral
        self.state = {
            "mem": mem,
            "spk": prev_spikes,
        }
        self.active_traces = self.trace_decay * self.active_traces + accumulated
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
        arr = self._coerce_embedding(embedding)
        self._ensure_projection_shape(int(arr.shape[0]))
        sensory_spikes = self.encode_to_spikes_top_k(arr)
        spike_indices = self._active_indices_from_spikes(sensory_spikes)
        neuron_indices = self._project_sensory_indices(spike_indices)
        trace = {
            "tag": clean_tag,
            "context_id": context,
            "embedding_dimensions": int(arr.shape[0]),
            "spike_indices": spike_indices,
            "neuron_indices": neuron_indices,
            "metadata": self._json_safe_metadata(metadata),
            "registered_at": time.time(),
            "source_text": str(source_text or "")[:1000],
        }

        self.registered_traces = [
            existing
            for existing in self.registered_traces
            if not (
                existing["tag"] == clean_tag
                and existing["context_id"] == context
            )
        ]
        self.registered_traces.append(trace)
        for neuron_idx in neuron_indices:
            self.memory_mapping[int(neuron_idx)] = clean_tag
        self._persist_runtime_state()
        return {
            "tag": clean_tag,
            "context_id": context,
            "spike_count": len(spike_indices),
            "neuron_count": len(neuron_indices),
            "registered_trace_count": len(self.registered_traces),
            "state_path": str(self.state_path),
        }

    def query(self, embedding: Any, *, context_id: str = "default", steps: int = 12) -> str:
        context = sanitize_context_id(context_id)
        if not self.is_enabled(context):
            return (
                f"SYNAPSE-S2 disabled for context {context}. "
                "Toggle it with set_spiking_attention_enabled(true)."
            )
        try:
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
                return "No high-salience spiking patterns registered. Fallback context active."
            return " / ".join(tags)
        except Exception:
            LOGGER.exception("query failed for context_id=%s", context)
            raise

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
        candidates: list[tuple[float, dict[str, Any]]] = []
        for trace in self.registered_traces:
            trace_context = trace["context_id"]
            if trace_context not in {context, "global"}:
                continue
            trace_spikes = set(int(idx) for idx in trace["spike_indices"])
            if not trace_spikes:
                continue
            overlap = len(query_spikes & trace_spikes)
            union = len(query_spikes | trace_spikes)
            jaccard = overlap / max(1, union)
            neuron_activity = 0.0
            for neuron_idx in trace["neuron_indices"]:
                if 0 <= int(neuron_idx) < len(firing_values):
                    neuron_activity += float(firing_values[int(neuron_idx)])
            activity_bonus = min(neuron_activity / max(1, len(trace["neuron_indices"])), 1.0)
            score = jaccard + 0.05 * activity_bonus
            if score > 0.0:
                candidates.append((score, trace))
        candidates.sort(key=lambda item: (item[0], item[1]["registered_at"]), reverse=True)
        return [
            f"{trace['tag']} (score={score:.3f}, context={trace['context_id']})"
            for score, trace in candidates[: self.recall_count]
        ]

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
            if tag is None:
                tag = f"{context}::neuron-{idx:06d}"
                self.memory_mapping[idx] = tag
            tags.append(tag)
        return tags

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
            "registered_trace_count": len(self.registered_traces),
            "memory_mapping_count": len(self.memory_mapping),
            "semantic_group_count": len(self.semantic_hierarchy),
            "mlx_available": mx is not None,
            "mlxsnn_available": self._mlxsnn_available,
            "mlx_device": os.getenv("MLX_DEVICE", "default"),
            "state_path": str(self.state_path),
        }

    def run_quick_pruning(self) -> dict[str, Any]:
        """Run non-LLM synaptic decay and transient membrane flushing."""
        native_mx = self._mx
        timing = ConsolidationTiming(time.perf_counter())
        try:
            elapsed_min = max(1.0, (time.monotonic() - self.last_pruning_monotonic) / 60.0)
            syn_decay = self.quick_decay_syn**elapsed_min
            lateral_decay = self.quick_decay_lateral**elapsed_min
            self.W_syn = self.W_syn * syn_decay
            self.W_lateral = self.W_lateral * lateral_decay
            self.active_traces = self.active_traces * self.trace_decay
            self.state = {
                "mem": native_mx.zeros_like(self.state["mem"]),
                "spk": native_mx.zeros_like(self.state["spk"]),
            }
            self.last_pruning_monotonic = time.monotonic()
            return {
                "mode": "quick-pruning",
                "elapsed_ms": timing.elapsed_ms(),
                "syn_decay": round(float(syn_decay), 6),
                "lateral_decay": round(float(lateral_decay), 6),
                "membrane_reset": True,
            }
        except Exception:
            LOGGER.exception("quick pruning failed")
            raise

    def run_deep_sleep_consolidation(self) -> dict[str, Any]:
        """Distill active traces into context-keyed semantic hierarchy groups."""
        timing = ConsolidationTiming(time.perf_counter())
        try:
            self.run_quick_pruning()
            ranked = self._rank_active_trace_indices(limit=max(self.recall_count, 32))
            grouped: dict[str, list[str]] = {}
            for idx in ranked:
                tag = self.memory_mapping.get(idx)
                if tag is None:
                    continue
                context = tag.split("::", 1)[0]
                grouped.setdefault(context, []).append(tag)

            self.semantic_hierarchy = {
                context: {
                    "members": members,
                    "member_count": len(members),
                    "distillation": "hebbian-active-trace",
                }
                for context, members in grouped.items()
            }
            self.active_traces = self.active_traces * 0.5
            return {
                "mode": "deep-sleep",
                "elapsed_ms": timing.elapsed_ms(),
                "contexts": sorted(self.semantic_hierarchy),
                "semantic_groups": len(self.semantic_hierarchy),
            }
        except Exception:
            LOGGER.exception("deep sleep consolidation failed")
            raise

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


def run_quick_pruning() -> dict[str, Any]:
    return get_backend().run_quick_pruning()


def run_offline_consolidation() -> dict[str, Any]:
    return get_backend().run_deep_sleep_consolidation()


def run_deep_sleep_consolidation() -> dict[str, Any]:
    return get_backend().run_deep_sleep_consolidation()

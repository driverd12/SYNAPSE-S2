from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import math
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from redaction import (
    redact_capture_text,
    redact_sensitive_value,
    reject_sensitive_identifier,
    safe_public_error,
)


MAX_PROVIDER_DIMS = 32_768
TOKEN_RE = re.compile(r"[a-z0-9_.:/#-]+")
DEFAULT_NEURAL_MODEL = "mlx-community/Qwen3-Embedding-0.6B-4bit-DWQ"
DEFAULT_NEURAL_POOLING = "mean"
DEFAULT_NEURAL_MAX_TOKENS = 512

CONCEPT_GROUPS: dict[str, set[str]] = {
    "local_compute": {
        "apple",
        "silicon",
        "m-series",
        "m1",
        "m2",
        "m3",
        "m4",
        "metal",
        "mlx",
        "gpu",
        "npu",
        "native",
        "kernel",
        "kernels",
        "compute",
        "acceleration",
        "accelerate",
        "accelerated",
        "unified",
        "memory",
        "on-chip",
    },
    "spiking_attention": {
        "snn",
        "spiking",
        "lif",
        "stdp",
        "synapse",
        "synapse-s2",
        "s2",
        "neuron",
        "neurons",
        "synaptic",
        "spike",
        "spikes",
        "attention",
        "plasticity",
    },
    "memory_recall": {
        "memory",
        "recall",
        "context",
        "graph",
        "relationship",
        "relationships",
        "temporal",
        "associative",
        "hydrate",
        "cursor",
        "deployment",
        "capture",
        "conversation",
    },
    "operations_safety": {
        "prune",
        "delete",
        "sensitive",
        "secret",
        "redact",
        "redaction",
        "safety",
        "audit",
        "backup",
        "restore",
        "operator",
        "governance",
    },
    "native_certification": {
        "certify",
        "certification",
        "native",
        "runtime",
        "profile",
        "envelope",
        "latency",
        "quick-prune",
        "quick",
        "prune",
        "mlxsnn",
        "mlx",
        "gpu",
        "evidence",
    },
    "client_integration": {
        "mcp",
        "codex",
        "claude",
        "desktop",
        "code",
        "client",
        "agent",
        "launcher",
        "wrapper",
        "session",
        "startup",
    },
}


@dataclass(frozen=True)
class EmbeddingResult:
    vector: list[float]
    provenance: dict[str, Any]


class EmbeddingProviderError(RuntimeError):
    pass


class EmbeddingProvider:
    provider_id = "provider"

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        raise NotImplementedError

    def info(self, *, dimensions: int) -> dict[str, Any]:
        sample = self.embed("synapse-s2 provider check", dimensions=dimensions)
        return sample.provenance


@dataclass(frozen=True)
class MLXNeuralEmbeddingConfig:
    model_id: str
    cache_dir: str | None
    revision: str | None
    pooling: str
    max_tokens: int
    normalize: bool
    local_files_only: bool


def resolve_embedding_provider(name: str | None = None) -> EmbeddingProvider:
    requested = (name or os.getenv("SYNAPSE_S2_EMBEDDING_PROVIDER") or "auto").strip()
    normalized = requested.lower()
    if normalized in {"", "auto", "default"}:
        return SemanticHashEmbeddingProvider()
    if normalized in {"semantic", "semantic-hash", "semantic-hash-v1"}:
        return SemanticHashEmbeddingProvider()
    if normalized in {"lexical", "hash", "lexical-hash", "lexical-hash-v1"}:
        return LexicalHashEmbeddingProvider()
    if normalized.startswith("python:"):
        return PythonCallableEmbeddingProvider(requested)
    if normalized in {"neural", "mlx", "mlx-neural", "mlx-neural-v1"}:
        return MLXNeuralEmbeddingProvider()
    if normalized.startswith("neural:"):
        _, model_id = requested.split(":", 1)
        return MLXNeuralEmbeddingProvider(model_id=model_id.strip() or None)
    if normalized.startswith("mlx-neural:"):
        _, model_id = requested.split(":", 1)
        return MLXNeuralEmbeddingProvider(model_id=model_id.strip() or None)
    raise EmbeddingProviderError(
        "unknown embedding provider; expected auto, semantic-hash, lexical-hash, "
        "mlx-neural[:model-id], or python:/path/to/module.py:function"
    )


class LexicalHashEmbeddingProvider(EmbeddingProvider):
    provider_id = "lexical-hash-v1"

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        dims = _validate_dimensions(dimensions)
        safe_text, _ = redact_capture_text(str(text or ""))
        normalized = safe_text.strip().lower()
        tokens = _tokens(normalized)
        features = tokens + [
            f"{tokens[index]}::{tokens[index + 1]}"
            for index in range(max(0, len(tokens) - 1))
        ]
        vector = _features_to_vector(features, dimensions=dims)
        return EmbeddingResult(
            vector=vector,
            provenance=_provenance(
                provider=self.provider_id,
                provider_type="lexical-hash",
                dimensions=dims,
                semantic=False,
                local_only=True,
                tokens=tokens,
                concepts=[],
                vector=vector,
                feature_count=len(features),
            ),
        )


class SemanticHashEmbeddingProvider(EmbeddingProvider):
    provider_id = "semantic-hash-v1"

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        dims = _validate_dimensions(dimensions)
        safe_text, _ = redact_capture_text(str(text or ""))
        normalized = safe_text.strip().lower()
        tokens = _tokens(normalized)
        normalized_tokens = _normalized_tokens(tokens)
        concepts = _matched_concepts(normalized_tokens)
        features: list[tuple[str, float]] = []
        for token in normalized_tokens:
            features.append((f"token:{token}", 1.0))
        for index in range(max(0, len(normalized_tokens) - 1)):
            features.append(
                (
                    f"bigram:{normalized_tokens[index]}::{normalized_tokens[index + 1]}",
                    0.75,
                )
            )
        for concept in concepts:
            features.append((f"concept:{concept}", 4.0))
            for token in sorted(CONCEPT_GROUPS[concept] & set(normalized_tokens)):
                features.append((f"concept-token:{concept}:{token}", 1.35))

        vector = _features_to_vector(features, dimensions=dims)
        return EmbeddingResult(
            vector=vector,
            provenance=_provenance(
                provider=self.provider_id,
                provider_type="semantic-hash",
                dimensions=dims,
                semantic=True,
                local_only=True,
                tokens=normalized_tokens,
                concepts=concepts,
                vector=vector,
                feature_count=len(features),
            ),
        )


class PythonCallableEmbeddingProvider(EmbeddingProvider):
    provider_id = "python-callable"

    def __init__(self, spec: str) -> None:
        try:
            safe_spec = reject_sensitive_identifier(
                spec,
                field="python provider spec",
            )
        except ValueError as exc:
            raise EmbeddingProviderError(
                "python provider spec must not contain credential material"
            ) from exc
        if not safe_spec.casefold().startswith("python:"):
            raise EmbeddingProviderError(
                "python provider must look like python:/path/to/module.py:function"
            )
        payload = safe_spec.split(":", 1)[1]
        module_ref, separator, function_name = payload.rpartition(":")
        if not separator or not module_ref.strip() or not function_name.strip():
            raise EmbeddingProviderError(
                "python provider must look like python:/path/to/module.py:function"
            )
        try:
            self.module_ref = reject_sensitive_identifier(
                module_ref.strip(),
                field="python provider module",
            )
            self.function_name = reject_sensitive_identifier(
                function_name.strip(),
                field="python provider function",
            )
        except ValueError as exc:
            raise EmbeddingProviderError(
                "python provider identifiers must not contain credential material"
            ) from exc
        self._callable = self._load_callable()

    def _load_callable(self) -> Callable[..., Any]:
        module_ref_path = Path(self.module_ref).expanduser()
        if module_ref_path.exists():
            module_name = (
                "synapse_s2_embedding_provider_"
                + hashlib.sha256(str(module_ref_path).encode("utf-8")).hexdigest()[:12]
            )
            spec = importlib.util.spec_from_file_location(module_name, module_ref_path)
            if spec is None or spec.loader is None:
                raise EmbeddingProviderError(f"cannot load provider module {module_ref_path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        else:
            module = importlib.import_module(self.module_ref)
        fn = getattr(module, self.function_name, None)
        if not callable(fn):
            raise EmbeddingProviderError(
                f"provider callable {self.function_name} not found in {self.module_ref}"
            )
        return fn

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        dims = _validate_dimensions(dimensions)
        safe_text, _ = redact_capture_text(str(text or ""))
        raw = self._callable(safe_text, dims)
        details: dict[str, Any] = {}
        model_id = f"{self.module_ref}:{self.function_name}"
        semantic = True
        if isinstance(raw, dict):
            vector = raw.get("vector")
            try:
                model_id = reject_sensitive_identifier(
                    str(raw.get("model_id") or model_id),
                    field="python provider model_id",
                )
            except ValueError as exc:
                raise EmbeddingProviderError(
                    "python provider model_id must not contain credential material"
                ) from exc
            semantic = bool(raw.get("semantic", True))
            if isinstance(raw.get("details"), dict):
                details = _json_safe(raw["details"])
        else:
            vector = raw
        safe_vector = _validate_vector(vector, dimensions=dims)
        return EmbeddingResult(
            vector=safe_vector,
            provenance=_provenance(
                provider=self.provider_id,
                provider_type="python-callable",
                dimensions=dims,
                semantic=semantic,
                local_only=True,
                tokens=_tokens(safe_text.lower()),
                concepts=[],
                vector=safe_vector,
                feature_count=None,
                model_id=model_id,
                details=details,
            ),
        )


class MLXNeuralEmbeddingProvider(EmbeddingProvider):
    provider_id = "mlx-neural-v1"

    def __init__(
        self,
        model_id: str | None = None,
        *,
        runtime_factory: Callable[[MLXNeuralEmbeddingConfig], Any] | None = None,
        pooling: str | None = None,
        max_tokens: int | None = None,
        cache_dir: str | os.PathLike[str] | None = None,
        revision: str | None = None,
        normalize: bool | None = None,
        local_files_only: bool | None = None,
    ) -> None:
        raw_model_id = (
            model_id
            or os.getenv("SYNAPSE_S2_NEURAL_MODEL")
            or DEFAULT_NEURAL_MODEL
        ).strip()
        if not raw_model_id:
            raise EmbeddingProviderError("MLX neural provider requires a model id")
        self.model_id = _provider_identifier(raw_model_id, field="MLX model_id")
        self.pooling = _validate_pooling(
            pooling or os.getenv("SYNAPSE_S2_NEURAL_POOLING") or DEFAULT_NEURAL_POOLING
        )
        self.max_tokens = _positive_int(
            max_tokens
            if max_tokens is not None
            else os.getenv("SYNAPSE_S2_NEURAL_MAX_TOKENS"),
            default=DEFAULT_NEURAL_MAX_TOKENS,
            name="SYNAPSE_S2_NEURAL_MAX_TOKENS",
        )
        raw_cache_dir = (
            cache_dir
            if cache_dir is not None
            else os.getenv("SYNAPSE_S2_NEURAL_CACHE_DIR")
        )
        if raw_cache_dir is None or not str(raw_cache_dir).strip():
            self.cache_dir = None
        else:
            safe_cache_dir = _provider_identifier(
                str(raw_cache_dir),
                field="MLX cache_dir",
            )
            self.cache_dir = _optional_path_str(safe_cache_dir)
        raw_revision = (
            revision
            if revision is not None
            else os.getenv("SYNAPSE_S2_NEURAL_REVISION")
        )
        self.revision = (
            _provider_identifier(str(raw_revision), field="MLX revision")
            if raw_revision is not None and str(raw_revision).strip()
            else None
        )
        self.normalize = _env_bool(
            "SYNAPSE_S2_NEURAL_NORMALIZE",
            default=True if normalize is None else bool(normalize),
        )
        self.local_files_only = _env_bool(
            "SYNAPSE_S2_NEURAL_LOCAL_FILES_ONLY",
            default=False if local_files_only is None else bool(local_files_only),
        )
        self._runtime_factory = runtime_factory or MLXNeuralEmbeddingRuntime
        self._runtime = None

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        dims = _validate_dimensions(dimensions)
        runtime = self._get_runtime()
        safe_text, _ = redact_capture_text(str(text or ""))
        try:
            raw_vector = runtime.embed_text(
                safe_text,
                pooling=self.pooling,
                max_tokens=self.max_tokens,
            )
        except EmbeddingProviderError:
            raise
        except Exception as exc:
            raise EmbeddingProviderError(
                f"MLX neural model {self.model_id} failed to embed text: "
                f"{safe_public_error(exc, fallback='model execution failed')}"
            ) from exc

        source_vector = _validate_float_list(raw_vector)
        vector = _project_vector(source_vector, dimensions=dims)
        if self.normalize:
            vector = _normalize_vector(vector)
        runtime_model_id = _provider_identifier(
            str(getattr(runtime, "model_id", self.model_id)),
            field="MLX runtime model_id",
        )
        raw_runtime_source = str(getattr(runtime, "source", ""))
        runtime_source = (
            _provider_identifier(raw_runtime_source, field="MLX runtime source")
            if raw_runtime_source
            else ""
        )
        provenance = _provenance(
            provider=self.provider_id,
            provider_type="mlx-neural",
            dimensions=dims,
            semantic=True,
            local_only=True,
            tokens=_tokens(safe_text.lower()),
            concepts=[],
            vector=vector,
            feature_count=None,
            model_id=runtime_model_id,
            details={
                "cache_dir": self.cache_dir or "",
                "revision": self.revision or "",
                "max_tokens": self.max_tokens,
                "local_files_only": bool(self.local_files_only),
                "projection": "signed-hash-projection-v1",
                "runtime_source": runtime_source,
                "cache_fallback_used": bool(
                    getattr(runtime, "cache_fallback_used", False)
                ),
            },
        )
        provenance.update(
            {
                "native_mlx": bool(getattr(runtime, "native_mlx", False)),
                "pooling": self.pooling,
                "source_dimensions": len(source_vector),
                "normalized": bool(self.normalize),
            }
        )
        return EmbeddingResult(vector=vector, provenance=provenance)

    def info(self, *, dimensions: int) -> dict[str, Any]:
        dims = _validate_dimensions(dimensions)
        return {
            "provider": self.provider_id,
            "provider_type": "mlx-neural",
            "model_id": self.model_id,
            "dimensions": dims,
            "semantic": True,
            "local_only": True,
            "native_mlx": True,
            "pooling": self.pooling,
            "max_tokens": self.max_tokens,
            "normalized": bool(self.normalize),
            "loaded": self._runtime is not None,
            "cache_dir": self.cache_dir or "",
            "revision": self.revision or "",
        }

    def _get_runtime(self):
        if self._runtime is not None:
            return self._runtime
        config = MLXNeuralEmbeddingConfig(
            model_id=self.model_id,
            cache_dir=self.cache_dir,
            revision=self.revision,
            pooling=self.pooling,
            max_tokens=self.max_tokens,
            normalize=self.normalize,
            local_files_only=self.local_files_only,
        )
        try:
            self._runtime = self._runtime_factory(config)
        except EmbeddingProviderError:
            raise
        except ImportError as exc:
            raise EmbeddingProviderError(
                "MLX neural embeddings require mlx-lm, huggingface-hub, "
                "tokenizers, and safetensors. Install with `uv add mlx-lm "
                "huggingface-hub tokenizers safetensors`, then set "
                "SYNAPSE_S2_NEURAL_MODEL to an MLX embedding model such as "
                f"{DEFAULT_NEURAL_MODEL}."
            ) from exc
        except Exception as exc:
            raise EmbeddingProviderError(
                f"failed to load MLX neural embedding model {self.model_id}; "
                "verify SYNAPSE_S2_NEURAL_MODEL, SYNAPSE_S2_NEURAL_CACHE_DIR, "
                "and network/cache access: "
                f"{safe_public_error(exc, fallback='model load failed')}"
            ) from exc
        return self._runtime


class MLXNeuralEmbeddingRuntime:
    native_mlx = True

    def __init__(self, config: MLXNeuralEmbeddingConfig) -> None:
        self.config = config
        self.model_id = config.model_id
        self.source = config.model_id
        self.cache_fallback_used = False
        self.model_config: dict[str, Any] = {}
        self.model, self.tokenizer = self._load_model(config)

    def _load_model(self, config: MLXNeuralEmbeddingConfig):
        from mlx_lm import load

        model_ref = self._resolve_model_ref(config)
        loaded = load(
            model_ref,
            lazy=False,
            return_config=True,
            revision=None if Path(str(model_ref)).expanduser().exists() else config.revision,
        )
        model, tokenizer, model_config = loaded
        self.model_config = _json_safe(model_config)
        return model, tokenizer

    def _resolve_model_ref(self, config: MLXNeuralEmbeddingConfig) -> str:
        local_path = Path(config.model_id).expanduser()
        if local_path.exists():
            self.source = str(local_path)
            return str(local_path)
        if not config.cache_dir:
            return config.model_id

        from huggingface_hub import snapshot_download

        cache_root = Path(config.cache_dir).expanduser()
        cache_root.mkdir(parents=True, exist_ok=True)
        try:
            model_path = snapshot_download(
                repo_id=config.model_id,
                cache_dir=str(cache_root),
                revision=config.revision,
                local_files_only=config.local_files_only,
                allow_patterns=[
                    "*.json",
                    "*.model",
                    "*.txt",
                    "*.py",
                    "*.safetensors",
                    "tokenizer*",
                    "special_tokens_map.json",
                    "generation_config.json",
                ],
            )
        except Exception:
            cached_snapshot = _latest_cached_snapshot(cache_root, config.model_id)
            if cached_snapshot is None:
                raise
            self.cache_fallback_used = True
            self.source = str(cached_snapshot)
            return str(cached_snapshot)
        self.source = model_path
        return model_path

    def embed_text(self, text: str, *, pooling: str, max_tokens: int) -> list[float]:
        import mlx.core as mx

        tokens = self._encode(text, max_tokens=max_tokens)
        token_array = mx.array([tokens], dtype=mx.int32)
        hidden = self._hidden_states(token_array)
        pooled = self._pool(hidden, pooling=pooling)
        denom = mx.sqrt(mx.sum(pooled * pooled))
        pooled = pooled / mx.maximum(denom, mx.array(1e-12))
        mx.eval(pooled)
        return [float(value) for value in pooled.tolist()]

    def _encode(self, text: str, *, max_tokens: int) -> list[int]:
        try:
            tokens = self.tokenizer.encode(str(text or ""), add_special_tokens=True)
        except TypeError:
            tokens = self.tokenizer.encode(str(text or ""))
        if not tokens:
            eos_token_id = getattr(self.tokenizer, "eos_token_id", None)
            tokens = [int(eos_token_id)] if eos_token_id is not None else [0]
        return [int(token) for token in tokens[:max_tokens]]

    def _hidden_states(self, token_array):
        core_model = getattr(self.model, "model", None)
        if callable(core_model):
            output = core_model(token_array)
        else:
            output = self.model(token_array)
        return _extract_array_output(output)

    def _pool(self, hidden, *, pooling: str):
        import mlx.core as mx

        if len(hidden.shape) == 3:
            sequence = hidden[0]
        elif len(hidden.shape) == 2:
            sequence = hidden
        elif len(hidden.shape) == 1:
            return hidden
        else:
            sequence = mx.reshape(hidden, (-1, hidden.shape[-1]))

        if pooling == "last":
            return sequence[-1]
        if pooling == "first":
            return sequence[0]
        return mx.mean(sequence, axis=0)


def _tokens(text: str) -> list[str]:
    tokens = TOKEN_RE.findall(text)
    return tokens or ["empty"]


def _latest_cached_snapshot(cache_root: Path, model_id: str) -> Path | None:
    snapshot_root = (
        cache_root
        / f"models--{str(model_id).strip().replace('/', '--')}"
        / "snapshots"
    )
    if not snapshot_root.exists():
        return None
    candidates = [path for path in snapshot_root.iterdir() if path.is_dir()]
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _normalized_tokens(tokens: list[str]) -> list[str]:
    normalized: list[str] = []
    for token in tokens:
        clean = token.strip("._:/#-")
        if not clean:
            continue
        if len(clean) > 4 and clean.endswith("s"):
            clean = clean[:-1]
        if clean == "kernel":
            normalized.extend(["kernel", "kernels"])
        else:
            normalized.append(clean)
    return normalized or ["empty"]


def _matched_concepts(tokens: list[str]) -> list[str]:
    token_set = set(tokens)
    concepts = [
        concept
        for concept, members in CONCEPT_GROUPS.items()
        if token_set & members
    ]
    return sorted(concepts)


def _features_to_vector(
    features: list[str] | list[tuple[str, float]],
    *,
    dimensions: int,
) -> list[float]:
    dims = _validate_dimensions(dimensions)
    vector = [0.0] * dims
    if not features:
        features = ["empty"]
    for feature in features:
        if isinstance(feature, tuple):
            name, weight = feature
        else:
            name, weight = feature, 1.0
        digest = hashlib.blake2b(str(name).encode("utf-8"), digest_size=16).digest()
        index = int.from_bytes(digest[:4], "big") % dims
        magnitude = 0.5 + (int.from_bytes(digest[4:8], "big") % 1000) / 1000.0
        sign = 1.0 if digest[8] % 2 == 0 else -1.0
        vector[index] += sign * magnitude * float(weight)
    return vector


def _validate_dimensions(dimensions: int) -> int:
    dims = int(dimensions)
    if dims <= 0 or dims > MAX_PROVIDER_DIMS:
        raise ValueError(f"dimensions must be between 1 and {MAX_PROVIDER_DIMS}")
    return dims


def _validate_vector(vector: Any, *, dimensions: int) -> list[float]:
    if not isinstance(vector, (list, tuple)):
        raise EmbeddingProviderError("provider returned vector must be a list")
    if len(vector) != dimensions:
        raise EmbeddingProviderError(
            f"provider returned {len(vector)} dimensions, expected {dimensions}"
        )
    safe: list[float] = []
    for value in vector:
        number = float(value)
        if not math.isfinite(number):
            raise EmbeddingProviderError("provider returned non-finite vector value")
        safe.append(number)
    return safe


def _validate_float_list(vector: Any) -> list[float]:
    if not isinstance(vector, (list, tuple)):
        raise EmbeddingProviderError("neural runtime returned vector must be a list")
    if not vector:
        raise EmbeddingProviderError("neural runtime returned an empty vector")
    safe: list[float] = []
    for value in vector:
        number = float(value)
        if not math.isfinite(number):
            raise EmbeddingProviderError("neural runtime returned non-finite vector value")
        safe.append(number)
    return safe


def _project_vector(vector: list[float], *, dimensions: int) -> list[float]:
    dims = _validate_dimensions(dimensions)
    if len(vector) == dims:
        return list(vector)
    projected = [0.0] * dims
    for index, value in enumerate(vector):
        digest = hashlib.blake2b(
            f"mlx-neural-v1:{len(vector)}:{index}".encode("utf-8"),
            digest_size=12,
        ).digest()
        target = int.from_bytes(digest[:4], "big") % dims
        sign = 1.0 if digest[4] % 2 == 0 else -1.0
        projected[target] += sign * float(value)
    return projected


def _normalize_vector(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(float(value) * float(value) for value in vector))
    if norm <= 1e-12:
        normalized = [0.0] * len(vector)
        if normalized:
            normalized[0] = 1.0
        return normalized
    return [float(value) / norm for value in vector]


def _validate_pooling(pooling: str) -> str:
    normalized = str(pooling or DEFAULT_NEURAL_POOLING).strip().lower()
    if normalized in {"mean", "avg", "average"}:
        return "mean"
    if normalized in {"last", "eos"}:
        return "last"
    if normalized in {"first", "cls"}:
        return "first"
    raise EmbeddingProviderError("SYNAPSE_S2_NEURAL_POOLING must be mean, last, or first")


def _positive_int(value: Any, *, default: int, name: str) -> int:
    if value is None or value == "":
        return int(default)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise EmbeddingProviderError(f"{name} must be a positive integer") from exc
    if parsed <= 0:
        raise EmbeddingProviderError(f"{name} must be a positive integer")
    return parsed


def _optional_path_str(value: str | os.PathLike[str] | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return str(Path(text).expanduser())


def _provider_identifier(value: Any, *, field: str) -> str:
    """Reject credential-shaped provider provenance without echoing it."""

    try:
        return reject_sensitive_identifier(value, field=field).strip()
    except ValueError as exc:
        raise EmbeddingProviderError(
            f"{field} must not contain credential material"
        ) from exc


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return bool(default)
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _extract_array_output(output: Any):
    if isinstance(output, dict):
        for key in ("last_hidden_state", "hidden_states", "embeddings", "logits"):
            if key in output:
                return _extract_array_output(output[key])
    if isinstance(output, (list, tuple)):
        if not output:
            raise EmbeddingProviderError("MLX neural model returned no hidden state")
        return _extract_array_output(output[0])
    shape = getattr(output, "shape", None)
    if shape is None:
        raise EmbeddingProviderError(
            f"MLX neural model returned unsupported output type {type(output).__name__}"
        )
    return output


def _provenance(
    *,
    provider: str,
    provider_type: str,
    dimensions: int,
    semantic: bool,
    local_only: bool,
    tokens: list[str],
    concepts: list[str],
    vector: list[float],
    feature_count: int | None,
    model_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "provider": provider,
        "provider_type": provider_type,
        "model_id": model_id or provider,
        "dimensions": int(dimensions),
        "semantic": bool(semantic),
        "local_only": bool(local_only),
        "token_count": len(tokens),
        "concepts": concepts,
        "vector_sha256": _vector_sha256(vector),
    }
    if feature_count is not None:
        payload["feature_count"] = int(feature_count)
    if details:
        payload["details"] = _json_safe(details)
    return payload


def _vector_sha256(vector: list[float]) -> str:
    encoded = json.dumps(
        [round(float(value), 8) for value in vector],
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_safe(value: Any) -> dict[str, Any]:
    safe_value, _ = redact_sensitive_value(value)
    try:
        payload = json.loads(json.dumps(safe_value, allow_nan=False))
        return payload if isinstance(payload, dict) else {"value": payload}
    except (TypeError, ValueError):
        return {"value": "[UNSERIALIZABLE]"}

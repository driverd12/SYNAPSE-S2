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


MAX_PROVIDER_DIMS = 32_768
TOKEN_RE = re.compile(r"[a-z0-9_.:/#-]+")

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
    raise EmbeddingProviderError(
        "unknown embedding provider; expected auto, semantic-hash, lexical-hash, "
        "or python:/path/to/module.py:function"
    )


class LexicalHashEmbeddingProvider(EmbeddingProvider):
    provider_id = "lexical-hash-v1"

    def embed(self, text: str, *, dimensions: int) -> EmbeddingResult:
        dims = _validate_dimensions(dimensions)
        normalized = str(text or "").strip().lower()
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
        normalized = str(text or "").strip().lower()
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
        _, payload = spec.split("python:", 1)
        module_ref, separator, function_name = payload.rpartition(":")
        if not separator or not module_ref.strip() or not function_name.strip():
            raise EmbeddingProviderError(
                "python provider must look like python:/path/to/module.py:function"
            )
        self.module_ref = module_ref.strip()
        self.function_name = function_name.strip()
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
        raw = self._callable(str(text or ""), dims)
        details: dict[str, Any] = {}
        model_id = f"{self.module_ref}:{self.function_name}"
        semantic = True
        if isinstance(raw, dict):
            vector = raw.get("vector")
            model_id = str(raw.get("model_id") or model_id)
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
                tokens=_tokens(str(text or "").lower()),
                concepts=[],
                vector=safe_vector,
                feature_count=None,
                model_id=model_id,
                details=details,
            ),
        )


def _tokens(text: str) -> list[str]:
    tokens = TOKEN_RE.findall(text)
    return tokens or ["empty"]


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
    try:
        payload = json.loads(json.dumps(value, default=str))
        return payload if isinstance(payload, dict) else {"value": payload}
    except Exception:
        return {"value": str(value)}

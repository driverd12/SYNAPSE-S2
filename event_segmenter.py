from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import sys
from collections import Counter
from typing import Any, Callable


LOGGER = logging.getLogger("synapse_s2.event_segmenter")
if not LOGGER.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(os.getenv("SYNAPSE_S2_LOG_LEVEL", "INFO").upper())
LOGGER.propagate = False

TOKEN_RE = re.compile(r"[a-z0-9_.:/#-]+")
SENTENCE_RE = re.compile(r"[^.!?\n]+(?:[.!?]+|\n|$)")
PROTECTED_SENTENCE_FRAGMENT_RE = re.compile(
    r"\b(?:https?://|file://|s2://)[^\s]+"
    r"|(?<![\w-])(?:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)"
    r"(?::[0-9]+)?(?:/[A-Za-z0-9_./:%#?=&+-]+)?(?![\w-])"
    r"|(?<![\w-])\.?[A-Za-z0-9_-]+(?:/[A-Za-z0-9_./:%#?=&+-]+)+(?![\w-])",
    re.IGNORECASE,
)
SAFE_TAG_RE = re.compile(r"[^A-Za-z0-9_.:-]+")
STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "into",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "then",
    "this",
    "to",
    "with",
}


def _stable_id(*parts: str) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:24]


EmbeddingFn = Callable[[str], Any]


def _safe_tag(value: str) -> str:
    cleaned = SAFE_TAG_RE.sub("-", str(value or "").strip()).strip(".-_:")
    return (cleaned or "event")[:96]


class BayesianSurpriseEventSegmenter:
    """Deterministic local event segmenter with semantic surprise when available.

    Sentence boundaries are opened by comparing each incoming sentence against
    the rolling posterior of the active event. If an embedding function is
    supplied, cosine distance drives the boundary decision and lexical surprise
    remains available as an auditable fallback score.
    """

    def __init__(
        self,
        *,
        surprise_threshold: float = 0.62,
        min_segment_sentences: int = 2,
        keyword_limit: int = 8,
        embedding_fn: EmbeddingFn | None = None,
    ) -> None:
        self.surprise_threshold = min(max(float(surprise_threshold), 0.0), 1.0)
        self.min_segment_sentences = max(1, int(min_segment_sentences))
        self.keyword_limit = max(1, int(keyword_limit))
        self.embedding_fn = embedding_fn

    def segment(
        self,
        text: str,
        *,
        context_id: str = "default",
        source_tag: str = "memory",
    ) -> list[dict[str, Any]]:
        sentences = self._sentences(text)
        if not sentences:
            return []

        source = _safe_tag(source_tag)
        sequence_id = _stable_id(context_id, source, " ".join(sentences))
        segments: list[dict[str, Any]] = []
        current: list[str] = []
        current_tokens: set[str] = set()
        current_vector_sum: list[float] | None = None
        current_vector_count = 0
        boundary = self._empty_boundary_state()

        for sentence in sentences:
            sentence_tokens = set(self._tokens(sentence))
            lexical_surprise = self._surprise(sentence_tokens, current_tokens)
            sentence_vector = self._embedding_vector(sentence)
            semantic_surprise = self._semantic_surprise(
                sentence_vector,
                self._centroid(current_vector_sum, current_vector_count),
            )
            surprise_mode = (
                "embedding"
                if semantic_surprise is not None or sentence_vector
                else "lexical"
            )
            surprise = semantic_surprise if semantic_surprise is not None else lexical_surprise
            if (
                current
                and len(current) >= self.min_segment_sentences
                and surprise >= self.surprise_threshold
            ):
                segments.append(
                    self._render_segment(
                        current,
                        context_id=context_id,
                        source_tag=source,
                        sequence_id=sequence_id,
                        segment_index=len(segments) + 1,
                        boundary=boundary,
                    )
                )
                current = []
                current_tokens = set()
                current_vector_sum = None
                current_vector_count = 0
                boundary = self._boundary_state(
                    surprise_score=surprise,
                    lexical_surprise_score=lexical_surprise,
                    semantic_surprise_score=semantic_surprise,
                    surprise_mode=surprise_mode,
                )
            else:
                boundary = self._merge_boundary_state(
                    boundary,
                    surprise_score=surprise,
                    lexical_surprise_score=lexical_surprise,
                    semantic_surprise_score=semantic_surprise,
                    surprise_mode=surprise_mode,
                )

            current.append(sentence)
            current_tokens.update(sentence_tokens)
            current_vector_sum, current_vector_count = self._add_vector(
                current_vector_sum,
                current_vector_count,
                sentence_vector,
            )

        if current:
            segments.append(
                self._render_segment(
                    current,
                    context_id=context_id,
                    source_tag=source,
                    sequence_id=sequence_id,
                    segment_index=len(segments) + 1,
                    boundary=boundary,
                )
            )
        return segments

    def _sentences(self, text: str) -> list[str]:
        normalized = str(text or "").strip()
        if not normalized:
            return []
        protected, replacements = self._protect_sentence_fragments(normalized)
        matches = [
            self._restore_sentence_fragments(match.group(0).strip(), replacements)
            for match in SENTENCE_RE.finditer(protected)
        ]
        return [sentence for sentence in matches if sentence]

    def _protect_sentence_fragments(self, text: str) -> tuple[str, dict[str, str]]:
        replacements: dict[str, str] = {}

        def replace(match: re.Match[str]) -> str:
            value = match.group(0)
            suffix = ""
            while value.endswith((".", "!")):
                suffix = value[-1] + suffix
                value = value[:-1]
            if not value:
                return match.group(0)
            token = f"__S2_PROTECTED_{len(replacements)}__"
            replacements[token] = value
            return f"{token}{suffix}"

        return PROTECTED_SENTENCE_FRAGMENT_RE.sub(replace, text), replacements

    def _restore_sentence_fragments(
        self, text: str, replacements: dict[str, str]
    ) -> str:
        restored = text
        for token, value in replacements.items():
            restored = restored.replace(token, value)
        return restored

    def _tokens(self, text: str) -> list[str]:
        tokens: list[str] = []
        for token in TOKEN_RE.findall(str(text or "").lower()):
            cleaned = token.strip("._:/#-")
            if cleaned and cleaned not in STOPWORDS:
                tokens.append(cleaned)
        return tokens

    def _surprise(self, incoming: set[str], posterior: set[str]) -> float:
        if not incoming:
            return 0.0
        if not posterior:
            return 0.0
        overlap = len(incoming & posterior)
        union = len(incoming | posterior)
        return round(1.0 - (overlap / max(1, union)), 6)

    def _embedding_vector(self, sentence: str) -> list[float]:
        if self.embedding_fn is None:
            return []
        try:
            raw = self.embedding_fn(sentence)
        except Exception:
            LOGGER.exception("semantic surprise embedding function failed")
            return []
        if isinstance(raw, dict):
            raw = raw.get("vector", [])
        elif hasattr(raw, "vector"):
            raw = getattr(raw, "vector")
        try:
            values = [float(value) for value in raw]
        except Exception:
            LOGGER.warning("semantic surprise embedding function returned invalid vector")
            return []
        safe_values = [value for value in values if math.isfinite(value)]
        if len(safe_values) != len(values):
            LOGGER.warning("semantic surprise vector contained non-finite coordinates")
            return []
        return safe_values

    def _semantic_surprise(
        self,
        incoming: list[float],
        posterior_centroid: list[float],
    ) -> float | None:
        if not incoming or not posterior_centroid:
            return None
        if len(incoming) != len(posterior_centroid):
            return None
        incoming_norm = math.sqrt(sum(value * value for value in incoming))
        posterior_norm = math.sqrt(sum(value * value for value in posterior_centroid))
        if incoming_norm <= 1e-12 or posterior_norm <= 1e-12:
            return None
        dot = sum(
            incoming[index] * posterior_centroid[index]
            for index in range(len(incoming))
        )
        cosine = dot / (incoming_norm * posterior_norm)
        clamped_cosine = max(-1.0, min(1.0, cosine))
        return round(1.0 - max(0.0, clamped_cosine), 6)

    def _centroid(
        self,
        vector_sum: list[float] | None,
        vector_count: int,
    ) -> list[float]:
        if not vector_sum or vector_count <= 0:
            return []
        return [value / float(vector_count) for value in vector_sum]

    def _add_vector(
        self,
        vector_sum: list[float] | None,
        vector_count: int,
        incoming: list[float],
    ) -> tuple[list[float] | None, int]:
        if not incoming:
            return vector_sum, vector_count
        if vector_sum is None:
            return list(incoming), 1
        if len(vector_sum) != len(incoming):
            LOGGER.warning("semantic surprise vector dimension changed inside one segment")
            return vector_sum, vector_count
        return (
            [vector_sum[index] + incoming[index] for index in range(len(incoming))],
            vector_count + 1,
        )

    def _empty_boundary_state(self) -> dict[str, Any]:
        return {
            "surprise_score": 0.0,
            "lexical_surprise_score": 0.0,
            "semantic_surprise_score": 0.0,
            "surprise_mode": "lexical",
        }

    def _boundary_state(
        self,
        *,
        surprise_score: float,
        lexical_surprise_score: float,
        semantic_surprise_score: float | None,
        surprise_mode: str,
    ) -> dict[str, Any]:
        return {
            "surprise_score": round(float(surprise_score), 6),
            "lexical_surprise_score": round(float(lexical_surprise_score), 6),
            "semantic_surprise_score": round(float(semantic_surprise_score or 0.0), 6),
            "surprise_mode": surprise_mode,
        }

    def _merge_boundary_state(
        self,
        boundary: dict[str, Any],
        *,
        surprise_score: float,
        lexical_surprise_score: float,
        semantic_surprise_score: float | None,
        surprise_mode: str,
    ) -> dict[str, Any]:
        merged = dict(boundary)
        if float(surprise_score) >= float(merged.get("surprise_score", 0.0)):
            merged.update(
                self._boundary_state(
                    surprise_score=surprise_score,
                    lexical_surprise_score=lexical_surprise_score,
                    semantic_surprise_score=semantic_surprise_score,
                    surprise_mode=surprise_mode,
                )
            )
        elif surprise_mode == "embedding" and merged.get("surprise_mode") == "lexical":
            merged["surprise_mode"] = "embedding"
        if semantic_surprise_score is not None:
            merged["semantic_surprise_score"] = round(
                max(
                    float(merged.get("semantic_surprise_score", 0.0)),
                    float(semantic_surprise_score),
                ),
                6,
            )
        merged["lexical_surprise_score"] = round(
            max(
                float(merged.get("lexical_surprise_score", 0.0)),
                float(lexical_surprise_score),
            ),
            6,
        )
        return merged

    def _render_segment(
        self,
        sentences: list[str],
        *,
        context_id: str,
        source_tag: str,
        sequence_id: str,
        segment_index: int,
        boundary: dict[str, Any],
    ) -> dict[str, Any]:
        text = " ".join(sentences).strip()
        keywords = self._keywords(text)
        return {
            "segment_id": _stable_id(sequence_id, str(segment_index), text),
            "sequence_id": sequence_id,
            "context_id": context_id,
            "source_tag": source_tag,
            "tag": f"{source_tag}-event-{segment_index:03d}",
            "segment_index": int(segment_index),
            "text": text,
            "sentence_count": len(sentences),
            "surprise_score": round(float(boundary.get("surprise_score", 0.0)), 6),
            "surprise_mode": str(boundary.get("surprise_mode") or "lexical"),
            "lexical_surprise_score": round(
                float(boundary.get("lexical_surprise_score", 0.0)),
                6,
            ),
            "semantic_surprise_score": round(
                float(boundary.get("semantic_surprise_score", 0.0)),
                6,
            ),
            "keywords": keywords,
        }

    def _keywords(self, text: str) -> list[str]:
        counts = Counter(self._tokens(text))
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return [token for token, _ in ranked[: self.keyword_limit]]

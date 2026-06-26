from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
from collections import Counter
from typing import Any


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


def _safe_tag(value: str) -> str:
    cleaned = SAFE_TAG_RE.sub("-", str(value or "").strip()).strip(".-_:")
    return (cleaned or "event")[:96]


class BayesianSurpriseEventSegmenter:
    """Deterministic lexical event segmenter.

    This is a local approximation of Bayesian surprise: each sentence is
    compared with the rolling token posterior of the current event. Low overlap
    implies high surprise and opens a new event boundary.
    """

    def __init__(
        self,
        *,
        surprise_threshold: float = 0.62,
        min_segment_sentences: int = 2,
        keyword_limit: int = 8,
    ) -> None:
        self.surprise_threshold = min(max(float(surprise_threshold), 0.0), 1.0)
        self.min_segment_sentences = max(1, int(min_segment_sentences))
        self.keyword_limit = max(1, int(keyword_limit))

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
        boundary_surprise = 0.0

        for sentence in sentences:
            sentence_tokens = set(self._tokens(sentence))
            surprise = self._surprise(sentence_tokens, current_tokens)
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
                        surprise_score=boundary_surprise,
                    )
                )
                current = []
                current_tokens = set()

            current.append(sentence)
            current_tokens.update(sentence_tokens)
            boundary_surprise = max(boundary_surprise, surprise)

        if current:
            segments.append(
                self._render_segment(
                    current,
                    context_id=context_id,
                    source_tag=source,
                    sequence_id=sequence_id,
                    segment_index=len(segments) + 1,
                    surprise_score=boundary_surprise,
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

    def _render_segment(
        self,
        sentences: list[str],
        *,
        context_id: str,
        source_tag: str,
        sequence_id: str,
        segment_index: int,
        surprise_score: float,
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
            "surprise_score": round(float(surprise_score), 6),
            "keywords": keywords,
        }

    def _keywords(self, text: str) -> list[str]:
        counts = Counter(self._tokens(text))
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return [token for token, _ in ranked[: self.keyword_limit]]

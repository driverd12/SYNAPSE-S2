from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any, Iterable


HARMONIC_SCAFFOLD_SCHEMA = "synapse-s2.harmonic-scaffold.v1"
HARMONIC_SCAFFOLD_GENERATOR = "deterministic-local-cues-v1"
HARMONIC_SCAFFOLD_MAX_CUES = 8

_SPACE_RE = re.compile(r"\s+")
_TECHNICAL_CUE_RE = re.compile(
    r"\b[A-Za-z][A-Za-z0-9]*(?:[_.:/-][A-Za-z0-9]+)+\b"
)
_CUE_STOP_WORDS = frozenset(
    {
        "about",
        "capture",
        "captured",
        "conversation",
        "default",
        "event",
        "feature",
        "memory",
        "namespace",
        "operator",
        "source",
        "stored",
        "text",
        "topic",
        "trace",
        "unknown",
    }
)


def _clean_phrase(value: Any, limit: int) -> str:
    if value is None or isinstance(value, (bool, dict, list, tuple, set)):
        return ""
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = "".join(
        " " if unicodedata.category(char).startswith("C") else char
        for char in text
    )
    text = _SPACE_RE.sub(" ", text).strip(" .,:;|/\t\r\n")
    if len(text) <= limit:
        return text
    return text[:limit].rstrip(" .,:;|/\t\r\n")


def _identity(value: str) -> str:
    return _SPACE_RE.sub(" ", str(value or "").casefold()).strip()


def _is_redaction_marker(value: str) -> bool:
    normalized = _identity(value)
    return "[redacted" in normalized or "redacted_secret" in normalized


def _stable_id(prefix: str, values: Iterable[str]) -> str:
    seed = "\x1f".join(str(value) for value in values).encode("utf-8")
    return f"{prefix}_" + hashlib.sha256(seed).hexdigest()[:32]


def _metadata_values(metadata: dict[str, Any], key: str) -> list[Any]:
    value = metadata.get(key)
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, set):
        return sorted(value, key=lambda item: str(item))
    return [] if value is None or value == "" else [value]


def _explicit_cue_value(value: Any) -> str:
    if isinstance(value, dict):
        return _clean_phrase(
            value.get("aspect") or value.get("label") or value.get("cue"),
            72,
        )
    return _clean_phrase(value, 72)


def build_harmonic_scaffold(
    *,
    source_text: str,
    context_id: str,
    source_memory_id: str,
    source_tag: str,
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a bounded, deterministic navigation layer over one source row.

    This deliberately does not summarize, merge, or replace the source value.
    The returned structure is stored inside that source row's metadata so its
    lifecycle follows the authoritative memory entry without orphan cleanup.
    """

    safe_metadata = metadata if isinstance(metadata, dict) else {}
    primary_candidates = (
        (safe_metadata.get("primary_abstraction"), "operator-metadata"),
        (safe_metadata.get("context_label"), "typed-context-label"),
        (safe_metadata.get("context_namespace_title"), "context-namespace"),
        (safe_metadata.get("display_label"), "display-label"),
        (source_tag, "source-tag"),
    )
    primary_label = ""
    primary_basis = "source-tag"
    for candidate, basis in primary_candidates:
        clean = _clean_phrase(candidate, 96)
        if clean and not _is_redaction_marker(clean):
            primary_label = clean
            primary_basis = basis
            break
    if not primary_label:
        primary_label = "Memory"

    primary_identity = _identity(primary_label)
    abstraction_id = _stable_id(
        "s2abs",
        (HARMONIC_SCAFFOLD_SCHEMA, context_id, primary_identity),
    )

    explicit_cues = _metadata_values(safe_metadata, "cue_anchors")
    cue_candidates: list[tuple[Any, str]] = [
        (value, "operator-metadata")
        for value in explicit_cues
    ]
    if not explicit_cues:
        for key, basis in (
            ("display_label", "display-label"),
            ("context_label", "typed-context-label"),
            ("semantic_facets", "semantic-facet"),
            ("keywords", "source-keyword"),
            ("detail_badges", "detail-badge"),
        ):
            cue_candidates.extend(
                (value, basis) for value in _metadata_values(safe_metadata, key)
            )
        cue_candidates.extend(
            (match.group(0), "technical-identifier")
            for match in _TECHNICAL_CUE_RE.finditer(str(source_text or ""))
        )
        cue_candidates.append((source_tag, "source-tag"))

    cue_records: list[dict[str, str]] = []
    seen: set[str] = {primary_identity}
    for raw_value, basis in cue_candidates:
        aspect = _explicit_cue_value(raw_value)
        normalized = _identity(aspect)
        if (
            len(normalized) < 2
            or normalized in seen
            or normalized in _CUE_STOP_WORDS
            or _is_redaction_marker(aspect)
        ):
            continue
        seen.add(normalized)
        cue_records.append(
            {
                "anchor_id": _stable_id(
                    "s2cue",
                    (
                        HARMONIC_SCAFFOLD_SCHEMA,
                        context_id,
                        abstraction_id,
                        normalized,
                    ),
                ),
                "aspect": aspect,
                "label": _clean_phrase(f"{primary_label} :: {aspect}", 160),
                "basis": basis,
            }
        )
        if len(cue_records) >= HARMONIC_SCAFFOLD_MAX_CUES:
            break

    return {
        "schema": HARMONIC_SCAFFOLD_SCHEMA,
        "generator": HARMONIC_SCAFFOLD_GENERATOR,
        "generation_mode": "deterministic-not-learned",
        "trust": "untrusted-memory-evidence",
        "primary_abstraction": {
            "abstraction_id": abstraction_id,
            "label": primary_label,
            "basis": primary_basis,
            "trust": "untrusted-memory-evidence",
        },
        "cue_anchors": cue_records,
        "provenance": {
            "source_memory_id": str(source_memory_id),
            "source_tag": str(source_tag),
            "source_binding": "co-located-memory-entry",
            "source_value": "memory_entries.source_text",
            "generator_input": "redacted-source-and-reviewed-metadata",
            "source_claim": "navigation-only-not-independent-evidence",
        },
        "retrieval": {
            "index": "memory_surface_terms",
            "many_to_many": True,
            "cross_namespace": False,
            "max_expansion_hops": 0,
        },
        "lifecycle": {
            "regenerable": True,
            "materialized_nodes": False,
            "delete_with_source": True,
        },
    }


def harmonic_scaffold_facets(
    metadata: dict[str, Any] | None,
    *,
    limit: int = 16,
) -> list[str]:
    safe_metadata = metadata if isinstance(metadata, dict) else {}
    scaffold = safe_metadata.get("harmonic_scaffold")
    if not isinstance(scaffold, dict):
        return []
    if scaffold.get("schema") != HARMONIC_SCAFFOLD_SCHEMA:
        return []
    values: list[Any] = []
    primary = scaffold.get("primary_abstraction")
    if isinstance(primary, dict):
        values.append(primary.get("label"))
    anchors = scaffold.get("cue_anchors")
    if isinstance(anchors, list):
        for anchor in anchors:
            if not isinstance(anchor, dict):
                continue
            values.append(anchor.get("aspect"))

    facets: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = _clean_phrase(raw_value, 160)
        normalized = _identity(value)
        if not value or normalized in seen:
            continue
        seen.add(normalized)
        facets.append(value)
        if len(facets) >= max(0, int(limit)):
            break
    return facets


def harmonic_scaffold_index_terms(
    metadata: dict[str, Any] | None,
    *,
    limit: int = 32,
) -> list[str]:
    safe_metadata = metadata if isinstance(metadata, dict) else {}
    scaffold = safe_metadata.get("harmonic_scaffold")
    if not isinstance(scaffold, dict):
        return []
    if scaffold.get("schema") != HARMONIC_SCAFFOLD_SCHEMA:
        return []
    values = harmonic_scaffold_facets(safe_metadata, limit=limit)
    primary = scaffold.get("primary_abstraction")
    if isinstance(primary, dict):
        values.append(primary.get("abstraction_id"))
    anchors = scaffold.get("cue_anchors")
    if isinstance(anchors, list):
        values.extend(
            anchor.get("label")
            for anchor in anchors
            if isinstance(anchor, dict)
        )
        values.extend(
            anchor.get("anchor_id")
            for anchor in anchors
            if isinstance(anchor, dict)
        )
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = _clean_phrase(raw_value, 160)
        if not value or value in seen:
            continue
        seen.add(value)
        cleaned.append(value)
        if len(cleaned) >= max(0, int(limit)):
            break
    return cleaned

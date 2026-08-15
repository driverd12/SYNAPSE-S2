"""Memora Shadow v1: bounded, deterministic, non-mutating consolidation planner.

This module proposes Memora-style consolidation clusters and cue bindings over
an exact one-namespace snapshot of durable memory entries.  It is shadow-only:

* nothing is persisted, promoted, or applied by the planner itself;
* retrieval results are never changed by anything produced here;
* every source row remains immutable and independently deletable;
* "learned" means pretrained embedding *inference* with the pinned local
  neural provider -- never fine-tuning, LLM content merging, GRPO, or any
  automatic promotion path.

Promotion of a proposed cluster into a governed cue binding is a separate,
explicit, operator-confirmed mutation implemented in
:mod:`memora_governance`; the planner only produces reviewable proposals.

The planner is pure: it receives an already-read snapshot plus an embedding
callable and produces a JSON-safe plan.  It never touches SQLite, sockets,
or the neural runtime state.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from redaction import redact_capture_text

MEMORA_SHADOW_SCHEMA = "synapse-s2.memora-shadow.v1"
MEMORA_SHADOW_SCHEMA_VERSION = 1
MEMORA_SHADOW_PLANNER_NAME = "memora-shadow-planner-v1"

MEMORA_SHADOW_MAX_ENTRIES = 64
MEMORA_SHADOW_MAX_INPUT_BYTES = 65_536
MEMORA_SHADOW_MAX_CLUSTERS = 16
MEMORA_SHADOW_MAX_CUES_PER_CLUSTER = 8
MEMORA_SHADOW_ENTRY_INPUT_BYTES = MEMORA_SHADOW_MAX_INPUT_BYTES // MEMORA_SHADOW_MAX_ENTRIES

# SQL-level materialization gates enforced by the store page read before any
# whole row is loaded into Python.  The source-text gate is deliberately wider
# than the planner's own raw-fragment character bound (4,096 characters can be
# up to 16,384 UTF-8 bytes), so the SQL gate never keeps something the planner
# would drop, and never drops something the planner would keep.
MEMORA_SHADOW_MAX_SOURCE_TEXT_BYTES = 16_384
MEMORA_SHADOW_MAX_METADATA_BYTES = 65_536

MEMORA_SHADOW_DEFAULT_SIMILARITY_THRESHOLD = 0.55

_LEARNED_PROVIDER_TYPE = "mlx-neural"
_REDACTION_SENTINEL_PREFIX = "[REDACTED"
_FRAGMENT_CHAR_LIMIT = 160
_FRAGMENT_RAW_CHAR_LIMIT = 4096
_MAX_LIST_FRAGMENTS = 16
_CUE_TERM_MIN_CHARS = 3
_CUE_TERM_MAX_CHARS = 48
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_./-]*")

# Only these already-redacted durable fields may contribute embeddable text.
# Everything else on an entry (paths, spike/neuron indices, embedding
# provenance, harmonic scaffolds, Cortex evidence, arbitrary metadata) is
# structurally excluded.
EMBED_TEXT_WHITELIST = (
    "tag",
    "display_label",
    "display_summary",
    "semantic_facets",
    "keywords",
    "detail_badges",
)


class MemoraShadowSnapshotDrift(RuntimeError):
    """Raised when the namespace revision changed while reading the snapshot."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def plan_digest(plan: Mapping[str, Any]) -> str:
    """Content digest over a plan body, excluding the digest field itself."""

    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    return hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()


def provider_identity(provider_info: Mapping[str, Any] | None) -> dict[str, Any]:
    """Project a bounded, vector-free identity from embedding provider info."""

    info = provider_info if isinstance(provider_info, Mapping) else {}
    details = info.get("details") if isinstance(info.get("details"), Mapping) else {}
    revision = info.get("revision")
    if not isinstance(revision, str):
        revision = details.get("revision") if isinstance(details.get("revision"), str) else ""
    config_fingerprint = info.get("configuration_sha256")
    if not isinstance(config_fingerprint, str):
        config_fingerprint = (
            details.get("configuration_sha256")
            if isinstance(details.get("configuration_sha256"), str)
            else ""
        )
    def _exact_bool(value: Any) -> bool:
        # Fail closed: anything but the exact boolean True (a truthy string,
        # 1, a missing field) reads as False for identity claims.
        return value is True

    identity = {
        "provider": str(info.get("provider") or info.get("provider_id") or "unknown"),
        "provider_type": str(info.get("provider_type") or "unavailable"),
        "model_id": str(info.get("model_id") or ""),
        "revision": revision,
        "config_fingerprint": config_fingerprint,
        "dimensions": int(info["dimensions"]) if isinstance(info.get("dimensions"), int) else None,
        "semantic": _exact_bool(info.get("semantic")),
        "local_only": _exact_bool(info.get("local_only")),
        "ready": _exact_bool(info.get("ready")),
    }
    identity["learned"] = provider_is_learned(identity)
    return identity


def provider_is_learned(identity: Mapping[str, Any]) -> bool:
    """True only for a ready, pinned, local-only neural provider.

    "Learned" claims pretrained embedding inference actually happened, so it
    additionally requires the full identity quintuple -- a nonempty provider
    name, model identity, immutable revision, and configuration fingerprint --
    plus exact bounded integer dimensions.  A neural provider that is
    configured but not ready, remote, unnamed, or missing any identity
    component reports ``learned: false`` (fail closed).
    """

    provider_name = str(identity.get("provider") or "").strip()
    dimensions = identity.get("dimensions")
    return (
        identity.get("provider_type") == _LEARNED_PROVIDER_TYPE
        and bool(identity.get("semantic"))
        and bool(identity.get("local_only"))
        and bool(identity.get("ready"))
        and bool(provider_name)
        and provider_name != "unknown"
        and bool(str(identity.get("model_id") or "").strip())
        and bool(str(identity.get("revision") or "").strip())
        and bool(str(identity.get("config_fingerprint") or "").strip())
        and type(dimensions) is int
        and 1 <= dimensions <= 65_536
    )


def entry_provider_conflict(
    entry: Mapping[str, Any],
    active_identity: Mapping[str, Any],
) -> str | None:
    """Return a reason string when stored provenance contradicts the active provider.

    Entries without stored embedding provenance are compatible: their durable
    text is re-embedded from scratch with the active provider, so no stale
    vector identity can leak in.
    """

    metadata = entry.get("metadata")
    stored = metadata.get("embedding_provider") if isinstance(metadata, Mapping) else None
    if not isinstance(stored, Mapping):
        return None
    stored_provider = stored.get("provider")
    if isinstance(stored_provider, str) and stored_provider:
        if stored_provider != active_identity.get("provider"):
            return "provider-mismatch"
    stored_model = stored.get("model_id")
    if isinstance(stored_model, str) and stored_model:
        if stored_model != active_identity.get("model_id"):
            return "provider-mismatch"
    stored_revision = stored.get("revision")
    if not isinstance(stored_revision, str) or not stored_revision:
        details = stored.get("details")
        if isinstance(details, Mapping) and isinstance(details.get("revision"), str):
            stored_revision = details["revision"]
        else:
            stored_revision = ""
    active_revision = active_identity.get("revision") or ""
    if stored_revision and active_revision and stored_revision != active_revision:
        return "provider-mismatch"
    return None


def _redact_fragment(value: Any) -> tuple[str, int, bool]:
    """Redact the full stored value first, then collapse and truncate.

    Returns ``(text, redaction_hits, dropped)``.  Redaction must always see
    the complete stored value: truncating raw text first could cut a
    credential at the length boundary and leave an unrecognizable secret
    tail that no pattern matches.  Only the already-redacted text is
    collapsed and truncated.  Oversized raw values are dropped entirely
    (``dropped=True``) instead of being truncated, for the same reason.
    """

    if not isinstance(value, str) or not value.strip():
        return "", 0, False
    if len(value) > _FRAGMENT_RAW_CHAR_LIMIT:
        return "", 0, True
    redacted, hits = redact_capture_text(value)
    collapsed = " ".join(redacted.split())
    return collapsed[:_FRAGMENT_CHAR_LIMIT].strip(), int(hits), False


def _list_fragments(raw: Any) -> tuple[list[Any], int]:
    """Return safe list items plus a malformed-value count.

    A scalar string counts as one fragment.  Any other shape (numbers,
    mappings, nested containers where strings are expected) is excluded
    safely rather than iterated: iterating a string as characters or
    raising on an unhashable type would silently corrupt cue proposals.
    """

    if raw is None:
        return [], 0
    if isinstance(raw, str):
        return [raw], 0
    if isinstance(raw, (list, tuple)):
        values: list[Any] = []
        malformed = 0
        for item in list(raw)[:_MAX_LIST_FRAGMENTS]:
            if isinstance(item, str):
                values.append(item)
            else:
                malformed += 1
        return values, malformed
    return [], 1


def build_embeddable_text(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Assemble the bounded, whitelisted, re-redacted embeddable text for one entry.

    Fail-closed rules:
    * the durable ``source_text`` is re-redacted; sentinel rewrites are counted;
    * whitelisted metadata fragments are redacted at full stored length before
      any truncation; fragments that trip redaction or exceed the raw-size
      bound are dropped entirely;
    * malformed (non-string) fragment values are excluded safely and counted;
    * only already-redacted text is truncated, ending with the
      ``MEMORA_SHADOW_ENTRY_INPUT_BYTES`` UTF-8 cap.
    """

    fragments: list[str] = []
    dropped_fragments = 0
    malformed_fragments = 0
    redaction_rewrites = 0

    if entry.get("source_text_oversized") is True:
        # The store's SQL gate refused to materialize the raw text; treat it
        # exactly like an oversized raw fragment: dropped, never truncated.
        dropped_fragments += 1
    source_text = entry.get("source_text")
    if isinstance(source_text, str) and source_text.strip():
        redacted, hits = redact_capture_text(source_text)
        redaction_rewrites += int(hits)
        cleaned = " ".join(redacted.split()).strip()
        if cleaned:
            fragments.append(cleaned)

    metadata = entry.get("metadata")
    safe_metadata = metadata if isinstance(metadata, Mapping) else {}
    for field in EMBED_TEXT_WHITELIST:
        raw = entry.get(field) if field == "tag" else safe_metadata.get(field)
        values, malformed = _list_fragments(raw)
        malformed_fragments += malformed
        for candidate in values:
            fragment, hits, oversized = _redact_fragment(candidate)
            if oversized or hits:
                dropped_fragments += 1
                continue
            if not fragment:
                continue
            fragments.append(fragment)

    text = "\n".join(fragments)
    encoded = text.encode("utf-8")
    truncated = False
    if len(encoded) > MEMORA_SHADOW_ENTRY_INPUT_BYTES:
        truncated = True
        encoded = encoded[:MEMORA_SHADOW_ENTRY_INPUT_BYTES]
        text = encoded.decode("utf-8", errors="ignore")
        encoded = text.encode("utf-8")
    return {
        "text": text,
        "byte_length": len(encoded),
        "truncated": truncated,
        "dropped_fragments": dropped_fragments,
        "malformed_fragments": malformed_fragments,
        "redaction_rewrites": redaction_rewrites,
    }


def _finite_vector(raw: Any) -> list[float] | None:
    if raw is None:
        return None
    try:
        vector = [float(value) for value in raw]
    except (TypeError, ValueError):
        return None
    if not vector:
        return None
    if any(not math.isfinite(value) for value in vector):
        return None
    return vector


def _cosine(left: Sequence[float], right: Sequence[float]) -> float | None:
    if len(left) != len(right):
        return None
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm <= 0.0 or right_norm <= 0.0:
        return None
    return dot / (left_norm * right_norm)


def _cue_terms(entry: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Extract (aspect, term) candidates from whitelisted, redaction-safe fields."""

    metadata = entry.get("metadata")
    safe_metadata = metadata if isinstance(metadata, Mapping) else {}
    candidates: list[tuple[str, str]] = []

    def _add(aspect: str, value: Any) -> None:
        fragment, hits, oversized = _redact_fragment(value)
        if oversized or hits or not fragment:
            return
        if _REDACTION_SENTINEL_PREFIX in fragment:
            return
        term = fragment.lower().strip()
        if _CUE_TERM_MIN_CHARS <= len(term) <= _CUE_TERM_MAX_CHARS:
            candidates.append((aspect, term))

    facet_values, _ = _list_fragments(safe_metadata.get("semantic_facets"))
    for facet in facet_values:
        _add("semantic-facet", facet)
    keyword_values, _ = _list_fragments(safe_metadata.get("keywords"))
    for keyword in keyword_values:
        _add("keyword", keyword)
    label_sources = [entry.get("tag"), safe_metadata.get("display_label")]
    for source in label_sources:
        fragment, hits, oversized = _redact_fragment(source)
        if oversized or hits or not fragment:
            continue
        for token in _TOKEN_RE.findall(fragment.lower()):
            if _CUE_TERM_MIN_CHARS <= len(token) <= _CUE_TERM_MAX_CHARS:
                candidates.append(("label-token", token))
    return candidates


_ASPECT_ORDER = {"semantic-facet": 0, "keyword": 1, "label-token": 2}


def _propose_cues(
    cluster_id: str,
    members: Sequence[Mapping[str, Any]],
    max_cues: int,
) -> list[dict[str, Any]]:
    if max_cues <= 0:
        return []
    # Deduplicate at the term level: capture merges harmonic facets into
    # semantic_facets, so the same term routinely arrives as both a
    # semantic-facet and a keyword or label token.  One term yields exactly
    # one cue under its highest-priority aspect, with member support pooled
    # across aspects.
    support: dict[str, set[str]] = {}
    best_aspect: dict[str, str] = {}
    for member in members:
        memory_id = str(member["memory_id"])
        for aspect, term in set(_cue_terms(member["entry"])):
            support.setdefault(term, set()).add(memory_id)
            current = best_aspect.get(term)
            if current is None or (
                _ASPECT_ORDER.get(aspect, 9) < _ASPECT_ORDER.get(current, 9)
            ):
                best_aspect[term] = aspect
    ranked = sorted(
        support.items(),
        key=lambda item: (
            -len(item[1]),
            _ASPECT_ORDER.get(best_aspect[item[0]], 9),
            item[0],
        ),
    )
    cues: list[dict[str, Any]] = []
    for term, member_ids in ranked[:max_cues]:
        aspect = best_aspect[term]
        digest = hashlib.sha256(
            f"{cluster_id}\x1f{aspect}\x1f{term}".encode("utf-8")
        ).hexdigest()
        cues.append(
            {
                "cue_id": f"s2shcue_{digest[:20]}",
                "aspect": aspect,
                "label": term,
                "member_support": len(member_ids),
                "supporting_memory_ids": sorted(member_ids),
                "binding": {"proposal_only": True, "applied": False},
                "trust": "untrusted-memory-evidence",
            }
        )
    return cues


def _round(value: float | None, places: int = 6) -> float | None:
    if value is None:
        return None
    return round(float(value), places)


def build_shadow_plan(
    *,
    context_id: str,
    entries: Sequence[Mapping[str, Any]],
    revision_before: Mapping[str, Any],
    revision_after: Mapping[str, Any],
    provider_info: Mapping[str, Any] | None,
    embed: Callable[[str], Any],
    max_clusters: int = MEMORA_SHADOW_MAX_CLUSTERS,
    max_cues: int = MEMORA_SHADOW_MAX_CUES_PER_CLUSTER,
    similarity_threshold: float = MEMORA_SHADOW_DEFAULT_SIMILARITY_THRESHOLD,
    cursor: Mapping[str, Any] | None = None,
    next_cursor: Mapping[str, Any] | None = None,
    witnesses: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a shadow consolidation plan from an exact one-namespace snapshot.

    ``revision_before``/``revision_after`` are keyset-page snapshots carrying
    the transaction-coupled ``revision`` plus honest totals: ``entry_count``
    is the whole namespace, ``sampled_count`` is what this bounded page read,
    and ``sampling_truncated`` says whether more rows exist beyond it.

    Deterministic for a fixed snapshot + provider: entries are processed in
    the page's stable total order re-sorted to ascending ``memory_id``, all
    floats are rounded, and every collection in the output is sorted.
    Raises :class:`MemoraShadowSnapshotDrift` when the namespace revision
    changed between the two reads, and ``ValueError`` on bound violations.
    """

    before_revision = str(revision_before.get("revision") or "")
    after_revision = str(revision_after.get("revision") or "")
    if not before_revision or before_revision != after_revision:
        raise MemoraShadowSnapshotDrift(
            "memora shadow snapshot changed during bounded read"
        )
    if len(entries) > MEMORA_SHADOW_MAX_ENTRIES:
        raise ValueError("memora shadow entry cap exceeded")
    bounded_clusters = min(max(int(max_clusters), 1), MEMORA_SHADOW_MAX_CLUSTERS)
    bounded_cues = min(max(int(max_cues), 0), MEMORA_SHADOW_MAX_CUES_PER_CLUSTER)
    threshold = float(similarity_threshold)
    if not math.isfinite(threshold):
        raise ValueError("similarity threshold must be finite")
    threshold = round(min(max(threshold, 0.0), 1.0), 4)

    identity = provider_identity(provider_info)
    learned = identity["learned"]

    total_entry_count = int(revision_before.get("entry_count") or 0)
    sampled_count = len(entries)
    sampling_truncated = bool(revision_before.get("sampling_truncated"))

    ordered = sorted(
        (entry for entry in entries if isinstance(entry, Mapping)),
        key=lambda entry: str(entry.get("memory_id") or ""),
    )

    excluded: list[dict[str, str]] = []
    embedded: list[dict[str, Any]] = []
    total_input_bytes = 0
    truncated_count = 0
    dropped_fragments = 0
    malformed_fragments = 0
    redaction_rewrites = 0

    for entry in ordered:
        memory_id = str(entry.get("memory_id") or "")
        if not memory_id:
            excluded.append({"memory_id": "", "reason": "missing-memory-id"})
            continue
        if str(entry.get("context_id") or "") != context_id:
            excluded.append({"memory_id": memory_id, "reason": "namespace-mismatch"})
            continue
        if entry.get("metadata_oversized") is True:
            excluded.append({"memory_id": memory_id, "reason": "metadata-oversized"})
            continue
        if entry.get("metadata_malformed") is True:
            # A row whose stored metadata JSON does not decode to an object is
            # out-of-band evidence, never a clean empty mapping: excluding it
            # keeps malformed rows from contributing cues or witnesses.
            excluded.append({"memory_id": memory_id, "reason": "metadata-malformed"})
            continue
        conflict = entry_provider_conflict(entry, identity)
        if conflict:
            excluded.append({"memory_id": memory_id, "reason": conflict})
            continue
        assembled = build_embeddable_text(entry)
        dropped_fragments += assembled["dropped_fragments"]
        malformed_fragments += assembled["malformed_fragments"]
        redaction_rewrites += assembled["redaction_rewrites"]
        if assembled["truncated"]:
            truncated_count += 1
        if not assembled["text"]:
            excluded.append({"memory_id": memory_id, "reason": "empty-embeddable-text"})
            continue
        if total_input_bytes + assembled["byte_length"] > MEMORA_SHADOW_MAX_INPUT_BYTES:
            excluded.append({"memory_id": memory_id, "reason": "input-byte-budget"})
            continue
        try:
            raw_vector = embed(assembled["text"])
        except Exception as exc:
            excluded.append(
                {
                    "memory_id": memory_id,
                    "reason": f"embedding-error:{type(exc).__name__}",
                }
            )
            continue
        vector = _finite_vector(raw_vector)
        if vector is None:
            excluded.append({"memory_id": memory_id, "reason": "non-finite-embedding"})
            continue
        if all(value == 0.0 for value in vector):
            excluded.append({"memory_id": memory_id, "reason": "zero-vector"})
            continue
        total_input_bytes += assembled["byte_length"]
        embedded.append({"memory_id": memory_id, "entry": entry, "vector": vector})

    # Greedy deterministic leader clustering over ascending memory_id order.
    clusters: list[dict[str, Any]] = []
    unclustered: list[str] = []
    for item in embedded:
        best_index: int | None = None
        best_similarity = -1.0
        for index, cluster in enumerate(clusters):
            similarity = _cosine(item["vector"], cluster["leader_vector"])
            if similarity is None:
                continue
            if similarity > best_similarity:
                best_similarity = similarity
                best_index = index
        if best_index is not None and best_similarity >= threshold:
            clusters[best_index]["members"].append(item)
        elif len(clusters) < bounded_clusters:
            clusters.append({"leader_vector": item["vector"], "members": [item]})
        else:
            unclustered.append(item["memory_id"])

    cluster_payloads: list[dict[str, Any]] = []
    for cluster in clusters:
        members = sorted(cluster["members"], key=lambda member: member["memory_id"])
        member_ids = [member["memory_id"] for member in members]
        cluster_id = "s2shdw_" + hashlib.sha256(
            "\x1f".join(member_ids).encode("utf-8")
        ).hexdigest()[:24]

        pair_similarities: list[float] = []
        affinity = {memory_id: 0.0 for memory_id in member_ids}
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                similarity = _cosine(members[i]["vector"], members[j]["vector"])
                if similarity is None:
                    continue
                pair_similarities.append(similarity)
                affinity[members[i]["memory_id"]] += similarity
                affinity[members[j]["memory_id"]] += similarity
        medoid_id = min(
            member_ids,
            key=lambda memory_id: (-affinity[memory_id], memory_id),
        )
        similarity_stats = {
            "metric": "cosine",
            "pair_count": len(pair_similarities),
            "min": _round(min(pair_similarities)) if pair_similarities else None,
            "mean": _round(sum(pair_similarities) / len(pair_similarities))
            if pair_similarities
            else None,
            "max": _round(max(pair_similarities)) if pair_similarities else None,
        }
        cluster_payloads.append(
            {
                "cluster_id": cluster_id,
                "medoid_memory_id": medoid_id,
                "member_memory_ids": member_ids,
                "source_memory_ids": member_ids,
                "member_count": len(member_ids),
                "similarity": similarity_stats,
                "proposed_cues": _propose_cues(cluster_id, members, bounded_cues),
            }
        )
    cluster_payloads.sort(key=lambda payload: (-payload["member_count"], payload["cluster_id"]))
    for ordinal, payload in enumerate(cluster_payloads):
        payload["cluster_ordinal"] = ordinal

    # Per-source lifecycle witnesses computed in the same read transaction as
    # the page this plan was built from.  They are digest-covered by
    # plan_digest, so a proposal reviewed against this plan is bound to these
    # exact source lifecycles -- a mutation through the store API between
    # planning and proposing changes the digest and fails closed.  Only
    # clustered members are carried; witnesses hold no content, digest, or
    # key material.
    clustered_ids = sorted(
        {
            memory_id
            for payload in cluster_payloads
            for memory_id in payload["source_memory_ids"]
        }
    )
    source_witnesses: dict[str, Any] = {}
    if witnesses is not None:
        for memory_id in clustered_ids:
            witness = witnesses.get(memory_id)
            if isinstance(witness, Mapping):
                source_witnesses[memory_id] = dict(witness)

    warnings: list[dict[str, Any]] = []
    if not learned:
        warnings.append(
            {
                "code": "non-learned-provider",
                "severity": "info",
                "message": (
                    "Non-learned fallback embedding provider active; proposals "
                    "are deterministic hash projections, not learned semantic "
                    "clusters."
                ),
                "action_required": False,
            }
        )
    mismatch_count = sum(
        1 for item in excluded if item["reason"] == "provider-mismatch"
    )
    if mismatch_count:
        warnings.append(
            {
                "code": "provider-mismatch-exclusions",
                "severity": "info",
                "message": (
                    f"{mismatch_count} entr"
                    f"{'y' if mismatch_count == 1 else 'ies'} excluded because "
                    "stored embedding provenance conflicts with the active "
                    "pinned provider."
                ),
                "action_required": False,
            }
        )
    if sampling_truncated:
        warnings.append(
            {
                "code": "namespace-sampling-truncated",
                "severity": "info",
                "message": (
                    f"This plan covers {sampled_count} of {total_entry_count} "
                    "entries in the namespace; continue with next_cursor for "
                    "the remaining rows."
                ),
                "action_required": False,
            }
        )

    payload = {
        "schema": MEMORA_SHADOW_SCHEMA,
        "schema_version": MEMORA_SHADOW_SCHEMA_VERSION,
        "mode": "shadow",
        "applied": False,
        "retrieval_effect": False,
        "raw_input_stored": False,
        "learned": learned,
        "context_id": context_id,
        "planner": {
            "name": MEMORA_SHADOW_PLANNER_NAME,
            "generation_mode": (
                "pretrained-embedding-inference"
                if learned
                else "deterministic-hash-projection-not-learned"
            ),
            "training_effect": "none",
            "promotion": "governed-operator-review-only",
        },
        "namespace": {
            "context_id": context_id,
            "scope": "exact-single-namespace",
            "include_global": False,
            "connected_scope_used": False,
            "total_entry_count": total_entry_count,
            "sampled_count": sampled_count,
            "sampling_truncated": sampling_truncated,
        },
        "snapshot": {
            "revision": before_revision,
            "entry_count": total_entry_count,
            "sampled_count": sampled_count,
            "sampling_truncated": sampling_truncated,
            "drift_checked": True,
        },
        "provider": identity,
        "limits": {
            "max_entries": MEMORA_SHADOW_MAX_ENTRIES,
            "max_input_bytes": MEMORA_SHADOW_MAX_INPUT_BYTES,
            "max_entry_input_bytes": MEMORA_SHADOW_ENTRY_INPUT_BYTES,
            "max_source_text_bytes": MEMORA_SHADOW_MAX_SOURCE_TEXT_BYTES,
            "max_metadata_bytes": MEMORA_SHADOW_MAX_METADATA_BYTES,
            "max_clusters": bounded_clusters,
            "max_cues_per_cluster": bounded_cues,
            "similarity_threshold": threshold,
        },
        "input": {
            "entries_considered": len(ordered),
            "entries_embedded": len(embedded),
            "embedded_input_bytes": total_input_bytes,
            "entry_truncated_count": truncated_count,
            "redaction_dropped_fragments": dropped_fragments,
            "malformed_fragments": malformed_fragments,
            "redaction_rewrites": redaction_rewrites,
            "excluded": sorted(
                excluded, key=lambda item: (item["memory_id"], item["reason"])
            ),
        },
        "clusters": cluster_payloads,
        "source_witnesses": source_witnesses,
        "unclustered_memory_ids": sorted(unclustered),
        "completeness": {
            "complete": not sampling_truncated,
            "namespace_total_entry_count": total_entry_count,
            "sampled_count": sampled_count,
            "sampling_truncated": sampling_truncated,
            "cursor": dict(cursor) if isinstance(cursor, Mapping) else None,
            "next_cursor": (
                dict(next_cursor) if isinstance(next_cursor, Mapping) else None
            ),
        },
        "provenance": {
            "source": "sqlite-memory-store",
            "read_only": True,
            "operation": "memora_shadow_plan",
            "source_revision": before_revision,
            "content_address_basis": "stable-memory-id-sha256",
        },
        "warnings": warnings,
    }
    payload["plan_digest"] = plan_digest(payload)
    return payload

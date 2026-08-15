from __future__ import annotations

import bisect
import math
import os
import stat
import struct
import time
from pathlib import Path
from typing import Any, Iterable

from apple_vision_enrichment import (
    APPLE_VISION_FEATURE_PRINT_REFERENCE_SCHEMA,
    MAX_VISION_SOURCE_BYTES,
    AppleVisionEnricher,
    AppleVisionError,
    AppleVisionUnavailable,
    VisionEnricher,
    privatize_vision_enrichment,
    validate_input_derivative,
    validate_public_vision_enrichment,
)
from core_client_binding import CoreClientBinding, validate_core_client_binding
from image_capture import (
    ImageCaptureNotFound,
    MAX_FEATURE_PRINT_BYTES,
    MAX_OBJECTS,
    MediaObjectReader,
    validate_media_id,
)


MEDIA_SIMILARITY_SCHEMA = "synapse-s2.media-similarity.v1"
DISTANCE_METRIC = "s2-feature-vector-l2-v1"
DEFAULT_RESULT_LIMIT = 10
MAX_RESULT_LIMIT = 50
DEFAULT_CANDIDATE_LIMIT = 128
MAX_CANDIDATE_LIMIT = 512
DEFAULT_TIME_BUDGET_SECONDS = 2.0
MAX_TIME_BUDGET_SECONDS = 10.0
TRANSIENT_QUERY_ACTION = "media-similarity-transient-recall"
TRANSIENT_QUERY_PROVENANCE = "transient-private-query-image"
DEFAULT_TRANSIENT_INPUT_DERIVATIVE = "source-transient-downsampled"
_SCORE_DECIMALS = 9


class MediaSimilarityError(RuntimeError):
    """A content-free failure at the bounded media-similarity boundary."""


class MediaSimilarityIncompatible(MediaSimilarityError):
    """The query feature print cannot be compared on this node."""


class MediaSimilarityNotReferenced(MediaSimilarityError):
    """The query media is not referenced inside the resolved recall scope."""


class MediaSimilarityIntegrityDrift(MediaSimilarityError):
    """An authoritative reference has no valid private cache derivative."""


def _validated_limit(value: Any, *, default: int, maximum: int, field: str) -> int:
    if value is None:
        return default
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{field} must be an integer between 1 and {maximum}")
    return value


def _validated_time_budget(value: Any) -> float:
    if value is None:
        return DEFAULT_TIME_BUDGET_SECONDS
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 < float(value) <= MAX_TIME_BUDGET_SECONDS
    ):
        raise ValueError(
            "time_budget_seconds must be a finite number between 0 and "
            f"{MAX_TIME_BUDGET_SECONDS}"
        )
    return float(value)


def _validated_reference_scope(values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes, dict)):
        raise ValueError("scope_media_ids must be an iterable of media IDs")
    references: set[str] = set()
    for value in values:
        references.add(validate_media_id(value))
        if len(references) > MAX_OBJECTS:
            raise ValueError("scope_media_ids exceeds the safe bound")
    return sorted(references)


def _transient_source_path(value: Path | str) -> Path:
    """Validate a caller-owned private regular query file; never echo the path.

    Private means owner uid AND no group/other permission bits (mode 0o600 or
    stricter), not merely owner-owned. The check is pathname-based, so a
    same-UID process could still swap the file between this check and the
    Vision helper's own re-check; that same-UID pathname TOCTOU is an
    explicitly documented trust boundary of this node-local, owner-only lane.
    """

    source = Path(value)
    if not source.is_absolute() or "\x00" in str(source):
        raise ValueError("transient query source must be a private absolute path")
    try:
        observed = source.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("transient query source is unavailable") from exc
    if (
        stat.S_ISLNK(observed.st_mode)
        or not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) & 0o077
        or observed.st_size <= 0
        or observed.st_size > MAX_VISION_SOURCE_BYTES
    ):
        raise ValueError(
            "transient query source must be an owner-only regular file "
            "within the vision size bound"
        )
    return source


def _reference_from_public(public: dict[str, Any]) -> dict[str, Any] | None:
    feature = public.get("feature_print")
    if (
        not isinstance(feature, dict)
        or feature.get("status") != "ready"
        or feature.get("schema") != APPLE_VISION_FEATURE_PRINT_REFERENCE_SCHEMA
    ):
        return None
    return {
        "provider": str(public["provider"]),
        "schema": str(feature["schema"]),
        "request_revision": int(feature["request_revision"]),
        "element_type": str(feature["element_type"]),
        "element_count": int(feature["element_count"]),
        "byte_count": int(feature["byte_count"]),
        "input_derivative": str(public["input_derivative"]),
    }


def _feature_reference(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """Return the validated public feature-print reference or None."""

    enrichment = manifest.get("public_metadata", {}).get("vision_enrichment")
    if not isinstance(enrichment, dict):
        return None
    try:
        public = validate_public_vision_enrichment(enrichment)
    except (AppleVisionError, ValueError) as exc:
        raise MediaSimilarityError("image cache enrichment contract is invalid") from exc
    return _reference_from_public(public)


_COMPATIBILITY_FIELDS = (
    "provider",
    "schema",
    "request_revision",
    "element_type",
    "element_count",
    "input_derivative",
)


def _compatibility_key(reference: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(reference[field] for field in _COMPATIBILITY_FIELDS)


def _decode_elements(
    data: bytes,
    *,
    element_type: str,
    element_count: int,
) -> tuple[float, ...]:
    width = 4 if element_type == "float32" else 8
    if len(data) != element_count * width or len(data) > MAX_FEATURE_PRINT_BYTES:
        raise MediaSimilarityError("private feature print shape is invalid")
    format_code = f"<{element_count}{'f' if element_type == 'float32' else 'd'}"
    elements = struct.unpack(format_code, data)
    if any(not math.isfinite(element) for element in elements):
        raise MediaSimilarityError("private feature print values are invalid")
    return elements


def _euclidean_distance(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    return math.sqrt(
        math.fsum(
            (a - b) * (a - b)
            for a, b in zip(left, right, strict=True)
        )
    )


class _StreamingTopK:
    """Bounded, deterministic top-k with (distance, media_id) ordering."""

    def __init__(self, k: int) -> None:
        self.k = k
        self._keys: list[tuple[float, str]] = []
        self._items: list[dict[str, Any]] = []

    def offer(self, *, distance: float, media_id: str, item: dict[str, Any]) -> None:
        key = (distance, media_id)
        if len(self._keys) >= self.k and key >= self._keys[-1]:
            return
        index = bisect.bisect_left(self._keys, key)
        self._keys.insert(index, key)
        self._items.insert(index, item)
        if len(self._keys) > self.k:
            self._keys.pop()
            self._items.pop()

    def items(self) -> list[dict[str, Any]]:
        return list(self._items)


def _public_result_item(
    *,
    media_id: str,
    distance: float,
    manifest: dict[str, Any],
    reference: dict[str, Any],
) -> dict[str, Any]:
    public_metadata = manifest["public_metadata"]
    return {
        "media_id": media_id,
        "distance": round(distance, _SCORE_DECIMALS),
        "score": round(1.0 / (1.0 + distance), _SCORE_DECIMALS),
        "artifact_schema": str(manifest["schema"]),
        "mime_type": str(public_metadata["mime_type"]),
        "source_dimensions": dict(public_metadata["source_dimensions"]),
        "thumbnail_dimensions": dict(public_metadata["thumbnail_dimensions"]),
        "thumbnail_available": True,
        "feature_print": {
            field: reference[field] for field in _COMPATIBILITY_FIELDS
        },
        "created_at": float(manifest["created_at"]),
    }


def _ranked_scan(
    reader: MediaObjectReader,
    *,
    scope_ids: list[str],
    exclude_media_id: str | None,
    query_key: tuple[Any, ...],
    query_elements: tuple[float, ...],
    result_limit: int,
    candidate_limit: int,
    deadline: float,
) -> dict[str, Any]:
    """Deterministic bounded candidate scan shared by durable and transient queries."""

    scanned_count = 0
    compatible_count = 0
    incompatible_count = 0
    missing_feature_count = 0
    candidate_truncated = False
    top = _StreamingTopK(result_limit)
    for candidate_id in scope_ids:
        if candidate_id == exclude_media_id:
            continue
        if compatible_count >= candidate_limit:
            candidate_truncated = True
            break
        if time.monotonic() > deadline:
            raise MediaSimilarityError("media similarity time budget exceeded")
        scanned_count += 1
        try:
            manifest, _thumbnail, feature = reader.read_object_with_feature(
                candidate_id
            )
        except ImageCaptureNotFound as exc:
            # A reference the authoritative store still holds must have a valid
            # node-local derivative; a partial ranking would hide the drift.
            raise MediaSimilarityIntegrityDrift(
                "an authoritative media reference has no local cache derivative"
            ) from exc
        reference = _feature_reference(manifest)
        if reference is None or feature is None:
            missing_feature_count += 1
            continue
        if _compatibility_key(reference) != query_key:
            incompatible_count += 1
            continue
        compatible_count += 1
        elements = _decode_elements(
            feature,
            element_type=reference["element_type"],
            element_count=reference["element_count"],
        )
        distance = _euclidean_distance(query_elements, elements)
        top.offer(
            distance=distance,
            media_id=candidate_id,
            item=_public_result_item(
                media_id=candidate_id,
                distance=distance,
                manifest=manifest,
                reference=reference,
            ),
        )
    if time.monotonic() > deadline:
        raise MediaSimilarityError("media similarity time budget exceeded")
    return {
        "results": [
            {"rank": index + 1, **item} for index, item in enumerate(top.items())
        ],
        "scanned_count": scanned_count,
        "compatible_count": compatible_count,
        "incompatible_count": incompatible_count,
        "missing_feature_count": missing_feature_count,
        "candidate_truncated": candidate_truncated,
    }


def _similarity_projection(
    *,
    action: str,
    query: dict[str, Any],
    scan: dict[str, Any],
    scope_reference_count: int,
    result_limit: int,
    candidate_limit: int,
    time_budget_seconds: float,
    elapsed_seconds: float,
) -> dict[str, Any]:
    results = scan["results"]
    return {
        "action": action,
        "schema": MEDIA_SIMILARITY_SCHEMA,
        "distance_metric": DISTANCE_METRIC,
        "query": query,
        "result_count": len(results),
        "results": results,
        "result_limit": result_limit,
        "result_truncated": scan["compatible_count"] > len(results),
        "candidate": {
            "scope_reference_count": scope_reference_count,
            "scanned_count": scan["scanned_count"],
            "compatible_count": scan["compatible_count"],
            "incompatible_count": scan["incompatible_count"],
            "missing_feature_count": scan["missing_feature_count"],
            "candidate_limit": candidate_limit,
            "truncated": scan["candidate_truncated"],
        },
        "confidence": {
            "calibrated": False,
            "signal": "deterministic-feature-print-distance",
            "warning": (
                "Feature-print distance ranks image-to-image similarity on "
                "this node; it is not a truth probability or cross-device "
                "semantic measure."
            ),
        },
        "time_budget_seconds": time_budget_seconds,
        "elapsed_seconds": round(elapsed_seconds, 6),
        "deterministic_tie_break": "distance-then-media-id",
        "feature_print_bytes_returned": False,
        "raw_original_stored": False,
    }


def query_similar_media(
    binding: CoreClientBinding,
    media_id: str,
    *,
    scope_media_ids: Iterable[str],
    result_limit: int | None = None,
    candidate_limit: int | None = None,
    time_budget_seconds: float | None = None,
) -> dict[str, Any]:
    """Bounded, deterministic image-to-image recall over the private cache.

    ``scope_media_ids`` must come from the authoritative scope-filtered
    reference listing (``list_media_references``); the query and every
    candidate are required to be referenced there before any cache access.
    Feature-print bytes are read only from the owner-only node-local media
    cache, compared in process, and never appear in the returned projection.
    Candidates from a different provider, feature-print schema, request
    revision, element type, element count, or input-derivative lane are
    excluded and counted; they are never coerced into the query space.
    """

    try:
        canonical = validate_core_client_binding(binding.to_wire())
    except Exception as exc:
        raise MediaSimilarityError("verified core binding is required") from exc
    canonical_media_id = validate_media_id(media_id)
    scope_ids = _validated_reference_scope(scope_media_ids)
    if canonical_media_id not in scope_ids:
        raise MediaSimilarityNotReferenced(
            "query media is not referenced inside the resolved recall scope"
        )
    canonical_result_limit = _validated_limit(
        result_limit,
        default=DEFAULT_RESULT_LIMIT,
        maximum=MAX_RESULT_LIMIT,
        field="result_limit",
    )
    canonical_candidate_limit = _validated_limit(
        candidate_limit,
        default=DEFAULT_CANDIDATE_LIMIT,
        maximum=MAX_CANDIDATE_LIMIT,
        field="candidate_limit",
    )
    canonical_budget = _validated_time_budget(time_budget_seconds)
    reader = MediaObjectReader(Path(canonical.data_root) / "media-cache")
    started = time.monotonic()
    deadline = started + canonical_budget

    try:
        query_manifest, _query_thumbnail, query_feature = (
            reader.read_object_with_feature(canonical_media_id)
        )
    except ImageCaptureNotFound as exc:
        raise MediaSimilarityIntegrityDrift(
            "an authoritative media reference has no local cache derivative"
        ) from exc
    query_reference = _feature_reference(query_manifest)
    if query_reference is None or query_feature is None:
        raise MediaSimilarityIncompatible(
            "query media has no ready Apple Vision feature print"
        )
    query_key = _compatibility_key(query_reference)
    query_elements = _decode_elements(
        query_feature,
        element_type=query_reference["element_type"],
        element_count=query_reference["element_count"],
    )

    scan = _ranked_scan(
        reader,
        scope_ids=scope_ids,
        exclude_media_id=canonical_media_id,
        query_key=query_key,
        query_elements=query_elements,
        result_limit=canonical_result_limit,
        candidate_limit=canonical_candidate_limit,
        deadline=deadline,
    )
    return _similarity_projection(
        action="media-similarity-recall",
        query={
            "media_id": canonical_media_id,
            **{field: query_reference[field] for field in _COMPATIBILITY_FIELDS},
        },
        scan=scan,
        scope_reference_count=len(scope_ids),
        result_limit=canonical_result_limit,
        candidate_limit=canonical_candidate_limit,
        time_budget_seconds=canonical_budget,
        elapsed_seconds=time.monotonic() - started,
    )


def query_similar_media_transient(
    binding: CoreClientBinding,
    source_path: Path | str,
    *,
    scope_media_ids: Iterable[str],
    result_limit: int | None = None,
    candidate_limit: int | None = None,
    time_budget_seconds: float | None = None,
    vision_enricher: VisionEnricher | None = None,
    vision_input_derivative: str = DEFAULT_TRANSIENT_INPUT_DERIVATIVE,
) -> dict[str, Any]:
    """Bounded one-shot similarity for a private query image that is never stored.

    The query is a caller-owned private regular file (owner uid, no symlink,
    within the Apple Vision size bound). Its feature print is produced only by
    the existing short-lived Vision helper (or an injected enricher for tests),
    privatized and decoded entirely in memory, and compared against the exact
    compatible authoritative cached candidates named by ``scope_media_ids``
    (from ``list_media_references``). Nothing about the query is persisted:
    no media object, manifest, feature vector, OCR, or content digest is
    written, the media-cache inventory is untouched even on failure, and the
    projection carries only a content-free compatibility descriptor plus
    transient provenance — never bytes, paths, or text. The caller may delete
    its private scratch file immediately after the call returns. The Vision
    helper keeps its own existing execution bound; ``time_budget_seconds``
    governs the candidate scan exactly as in :func:`query_similar_media`.
    """

    try:
        canonical = validate_core_client_binding(binding.to_wire())
    except Exception as exc:
        raise MediaSimilarityError("verified core binding is required") from exc
    derivative = validate_input_derivative(vision_input_derivative)
    source = _transient_source_path(source_path)
    scope_ids = _validated_reference_scope(scope_media_ids)
    canonical_result_limit = _validated_limit(
        result_limit,
        default=DEFAULT_RESULT_LIMIT,
        maximum=MAX_RESULT_LIMIT,
        field="result_limit",
    )
    canonical_candidate_limit = _validated_limit(
        candidate_limit,
        default=DEFAULT_CANDIDATE_LIMIT,
        maximum=MAX_CANDIDATE_LIMIT,
        field="candidate_limit",
    )
    canonical_budget = _validated_time_budget(time_budget_seconds)

    try:
        enricher = (
            vision_enricher
            if vision_enricher is not None
            else AppleVisionEnricher(binding).enrich
        )
        raw = enricher(source, "feature-print", derivative)
        public, feature_bytes = privatize_vision_enrichment(raw)
    except AppleVisionUnavailable as exc:
        raise MediaSimilarityError(
            "transient vision helper is unavailable on this node"
        ) from exc
    except (AppleVisionError, ValueError) as exc:
        raise MediaSimilarityError("transient vision enrichment failed") from exc
    query_reference = _reference_from_public(public)
    if query_reference is None or feature_bytes is None:
        raise MediaSimilarityIncompatible(
            "transient query produced no ready Apple Vision feature print"
        )
    if query_reference["input_derivative"] != derivative:
        raise MediaSimilarityError(
            "transient vision enrichment changed the input lane"
        )
    query_elements = _decode_elements(
        feature_bytes,
        element_type=query_reference["element_type"],
        element_count=query_reference["element_count"],
    )

    reader = MediaObjectReader(Path(canonical.data_root) / "media-cache")
    started = time.monotonic()
    deadline = started + canonical_budget
    scan = _ranked_scan(
        reader,
        scope_ids=scope_ids,
        exclude_media_id=None,
        query_key=_compatibility_key(query_reference),
        query_elements=query_elements,
        result_limit=canonical_result_limit,
        candidate_limit=canonical_candidate_limit,
        deadline=deadline,
    )
    projection = _similarity_projection(
        action=TRANSIENT_QUERY_ACTION,
        query={
            "transient": True,
            **{field: query_reference[field] for field in _COMPATIBILITY_FIELDS},
        },
        scan=scan,
        scope_reference_count=len(scope_ids),
        result_limit=canonical_result_limit,
        candidate_limit=canonical_candidate_limit,
        time_budget_seconds=canonical_budget,
        elapsed_seconds=time.monotonic() - started,
    )
    projection["query_provenance"] = {
        "kind": TRANSIENT_QUERY_PROVENANCE,
        "persisted": False,
        "media_cache_written": False,
        "query_media_id_assigned": False,
        "input_derivative": derivative,
    }
    return projection


__all__ = [
    "DEFAULT_CANDIDATE_LIMIT",
    "DEFAULT_RESULT_LIMIT",
    "DEFAULT_TIME_BUDGET_SECONDS",
    "DEFAULT_TRANSIENT_INPUT_DERIVATIVE",
    "DISTANCE_METRIC",
    "MAX_CANDIDATE_LIMIT",
    "MAX_RESULT_LIMIT",
    "MAX_TIME_BUDGET_SECONDS",
    "MEDIA_SIMILARITY_SCHEMA",
    "TRANSIENT_QUERY_ACTION",
    "TRANSIENT_QUERY_PROVENANCE",
    "MediaSimilarityError",
    "MediaSimilarityIncompatible",
    "MediaSimilarityIntegrityDrift",
    "MediaSimilarityNotReferenced",
    "query_similar_media",
    "query_similar_media_transient",
]

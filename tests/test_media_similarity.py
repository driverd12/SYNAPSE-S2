from __future__ import annotations

import base64
import binascii
import json
import sqlite3
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

import media_similarity
from apple_vision_enrichment import AppleVisionError, AppleVisionUnavailable
from core_client_binding import CoreClientBinding
from image_capture import ConversionResult, ImageCaptureCache
from media_similarity import (
    MediaSimilarityError,
    MediaSimilarityIncompatible,
    MediaSimilarityNotReferenced,
    query_similar_media,
    query_similar_media_transient,
)
from memory_store import media_references_from_connection


def _png_bytes(width: int = 32, height: int = 16, *, seed: int = 0) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
        )

    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            rows.extend(
                (
                    (x * 7 + seed) % 256,
                    (y * 13 + seed) % 256,
                    ((x + y) * 11 + seed) % 256,
                )
            )
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


def _bmp_bytes(width: int = 32, height: int = 16) -> bytes:
    row_stride = ((width * 24 + 31) // 32) * 4
    pixel_bytes = bytearray()
    for source_y in range(height - 1, -1, -1):
        row = bytearray()
        for x in range(width):
            row.extend(((x * 3) % 256, (source_y * 5) % 256, ((x + source_y) * 7) % 256))
        row.extend(b"\x00" * (row_stride - len(row)))
        pixel_bytes.extend(row)
    pixel_offset = 14 + 40
    return (
        b"BM"
        + struct.pack("<IHHI", pixel_offset + len(pixel_bytes), 0, 0, pixel_offset)
        + struct.pack(
            "<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixel_bytes), 2835, 2835, 0, 0
        )
        + bytes(pixel_bytes)
    )


def _fake_converter(source: Path, work_root: Path) -> ConversionResult:
    del source
    bmp_path = work_root / "normalized.bmp"
    thumbnail_path = work_root / "thumbnail.jpg"
    bmp_path.write_bytes(_bmp_bytes())
    thumbnail_path.write_bytes(b"\xff\xd8\xff\xe0deterministic-thumbnail\xff\xd9")
    bmp_path.chmod(0o600)
    thumbnail_path.chmod(0o600)
    return ConversionResult(
        source_width=32,
        source_height=16,
        bmp_path=bmp_path,
        thumbnail_path=thumbnail_path,
    )


def _vision_payload(
    mode: str,
    derivative: str,
    *,
    elements: tuple[float, ...],
    element_type: str = "float32",
    request_revision: int = 2,
) -> dict:
    width = {"float32": "f", "float64": "d"}[element_type]
    feature_data = struct.pack(f"<{len(elements)}{width}", *elements)
    return {
        "schema": "synapse-s2.apple-vision-enrichment.v1",
        "provider": "apple-vision",
        "mode": mode,
        "status": "ready",
        "input_derivative": derivative,
        "input_dimensions": {"width": 32, "height": 16},
        "feature_print": {
            "status": "ready",
            "schema": "synapse-s2.apple-vision-feature-print.v1",
            "request_revision": request_revision,
            "element_type": element_type,
            "element_count": len(elements),
            "encoding": "base64-little-endian",
            "data": base64.b64encode(feature_data).decode("ascii"),
        },
    }


class _MediaSimilarityFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary_parent = Path("/private/tmp")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="s2-media-similarity-",
            dir=str(temporary_parent) if temporary_parent.is_dir() else None,
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo_root = self.root / "repo"
        self.data_root = self.repo_root / ".synapse_s2"
        core_root = self.data_root / "core"
        core_root.mkdir(parents=True, mode=0o700)
        self.data_root.chmod(0o700)
        self.binding = CoreClientBinding(
            repo_root=self.repo_root,
            data_root=self.data_root,
            config_path=core_root / "service.json",
            socket_path=core_root / "service.sock",
            state_path=self.data_root / "runtime_state.json",
            memory_path=self.data_root / "memory.sqlite3",
            capture_root=self.data_root,
            export_root=self.data_root / "exports",
            backup_root=self.data_root / "backups",
            recovery_root=self.data_root / "recovery",
            replication_inbox_root=self.data_root / "replication" / "inbox",
            core_label="media-similarity-test-core",
            config_digest="a" * 64,
            config_fingerprint="b" * 64,
            embedding_space_identity="c" * 64,
            layout="canonical",
            authority_mode="authoritative-core-v6",
        )
        self.sources: dict[str, Path] = {}

    def _capture(
        self,
        media_id: str,
        *,
        elements: tuple[float, ...] | None,
        element_type: str = "float32",
        request_revision: int = 2,
        derivative: str = "source-transient-downsampled",
        seed: int | None = None,
    ) -> None:
        source = self.root / f"source-{media_id}.png"
        source.write_bytes(
            _png_bytes(seed=seed if seed is not None else len(self.sources))
        )
        source.chmod(0o600)
        self.sources[media_id] = source
        if elements is None:
            cache = ImageCaptureCache(self.binding, converter=_fake_converter)
            cache.capture_image(source, media_id=media_id)
            return

        def enricher(_source: Path, mode: str, input_derivative: str) -> dict:
            del input_derivative
            return _vision_payload(
                mode,
                derivative,
                elements=elements,
                element_type=element_type,
                request_revision=request_revision,
            )

        cache = ImageCaptureCache(
            self.binding,
            converter=_fake_converter,
            vision_enricher=enricher,
        )
        cache.capture_image(
            source,
            media_id=media_id,
            vision_mode="feature-print",
            vision_required=True,
            vision_input_derivative=derivative,
        )

    def _media_inventory(self) -> list[tuple[str, int]]:
        root = self.data_root / "media-cache"
        if not root.is_dir():
            return []
        return sorted(
            (str(item.relative_to(root)), item.stat().st_size)
            for item in root.rglob("*")
            if item.is_file()
        )

    def _transient_source(
        self, name: str = "transient-query.png", mode: int = 0o600
    ) -> Path:
        path = self.root / name
        path.write_bytes(_png_bytes(seed=99))
        path.chmod(mode)
        return path

    def _transient_enricher(
        self,
        elements: tuple[float, ...],
        *,
        derivative_override: str | None = None,
        calls: list[tuple[Path, str, str]] | None = None,
    ):
        def enricher(source: Path, mode: str, input_derivative: str) -> dict:
            if calls is not None:
                calls.append((Path(source), mode, input_derivative))
            return _vision_payload(
                mode,
                derivative_override or input_derivative,
                elements=elements,
            )

        return enricher


class MediaSimilarityTests(_MediaSimilarityFixture):
    def test_ranks_by_distance_with_stable_media_id_tie_break(self) -> None:
        query_id = "s2img_" + "0" * 32
        near_id = "s2img_" + "1" * 32
        tie_high = "s2img_" + "9" * 32
        tie_low = "s2img_" + "2" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))
        self._capture(near_id, elements=(0.1, 0.0, 0.0, 0.0))
        # Both tie candidates are exactly distance 1.0 from the query.
        self._capture(tie_high, elements=(0.0, 1.0, 0.0, 0.0))
        self._capture(tie_low, elements=(1.0, 0.0, 0.0, 0.0))

        scope = [query_id, near_id, tie_high, tie_low]
        first = query_similar_media(self.binding, query_id, scope_media_ids=scope)
        second = query_similar_media(self.binding, query_id, scope_media_ids=scope)

        self.assertEqual([item["media_id"] for item in first["results"]], [near_id, tie_low, tie_high])
        self.assertEqual([item["rank"] for item in first["results"]], [1, 2, 3])
        self.assertEqual(first["results"][1]["distance"], first["results"][2]["distance"])
        self.assertGreater(first["results"][0]["score"], first["results"][1]["score"])
        self.assertEqual(first["candidate"]["compatible_count"], 3)
        self.assertEqual(first["candidate"]["incompatible_count"], 0)
        self.assertFalse(first["result_truncated"])
        stable_fields = {
            key: value
            for key, value in first.items()
            if key != "elapsed_seconds"
        }
        stable_again = {
            key: value
            for key, value in second.items()
            if key != "elapsed_seconds"
        }
        self.assertEqual(stable_fields, stable_again)

    def test_query_must_be_referenced_in_scope_before_cache_access(self) -> None:
        query_id = "s2img_" + "0" * 32
        other_id = "s2img_" + "1" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))
        self._capture(other_id, elements=(1.0, 0.0, 0.0, 0.0))

        with self.assertRaises(MediaSimilarityNotReferenced):
            query_similar_media(
                self.binding,
                query_id,
                scope_media_ids=[other_id],
            )

    def test_unreferenced_cache_objects_are_never_candidates(self) -> None:
        query_id = "s2img_" + "0" * 32
        referenced = "s2img_" + "1" * 32
        orphan = "s2img_" + "2" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))
        self._capture(referenced, elements=(0.5, 0.0, 0.0, 0.0))
        self._capture(orphan, elements=(0.0, 0.0, 0.0, 0.0))

        result = query_similar_media(
            self.binding,
            query_id,
            scope_media_ids=[query_id, referenced],
        )

        media_ids = [item["media_id"] for item in result["results"]]
        self.assertEqual(media_ids, [referenced])
        self.assertEqual(result["candidate"]["scanned_count"], 1)

    def test_incompatible_prints_are_excluded_never_coerced(self) -> None:
        query_id = "s2img_" + "0" * 32
        compatible = "s2img_" + "1" * 32
        other_revision = "s2img_" + "2" * 32
        other_type = "s2img_" + "3" * 32
        other_count = "s2img_" + "4" * 32
        other_derivative = "s2img_" + "5" * 32
        no_feature = "s2img_" + "6" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))
        self._capture(compatible, elements=(0.5, 0.0, 0.0, 0.0))
        self._capture(other_revision, elements=(0.0, 0.0, 0.0, 0.0), request_revision=1)
        self._capture(other_type, elements=(0.0, 0.0, 0.0, 0.0), element_type="float64")
        self._capture(other_count, elements=(0.0, 0.0, 0.0))
        self._capture(
            other_derivative,
            elements=(0.0, 0.0, 0.0, 0.0),
            derivative="thumbnail-transient-downsampled",
        )
        self._capture(no_feature, elements=None)

        scope = [
            query_id,
            compatible,
            other_revision,
            other_type,
            other_count,
            other_derivative,
            no_feature,
        ]
        result = query_similar_media(self.binding, query_id, scope_media_ids=scope)

        self.assertEqual(
            [item["media_id"] for item in result["results"]], [compatible]
        )
        self.assertEqual(result["candidate"]["compatible_count"], 1)
        self.assertEqual(result["candidate"]["incompatible_count"], 4)
        self.assertEqual(result["candidate"]["missing_feature_count"], 1)

    def test_query_without_feature_print_fails_closed(self) -> None:
        query_id = "s2img_" + "0" * 32
        self._capture(query_id, elements=None)

        with self.assertRaises(MediaSimilarityIncompatible):
            query_similar_media(
                self.binding,
                query_id,
                scope_media_ids=[query_id],
            )

    def test_result_and_candidate_bounds_stream_top_k(self) -> None:
        query_id = "s2img_" + "0" * 32
        first = "s2img_" + "1" * 32
        second = "s2img_" + "2" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))
        self._capture(first, elements=(0.5, 0.0, 0.0, 0.0))
        self._capture(second, elements=(1.5, 0.0, 0.0, 0.0))

        result = query_similar_media(
            self.binding,
            query_id,
            scope_media_ids=[query_id, first, second],
            result_limit=1,
            candidate_limit=1,
        )

        self.assertEqual([item["media_id"] for item in result["results"]], [first])
        self.assertTrue(result["candidate"]["truncated"])

        unbounded = query_similar_media(
            self.binding,
            query_id,
            scope_media_ids=[query_id, first, second],
            result_limit=1,
        )
        self.assertTrue(unbounded["result_truncated"])
        self.assertEqual(unbounded["result_count"], 1)
        self.assertEqual(unbounded["distance_metric"], "s2-feature-vector-l2-v1")

    def test_reference_without_cache_derivative_is_integrity_drift(self) -> None:
        query_id = "s2img_" + "0" * 32
        missing = "s2img_" + "3" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))

        with self.assertRaises(media_similarity.MediaSimilarityIntegrityDrift):
            query_similar_media(
                self.binding,
                query_id,
                scope_media_ids=[query_id, missing],
            )
        with self.assertRaises(media_similarity.MediaSimilarityIntegrityDrift):
            query_similar_media(
                self.binding,
                missing,
                scope_media_ids=[query_id, missing],
            )

    def test_time_budget_fails_closed(self) -> None:
        query_id = "s2img_" + "0" * 32
        candidate = "s2img_" + "1" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))
        self._capture(candidate, elements=(1.0, 0.0, 0.0, 0.0))

        with self.assertRaises(MediaSimilarityError):
            query_similar_media(
                self.binding,
                query_id,
                scope_media_ids=[query_id, candidate],
                time_budget_seconds=1e-9,
            )

    def test_limit_validation_rejects_out_of_bounds_requests(self) -> None:
        query_id = "s2img_" + "0" * 32
        self._capture(query_id, elements=(0.0, 0.0, 0.0, 0.0))
        scope = [query_id]
        for arguments in (
            {"result_limit": 0},
            {"result_limit": media_similarity.MAX_RESULT_LIMIT + 1},
            {"candidate_limit": 0},
            {"candidate_limit": media_similarity.MAX_CANDIDATE_LIMIT + 1},
            {"time_budget_seconds": 0.0},
            {"time_budget_seconds": media_similarity.MAX_TIME_BUDGET_SECONDS + 1.0},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    query_similar_media(
                        self.binding,
                        query_id,
                        scope_media_ids=scope,
                        **arguments,
                    )
        with self.assertRaises(ValueError):
            query_similar_media(
                self.binding,
                "not-a-media-id",
                scope_media_ids=scope,
            )

    def test_projection_is_content_free(self) -> None:
        query_id = "s2img_" + "0" * 32
        candidate = "s2img_" + "1" * 32
        elements = (0.25, 0.5, 0.75, 1.0)
        self._capture(query_id, elements=elements)
        self._capture(candidate, elements=(0.25, 0.5, 0.75, 0.5))

        result = query_similar_media(
            self.binding,
            query_id,
            scope_media_ids=[query_id, candidate],
        )

        rendered = json.dumps(result, sort_keys=True)
        self.assertFalse(result["feature_print_bytes_returned"])
        self.assertFalse(result["confidence"]["calibrated"])
        feature_data = struct.pack("<4f", *elements)
        self.assertNotIn(base64.b64encode(feature_data).decode("ascii"), rendered)
        self.assertNotIn("sha256", rendered.lower())
        self.assertNotIn("tensor_data", rendered)
        self.assertNotIn("ocr", rendered.lower())
        for source in self.sources.values():
            self.assertNotIn(str(source), rendered)


class MediaSimilarityTransientQueryTests(_MediaSimilarityFixture):
    """The transient lane never persists, never leaks, and stays bounded."""

    def test_transient_query_ranks_compatible_candidates_with_stable_ties(self) -> None:
        near = "s2img_" + "1" * 32
        tie_high = "s2img_" + "9" * 32
        tie_low = "s2img_" + "2" * 32
        other_lane = "s2img_" + "5" * 32
        no_feature = "s2img_" + "6" * 32
        self._capture(near, elements=(0.1, 0.0, 0.0, 0.0))
        self._capture(tie_high, elements=(0.0, 1.0, 0.0, 0.0))
        self._capture(tie_low, elements=(1.0, 0.0, 0.0, 0.0))
        self._capture(
            other_lane,
            elements=(0.0, 0.0, 0.0, 0.0),
            derivative="thumbnail-transient-downsampled",
        )
        self._capture(no_feature, elements=None)
        scope = [near, tie_high, tie_low, other_lane, no_feature]
        source = self._transient_source()
        calls: list[tuple[Path, str, str]] = []
        enricher = self._transient_enricher(
            (0.0, 0.0, 0.0, 0.0), calls=calls
        )

        first = query_similar_media_transient(
            self.binding,
            source,
            scope_media_ids=scope,
            vision_enricher=enricher,
        )
        second = query_similar_media_transient(
            self.binding,
            source,
            scope_media_ids=scope,
            vision_enricher=enricher,
        )

        self.assertEqual(
            [item["media_id"] for item in first["results"]],
            [near, tie_low, tie_high],
        )
        self.assertEqual([item["rank"] for item in first["results"]], [1, 2, 3])
        self.assertEqual(
            first["results"][1]["distance"], first["results"][2]["distance"]
        )
        self.assertEqual(first["action"], "media-similarity-transient-recall")
        self.assertEqual(first["candidate"]["compatible_count"], 3)
        self.assertEqual(first["candidate"]["incompatible_count"], 1)
        self.assertEqual(first["candidate"]["missing_feature_count"], 1)
        self.assertTrue(first["query"]["transient"])
        self.assertNotIn("media_id", first["query"])
        provenance = first["query_provenance"]
        self.assertEqual(provenance["kind"], "transient-private-query-image")
        self.assertFalse(provenance["persisted"])
        self.assertFalse(provenance["media_cache_written"])
        self.assertFalse(provenance["query_media_id_assigned"])
        self.assertEqual(
            provenance["input_derivative"], "source-transient-downsampled"
        )
        self.assertEqual(
            calls[0], (source, "feature-print", "source-transient-downsampled")
        )
        stable_first = {k: v for k, v in first.items() if k != "elapsed_seconds"}
        stable_second = {k: v for k, v in second.items() if k != "elapsed_seconds"}
        self.assertEqual(stable_first, stable_second)

    def test_transient_scope_isolation_excludes_unreferenced_cache_objects(self) -> None:
        referenced = "s2img_" + "1" * 32
        orphan = "s2img_" + "2" * 32
        self._capture(referenced, elements=(0.5, 0.0, 0.0, 0.0))
        self._capture(orphan, elements=(0.0, 0.0, 0.0, 0.0))

        result = query_similar_media_transient(
            self.binding,
            self._transient_source(),
            scope_media_ids=[referenced],
            vision_enricher=self._transient_enricher((0.0, 0.0, 0.0, 0.0)),
        )

        self.assertEqual(
            [item["media_id"] for item in result["results"]], [referenced]
        )
        self.assertEqual(result["candidate"]["scanned_count"], 1)
        self.assertNotIn(orphan, json.dumps(result, sort_keys=True))

    def test_transient_projection_leaks_no_bytes_paths_or_text(self) -> None:
        candidate = "s2img_" + "1" * 32
        candidate_elements = (0.25, 0.5, 0.75, 0.5)
        query_elements = (0.25, 0.5, 0.75, 1.0)
        self._capture(candidate, elements=candidate_elements)
        source = self._transient_source()

        result = query_similar_media_transient(
            self.binding,
            source,
            scope_media_ids=[candidate],
            vision_enricher=self._transient_enricher(query_elements),
        )

        rendered = json.dumps(result, sort_keys=True)
        self.assertFalse(result["feature_print_bytes_returned"])
        self.assertFalse(result["raw_original_stored"])
        self.assertFalse(result["confidence"]["calibrated"])
        for elements in (query_elements, candidate_elements):
            encoded = base64.b64encode(struct.pack("<4f", *elements)).decode("ascii")
            self.assertNotIn(encoded, rendered)
        self.assertNotIn(str(source), rendered)
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn("sha256", rendered.lower())
        self.assertNotIn("ocr", rendered.lower())
        self.assertNotIn("tensor_data", rendered)
        for stored in self.sources.values():
            self.assertNotIn(str(stored), rendered)

    def test_transient_query_never_changes_media_cache_inventory(self) -> None:
        candidate = "s2img_" + "1" * 32
        missing = "s2img_" + "3" * 32
        self._capture(candidate, elements=(0.5, 0.0, 0.0, 0.0))
        source = self._transient_source()
        before = self._media_inventory()
        self.assertTrue(before)

        query_similar_media_transient(
            self.binding,
            source,
            scope_media_ids=[candidate],
            vision_enricher=self._transient_enricher((0.0, 0.0, 0.0, 0.0)),
        )
        self.assertEqual(self._media_inventory(), before)

        def unavailable(_source: Path, _mode: str, _derivative: str) -> dict:
            raise AppleVisionUnavailable("vision helper is unavailable")

        with self.assertRaises(MediaSimilarityError):
            query_similar_media_transient(
                self.binding,
                source,
                scope_media_ids=[candidate],
                vision_enricher=unavailable,
            )
        self.assertEqual(self._media_inventory(), before)

        with self.assertRaises(media_similarity.MediaSimilarityIntegrityDrift):
            query_similar_media_transient(
                self.binding,
                source,
                scope_media_ids=[candidate, missing],
                vision_enricher=self._transient_enricher((0.0, 0.0, 0.0, 0.0)),
            )
        self.assertEqual(self._media_inventory(), before)
        # The caller owns its scratch and may delete it immediately.
        source.unlink()
        self.assertEqual(self._media_inventory(), before)

    def test_helper_unavailable_and_timeout_map_to_content_free_errors(self) -> None:
        candidate = "s2img_" + "1" * 32
        self._capture(candidate, elements=(0.5, 0.0, 0.0, 0.0))
        source = self._transient_source()

        def unavailable(_source: Path, _mode: str, _derivative: str) -> dict:
            raise AppleVisionUnavailable("vision helper is unavailable")

        def timed_out(_source: Path, _mode: str, _derivative: str) -> dict:
            # AppleVisionEnricher.enrich maps subprocess timeouts to this error.
            raise AppleVisionError("Apple Vision enrichment failed")

        with self.assertRaises(MediaSimilarityError) as unavailable_error:
            query_similar_media_transient(
                self.binding,
                source,
                scope_media_ids=[candidate],
                vision_enricher=unavailable,
            )
        with self.assertRaises(MediaSimilarityError) as timeout_error:
            query_similar_media_transient(
                self.binding,
                source,
                scope_media_ids=[candidate],
                vision_enricher=timed_out,
            )

        self.assertEqual(
            str(unavailable_error.exception),
            "transient vision helper is unavailable on this node",
        )
        self.assertEqual(
            str(timeout_error.exception), "transient vision enrichment failed"
        )
        for message in (
            str(unavailable_error.exception),
            str(timeout_error.exception),
        ):
            self.assertNotIn(str(source), message)
            self.assertNotIn(str(self.root), message)

    def test_transient_enricher_lane_drift_fails_closed(self) -> None:
        candidate = "s2img_" + "1" * 32
        self._capture(candidate, elements=(0.5, 0.0, 0.0, 0.0))

        with self.assertRaises(MediaSimilarityError) as error:
            query_similar_media_transient(
                self.binding,
                self._transient_source(),
                scope_media_ids=[candidate],
                vision_enricher=self._transient_enricher(
                    (0.0, 0.0, 0.0, 0.0),
                    derivative_override="thumbnail-transient-downsampled",
                ),
            )
        self.assertIn("input lane", str(error.exception))

    def test_transient_time_budget_fails_closed(self) -> None:
        candidate = "s2img_" + "1" * 32
        self._capture(candidate, elements=(0.5, 0.0, 0.0, 0.0))

        with self.assertRaises(MediaSimilarityError):
            query_similar_media_transient(
                self.binding,
                self._transient_source(),
                scope_media_ids=[candidate],
                vision_enricher=self._transient_enricher((0.0, 0.0, 0.0, 0.0)),
                time_budget_seconds=1e-9,
            )

    def test_transient_bounds_and_source_validation(self) -> None:
        candidate = "s2img_" + "1" * 32
        self._capture(candidate, elements=(0.5, 0.0, 0.0, 0.0))
        source = self._transient_source()

        def never_called(_source: Path, _mode: str, _derivative: str) -> dict:
            raise AssertionError("validation must reject before enrichment")

        for arguments in (
            {"result_limit": 0},
            {"result_limit": media_similarity.MAX_RESULT_LIMIT + 1},
            {"candidate_limit": 0},
            {"candidate_limit": media_similarity.MAX_CANDIDATE_LIMIT + 1},
            {"time_budget_seconds": 0.0},
            {"time_budget_seconds": media_similarity.MAX_TIME_BUDGET_SECONDS + 1.0},
            {"vision_input_derivative": "raw-original"},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    query_similar_media_transient(
                        self.binding,
                        source,
                        scope_media_ids=[candidate],
                        vision_enricher=never_called,
                        **arguments,
                    )

        group_readable = self._transient_source(name="group-readable.png", mode=0o644)
        symlink = self.root / "query-link.png"
        symlink.symlink_to(source)
        for bad_source in (
            Path("relative/query.png"),
            self.root / "missing.png",
            symlink,
            group_readable,
        ):
            with self.subTest(bad_source=str(bad_source)):
                with self.assertRaises(ValueError):
                    query_similar_media_transient(
                        self.binding,
                        bad_source,
                        scope_media_ids=[candidate],
                        vision_enricher=never_called,
                    )


class MediaSimilarityMcpToolTests(unittest.TestCase):
    """MCP parity surface: same scope gate, bounds, and zero byte exposure."""

    def setUp(self) -> None:
        import mlx_backend

        temporary_parent = Path("/private/tmp")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="s2-media-similarity-mcp-",
            dir=str(temporary_parent) if temporary_parent.is_dir() else None,
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo_root = self.root / "repo"
        self.data_root = self.repo_root / ".synapse_s2"
        core_root = self.data_root / "core"
        core_root.mkdir(parents=True, mode=0o700)
        self.data_root.chmod(0o700)
        self.binding = CoreClientBinding(
            repo_root=self.repo_root,
            data_root=self.data_root,
            config_path=core_root / "service.json",
            socket_path=core_root / "service.sock",
            state_path=self.data_root / "runtime_state.json",
            memory_path=self.data_root / "memory.sqlite3",
            capture_root=self.data_root,
            export_root=self.data_root / "exports",
            backup_root=self.data_root / "backups",
            recovery_root=self.data_root / "recovery",
            replication_inbox_root=self.data_root / "replication" / "inbox",
            core_label="media-similarity-mcp-test-core",
            config_digest="a" * 64,
            config_fingerprint="b" * 64,
            embedding_space_identity="c" * 64,
            layout="canonical",
            authority_mode="authoritative-core-v6",
        )
        self.backend = mlx_backend.SpikingAttentionBackend(
            dimension=6,
            num_neurons=10,
            default_top_k=2,
            recall_count=3,
            compile_graph=False,
            state_path=self.root / "state.json",
            memory_path=self.root / "memory.sqlite3",
        )
        mlx_backend._ENGINE_INSTANCE = self.backend
        mlx_backend._CONTROL_PLANE_INSTANCE = self.backend
        self.addCleanup(lambda: setattr(mlx_backend, "_ENGINE_INSTANCE", None))
        self.addCleanup(
            lambda: setattr(mlx_backend, "_CONTROL_PLANE_INSTANCE", None)
        )

    def _reference(self, media_id: str, index: int) -> None:
        self.backend.memory_store.upsert_entry(
            tag=f"mcp-image-memory-{index}",
            context_id="default",
            source_text=f"MCP image memory fixture {index}",
            metadata={"context_memory_type": "image", "media_id": media_id},
            embedding_dimensions=6,
            spike_indices=[1],
            neuron_indices=[2],
            registered_at=100.0 + index,
        )

    def _capture(self, media_id: str, elements: tuple[float, ...]) -> None:
        source = self.root / f"source-{media_id}.png"
        source.write_bytes(_png_bytes(seed=int(media_id[6:8], 16)))
        source.chmod(0o600)

        def enricher(_source: Path, mode: str, derivative: str) -> dict:
            return _vision_payload(mode, derivative, elements=elements)

        ImageCaptureCache(
            self.binding,
            converter=_fake_converter,
            vision_enricher=enricher,
        ).capture_image(
            source,
            media_id=media_id,
            vision_mode="feature-print",
            vision_required=True,
        )

    @staticmethod
    def _payload(response) -> dict:
        if isinstance(response, dict):
            return response
        structured = getattr(response, "structured_content", None)
        assert isinstance(structured, dict)
        return structured

    def test_mcp_tool_ranks_with_contract_and_zero_byte_exposure(self) -> None:
        from unittest import mock

        import mcp_server

        query_id = "s2img_" + "0" * 32
        near_id = "s2img_" + "1" * 32
        far_id = "s2img_" + "2" * 32
        orphan_id = "s2img_" + "3" * 32
        elements = {
            query_id: (0.0, 0.0, 0.0, 0.0),
            near_id: (0.5, 0.0, 0.0, 0.0),
            far_id: (2.0, 0.0, 0.0, 0.0),
            orphan_id: (0.0, 0.0, 0.0, 0.0),
        }
        for index, media_id in enumerate((query_id, near_id, far_id)):
            self._reference(media_id, index)
        for media_id, vector in elements.items():
            self._capture(media_id, vector)

        with mock.patch(
            "core_client_binding.binding_from_environment",
            return_value=self.binding,
        ):
            payload = self._payload(
                mcp_server.query_spiking_media_similarity(media_id=query_id)
            )

        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["operation"], "media-similarity")
        self.assertEqual(payload["schema"], "synapse-s2.token-contract.v1")
        data = payload["data"]
        self.assertEqual(
            [item["media_id"] for item in data["results"]], [near_id, far_id]
        )
        self.assertEqual(data["distance_metric"], "s2-feature-vector-l2-v1")
        self.assertFalse(data["feature_print_bytes_returned"])
        self.assertFalse(data["confidence"]["calibrated"])
        rendered = json.dumps(payload, sort_keys=True)
        for vector in elements.values():
            encoded = base64.b64encode(struct.pack("<4f", *vector)).decode("ascii")
            self.assertNotIn(encoded, rendered)
        self.assertNotIn(orphan_id, rendered)
        self.assertNotIn("tensor_data", rendered)

    def test_mcp_tool_fails_closed_without_reference_or_binding(self) -> None:
        from unittest import mock

        import mcp_server

        query_id = "s2img_" + "0" * 32
        self._capture(query_id, (0.0, 0.0, 0.0, 0.0))

        with mock.patch(
            "core_client_binding.binding_from_environment",
            return_value=self.binding,
        ):
            unreferenced = self._payload(
                mcp_server.query_spiking_media_similarity(media_id=query_id)
            )
        self.assertFalse(unreferenced["ok"])
        self.assertEqual(unreferenced["operation"], "media-similarity")

        with mock.patch(
            "core_client_binding.binding_from_environment",
            return_value=None,
        ):
            unbound = self._payload(
                mcp_server.query_spiking_media_similarity(media_id=query_id)
            )
        self.assertFalse(unbound["ok"])
        self.assertIn(
            "core binding", unbound["data"]["error"]["message"]
        )


class MediaSimilarityCompactProjectionTests(unittest.TestCase):
    """The compact projection must never claim completeness it removed."""

    @staticmethod
    def _payload(result_count: int, result_limit: int) -> dict:
        feature = {
            "provider": "apple-vision",
            "schema": "vision-feature-print.v1",
            "request_revision": 1,
            "element_type": "float32",
            "element_count": 4,
            "input_derivative": "thumbnail",
        }
        results = [
            {
                "rank": index + 1,
                "media_id": "s2img_" + f"{index:032x}",
                "distance": round(0.1 * index, 6),
                "score": round(1.0 / (1.0 + 0.1 * index), 6),
                "artifact_schema": "synapse-s2.media-object.v1",
                "mime_type": "image/png",
                "source_dimensions": {"width": 8, "height": 8},
                "thumbnail_dimensions": {"width": 4, "height": 4},
                "thumbnail_available": True,
                "feature_print": dict(feature),
            }
            for index in range(result_count)
        ]
        return {
            "action": "media-similarity-recall",
            "schema": "synapse-s2.media-similarity.v1",
            "distance_metric": "s2-feature-vector-l2-v1",
            "query": {"media_id": "s2img_" + "f" * 32, **feature},
            "result_count": result_count,
            "results": results,
            "result_limit": result_limit,
            "result_truncated": False,
            "candidate": {
                "scope_reference_count": result_count + 1,
                "scanned_count": result_count,
                "compatible_count": result_count,
                "incompatible_count": 0,
                "missing_feature_count": 0,
                "candidate_limit": 128,
                "truncated": False,
            },
            "confidence": {
                "calibrated": False,
                "signal": "deterministic-feature-print-distance",
                "warning": "Deterministic node-local ranking only.",
            },
            "time_budget_seconds": 2.0,
            "elapsed_seconds": 0.01,
            "deterministic_tie_break": "distance-then-media-id",
            "feature_print_bytes_returned": False,
            "raw_original_stored": False,
        }

    def test_eleven_results_cannot_claim_complete(self) -> None:
        from token_contracts import COMPACT_SOURCE_LIMITS, project_media_similarity

        cap = COMPACT_SOURCE_LIMITS["media-similarity"]
        projected = project_media_similarity(self._payload(cap + 1, cap + 5))
        pagination = projected["pagination"]
        completeness = projected["completeness"]
        self.assertEqual(len(projected["data"]["results"]), cap)
        self.assertEqual(pagination["returned"], cap)
        self.assertEqual(pagination["requested_limit"], cap + 5)
        self.assertEqual(pagination["effective_limit"], cap)
        self.assertTrue(pagination["has_more"])
        self.assertFalse(completeness["complete"])
        self.assertTrue(completeness["result_set_truncated"])
        self.assertEqual(completeness["reason"], "bounded-result-set-has-more")
        self.assertTrue(projected["data"]["result_truncated"])
        self.assertTrue(projected["response_contract"]["truncated"])
        self.assertEqual(
            projected["response_contract"]["omissions"].get(
                "media_similarity_results"
            ),
            1,
        )

    def test_bounded_results_stay_complete(self) -> None:
        from token_contracts import COMPACT_SOURCE_LIMITS, project_media_similarity

        cap = COMPACT_SOURCE_LIMITS["media-similarity"]
        projected = project_media_similarity(self._payload(cap, cap))
        self.assertEqual(len(projected["data"]["results"]), cap)
        self.assertEqual(projected["pagination"]["effective_limit"], cap)
        self.assertFalse(projected["pagination"]["has_more"])
        self.assertTrue(projected["completeness"]["complete"])
        self.assertFalse(projected["data"]["result_truncated"])


class MediaReferenceScanTests(unittest.TestCase):
    def _connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE memory_entries ("
            "memory_id TEXT PRIMARY KEY, context_id TEXT NOT NULL, "
            "metadata_json TEXT NOT NULL DEFAULT '{}')"
        )
        return conn

    def _insert(self, conn: sqlite3.Connection, memory_id: str, context: str, metadata: dict) -> None:
        conn.execute(
            "INSERT INTO memory_entries VALUES (?, ?, ?)",
            (memory_id, context, json.dumps(metadata)),
        )

    def test_scan_is_scope_filtered_and_deduplicated(self) -> None:
        conn = self._connection()
        media_a = "s2img_" + "a" * 32
        media_b = "s2img_" + "b" * 32
        self._insert(conn, "m1", "default", {"context_memory_type": "image", "media_id": media_a})
        self._insert(conn, "m2", "default", {"context_memory_type": "image", "media_id": media_a})
        self._insert(conn, "m3", "other", {"context_memory_type": "image", "media_id": media_b})
        self._insert(conn, "m4", "default", {"kind": "text"})

        scoped = media_references_from_connection(conn, context_ids=["default"])
        self.assertEqual(scoped["media_ids"], [media_a])
        self.assertEqual(scoped["reference_count"], 1)
        self.assertEqual(scoped["image_entry_count"], 2)

        unscoped = media_references_from_connection(conn)
        self.assertEqual(unscoped["media_ids"], sorted([media_a, media_b]))

    def test_malformed_image_reference_fails_closed(self) -> None:
        conn = self._connection()
        self._insert(
            conn,
            "m1",
            "default",
            {"context_memory_type": "image", "media_id": "../../escape"},
        )
        with self.assertRaises(RuntimeError):
            media_references_from_connection(conn)

    def test_reference_bound_is_enforced(self) -> None:
        conn = self._connection()
        for index in range(3):
            self._insert(
                conn,
                f"m{index}",
                "default",
                {
                    "context_memory_type": "image",
                    "media_id": "s2img_" + f"{index:032x}",
                },
            )
        with self.assertRaises(RuntimeError):
            media_references_from_connection(conn, limit=2)
        bounded = media_references_from_connection(conn, limit=3)
        self.assertEqual(bounded["reference_count"], 3)


if __name__ == "__main__":
    unittest.main()

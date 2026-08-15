"""Focused Stage 1B contracts for the official SYNAPSE-S2 Memory adapter."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
import time
import types
import unittest
import zlib
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from official_longmem import bootstrap as bootstrap_module  # noqa: E402
from apple_vision_enrichment import AppleVisionUnavailable  # noqa: E402
from image_capture import ConversionResult  # noqa: E402

OFFICIAL_ROOT = Path(
    os.environ.get(
        "LONGMEM_V2_OFFICIAL_ROOT",
        "/private/tmp/s2-frontier-review.CqgTZr/longmemeval-v2",
    )
)
SMALL_BACKEND = {
    "dimension": 32,
    "num_neurons": 64,
    "default_top_k": 8,
    "recall_count": 16,
    "embedding_provider": "semantic-hash",
}


def _trajectory(trajectory_id: str, text: str) -> dict[str, object]:
    return {
        "id": trajectory_id,
        "goal": "remember the bounded observation",
        "states": [
            {
                "url": "https://example.test/item",
                "action": "inspect item",
                "thought": "retain the useful detail",
                "accessibility_tree": text,
            }
        ],
    }


def _image_trajectory(
    trajectory_id: str, text: str, screenshot: Path
) -> dict[str, object]:
    trajectory = _trajectory(trajectory_id, text)
    trajectory["states"][0]["screenshot"] = str(screenshot)
    return trajectory


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
    pixels = bytearray()
    for source_y in range(height - 1, -1, -1):
        row = bytearray()
        for x in range(width):
            row.extend(
                (
                    (x * 3) % 256,
                    (source_y * 5) % 256,
                    ((x + source_y) * 7) % 256,
                )
            )
        row.extend(b"\x00" * (row_stride - len(row)))
        pixels.extend(row)
    offset = 14 + 40
    return (
        b"BM"
        + struct.pack("<IHHI", offset + len(pixels), 0, 0, offset)
        + struct.pack(
            "<IiiHHIIiiII",
            40,
            width,
            height,
            1,
            24,
            0,
            len(pixels),
            2835,
            2835,
            0,
            0,
        )
        + bytes(pixels)
    )


def _fake_converter(_source: Path, work_root: Path) -> ConversionResult:
    bmp_path = work_root / "normalized.bmp"
    thumbnail_path = work_root / "thumbnail.jpg"
    bmp_path.write_bytes(_bmp_bytes())
    thumbnail_path.write_bytes(b"\xff\xd8\xff\xe0longmem-thumbnail\xff\xd9")
    bmp_path.chmod(0o600)
    thumbnail_path.chmod(0o600)
    return ConversionResult(
        source_width=32,
        source_height=16,
        bmp_path=bmp_path,
        thumbnail_path=thumbnail_path,
    )


def _vision_payload(
    mode: str, derivative: str, elements: tuple[float, ...]
) -> dict[str, object]:
    feature = struct.pack(f"<{len(elements)}f", *elements)
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
            "request_revision": 2,
            "element_type": "float32",
            "element_count": len(elements),
            "encoding": "base64-little-endian",
            "data": base64.b64encode(feature).decode("ascii"),
        },
    }


@unittest.skipUnless(
    OFFICIAL_ROOT.is_dir(),
    f"pinned official checkout not present at {OFFICIAL_ROOT}",
)
class OfficialLongMemAdapterTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        if bootstrap_module.active_run_root() is not None:
            bootstrap_module.deactivate_run_root()
        cls.run_root = bootstrap_module.activate_run_root()
        cls.original_pycache_prefix = sys.pycache_prefix
        pycache = Path(
            tempfile.mkdtemp(prefix="adapter-tests-", dir=cls.run_root.pycache_parent)
        )
        os.chmod(pycache, 0o700)
        sys.pycache_prefix = str(pycache)
        bootstrap_module.bootstrap_official(OFFICIAL_ROOT)
        import memory_modules.memory as official
        import official_longmem.synapse_s2_memory as adapter

        cls.official = official
        cls.adapter = adapter

    @classmethod
    def tearDownClass(cls) -> None:
        sys.pycache_prefix = cls.original_pycache_prefix
        if bootstrap_module.active_run_root() is not None:
            bootstrap_module.deactivate_run_root()

    def setUp(self) -> None:
        self.memories: list[object] = []
        self.external_roots: list[Path] = []
        self.output_root = Path(
            tempfile.mkdtemp(prefix="adapter-case-", dir=self.run_root.output_parent)
        )
        os.chmod(self.output_root, 0o700)

    def tearDown(self) -> None:
        failures: list[BaseException] = []
        for memory in reversed(self.memories):
            try:
                memory.close()
            except BaseException as exc:  # pragma: no cover - cleanup evidence
                failures.append(exc)
        if self.output_root.exists():
            try:
                bootstrap_module.remove_tree_checked(
                    self.output_root,
                    owner="adapter test output",
                    safe_root=self.run_root.base,
                )
            except BaseException as exc:  # pragma: no cover - cleanup evidence
                failures.append(exc)
        for root in self.external_roots:
            shutil.rmtree(root, ignore_errors=True)
        if failures:
            raise failures[0]

    def _build(self, **overrides: object):
        params: dict[str, object] = {"backend": dict(SMALL_BACKEND)}
        params.update(overrides)
        memory = self.official.build_memory(
            {"memory_type": "synapse_s2", "memory_params": params}
        )
        self.memories.append(memory)
        return memory

    def _manifest_digest(self, artifact: Path) -> str:
        return hashlib.sha256(
            (artifact / self.adapter.MANIFEST_NAME).read_bytes()
        ).hexdigest()

    def _requested_config(
        self, artifact: Path, *, digest: str | None = None, release: bool = False
    ) -> dict[str, object]:
        config = json.loads(
            (artifact / self.adapter.MEMORY_CONFIG_NAME).read_text(encoding="utf-8")
        )
        config["memory_params"][self.adapter.EXPECTED_MANIFEST_SHA256_PARAM] = (
            digest or self._manifest_digest(artifact)
        )
        config["memory_params"][self.adapter.RELEASE_AFTER_QUERY_PARAM] = release
        return config

    def _sealed_artifact(self, name: str = "artifact") -> Path:
        memory = self._build()
        memory.insert(_trajectory("traj-alpha", "red stapler total 12.99"))
        artifact = self.output_root / name
        memory.save_memory(artifact)
        memory.close()
        return artifact

    def _rewrite_manifest(self, artifact: Path, manifest: dict[str, object]) -> str:
        raw = self.adapter._canonical_json_bytes(manifest)
        path = artifact / self.adapter.MANIFEST_NAME
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return hashlib.sha256(raw).hexdigest()

    def _resign_artifact_files(
        self,
        artifact: Path,
        *,
        changed: tuple[str, ...] = (),
        removed: tuple[str, ...] = (),
    ) -> str:
        manifest_path = artifact / self.adapter.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        files = manifest["files"]
        for relative in removed:
            files.pop(relative)
        for relative in changed:
            payload = (artifact / relative).read_bytes()
            files[relative] = {
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        return self._rewrite_manifest(artifact, manifest)

    def test_operations_require_wrapper_created_run_contract(self) -> None:
        memory = self._build()
        with mock.patch.object(
            self.adapter._bootstrap, "active_run_root", return_value=None
        ):
            with self.assertRaisesRegex(RuntimeError, "wrapper-created"):
                memory.insert(_trajectory("traj-no-wrapper", "text"))

    def test_long_configured_workspace_uses_short_private_runtime_and_is_removed(self) -> None:
        workspace = (
            self.output_root
            / ("outer segment " + "x" * 80)
            / ("inner segment " + "y" * 80)
            / "question workspace"
        )
        memory = self._build(workspace_dir=str(workspace))
        memory.insert(_trajectory("traj-space", "red stapler near lamp"))
        runtime_root = memory._runtime.runtime_root
        socket_path = (
            runtime_root / "repo" / ".synapse_s2" / "core" / "service.sock"
        )
        self.assertTrue(workspace.is_relative_to(self.run_root.base))
        self.assertEqual(stat.S_IMODE(workspace.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(runtime_root.stat().st_mode), 0o700)
        self.assertLessEqual(len(str(socket_path).encode("utf-8")), 103)
        memory.close()
        self.assertFalse(workspace.exists())
        self.assertFalse(runtime_root.exists())

    def test_redaction_precedes_truncation_and_persisted_binding_is_not_content_hash(
        self,
    ) -> None:
        raw = "A" * 500 + " sk-123456789012345678901234567890"
        sanitized, truncated = self.adapter._sanitize_bounded(raw, 512)
        self.assertTrue(truncated)
        self.assertNotIn("sk-123", sanitized)

        memory = self._build(insert={"max_state_text_bytes": 512})
        trajectory = _trajectory(
            "traj-redacted",
            "A" * 465 + " sk-123456789012345678901234567890",
        )
        prepared = memory._prepared_states(trajectory, "traj-redacted")
        private_identity = memory._trajectory_fingerprint(
            trajectory, "traj-redacted", prepared
        )
        memory.insert(trajectory)
        record = memory._ledger["trajectories"]["traj-redacted"]
        entry = memory._runtime.adapter.get_entry(record["memory_ids"][0])
        source_text = entry["source_text"]
        metadata = entry["metadata"]
        self.assertNotIn("sk-123", source_text)
        self.assertNotEqual(record["fingerprint"], private_identity)
        self.assertNotEqual(
            record["fingerprint"],
            hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        )
        self.assertNotIn("trajectory_fingerprint", metadata)
        self.assertEqual(metadata["trajectory_binding"], record["fingerprint"])

        artifact = self.output_root / "redacted-artifact"
        workspace_text = str(memory._runtime.workspace_dir)
        runtime_text = str(memory._runtime.runtime_root)
        memory.save_memory(artifact)
        for filename in (
            self.adapter.MEMORY_CONFIG_NAME,
            self.adapter.LEDGER_NAME,
            self.adapter.MANIFEST_NAME,
        ):
            rendered = (artifact / filename).read_text(encoding="utf-8")
            self.assertNotIn("sk-123", rendered)
            self.assertNotIn(private_identity, rendered)
            self.assertNotIn(workspace_text, rendered)
            self.assertNotIn(runtime_text, rendered)
        public_config = json.loads(
            (artifact / self.adapter.MEMORY_CONFIG_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(
            set(public_config["memory_params"]), set(self.adapter.PUBLIC_PARAM_KEYS)
        )

    def test_vision_mode_is_fixed_and_screenshot_errors_are_content_free(self) -> None:
        private_mode = "/private/operator/secret-vision-mode"
        with self.assertRaises(RuntimeError) as invalid_mode:
            self._build(image={"vision_mode": private_mode})
        self.assertNotIn(private_mode, str(invalid_mode.exception))

        memory = self._build()
        private_source = "/private/operator/sk-12345678901234567890.png"
        trajectory = _trajectory("traj-missing-image", "image observation")
        trajectory["states"][0]["screenshot"] = private_source
        with self.assertRaises(RuntimeError) as missing_source:
            memory.insert(trajectory)
        self.assertNotIn(private_source, str(missing_source.exception))
        self.assertIn("unavailable", str(missing_source.exception))

    def test_save_validates_destination_before_base_config_write(self) -> None:
        memory = self._build()
        memory.insert(_trajectory("traj-safe-save", "safe save"))
        external = Path(tempfile.mkdtemp(prefix="s2lm-outside-", dir="/private/tmp"))
        os.chmod(external, 0o700)
        self.external_roots.append(external)
        destination = external / "artifact"
        with self.assertRaisesRegex(RuntimeError, "disposable path validation"):
            memory.save_memory(destination)
        self.assertFalse(destination.exists())
        self.assertFalse((destination / self.adapter.MEMORY_CONFIG_NAME).exists())

    def test_load_requires_exact_out_of_band_manifest_pin_and_roundtrips(self) -> None:
        artifact = self._sealed_artifact()
        with self.assertRaisesRegex(RuntimeError, "caller-supplied"):
            self.official.load_memory(artifact)

        wrong = self._requested_config(artifact, digest="0" * 64)
        with self.assertRaisesRegex(RuntimeError, "caller-supplied digest"):
            self.official.load_memory(artifact, requested_config=wrong)

        loaded = self.official.load_memory(
            artifact, requested_config=self._requested_config(artifact)
        )
        self.memories.append(loaded)
        items = loaded.query("what was the stapler total")
        self.assertTrue(items)
        self.assertTrue(any(item["type"] == "text" for item in items))

    def test_exact_inventory_rejects_unlisted_symlink(self) -> None:
        artifact = self._sealed_artifact()
        (artifact / "unlisted").symlink_to(artifact / self.adapter.STORE_DIR_NAME)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.official.load_memory(
                artifact, requested_config=self._requested_config(artifact)
            )

    def test_resigned_retrieval_index_tamper_fails_semantic_restore(self) -> None:
        artifact = self._sealed_artifact()
        db_path = artifact / self.adapter.STORE_FILE_RELATIVE
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "UPDATE memory_entries SET spike_indices_json = '[]'"
            )
            connection.execute("DELETE FROM memory_spikes")
            connection.commit()
        finally:
            connection.close()
        os.chmod(db_path, 0o600)

        manifest_path = artifact / self.adapter.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        db_raw = db_path.read_bytes()
        manifest["files"][self.adapter.STORE_FILE_RELATIVE] = {
            "sha256": hashlib.sha256(db_raw).hexdigest(),
            "bytes": len(db_raw),
        }
        resigned_digest = self._rewrite_manifest(artifact, manifest)
        requested = self._requested_config(artifact, digest=resigned_digest)
        with self.assertRaisesRegex(RuntimeError, "retrieval coordinates"):
            self.official.load_memory(artifact, requested_config=requested)
        self.assertFalse(any(self.run_root.runtime_parent.iterdir()))
        self.assertFalse(any(self.run_root.workspace_parent.iterdir()))

    def test_resigned_duplicate_event_fails_bounded_semantic_restore(self) -> None:
        artifact = self._sealed_artifact()
        db_path = artifact / self.adapter.STORE_FILE_RELATIVE
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "INSERT INTO memory_events "
                "(memory_id, event_type, payload_json, created_at) "
                "SELECT memory_id, event_type, payload_json, created_at "
                "FROM memory_events ORDER BY event_id LIMIT 1"
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(db_path, 0o600)

        manifest_path = artifact / self.adapter.MANIFEST_NAME
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        db_raw = db_path.read_bytes()
        manifest["files"][self.adapter.STORE_FILE_RELATIVE] = {
            "sha256": hashlib.sha256(db_raw).hexdigest(),
            "bytes": len(db_raw),
        }
        resigned_digest = self._rewrite_manifest(artifact, manifest)
        requested = self._requested_config(artifact, digest=resigned_digest)
        with self.assertRaisesRegex(RuntimeError, "ledger event binding"):
            self.official.load_memory(artifact, requested_config=requested)
        self.assertFalse(any(self.run_root.runtime_parent.iterdir()))
        self.assertFalse(any(self.run_root.workspace_parent.iterdir()))

    def test_source_build_binding_and_random_artifact_bindings(self) -> None:
        first = self._sealed_artifact("artifact-one")
        second = self._sealed_artifact("artifact-two")
        first_ledger = json.loads(
            (first / self.adapter.LEDGER_NAME).read_text(encoding="utf-8")
        )
        second_ledger = json.loads(
            (second / self.adapter.LEDGER_NAME).read_text(encoding="utf-8")
        )
        self.assertNotEqual(
            first_ledger["trajectories"]["traj-alpha"]["fingerprint"],
            second_ledger["trajectories"]["traj-alpha"]["fingerprint"],
        )
        manifest = json.loads(
            (first / self.adapter.MANIFEST_NAME).read_text(encoding="utf-8")
        )
        self.assertRegex(manifest["source_build_id"], r"^source-[0-9a-f]{64}$")
        self.assertEqual(
            set(manifest["source_manifest"]),
            set(self.adapter.EXECUTABLE_SOURCE_MODULES)
            | {
                f"build:{relative}"
                for relative in self.adapter.EXECUTABLE_BUILD_FILES
            },
        )

    def _write_image(self, name: str, *, seed: int) -> Path:
        source = self.output_root / name
        source.write_bytes(_png_bytes(seed=seed))
        source.chmod(0o600)
        return source

    @staticmethod
    def _file_inventory(root: Path) -> list[tuple[str, int]]:
        if not root.is_dir():
            return []
        return sorted(
            (str(path.relative_to(root)), path.stat().st_size)
            for path in root.rglob("*")
            if path.is_file()
        )

    def test_query_image_ranks_only_authoritative_scope_without_writes_or_leaks(
        self,
    ) -> None:
        near_source = self._write_image("candidate-near.png", seed=1)
        far_source = self._write_image("candidate-far.png", seed=2)
        orphan_source = self._write_image("orphan.png", seed=3)
        query_source = self._write_image("operator-private-query.png", seed=4)
        vectors = {
            hashlib.sha256(near_source.read_bytes()).hexdigest(): (0.1, 0.0, 0.0, 0.0),
            hashlib.sha256(far_source.read_bytes()).hexdigest(): (3.0, 0.0, 0.0, 0.0),
            hashlib.sha256(orphan_source.read_bytes()).hexdigest(): (0.0, 0.0, 0.0, 0.0),
            hashlib.sha256(query_source.read_bytes()).hexdigest(): (0.0, 0.0, 0.0, 0.0),
        }
        calls: list[tuple[Path, int]] = []

        def enricher(source: Path, mode: str, derivative: str) -> dict[str, object]:
            calls.append((Path(source), stat.S_IMODE(Path(source).stat().st_mode)))
            digest = hashlib.sha256(Path(source).read_bytes()).hexdigest()
            return _vision_payload(mode, derivative, vectors[digest])

        memory = self._build(image={"vision_mode": "feature-print"})
        memory.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=enricher,
        )
        memory.insert(_image_trajectory("traj-near", "unrelated alpha", near_source))
        memory.insert(_image_trajectory("traj-far", "unrelated beta", far_source))
        runtime = memory._runtime
        near_id = memory._ledger["trajectories"]["traj-near"]["media"][0]["media_id"]
        far_id = memory._ledger["trajectories"]["traj-far"]["media"][0]["media_id"]
        near_public = runtime.cache.get_public_metadata(near_id)
        self.assertEqual(
            near_public["vision_enrichment"]["input_derivative"],
            self.adapter.QUERY_IMAGE_INPUT_DERIVATIVE,
        )
        orphan_id = "s2img_" + "f" * 32
        runtime.cache.capture_image(
            orphan_source,
            media_id=orphan_id,
            vision_mode="feature-print",
            vision_required=True,
        )
        before_inventory = self._file_inventory(runtime.cache.root)
        before_children = sorted(path.name for path in runtime.runtime_root.iterdir())

        items = memory.query("bounded visual lookup", query_image=str(query_source))
        metadata = memory.post_query_hook(
            query="bounded visual lookup",
            query_image=str(query_source),
            memory_context=items,
        )

        image_ids = [
            Path(item["value"]).stem for item in items if item["type"] == "image"
        ]
        self.assertEqual(image_ids[:2], [near_id, far_id])
        self.assertEqual(len(image_ids), len(set(image_ids)))
        self.assertNotIn(orphan_id, image_ids)
        self.assertEqual(self._file_inventory(runtime.cache.root), before_inventory)
        self.assertEqual(
            sorted(path.name for path in runtime.runtime_root.iterdir()),
            before_children,
        )
        self.assertEqual(metadata["query_image"]["status"], "applied")
        self.assertEqual(metadata["query_image"]["scope_reference_count"], 2)
        self.assertEqual(metadata["query_image"]["compatible_candidate_count"], 2)
        self.assertTrue(metadata["query_image"]["scope_complete"])
        self.assertTrue(metadata["query_image"]["scratch_removed"])
        query_calls = [
            (path, mode)
            for path, mode in calls
            if path.parent.name.startswith(".query-image-")
        ]
        self.assertEqual(len(query_calls), 1)
        self.assertEqual(query_calls[0][1], 0o600)
        self.assertFalse(query_calls[0][0].exists())
        rendered = json.dumps(metadata, sort_keys=True)
        self.assertNotIn(str(query_source), rendered)
        self.assertNotIn(str(runtime.runtime_root), rendered)
        self.assertNotIn("sha256", rendered.lower())
        self.assertNotIn("ocr", rendered.lower())
        for elements in vectors.values():
            encoded = base64.b64encode(struct.pack("<4f", *elements)).decode("ascii")
            self.assertNotIn(encoded, rendered)

    def test_query_image_failure_and_incompatible_candidates_fall_back_cleanly(
        self,
    ) -> None:
        stored_source = self._write_image("stored-no-feature.png", seed=10)
        query_source = self._write_image("query-failure.png", seed=11)
        query_digest = hashlib.sha256(query_source.read_bytes()).hexdigest()
        scratch_calls: list[Path] = []

        def failing_enricher(
            source: Path, mode: str, derivative: str
        ) -> dict[str, object]:
            digest = hashlib.sha256(Path(source).read_bytes()).hexdigest()
            if digest == query_digest:
                scratch_calls.append(Path(source))
                raise AppleVisionUnavailable("operator-private-enricher-detail")
            return _vision_payload(mode, derivative, (1.0, 0.0, 0.0, 0.0))

        memory = self._build(image={"vision_mode": "off"})
        memory.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=failing_enricher,
        )
        memory.insert(
            _image_trajectory("traj-fallback", "text fallback survives", stored_source)
        )
        runtime = memory._runtime
        before_inventory = self._file_inventory(runtime.cache.root)
        items = memory.query("fallback survives", query_image=str(query_source))
        metadata = memory.post_query_hook(
            query="fallback survives",
            query_image=str(query_source),
            memory_context=items,
        )
        self.assertTrue(any(item["type"] == "text" for item in items))
        self.assertEqual(metadata["query_image"]["status"], "degraded")
        self.assertEqual(
            metadata["query_image"]["reason_code"],
            "vision-or-similarity-unavailable",
        )
        self.assertTrue(metadata["query_image"]["scratch_removed"])
        self.assertEqual(len(scratch_calls), 1)
        self.assertFalse(scratch_calls[0].exists())
        self.assertEqual(self._file_inventory(runtime.cache.root), before_inventory)
        rendered = json.dumps(metadata, sort_keys=True)
        self.assertNotIn("operator-private-enricher-detail", rendered)
        self.assertNotIn(str(query_source), rendered)

        missing_private_path = self.output_root / "private-missing-query.png"
        failed_items = memory.query(
            "fallback survives", query_image=str(missing_private_path)
        )
        failed_meta = memory.post_query_hook(
            query="fallback survives",
            query_image=str(missing_private_path),
            memory_context=failed_items,
        )
        self.assertTrue(any(item["type"] == "text" for item in failed_items))
        self.assertEqual(failed_meta["query_image"]["status"], "failure")
        self.assertEqual(
            failed_meta["query_image"]["reason_code"], "query-image-rejected"
        )
        self.assertNotIn(str(missing_private_path), json.dumps(failed_meta))

        def compatible_query(
            source: Path, mode: str, derivative: str
        ) -> dict[str, object]:
            return _vision_payload(mode, derivative, (0.0, 0.0, 0.0, 0.0))

        second = self._build(image={"vision_mode": "off"})
        second.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=compatible_query,
        )
        second.insert(
            _image_trajectory("traj-no-feature", "honest text fallback", stored_source)
        )
        second_items = second.query(
            "honest text fallback", query_image=str(query_source)
        )
        second_meta = second.post_query_hook(
            query="honest text fallback",
            query_image=str(query_source),
            memory_context=second_items,
        )
        self.assertTrue(any(item["type"] == "text" for item in second_items))
        self.assertEqual(second_meta["query_image"]["status"], "degraded")
        self.assertEqual(
            second_meta["query_image"]["reason_code"],
            "no-compatible-feature-prints",
        )
        self.assertTrue(second_meta["query_image"]["scratch_removed"])

    def test_release_after_query_defers_image_cleanup_until_runner_finally(
        self,
    ) -> None:
        stored_source = self._write_image("release-stored.png", seed=20)
        query_source = self._write_image("release-query.png", seed=21)
        vectors = {
            hashlib.sha256(stored_source.read_bytes()).hexdigest(): (0.1, 0.0, 0.0, 0.0),
            hashlib.sha256(query_source.read_bytes()).hexdigest(): (0.0, 0.0, 0.0, 0.0),
        }

        def enricher(source: Path, mode: str, derivative: str) -> dict[str, object]:
            digest = hashlib.sha256(Path(source).read_bytes()).hexdigest()
            return _vision_payload(mode, derivative, vectors[digest])

        memory = self._build(
            release_after_query=True,
            image={"vision_mode": "feature-print"},
        )
        memory.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=enricher,
        )
        memory.insert(
            _image_trajectory("traj-release-image", "release image", stored_source)
        )
        runtime_root = memory._runtime.runtime_root
        workspace = memory._runtime.workspace_dir
        items = memory.query("release image", query_image=str(query_source))
        image_paths = [Path(item["value"]) for item in items if item["type"] == "image"]
        self.assertTrue(image_paths)
        metadata = memory.post_query_hook(
            query="release image",
            query_image=str(query_source),
            memory_context=items,
        )
        self.assertFalse(metadata["released_after_query"])
        self.assertEqual(
            metadata["release_state"], "deferred-for-image-consumption"
        )
        self.assertTrue(all(path.is_file() for path in image_paths))
        self.assertTrue(runtime_root.is_dir())

        # This is the runner wrapper's per-question finally boundary: it runs
        # after the pinned harness has tokenized/converted the returned images.
        memory.close()
        self.assertFalse(runtime_root.exists())
        self.assertFalse(workspace.exists())
        self.assertTrue(all(not path.exists() for path in image_paths))

    def test_query_image_scope_work_stops_at_candidate_bound_and_reports_truncation(
        self,
    ) -> None:
        memory = self._build()
        trajectory_id = "traj-bounded-scope"
        count = self.adapter.QUERY_IMAGE_CANDIDATE_LIMIT_CEILING + 1
        memory_ids = [f"memory-{index}" for index in range(count)]
        media: list[dict[str, object]] = []
        entries: dict[str, dict[str, object]] = {}
        for state_index in range(count):
            media_id = memory._media_id(trajectory_id, state_index)
            reference = {
                "media_id": media_id,
                "state_index": state_index,
                "thumbnail_sha256": "a" * 64,
                "thumbnail_bytes": 24,
            }
            media.append(reference)
            memory._media_reference_index[media_id] = {
                "trajectory_id": trajectory_id,
                "state_index": state_index,
                "memory_id": memory_ids[state_index],
                "thumbnail_sha256": "a" * 64,
                "thumbnail_bytes": 24,
            }
            entries[memory_ids[state_index]] = {
                "metadata": {
                    "benchmark_namespace": memory._namespace,
                    "trajectory_id": trajectory_id,
                    "state_index": state_index,
                    "media_id": media_id,
                    "memory_type": "image",
                }
            }
        memory._ledger = {
            "next_ordinal": count,
            "trajectories": {
                trajectory_id: {
                    "fingerprint": "b" * 64,
                    "state_count": count,
                    "ordinal_start": 0,
                    "memory_ids": memory_ids,
                    "media": media,
                }
            },
        }
        adapter = mock.Mock()
        adapter.get_entry.side_effect = entries.__getitem__
        runtime = types.SimpleNamespace(adapter=adapter)

        scope, summary = memory._authoritative_media_scope(
            runtime,
            maximum_references=self.adapter.QUERY_IMAGE_CANDIDATE_LIMIT_CEILING,
        )

        self.assertEqual(
            len(scope), self.adapter.QUERY_IMAGE_CANDIDATE_LIMIT_CEILING
        )
        self.assertEqual(
            adapter.get_entry.call_count,
            self.adapter.QUERY_IMAGE_CANDIDATE_LIMIT_CEILING,
        )
        self.assertEqual(summary["total_reference_count"], count)
        self.assertEqual(summary["truncated_reference_count"], 1)
        self.assertFalse(summary["complete"])

    def test_query_image_shape_is_strict_and_thumbnail_tamper_fails_closed(
        self,
    ) -> None:
        text_memory = self._build()
        text_memory.insert(_trajectory("traj-shape", "strict image query shape"))
        for invalid in ("", "   ", 7, object()):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaisesRegex(
                    RuntimeError, "query_image must be null or a non-empty path string"
                ):
                    text_memory.query("strict shape", query_image=invalid)

        source = self._write_image("tamper-stored.png", seed=30)

        def enricher(path: Path, mode: str, derivative: str) -> dict[str, object]:
            del path
            return _vision_payload(mode, derivative, (0.2, 0.0, 0.0, 0.0))

        memory = self._build(image={"vision_mode": "feature-print"})
        memory.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=enricher,
        )
        memory.insert(_image_trajectory("traj-tamper", "tamper evidence", source))
        media_id = memory._ledger["trajectories"]["traj-tamper"]["media"][0][
            "media_id"
        ]
        derivative = memory._runtime.derivatives_dir / f"{media_id}.jpg"
        derivative.write_bytes(b"\xff\xd8\xff\xe0tampered-thumbnail\xff\xd9")
        derivative.chmod(0o600)

        with self.assertRaisesRegex(
            RuntimeError, "thumbnail derivative does not match its sealed ledger binding"
        ) as caught:
            memory.query("tamper evidence")
        self.assertNotIn(str(derivative), str(caught.exception))

    def test_regular_file_reader_rejects_fifo_without_blocking_or_path_leak(
        self,
    ) -> None:
        fifo = self.output_root / "operator-private-query.fifo"
        os.mkfifo(fifo, 0o600)
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, "must be a regular file") as caught:
            self.adapter._read_regular_file_bytes(
                fifo,
                owner="bounded query input",
                maximum_bytes=1024,
            )
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertNotIn(str(fifo), str(caught.exception))

    def test_insert_preflights_complete_media_delta_without_partial_mutation(
        self,
    ) -> None:
        first_source = self._write_image("bounded-first.png", seed=71)
        rejected_source = self._write_image("bounded-rejected.png", seed=72)
        memory = self._build(image={"vision_mode": "off"})
        memory.configure_runtime(image_converter=_fake_converter)
        memory.insert(
            _image_trajectory("traj-bounded-first", "first image", first_source)
        )
        runtime = memory._runtime
        ledger_before = self.adapter._canonical_json_bytes(memory._ledger)
        cache_before = self._file_inventory(runtime.cache.root)
        derivatives_before = self._file_inventory(runtime.derivatives_dir)
        runtime_children_before = sorted(path.name for path in runtime.runtime_root.iterdir())
        connection = sqlite3.connect(runtime.backend.memory_store.db_path)
        try:
            store_rows_before = connection.execute(
                "SELECT COUNT(*) FROM memory_entries"
            ).fetchone()[0]
        finally:
            connection.close()

        with mock.patch.object(self.adapter, "MAX_MEDIA_CACHE_OBJECTS", 1):
            with self.assertRaisesRegex(
                RuntimeError, "media count exceeds the fixed cache object bound"
            ):
                memory.insert(
                    _image_trajectory(
                        "traj-bounded-rejected",
                        "must never be inserted",
                        rejected_source,
                    )
                )

        connection = sqlite3.connect(runtime.backend.memory_store.db_path)
        try:
            store_rows_after = connection.execute(
                "SELECT COUNT(*) FROM memory_entries"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(store_rows_after, store_rows_before)
        self.assertEqual(
            self.adapter._canonical_json_bytes(memory._ledger), ledger_before
        )
        self.assertEqual(self._file_inventory(runtime.cache.root), cache_before)
        self.assertEqual(
            self._file_inventory(runtime.derivatives_dir), derivatives_before
        )
        self.assertEqual(
            sorted(path.name for path in runtime.runtime_root.iterdir()),
            runtime_children_before,
        )
        self.assertNotIn("traj-bounded-rejected", memory._content_identities)

    def test_sealed_media_cache_roundtrip_preserves_visual_query_without_orphans(
        self,
    ) -> None:
        stored_source = self._write_image("portable-stored.png", seed=41)
        orphan_source = self._write_image("portable-orphan.png", seed=42)
        query_source = self._write_image("portable-query.png", seed=43)
        vectors = {
            hashlib.sha256(stored_source.read_bytes()).hexdigest(): (
                0.1,
                0.0,
                0.0,
                0.0,
            ),
            hashlib.sha256(orphan_source.read_bytes()).hexdigest(): (
                4.0,
                0.0,
                0.0,
                0.0,
            ),
            hashlib.sha256(query_source.read_bytes()).hexdigest(): (
                0.0,
                0.0,
                0.0,
                0.0,
            ),
        }

        def enricher(source: Path, mode: str, derivative: str) -> dict[str, object]:
            digest = hashlib.sha256(Path(source).read_bytes()).hexdigest()
            return _vision_payload(mode, derivative, vectors[digest])

        memory = self._build(image={"vision_mode": "feature-print"})
        memory.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=enricher,
        )
        memory.insert(
            _image_trajectory(
                "traj-portable-visual", "portable visual evidence", stored_source
            )
        )
        media_id = memory._ledger["trajectories"]["traj-portable-visual"][
            "media"
        ][0]["media_id"]
        orphan_id = "s2img_" + "e" * 32
        memory._runtime.cache.capture_image(
            orphan_source,
            media_id=orphan_id,
            vision_mode="feature-print",
            vision_required=True,
        )
        artifact = self.output_root / "portable-visual-artifact"
        memory.save_memory(artifact)
        artifact_reader = self.adapter._synapse()[
            "image_capture"
        ].MediaObjectReader(artifact / self.adapter.MEDIA_CACHE_DIR_NAME)
        self.assertEqual(artifact_reader.object_ids(), [media_id])
        self.assertNotIn(
            orphan_id,
            "\n".join(
                str(path.relative_to(artifact)) for path in artifact.rglob("*")
            ),
        )
        memory.close()

        loaded = self.official.load_memory(
            artifact,
            requested_config=self._requested_config(artifact),
        )
        self.memories.append(loaded)
        loaded.configure_runtime(query_vision_enricher=enricher)
        before_inventory = self._file_inventory(loaded._runtime.cache.root)
        items = loaded.query(
            "portable visual evidence", query_image=str(query_source)
        )
        metadata = loaded.post_query_hook(
            query="portable visual evidence",
            query_image=str(query_source),
            memory_context=items,
        )
        self.assertEqual(
            [Path(item["value"]).stem for item in items if item["type"] == "image"][
                0
            ],
            media_id,
        )
        self.assertEqual(metadata["query_image"]["status"], "applied")
        self.assertEqual(metadata["query_image"]["compatible_candidate_count"], 1)
        self.assertEqual(
            self._file_inventory(loaded._runtime.cache.root), before_inventory
        )
        self.assertEqual(loaded._runtime.cache.reader.object_ids(), [media_id])
        self.assertTrue(metadata["query_image"]["scratch_removed"])

    def test_resigned_private_media_object_tampering_fails_without_residue(
        self,
    ) -> None:
        stored_source = self._write_image("sealed-stored.png", seed=51)

        def enricher(source: Path, mode: str, derivative: str) -> dict[str, object]:
            del source
            return _vision_payload(mode, derivative, (0.2, 0.0, 0.0, 0.0))

        memory = self._build(image={"vision_mode": "feature-print"})
        memory.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=enricher,
        )
        memory.insert(
            _image_trajectory("traj-sealed-media", "sealed media", stored_source)
        )
        media_id = memory._ledger["trajectories"]["traj-sealed-media"]["media"][
            0
        ]["media_id"]
        object_prefix = (
            f"{self.adapter.MEDIA_CACHE_OBJECTS_RELATIVE}/{media_id}"
        )

        def fresh_artifact(case: str) -> Path:
            artifact = self.output_root / f"sealed-{case}"
            memory.save_memory(artifact)
            return artifact

        cases: list[tuple[str, Path, str]] = []

        manifest_artifact = fresh_artifact("manifest")
        manifest_relative = f"{object_prefix}/manifest.json"
        media_manifest_path = manifest_artifact / manifest_relative
        media_manifest = json.loads(media_manifest_path.read_text(encoding="utf-8"))
        media_manifest["created_at"] = float(media_manifest["created_at"]) + 1.0
        media_manifest_path.write_text(
            json.dumps(media_manifest, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        media_manifest_path.chmod(0o600)
        cases.append(
            (
                "manifest",
                manifest_artifact,
                self._resign_artifact_files(
                    manifest_artifact, changed=(manifest_relative,)
                ),
            )
        )

        vector_artifact = fresh_artifact("vector")
        vector_relative = f"{object_prefix}/feature-print.bin"
        vector_path = vector_artifact / vector_relative
        vector = bytearray(vector_path.read_bytes())
        vector[0] ^= 0x01
        vector_path.write_bytes(bytes(vector))
        vector_path.chmod(0o600)
        cases.append(
            (
                "vector",
                vector_artifact,
                self._resign_artifact_files(
                    vector_artifact, changed=(vector_relative,)
                ),
            )
        )

        missing_artifact = fresh_artifact("missing")
        missing_relative = f"{object_prefix}/feature-print.bin"
        (missing_artifact / missing_relative).unlink()
        cases.append(
            (
                "missing",
                missing_artifact,
                self._resign_artifact_files(
                    missing_artifact, removed=(missing_relative,)
                ),
            )
        )

        extra_file_artifact = fresh_artifact("extra-file")
        extra_relative = f"{object_prefix}/extra.bin"
        extra_path = extra_file_artifact / extra_relative
        extra_path.write_bytes(b"unlisted-private-object-data")
        extra_path.chmod(0o600)
        cases.append(
            (
                "extra-file",
                extra_file_artifact,
                self._resign_artifact_files(
                    extra_file_artifact, changed=(extra_relative,)
                ),
            )
        )

        orphan_artifact = fresh_artifact("orphan")
        orphan_id = "s2img_" + "d" * 32
        source_object = orphan_artifact / object_prefix
        orphan_prefix = (
            f"{self.adapter.MEDIA_CACHE_OBJECTS_RELATIVE}/{orphan_id}"
        )
        orphan_object = orphan_artifact / orphan_prefix
        shutil.copytree(source_object, orphan_object)
        for path in orphan_object.rglob("*"):
            if path.is_file():
                path.chmod(0o600)
            elif path.is_dir():
                path.chmod(0o700)
        orphan_manifest_path = orphan_object / "manifest.json"
        orphan_manifest = json.loads(orphan_manifest_path.read_text(encoding="utf-8"))
        orphan_manifest["media_id"] = orphan_id
        orphan_manifest["public_metadata"]["media_id"] = orphan_id
        orphan_manifest_path.write_text(
            json.dumps(orphan_manifest, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        orphan_manifest_path.chmod(0o600)
        orphan_relatives = tuple(
            f"{orphan_prefix}/{path.name}"
            for path in sorted(orphan_object.iterdir())
        )
        cases.append(
            (
                "orphan",
                orphan_artifact,
                self._resign_artifact_files(
                    orphan_artifact, changed=orphan_relatives
                ),
            )
        )

        thumbnail_artifact = fresh_artifact("thumbnail")
        thumbnail_relative = f"{object_prefix}/thumbnail.jpg"
        thumbnail_path = thumbnail_artifact / thumbnail_relative
        thumbnail_payload = b"\xff\xd8\xff\xe0coherent-tamper\xff\xd9"
        thumbnail_path.write_bytes(thumbnail_payload)
        thumbnail_path.chmod(0o600)
        thumbnail_manifest_path = thumbnail_artifact / manifest_relative
        thumbnail_manifest = json.loads(
            thumbnail_manifest_path.read_text(encoding="utf-8")
        )
        thumbnail_manifest["thumbnail_sha256"] = hashlib.sha256(
            thumbnail_payload
        ).hexdigest()
        thumbnail_manifest["thumbnail_size_bytes"] = len(thumbnail_payload)
        thumbnail_manifest_path.write_text(
            json.dumps(thumbnail_manifest, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        thumbnail_manifest_path.chmod(0o600)
        cases.append(
            (
                "thumbnail",
                thumbnail_artifact,
                self._resign_artifact_files(
                    thumbnail_artifact,
                    changed=(thumbnail_relative, manifest_relative),
                ),
            )
        )

        memory.close()
        for case, artifact, digest in cases:
            with self.subTest(case=case):
                runtime_before = sorted(self.run_root.runtime_parent.iterdir())
                workspace_before = sorted(self.run_root.workspace_parent.iterdir())
                with self.assertRaises(Exception) as caught:
                    self.official.load_memory(
                        artifact,
                        requested_config=self._requested_config(
                            artifact, digest=digest
                        ),
                    )
                self.assertNotIn(str(artifact), str(caught.exception))
                self.assertEqual(
                    sorted(self.run_root.runtime_parent.iterdir()), runtime_before
                )
                self.assertEqual(
                    sorted(self.run_root.workspace_parent.iterdir()), workspace_before
                )

    def test_save_rejects_media_object_drift_and_removes_partial_artifact(
        self,
    ) -> None:
        stored_source = self._write_image("save-drift-stored.png", seed=61)

        def enricher(source: Path, mode: str, derivative: str) -> dict[str, object]:
            del source
            return _vision_payload(mode, derivative, (0.3, 0.0, 0.0, 0.0))

        memory = self._build(image={"vision_mode": "feature-print"})
        memory.configure_runtime(
            image_converter=_fake_converter,
            vision_enricher=enricher,
        )
        memory.insert(
            _image_trajectory("traj-save-drift", "save drift", stored_source)
        )
        media_id = memory._ledger["trajectories"]["traj-save-drift"]["media"][0][
            "media_id"
        ]
        manifest_path = (
            memory._runtime.cache.objects_root / media_id / "manifest.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["created_at"] = float(manifest["created_at"]) + 1.0
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        manifest_path.chmod(0o600)
        artifact = self.output_root / "save-drift-artifact"
        with self.assertRaisesRegex(
            RuntimeError, "media cache object bytes do not bind"
        ) as caught:
            memory.save_memory(artifact)
        self.assertFalse(artifact.exists())
        self.assertNotIn(str(manifest_path), str(caught.exception))

    def test_release_after_query_closes_owned_roots_idempotently(self) -> None:
        memory = self._build(release_after_query=True)
        memory.insert(_trajectory("traj-release", "release after one question"))
        runtime_root = memory._runtime.runtime_root
        workspace = memory._runtime.workspace_dir
        items = memory.query("what should be released")
        metadata = memory.post_query_hook(
            query="what should be released",
            query_image=None,
            memory_context=items,
        )
        self.assertTrue(metadata["released_after_query"])
        self.assertIsNone(memory._runtime)
        self.assertFalse(runtime_root.exists())
        self.assertFalse(workspace.exists())
        memory.close()
        with self.assertRaisesRegex(RuntimeError, "closed"):
            memory.query("cannot reuse a released question memory")


if __name__ == "__main__":
    unittest.main()

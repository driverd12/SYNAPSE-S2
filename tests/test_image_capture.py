from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import struct
import tempfile
import unittest
import zlib
from dataclasses import replace
from pathlib import Path
from unittest import mock

import image_capture
from core_client_binding import CoreClientBinding
from image_capture import (
    ConversionResult,
    ImageCaptureCache,
    ImageCaptureError,
    ImageCaptureNotFound,
    MAX_SOURCE_BYTES,
)


def _png_bytes(width: int = 32, height: int = 16) -> bytes:
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
            rows.extend(((x * 7) % 256, (y * 13) % 256, ((x + y) * 11) % 256))
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
            red = (x * 7) % 256
            green = (source_y * 13) % 256
            blue = ((x + source_y) * 11) % 256
            row.extend((blue, green, red))
        row.extend(b"\x00" * (row_stride - len(row)))
        pixel_bytes.extend(row)
    pixel_offset = 14 + 40
    file_size = pixel_offset + len(pixel_bytes)
    return (
        b"BM"
        + struct.pack("<IHHI", file_size, 0, 0, pixel_offset)
        + struct.pack(
            "<IiiHHIIiiII",
            40,
            width,
            height,
            1,
            24,
            0,
            len(pixel_bytes),
            2835,
            2835,
            0,
            0,
        )
        + bytes(pixel_bytes)
    )


def _fake_converter(source: Path, work_root: Path) -> ConversionResult:
    del source
    bmp_path = work_root / "normalized.bmp"
    thumbnail_path = work_root / "thumbnail.jpg"
    bmp_path.write_bytes(_bmp_bytes())
    thumbnail_path.write_bytes(b"\xff\xd8\xff\xe0deterministic-thumbnail\xff\xd9")
    os.chmod(bmp_path, 0o600)
    os.chmod(thumbnail_path, 0o600)
    return ConversionResult(
        source_width=32,
        source_height=16,
        bmp_path=bmp_path,
        thumbnail_path=thumbnail_path,
    )


class ImageCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_parent = Path("/private/tmp")
        self.temporary = tempfile.TemporaryDirectory(
            prefix="s2-image-test-",
            dir=str(temporary_parent) if temporary_parent.is_dir() else None,
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo_root = self.root / "repo"
        self.data_root = self.repo_root / ".synapse_s2"
        self.core_root = self.data_root / "core"
        self.core_root.mkdir(parents=True, mode=0o700)
        self.data_root.chmod(0o700)
        self.core_root.chmod(0o700)
        self.binding = CoreClientBinding(
            repo_root=self.repo_root,
            data_root=self.data_root,
            config_path=self.core_root / "service.json",
            socket_path=self.core_root / "service.sock",
            state_path=self.data_root / "runtime_state.json",
            memory_path=self.data_root / "memory.sqlite3",
            capture_root=self.data_root,
            export_root=self.data_root / "exports",
            backup_root=self.data_root / "backups",
            recovery_root=self.data_root / "recovery",
            replication_inbox_root=self.data_root / "replication" / "inbox",
            core_label="image-test-core",
            config_digest="a" * 64,
            config_fingerprint="b" * 64,
            embedding_space_identity="c" * 64,
            layout="canonical",
            authority_mode="authoritative-core-v6",
        )
        self.source = self.root / "sensitive-original-name.png"
        self.source.write_bytes(_png_bytes())
        self.source.chmod(0o600)

    def cache(self, *, converter=_fake_converter) -> ImageCaptureCache:
        return ImageCaptureCache(self.binding, converter=converter)

    def test_capture_publishes_private_cache_and_public_descriptor(self) -> None:
        media_id = "s2img_" + "1" * 32
        cache = self.cache()

        result = cache.capture_image(self.source, media_id=media_id)

        public = result["public_metadata"]
        self.assertEqual(result["raw_original_stored"], False)
        self.assertEqual(result["source_path_stored"], False)
        self.assertEqual(public["media_id"], media_id)
        self.assertEqual(public["context_memory_type"], "image")
        self.assertEqual(public["mime_type"], "image/png")
        self.assertEqual(public["source_dimensions"], {"width": 32, "height": 16})
        self.assertEqual(public["thumbnail_dimensions"], {"width": 32, "height": 16})
        public_text = json.dumps(public, sort_keys=True)
        self.assertNotIn(str(self.source), public_text)
        self.assertNotIn("sha256", public_text.lower())
        self.assertNotIn("thumbnail_bytes", public_text.lower())

        descriptor = public["visual_descriptor"]
        self.assertEqual(len(base64.b64decode(descriptor["tensor_data"])), 16 * 16 * 3)
        self.assertEqual(len(base64.b64decode(descriptor["rgb_histogram_data"])), 3 * 16)
        self.assertEqual(len(base64.b64decode(descriptor["edge_histogram_data"])), 8)
        self.assertRegex(descriptor["difference_bits_hex"], r"^[0-9a-f]{16}$")

        object_root = cache.objects_root / media_id
        manifest_path = object_root / "manifest.json"
        thumbnail_path = object_root / "thumbnail.jpg"
        self.assertEqual(stat.S_IMODE(cache.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(cache.objects_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(object_root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(thumbnail_path.stat().st_mode), 0o600)
        self.assertEqual(
            sorted(path.name for path in object_root.iterdir()),
            ["manifest.json", "thumbnail.jpg"],
        )

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        source_bytes = self.source.read_bytes()
        thumbnail_bytes = thumbnail_path.read_bytes()
        self.assertEqual(manifest["source_sha256"], hashlib.sha256(source_bytes).hexdigest())
        self.assertEqual(
            manifest["thumbnail_sha256"],
            hashlib.sha256(thumbnail_bytes).hexdigest(),
        )
        manifest_text = json.dumps(manifest, sort_keys=True)
        self.assertNotIn(str(self.source), manifest_text)
        self.assertNotIn(self.source.name, manifest_text)
        self.assertNotEqual(source_bytes, thumbnail_bytes)

        thumbnail = cache.get_thumbnail(media_id)
        self.assertEqual(thumbnail.content_type, "image/jpeg")
        self.assertEqual(thumbnail.data, thumbnail_bytes)
        audit = cache.audit(referenced_media_ids=[media_id])
        self.assertTrue(audit["healthy"])
        self.assertEqual(audit["valid_count"], 1)
        self.assertEqual(audit["orphan_count"], 0)
        self.assertEqual(cache.get_public_metadata(media_id), result["public_metadata"])

        replay = cache.capture_image(self.source, media_id=media_id)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["public_metadata"], result["public_metadata"])
        with self.assertRaises(ImageCaptureNotFound):
            cache.get_thumbnail("s2img_" + "f" * 32)

    def test_source_path_type_magic_permission_and_size_guards(self) -> None:
        cache = self.cache()
        with self.assertRaises(ValueError):
            cache.capture_image("relative.png")
        with self.assertRaises(ValueError):
            cache.capture_image("~/not-an-absolute-source.png")

        symlink = self.root / "source-link.png"
        symlink.symlink_to(self.source)
        with self.assertRaises(ValueError):
            cache.capture_image(symlink)

        real_parent = self.root / "real-parent"
        real_parent.mkdir(mode=0o700)
        nested_source = real_parent / "nested.png"
        nested_source.write_bytes(_png_bytes())
        nested_source.chmod(0o600)
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            cache.capture_image(linked_parent / "nested.png")

        unsupported = self.root / "unsupported.png"
        unsupported.write_bytes(b"not actually a supported image")
        unsupported.chmod(0o600)
        with self.assertRaises(ValueError):
            cache.capture_image(unsupported)

        self.source.chmod(0o000)
        try:
            with self.assertRaises(ValueError):
                cache.capture_image(self.source)
        finally:
            self.source.chmod(0o600)

        oversized = self.root / "oversized.png"
        descriptor = os.open(oversized, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, b"\x89PNG\r\n\x1a\n")
            os.ftruncate(descriptor, MAX_SOURCE_BYTES + 1)
        finally:
            os.close(descriptor)
        with self.assertRaises(ValueError):
            cache.capture_image(oversized)

    def test_atomic_publication_cleans_stage_on_manifest_write_failure(self) -> None:
        media_id = "s2img_" + "2" * 32
        cache = self.cache()
        real_write = image_capture._write_private_exclusive

        def fail_manifest(path: Path, data: bytes) -> None:
            if path.name == "manifest.json":
                raise OSError("synthetic publication failure")
            real_write(path, data)

        with mock.patch("image_capture._write_private_exclusive", side_effect=fail_manifest):
            with self.assertRaises(OSError):
                cache.capture_image(self.source, media_id=media_id)

        self.assertFalse((cache.objects_root / media_id).exists())
        self.assertFalse(any(path.name.startswith(".stage-") for path in cache.root.iterdir()))

    def test_audit_and_revision_guarded_orphan_prune(self) -> None:
        first = "s2img_" + "3" * 32
        second = "s2img_" + "4" * 32
        cache = self.cache()
        cache.capture_image(self.source, media_id=first)
        cache.capture_image(self.source, media_id=second)

        audit = cache.audit(referenced_media_ids=[first])
        self.assertTrue(audit["healthy"])
        self.assertEqual(audit["orphan_ids"], [second])
        with self.assertRaises(ValueError):
            cache.prune_orphans(
                referenced_media_ids=[first],
                expected_revision="0" * 64,
                confirm=True,
            )
        with self.assertRaises(ValueError):
            cache.prune_orphans(
                referenced_media_ids=[first],
                expected_revision=audit["revision"],
                confirm=False,
            )

        result = cache.prune_orphans(
            referenced_media_ids=[first],
            expected_revision=audit["revision"],
            confirm=True,
        )
        self.assertEqual(result["removed_ids"], [second])
        self.assertTrue((cache.objects_root / first).is_dir())
        self.assertFalse((cache.objects_root / second).exists())

    def test_corruption_is_detected_and_blocks_automatic_prune(self) -> None:
        media_id = "s2img_" + "5" * 32
        cache = self.cache()
        cache.capture_image(self.source, media_id=media_id)
        thumbnail_path = cache.objects_root / media_id / "thumbnail.jpg"
        thumbnail_path.write_bytes(b"\xff\xd8\xfftampered")
        thumbnail_path.chmod(0o600)

        audit = cache.audit(referenced_media_ids=[])
        self.assertFalse(audit["healthy"])
        self.assertEqual(audit["corrupt_ids"], [media_id])
        with self.assertRaises(ImageCaptureError):
            cache.get_thumbnail(media_id)
        with self.assertRaises(ImageCaptureError):
            cache.prune_orphans(
                referenced_media_ids=[],
                expected_revision=audit["revision"],
                confirm=True,
            )

    def test_descriptor_is_deterministic_and_invalid_names_are_not_reflected(self) -> None:
        first = "s2img_" + "6" * 32
        second = "s2img_" + "7" * 32
        cache = self.cache()
        first_result = cache.capture_image(self.source, media_id=first)
        second_result = cache.capture_image(self.source, media_id=second)
        self.assertEqual(
            first_result["public_metadata"]["visual_descriptor"],
            second_result["public_metadata"]["visual_descriptor"],
        )

        unsafe_name = "operator-secret-name"
        (cache.objects_root / unsafe_name).mkdir(mode=0o700)
        audit = cache.audit()
        self.assertEqual(audit["invalid_entry_count"], 1)
        self.assertNotIn(unsafe_name, json.dumps(audit, sort_keys=True))
        self.assertIn("invalid-entry-0001", audit["corrupt_ids"])

    def test_cache_root_comes_only_from_a_verified_binding(self) -> None:
        cache = self.cache()
        self.assertEqual(cache.root, self.binding.data_root / "media-cache")
        tampered = replace(
            self.binding,
            data_root=self.root / "unexpected-data-root",
        )
        with self.assertRaises(ImageCaptureError):
            ImageCaptureCache(tampered, converter=_fake_converter)

    @unittest.skipUnless(Path("/usr/bin/sips").is_file(), "macOS sips is unavailable")
    def test_real_sips_conversion_path(self) -> None:
        media_id = "s2img_" + "8" * 32
        cache = ImageCaptureCache(self.binding)

        result = cache.capture_image(self.source, media_id=media_id)

        public = result["public_metadata"]
        self.assertEqual(public["source_dimensions"], {"width": 32, "height": 16})
        self.assertLessEqual(public["thumbnail_dimensions"]["width"], 320)
        self.assertLessEqual(public["thumbnail_dimensions"]["height"], 320)
        self.assertTrue(cache.get_thumbnail(media_id).data.startswith(b"\xff\xd8\xff"))


if __name__ == "__main__":
    unittest.main()

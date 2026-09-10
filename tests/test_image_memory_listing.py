"""Bounded authoritative gallery projection without sampling text memories."""

import inspect
import json
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core_client import CoreClient
from core_protocol import CoreProtocolError
from core_service import CORE_OPERATION_CONTRACTS, SAFE_READ_OPERATIONS
from memory_store import DurableMemoryStore
from mlx_backend import SpikingAttentionBackend


class ImageMemoryListingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = DurableMemoryStore(Path(self.temporary.name) / "memory.sqlite3")
        self.addCleanup(self.store.close)

    def entry(self, tag, *, context="alpha", media=1, at=10.0, metadata=None):
        if metadata is None:
            metadata = {
                "context_memory_type": "image",
                "media_id": f"s2img_{media:032x}",
                "display_label": f"Image {tag}",
                "thumbnail_dimensions": {"width": 320, "height": 180},
            }
        with patch("memory_store.time.time", return_value=at):
            return self.store.upsert_entry(
                tag=tag, context_id=context,
                source_text="Private source body excluded from gallery",
                metadata=metadata, embedding_dimensions=32,
                spike_indices=[1, 2, 3], neuron_indices=[0],
            )

    def test_older_images_survive_more_than_200_newer_text_memories(self):
        image = self.entry("older-image")
        self.entry("other-namespace", context="beta", media=2)
        self.entry("inherited-global-is-excluded", context="global", media=3)
        for index in range(205):
            self.entry(f"recent-text-{index}", at=1000 + index,
                       metadata={"context_memory_type": "note"})
        with (
            patch.object(self.store, "_row_to_entry", side_effect=AssertionError("no entry bodies")),
            patch.object(self.store, "list_entries", side_effect=AssertionError("no recent-entry sampling")),
            patch.object(self.store, "_connect", side_effect=AssertionError("no writer connection")),
        ):
            result = self.store.list_image_memories(context_id="alpha", limit=200)
        self.assertEqual(result["item_count"], 1)
        self.assertEqual(result["items"][0]["memory_id"], image["memory_id"])
        self.assertEqual(result["items"][0]["media_id"], f"s2img_{1:032x}")
        self.assertFalse(result["has_more"])
        self.assertNotIn("source_text", json.dumps(result))
        self.assertNotIn("Private source body", json.dumps(result))
        self.assertEqual(self.store.list_image_memories(context_id="beta")["item_count"], 1)
        self.assertEqual(self.store.list_image_memories(context_id="global")["item_count"], 1)
        self.assertEqual(self.store.list_image_memories(context_id="missing")["item_count"], 0)

    def test_distinct_media_limit_uses_newest_memory_and_detects_more(self):
        self.entry("old-copy", media=1, at=1)
        latest = self.entry("latest-copy", media=1, at=50)
        self.entry("second-image", media=2, at=40)
        self.entry("third-image", media=3, at=30)
        result = self.store.list_image_memories(context_id="alpha", limit=2)
        self.assertTrue(result["has_more"])
        self.assertEqual(result["item_count"], 2)
        self.assertEqual(result["items"][0]["memory_id"], latest["memory_id"])
        self.assertEqual([item["media_id"] for item in result["items"]],
                         [f"s2img_{1:032x}", f"s2img_{2:032x}"])
        self.store.delete_entry(context_id="alpha", memory_id=latest["memory_id"])
        after_delete = self.store.list_image_memories(context_id="alpha", limit=3)
        self.assertFalse(after_delete["has_more"])
        self.assertEqual(after_delete["items"][-1]["display_label"], "Image old-copy")

    def test_malformed_metadata_is_skipped_or_safely_defaulted(self):
        entries = [self.entry(f"malformed-{n}", media=n + 1) for n in range(7)]
        raw = [
            "{invalid-json",
            json.dumps([{"context_memory_type": "image"}]),
            json.dumps({"context_memory_type": "image", "media_id": ["invalid"]}),
            json.dumps({"context_memory_type": "image", "media_id": "s2img_" + "g" * 32}),
            json.dumps({"context_memory_type": "image", "media_id": f"s2img_{5:032x}",
                        "display_label": {"private": "excluded"},
                        "thumbnail_dimensions": {"width": True, "height": "320"}}),
            json.dumps({"context_memory_type": "image", "media_id": f"s2img_{6:032x}",
                        "display_label": "Photo api_key=sk-test-secret123",
                        "thumbnail_dimensions": {"width": -1, "height": 10000000}}),
            json.dumps({"context_memory_type": "image", "media_id": f"s2img_{7:032x}",
                        "display_label": "x" * 10000, "title": "Safe fallback title"}),
        ]
        with closing(sqlite3.connect(self.store.db_path)) as conn:
            conn.executemany("UPDATE memory_entries SET metadata_json=? WHERE memory_id=?",
                             [(text, entry["memory_id"]) for text, entry in zip(raw, entries)])
            conn.commit()
        result = self.store.list_image_memories(context_id="alpha")
        self.assertEqual(result["item_count"], 3)
        by_media = {item["media_id"]: item for item in result["items"]}
        self.assertEqual(by_media[f"s2img_{5:032x}"]["thumbnail_width"], 0)
        self.assertEqual(by_media[f"s2img_{5:032x}"]["thumbnail_height"], 0)
        self.assertEqual(by_media[f"s2img_{6:032x}"]["thumbnail_height"], 0)
        self.assertEqual(by_media[f"s2img_{7:032x}"]["display_label"], "Safe fallback title")
        self.assertNotIn("sk-test-secret123", json.dumps(result))
        self.assertNotIn("excluded", json.dumps(result))

    def test_maximum_gallery_has_only_bounded_scalar_fields(self):
        for index in range(201):
            self.entry(f"image-{index}", media=index, metadata={
                "context_memory_type": "image", "media_id": f"s2img_{index:032x}",
                "display_label": "\U0001f4f7" * 512,
                "thumbnail_dimensions": {"width": 320, "height": 320},
                "private_nested_metadata": {"large": "excluded" * 100},
            })
        result = self.store.list_image_memories(context_id="alpha", limit=200)
        self.assertEqual(result["item_count"], 200)
        self.assertTrue(result["has_more"])
        for item in result["items"]:
            self.assertEqual(set(item), {
                "memory_id", "media_id", "display_label", "created_at", "capture_kind",
                "thumbnail_width", "thumbnail_height", "cache_authoritative",
            })
            self.assertLessEqual(len(item["display_label"].encode("utf-8")), 256)
            self.assertEqual(item["capture_kind"], "image")
        self.assertLess(len(json.dumps(result, allow_nan=False).encode()), 256 * 1024)
        for limit in (0, 201, -1, True, 1.5, "2", None):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.store.list_image_memories(context_id="alpha", limit=limit)

    def test_core_contract_backend_and_client_forward_exact_namespace(self):
        contract = CORE_OPERATION_CONTRACTS["list_image_memories"]
        self.assertEqual(contract.allowed_arguments, {"context_id", "limit"})
        self.assertEqual(set(inspect.signature(SpikingAttentionBackend.list_image_memories).parameters)
                         - {"self"}, contract.allowed_arguments)
        self.assertFalse(contract.mutation)
        self.assertTrue(contract.retry_safe)
        self.assertIn("list_image_memories", SAFE_READ_OPERATIONS)
        with self.assertRaises(CoreProtocolError):
            contract.validate_arguments({"context_id": "alpha", "include_global": True})
        backend = SpikingAttentionBackend.__new__(SpikingAttentionBackend)
        backend.memory_store = self.store
        expected = backend.list_image_memories(context_id="alpha", limit=7)
        client = CoreClient(socket_path=Path(self.temporary.name) / "core" / "service.sock")
        with patch.object(client, "call", return_value=expected) as call:
            self.assertEqual(client.list_image_memories(context_id="alpha", limit=7), expected)
        call.assert_called_once_with("list_image_memories", {"context_id": "alpha", "limit": 7})


if __name__ == "__main__":
    unittest.main()

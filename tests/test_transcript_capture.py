import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mlx_backend import SpikingAttentionBackend
from transcript_capture import (
    MAX_TRANSCRIPT_DELTA_BYTES,
    TranscriptCaptureManager,
    _capture_id_for_file_delta,
)


class TranscriptCaptureManagerTests(unittest.TestCase):
    def make_backend(self, tmp: str) -> SpikingAttentionBackend:
        return SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=3,
            compile_graph=False,
            state_path=Path(tmp) / "state.json",
            memory_path=Path(tmp) / "memory.sqlite3",
            embedding_provider_name="semantic-hash",
        )

    def test_file_tail_source_requires_confirmation_and_rejects_sensitive_paths(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            transcript = Path(tmp) / "session.log"
            transcript.write_text("Existing transcript line.\n", encoding="utf-8")
            sensitive = Path(tmp) / ".ssh" / "id_rsa.txt"
            sensitive.parent.mkdir()
            sensitive.write_text("not a transcript", encoding="utf-8")

            with self.assertRaises(ValueError):
                manager.register_file_source(
                    source_id="unconfirmed",
                    path=transcript,
                    context_id="demo",
                    source_tag="codex-live",
                    speaker="codex",
                    confirmed=False,
                )
            with self.assertRaises(ValueError):
                manager.register_file_source(
                    source_id="sensitive",
                    path=sensitive,
                    context_id="demo",
                    source_tag="codex-live",
                    speaker="codex",
                    confirmed=True,
                )

    def test_file_tail_source_captures_only_new_redacted_transcript_delta(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "codex-session.log"
            transcript.write_text("Historical line should not be captured.\n", encoding="utf-8")

            registered = manager.register_file_source(
                source_id="codex-live",
                path=transcript,
                context_id="demo",
                source_tag="codex-live",
                speaker="codex",
                confirmed=True,
                start_at_end=True,
            )
            transcript.write_text(
                transcript.read_text(encoding="utf-8")
                + "User asks SYNAPSE-S2 to capture transcript deltas. api_key=sk-secret123\n"
                + "Codex records only newly appended text into semantic memory.\n",
                encoding="utf-8",
            )

            first_poll = manager.poll_sources(source_id="codex-live")
            second_poll = manager.poll_sources(source_id="codex-live")
            memory = backend.list_memory(context_id="demo", limit=10)
            captured = [
                entry
                for entry in memory["entries"]
                if entry["metadata"].get("transcript_adapter") is True
            ]

        self.assertEqual(registered["cursor"], len("Historical line should not be captured.\n".encode("utf-8")))
        self.assertEqual(first_poll["captured_source_count"], 1)
        self.assertGreaterEqual(first_poll["captured_event_count"], 1)
        self.assertEqual(first_poll["captures"][0]["protocol"], "capture.v2")
        self.assertEqual(first_poll["captures"][0]["capture_protocol"], "capture.v2")
        self.assertEqual(second_poll["captured_source_count"], 0)
        self.assertTrue(captured)
        self.assertTrue(all("Historical line" not in entry["source_text"] for entry in captured))
        self.assertTrue(all("sk-secret123" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))
        self.assertTrue(any(entry["metadata"]["adapter_kind"] == "file-tail" for entry in captured))
        self.assertTrue(any(entry["metadata"]["redaction_count"] >= 1 for entry in captured))

    def test_file_tail_capture_failure_does_not_advance_durable_cursor(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "failed-session.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="failed-live",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            transcript.write_text("existing\nnew delta\n", encoding="utf-8")
            original_capture = backend.capture_conversation

            def fail_capture(**_kwargs):
                raise RuntimeError("injected capture failure")

            backend.capture_conversation = fail_capture  # type: ignore[method-assign]
            failed = manager.poll_sources(source_id="failed-live")
            backend.capture_conversation = original_capture  # type: ignore[method-assign]
            saved = manager.list_sources()["sources"][0]
            retried = manager.poll_sources(source_id="failed-live")

        self.assertEqual(failed["captured_source_count"], 0)
        self.assertEqual(len(failed["errors"]), 1)
        self.assertEqual(saved["cursor"], registered["cursor"])
        self.assertEqual(retried["captured_source_count"], 1)

    def test_file_tail_lost_state_write_replays_same_capture_without_duplicate_effects(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "lost-response.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="lost-response-live",
                path=transcript,
                context_id="demo",
                source_tag="lost-response-live",
                confirmed=True,
                start_at_end=True,
            )
            appended = "a newly committed transcript delta\n"
            transcript.write_text("existing\n" + appended, encoding="utf-8")
            expected_capture_id = _capture_id_for_file_delta(
                source_instance_id=registered["source_instance_id"],
                stream_generation=0,
                cursor_start=registered["cursor"],
                cursor_end=registered["cursor"] + len(appended.encode("utf-8")),
            )
            original_write = manager._write_state
            write_calls = 0

            def lose_first_state_write(state):
                nonlocal write_calls
                write_calls += 1
                if write_calls == 1:
                    raise OSError("injected state write loss")
                return original_write(state)

            manager._write_state = lose_first_state_write  # type: ignore[method-assign]
            with self.assertRaises(OSError):
                manager.poll_sources(source_id="lost-response-live")
            after_lost_response = backend.list_memory_graph(context_id="demo", limit=100)

            replay = manager.poll_sources(source_id="lost-response-live")
            after_replay = backend.list_memory_graph(context_id="demo", limit=100)

        self.assertEqual(replay["captured_source_count"], 1)
        self.assertEqual(replay["captures"][0]["capture_id"], expected_capture_id)
        self.assertTrue(replay["captures"][0]["idempotent_replay"])
        self.assertEqual(
            after_replay["entry_count"],
            after_lost_response["entry_count"],
        )
        self.assertEqual(
            len(after_replay["relationships"]),
            len(after_lost_response["relationships"]),
        )

    def test_file_tail_rotation_advances_stream_generation(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "rotating.log"
            transcript.write_text("old stream content\n", encoding="utf-8")
            manager.register_file_source(
                source_id="rotating-live",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            replacement = Path(tmp) / "replacement.log"
            replacement.write_text("new stream content after rotation\n", encoding="utf-8")
            replacement.replace(transcript)

            capture = manager.poll_sources(source_id="rotating-live")
            saved = manager.list_sources()["sources"][0]

        self.assertEqual(capture["captured_source_count"], 1)
        self.assertEqual(capture["captures"][0]["stream_generation"], 1)
        self.assertEqual(saved["stream_generation"], 1)

    def test_concurrent_overlapping_polls_defer_and_commit_disjoint_ranges(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            first_manager = TranscriptCaptureManager(root=root, backend=backend)
            second_manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "concurrent.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = first_manager.register_file_source(
                source_id="shared-live",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            appended = "first concurrent chunk. second concurrent chunk.\n"
            transcript.write_text("existing\n" + appended, encoding="utf-8")
            capture_entered = threading.Event()
            release_capture = threading.Event()
            original_capture = backend.capture_conversation

            def blocking_first_capture(**kwargs):
                if not capture_entered.is_set():
                    capture_entered.set()
                    if not release_capture.wait(timeout=5):
                        raise RuntimeError("test timed out waiting to release capture")
                return original_capture(**kwargs)

            backend.capture_conversation = blocking_first_capture  # type: ignore[method-assign]
            thread_result: dict[str, object] = {}

            def run_first_poll():
                try:
                    thread_result["poll"] = first_manager.poll_sources(
                        source_id="shared-live",
                        max_bytes=24,
                    )
                except BaseException as exc:  # pragma: no cover - surfaced below
                    thread_result["error"] = exc

            worker = threading.Thread(target=run_first_poll, daemon=True)
            worker.start()
            self.assertTrue(capture_entered.wait(timeout=5))
            deferred = second_manager.poll_sources(
                source_id="shared-live",
                max_bytes=MAX_TRANSCRIPT_DELTA_BYTES,
            )
            release_capture.set()
            worker.join(timeout=5)
            backend.capture_conversation = original_capture  # type: ignore[method-assign]
            self.assertFalse(worker.is_alive())
            if "error" in thread_result:
                raise thread_result["error"]  # type: ignore[misc]

            first = thread_result["poll"]
            self.assertIsInstance(first, dict)
            remaining = second_manager.poll_sources(
                source_id="shared-live",
                max_bytes=MAX_TRANSCRIPT_DELTA_BYTES,
            )

        first_capture = first["captures"][0]  # type: ignore[index]
        second_capture = remaining["captures"][0]
        self.assertEqual(deferred["captured_source_count"], 0)
        self.assertEqual(deferred["deferred_source_count"], 1)
        self.assertEqual(deferred["deferred_sources"][0]["reason"], "source-busy")
        self.assertEqual(first_capture["cursor_start"], registered["cursor"])
        self.assertEqual(first_capture["cursor_end"], registered["cursor"] + 24)
        self.assertEqual(second_capture["cursor_start"], first_capture["cursor_end"])
        self.assertNotEqual(first_capture["capture_id"], second_capture["capture_id"])

    def test_re_registration_requires_caught_up_source_and_rotates_instance(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "re-register.log"
            transcript.write_text("existing\n", encoding="utf-8")
            first = manager.register_file_source(
                source_id="re-register-live",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            transcript.write_text("existing\nunread delta\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "poll it first"):
                manager.register_file_source(
                    source_id="re-register-live",
                    path=transcript,
                    context_id="demo",
                    confirmed=True,
                )

            manager.poll_sources(source_id="re-register-live")
            second = manager.register_file_source(
                source_id="re-register-live",
                path=transcript,
                context_id="demo",
                confirmed=True,
            )

        self.assertNotEqual(first["source_instance_id"], second["source_instance_id"])
        self.assertEqual(
            second["registration_generation"],
            first["registration_generation"] + 1,
        )

    def test_source_lineage_recovers_identity_and_cursor_after_state_loss(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "state-loss.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="state-loss-live",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            transcript.write_text("existing\nfirst delta\n", encoding="utf-8")
            manager.poll_sources(source_id="state-loss-live")
            before_loss = manager.list_sources()["sources"][0]
            manager.paths()["source_state_path"].unlink()

            recovered_manager = TranscriptCaptureManager(root=root, backend=backend)
            recovered = recovered_manager.register_file_source(
                source_id="state-loss-live",
                path=transcript,
                context_id="demo",
                confirmed=True,
            )

        self.assertEqual(recovered["source_instance_id"], registered["source_instance_id"])
        self.assertEqual(recovered["registration_generation"], registered["registration_generation"])
        self.assertEqual(recovered["cursor"], before_loss["cursor"])

    def test_same_source_id_in_distinct_capture_roots_cannot_collide(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            first_manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root-a",
                backend=backend,
            )
            second_manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root-b",
                backend=backend,
            )
            transcript = Path(tmp) / "shared-file.log"
            transcript.write_text("existing\n", encoding="utf-8")
            first_registered = first_manager.register_file_source(
                source_id="same-source",
                path=transcript,
                context_id="demo",
                source_tag="same-source",
                confirmed=True,
                start_at_end=True,
            )
            second_registered = second_manager.register_file_source(
                source_id="same-source",
                path=transcript,
                context_id="demo",
                source_tag="same-source",
                confirmed=True,
                start_at_end=True,
            )
            transcript.write_text("existing\nshared new delta\n", encoding="utf-8")
            first_capture = first_manager.poll_sources(source_id="same-source")
            second_capture = second_manager.poll_sources(source_id="same-source")

        self.assertNotEqual(
            first_registered["source_instance_id"],
            second_registered["source_instance_id"],
        )
        self.assertNotEqual(
            first_capture["captures"][0]["capture_id"],
            second_capture["captures"][0]["capture_id"],
        )

    def test_same_inode_truncate_advances_stream_generation(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
            )
            transcript = Path(tmp) / "same-inode-truncate.log"
            transcript.write_text("long original transcript content\n", encoding="utf-8")
            manager.register_file_source(
                source_id="same-inode-truncate",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            original_inode = transcript.stat().st_ino
            transcript.write_text("short rewrite\n", encoding="utf-8")
            self.assertEqual(transcript.stat().st_ino, original_inode)

            capture = manager.poll_sources(source_id="same-inode-truncate")

        self.assertEqual(capture["captures"][0]["cursor_start"], 0)
        self.assertEqual(capture["captures"][0]["stream_generation"], 1)

    def test_same_inode_same_size_rewrite_advances_stream_generation_without_digest(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
            )
            transcript = Path(tmp) / "same-size-rewrite.log"
            transcript.write_text("alpha memory\n", encoding="utf-8")
            manager.register_file_source(
                source_id="same-size-rewrite",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            original_stat = transcript.stat()
            transcript.write_text("omega memory\n", encoding="utf-8")
            os.utime(
                transcript,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000_000),
            )
            self.assertEqual(transcript.stat().st_ino, original_stat.st_ino)
            self.assertEqual(transcript.stat().st_size, original_stat.st_size)

            capture = manager.poll_sources(source_id="same-size-rewrite")
            private_state = manager.paths()["source_state_path"].read_text(encoding="utf-8")

        self.assertEqual(capture["captures"][0]["cursor_start"], 0)
        self.assertEqual(capture["captures"][0]["stream_generation"], 1)
        self.assertNotIn("cursor_tail", private_state)

    def test_clipboard_capture_is_explicit_one_shot_and_redacted(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=Path(tmp) / "capture-root", backend=backend)

            capture = manager.capture_clipboard_once(
                text="Selected Claude answer copied by operator. password=hunter2",
                context_id="demo",
                source_tag="frontmost-selection",
                speaker="operator",
            )
            memory = backend.list_memory(context_id="demo", limit=10)
            captured = [
                entry
                for entry in memory["entries"]
                if entry["metadata"].get("adapter_kind") == "clipboard-once"
            ]

        self.assertEqual(capture["adapter_kind"], "clipboard-once")
        self.assertGreaterEqual(capture["event_count"], 1)
        self.assertEqual(capture["protocol"], "capture.v2")
        self.assertEqual(capture["capture_protocol"], "capture.v2")
        self.assertTrue(captured)
        self.assertTrue(all("hunter2" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))
        self.assertEqual(captured[0]["metadata"]["capture_mode"], "explicit-one-shot")

    def test_detected_running_app_can_be_attached_and_snapshotted(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Google Chrome",
                        "bundle_id": "com.google.Chrome",
                        "pid": 1234,
                    }
                ],
                app_snapshot_provider=lambda app: (
                    f"{app['app_name']} active transcript: working on SYNAPSE-S2. "
                    "token=sk-app-secret123"
                ),
            )

            with self.assertRaises(ValueError):
                manager.connect_running_app(
                    app_name="Google Chrome",
                    context_id="demo",
                    source_tag="chrome-live",
                    speaker="operator",
                    confirmed=False,
                )

            attached = manager.connect_running_app(
                app_name="Google Chrome",
                context_id="demo",
                source_tag="chrome-live",
                speaker="operator",
                confirmed=True,
            )
            snapshot = manager.capture_app_snapshot(
                connection_id=attached["connection_id"],
                confirmed=True,
            )
            connections = manager.list_app_connections()
            memory = backend.list_memory(context_id="demo", limit=10)
            captured = [
                entry
                for entry in memory["entries"]
                if entry["metadata"].get("adapter_kind") == "app-accessibility-snapshot"
            ]

        self.assertEqual(attached["app_name"], "Google Chrome")
        self.assertEqual(attached["bundle_id"], "com.google.Chrome")
        self.assertEqual(connections["connection_count"], 1)
        self.assertEqual(snapshot["adapter_kind"], "app-accessibility-snapshot")
        self.assertGreaterEqual(snapshot["event_count"], 1)
        self.assertEqual(snapshot["protocol"], "capture.v2")
        self.assertEqual(snapshot["capture_protocol"], "capture.v2")
        self.assertTrue(captured)
        self.assertTrue(all("sk-app-secret123" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))
        self.assertEqual(captured[0]["metadata"]["app_name"], "Google Chrome")

    def test_app_snapshot_lost_response_replays_without_observing_changed_app(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            snapshot_calls = 0

            def changing_snapshot(_app):
                nonlocal snapshot_calls
                snapshot_calls += 1
                if snapshot_calls == 1:
                    return "Original durable app snapshot. token=sk-original-secret123"
                return "Changed live app content must not replace the durable operation."

            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
                app_snapshot_provider=changing_snapshot,
            )
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )
            capture_id = "s2cap_" + ("a" * 32)
            first = manager.capture_app_snapshot(
                connection_id=attached["connection_id"],
                confirmed=True,
                capture_id=capture_id,
            )
            replay = manager.capture_app_snapshot(
                connection_id=attached["connection_id"],
                confirmed=True,
                capture_id=capture_id,
            )

        self.assertEqual(snapshot_calls, 1)
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["capture_id"], capture_id)
        self.assertEqual(replay["protocol"], "capture.v2")
        self.assertEqual(replay["capture_protocol"], "capture.v2")
        self.assertTrue(replay["receipt_compact"])
        self.assertTrue(replay["replay_without_live_read"])
        self.assertFalse(replay["snapshot_quality"]["signal_stats_known"])
        self.assertEqual(replay["quality_badge"]["label"], "Durable replay")

    def test_dynamic_clipboard_lost_response_replays_without_reading_changed_text(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
            )
            clipboard_calls = 0

            def changing_clipboard():
                nonlocal clipboard_calls
                clipboard_calls += 1
                if clipboard_calls == 1:
                    return "Original clipboard selection. password=hunter2"
                return "Changed clipboard text must not replace the durable operation."

            manager._read_clipboard = changing_clipboard  # type: ignore[method-assign]
            capture_id = "s2cap_" + ("b" * 32)
            first = manager.capture_clipboard_once(
                text=None,
                context_id="demo",
                source_tag="frontmost-selection",
                speaker="operator",
                capture_id=capture_id,
            )
            replay = manager.capture_clipboard_once(
                text=None,
                context_id="demo",
                source_tag="frontmost-selection",
                speaker="operator",
                capture_id=capture_id,
            )

        self.assertEqual(clipboard_calls, 1)
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["capture_id"], capture_id)
        self.assertEqual(replay["protocol"], "capture.v2")
        self.assertEqual(replay["capture_protocol"], "capture.v2")
        self.assertTrue(replay["receipt_compact"])
        self.assertTrue(replay["replay_without_live_read"])

    def test_app_snapshot_preview_reports_quality_without_writing_memory(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
                app_snapshot_provider=lambda app: (
                    f"{app['app_name']} active transcript: SYNAPSE-S2 is validating App Connect. "
                    "token=sk-preview-secret123\nWindow: Workbench\nButton: Snapshot to memory"
                ),
            )
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )
            before = backend.list_memory(context_id="demo", limit=20)["entry_count"]

            preview = manager.preview_app_snapshot(connection_id=attached["connection_id"])
            after = backend.list_memory(context_id="demo", limit=20)["entry_count"]

        self.assertEqual(preview["action"], "preview-app-snapshot")
        self.assertEqual(preview["adapter_kind"], "app-accessibility-snapshot")
        self.assertEqual(preview["app_name"], "Codex")
        self.assertIn("SYNAPSE-S2 is validating App Connect", preview["preview_text"])
        self.assertNotIn("sk-preview-secret123", preview["preview_text"])
        self.assertGreaterEqual(preview["snapshot_quality"]["signal_chars"], 40)
        self.assertIn(preview["quality_badge"]["status"], {"ready", "degraded", "blocked"})
        self.assertIn(preview["capability_badge"]["level"], {
            "rich_text_available",
            "window_metadata_only",
            "selection_capture_recommended",
            "accessibility_blocked",
        })
        self.assertTrue(preview["capture_guidance"])
        self.assertEqual(after, before)

    def test_app_snapshot_preview_never_returns_raw_secret_or_raw_input_digest(self):
        raw_snapshot = (
            "Application: Codex\n"
            "Window: Production hardening\n"
            "API token=sk-preview-raw-secret123\n"
            "Button: Capture\n"
        )
        raw_digest = hashlib.sha256(raw_snapshot.encode("utf-8")).hexdigest()
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
                app_snapshot_provider=lambda _app: raw_snapshot,
            )
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )

            preview = manager.preview_app_snapshot(
                connection_id=attached["connection_id"]
            )
            serialized = json.dumps(preview, sort_keys=True)

        self.assertNotIn("sk-preview-raw-secret123", serialized)
        self.assertNotIn(raw_digest, serialized)
        self.assertNotIn("input_sha256", preview)
        self.assertIn("[REDACTED_SECRET]", preview["preview_text"])

    def test_app_snapshot_preview_failure_returns_blocked_receipt_without_writing_memory(self):
        def fail_snapshot(_app):
            raise ValueError("Accessibility blocked this app")

        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
                app_snapshot_provider=fail_snapshot,
            )
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )
            before = backend.list_memory(context_id="demo", limit=20)["entry_count"]

            preview = manager.preview_app_snapshot(connection_id=attached["connection_id"])
            after = backend.list_memory(context_id="demo", limit=20)["entry_count"]

        self.assertEqual(preview["action"], "preview-app-snapshot")
        self.assertEqual(preview["app_name"], "Codex")
        self.assertEqual(preview["quality_badge"]["status"], "blocked")
        self.assertEqual(preview["snapshot_quality"]["quality"], "blocked")
        self.assertEqual(preview["snapshot_quality"]["signal_chars"], 0)
        self.assertIn("selected-text", " ".join(preview["capture_guidance"]))
        self.assertFalse(preview["writes_memory"])
        self.assertEqual(after, before)

    def test_app_selected_text_capture_uses_connection_metadata_and_redacts(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
            )
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )

            with self.assertRaises(ValueError):
                manager.capture_app_selected_text(
                    connection_id=attached["connection_id"],
                    text="Selected Codex transcript should require confirmation.",
                    confirmed=False,
                )

            capture = manager.capture_app_selected_text(
                connection_id=attached["connection_id"],
                text="Selected Codex transcript contains token=sk-selected-secret123.",
                confirmed=True,
                metadata={"source": "unit-test"},
            )
            memory = backend.list_memory(context_id="demo", limit=10)
            captured = [
                entry
                for entry in memory["entries"]
                if entry["metadata"].get("adapter_kind") == "app-selected-text"
            ]

        self.assertEqual(capture["adapter_kind"], "app-selected-text")
        self.assertEqual(capture["app_name"], "Codex")
        self.assertEqual(capture["connection_id"], attached["connection_id"])
        self.assertIn("app-selected-text", attached["adapter_kinds"])
        self.assertGreaterEqual(capture["event_count"], 1)
        self.assertEqual(capture["protocol"], "capture.v2")
        self.assertEqual(capture["capture_protocol"], "capture.v2")
        self.assertTrue(captured)
        self.assertEqual(captured[0]["metadata"]["app_name"], "Codex")
        self.assertEqual(captured[0]["metadata"]["connection_id"], attached["connection_id"])
        self.assertEqual(captured[0]["metadata"]["capture_mode"], "confirmed-selected-text-fallback")
        self.assertTrue(all("sk-selected-secret123" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))

    def test_dynamic_app_selected_text_replays_before_changed_clipboard_read(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
            )
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )
            clipboard_calls = 0

            def changing_clipboard():
                nonlocal clipboard_calls
                clipboard_calls += 1
                if clipboard_calls == 1:
                    return "Original selected app text. token=sk-selected-original123"
                return "Changed selected text must not replace durable capture."

            manager._read_clipboard = changing_clipboard  # type: ignore[method-assign]
            capture_id = "s2cap_" + ("c" * 32)
            first = manager.capture_app_selected_text(
                connection_id=attached["connection_id"],
                text=None,
                confirmed=True,
                capture_id=capture_id,
            )
            replay = manager.capture_app_selected_text(
                connection_id=attached["connection_id"],
                text=None,
                confirmed=True,
                capture_id=capture_id,
            )

        self.assertEqual(clipboard_calls, 1)
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["capture_id"], capture_id)
        self.assertEqual(replay["protocol"], "capture.v2")
        self.assertEqual(replay["capture_protocol"], "capture.v2")
        self.assertTrue(replay["receipt_compact"])
        self.assertTrue(replay["replay_without_live_read"])

    def test_explicit_selected_text_retry_retains_fingerprint_conflict_check(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
            )
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                source_tag="codex-app",
                speaker="operator",
                confirmed=True,
            )
            capture_id = "s2cap_" + ("d" * 32)
            manager.capture_app_selected_text(
                connection_id=attached["connection_id"],
                text="Original explicit selected text.",
                confirmed=True,
                capture_id=capture_id,
            )

            with self.assertRaisesRegex(
                ValueError,
                r"different (?:capture )?request",
            ):
                manager.capture_app_selected_text(
                    connection_id=attached["connection_id"],
                    text="Changed explicit selected text.",
                    confirmed=True,
                    capture_id=capture_id,
                )

    def test_accessibility_snapshot_resolves_ps_name_to_visible_app_name(self):
        with TemporaryDirectory() as tmp:
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=self.make_backend(tmp),
            )
            manager._detect_visible_application_processes = lambda: [  # type: ignore[method-assign]
                {
                    "app_name": "Codex",
                    "bundle_id": "com.openai.codex",
                    "pid": 4242,
                    "detection": "system-events",
                }
            ]
            calls = []

            def fake_run(args, **_kwargs):
                calls.append(args)
                return SimpleNamespace(
                    stdout=(
                        "Application: Codex\n"
                        "missing value\n"
                        "Window 1: Codex\n"
                        "Window 1: Codex\n"
                    )
                )

            with patch("transcript_capture.subprocess.run", side_effect=fake_run):
                snapshot = manager._snapshot_app_accessibility(
                    {
                        "app_name": "codex",
                        "bundle_id": "",
                        "pid": 4242,
                    }
                )

        self.assertEqual(calls[0][-1], "Codex")
        self.assertIn("Application: Codex", snapshot)
        self.assertNotIn("missing value", snapshot)
        self.assertEqual(snapshot.count("Window 1: Codex"), 1)

    def test_running_app_detection_falls_back_to_process_list_when_provider_fails(self):
        with TemporaryDirectory() as tmp:
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(
                root=Path(tmp) / "capture-root",
                backend=backend,
                running_app_provider=lambda: (_ for _ in ()).throw(RuntimeError("blocked")),
            )
            manager._detect_running_apps_ps = lambda: [  # type: ignore[method-assign]
                {
                    "app_name": "Terminal",
                    "bundle_id": "",
                    "pid": 9001,
                    "detection": "ps",
                }
            ]

            detected = manager.detect_running_apps()

        self.assertEqual(detected["warning"], "RuntimeError")
        self.assertGreaterEqual(detected["elapsed_ms"], 0)
        self.assertEqual(detected["app_count"], 1)
        self.assertEqual(detected["apps"][0]["app_name"], "Terminal")


if __name__ == "__main__":
    unittest.main()

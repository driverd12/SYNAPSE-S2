import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mlx_backend import SpikingAttentionBackend
from transcript_capture import TranscriptCaptureManager


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
        self.assertEqual(second_poll["captured_source_count"], 0)
        self.assertTrue(captured)
        self.assertTrue(all("Historical line" not in entry["source_text"] for entry in captured))
        self.assertTrue(all("sk-secret123" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))
        self.assertTrue(any(entry["metadata"]["adapter_kind"] == "file-tail" for entry in captured))
        self.assertTrue(any(entry["metadata"]["redaction_count"] >= 1 for entry in captured))

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
        self.assertTrue(captured)
        self.assertTrue(all("sk-app-secret123" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))
        self.assertEqual(captured[0]["metadata"]["app_name"], "Google Chrome")

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
        self.assertTrue(captured)
        self.assertEqual(captured[0]["metadata"]["app_name"], "Codex")
        self.assertEqual(captured[0]["metadata"]["connection_id"], attached["connection_id"])
        self.assertEqual(captured[0]["metadata"]["capture_mode"], "confirmed-selected-text-fallback")
        self.assertTrue(all("sk-selected-secret123" not in entry["source_text"] for entry in captured))
        self.assertTrue(any("[REDACTED_SECRET]" in entry["source_text"] for entry in captured))

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

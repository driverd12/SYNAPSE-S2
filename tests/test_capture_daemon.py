import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from capture_daemon import CaptureInboxDaemon, redact_capture_text, write_capture_drop
from mlx_backend import SpikingAttentionBackend


class CaptureInboxDaemonTests(unittest.TestCase):
    def test_redacts_common_secret_shapes(self):
        text = (
            "api_key=sk-test-secret123 token: ghp_abcdefghijklmnopqrstuvwxyz123456 "
            "password=hunter2"
        )

        redacted, count = redact_capture_text(text)

        self.assertGreaterEqual(count, 3)
        self.assertNotIn("sk-test-secret123", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", redacted)
        self.assertNotIn("hunter2", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_process_once_ingests_inbox_payloads_and_moves_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = SpikingAttentionBackend(
                dimension=32,
                num_neurons=24,
                default_top_k=4,
                recall_count=4,
                compile_graph=False,
                state_path=root / "runtime_state.json",
                memory_path=root / "memory.sqlite3",
            )
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            drop_path = write_capture_drop(
                root=root,
                context_id="demo",
                source_tag="magic-session",
                speaker="codex",
                text=(
                    "User asked for passive SYNAPSE-S2 capture. "
                    "Codex added a local inbox daemon. "
                    "The daemon redacts api_key=sk-test-secret123 before ingestion."
                ),
                metadata={"surface": "unit-test"},
            )

            result = daemon.process_once()
            empty_poll = daemon.process_once()
            graph = backend.list_memory_graph(context_id="demo", limit=20)
            status = daemon.status()

        self.assertEqual(result["processed_file_count"], 1)
        self.assertEqual(result["captured_event_count"], 3)
        self.assertEqual(result["error_file_count"], 0)
        self.assertEqual(empty_poll["processed_file_count"], 0)
        self.assertFalse(drop_path.exists())
        self.assertEqual(status["pending_file_count"], 0)
        self.assertEqual(status["processed_file_count"], 1)
        self.assertEqual(status["last_result"]["captured_event_count"], 3)
        self.assertTrue(
            any(
                entry["tag"].startswith("magic-session-event")
                for entry in graph["entries"]
            )
        )
        self.assertTrue(
            all("sk-test-secret123" not in entry["source_text"] for entry in graph["entries"])
        )
        captured = [
            entry for entry in graph["entries"]
            if entry["tag"].startswith("magic-session-event")
        ]
        self.assertTrue(all(entry["metadata"]["capture_daemon"] is True for entry in captured))
        self.assertTrue(any(entry["metadata"]["redaction_count"] >= 1 for entry in captured))

    def test_jsonl_drop_processes_multiple_payloads(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = SpikingAttentionBackend(
                dimension=32,
                num_neurons=24,
                default_top_k=4,
                recall_count=4,
                compile_graph=False,
                state_path=root / "runtime_state.json",
                memory_path=root / "memory.sqlite3",
            )
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            (inbox / "multi-session.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "context_id": "demo",
                                "source_tag": "multi-one",
                                "speaker": "codex",
                                "text": "First dropped capture payload is temporal.",
                            }
                        ),
                        json.dumps(
                            {
                                "context_id": "demo",
                                "source_tag": "multi-two",
                                "speaker": "codex",
                                "text": "Second dropped capture payload is also temporal.",
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )

            result = daemon.process_once()
            graph = backend.list_memory_graph(context_id="demo", limit=20)

        self.assertEqual(result["processed_file_count"], 1)
        self.assertEqual(result["captured_payload_count"], 2)
        self.assertTrue(any(entry["tag"].startswith("multi-one") for entry in graph["entries"]))
        self.assertTrue(any(entry["tag"].startswith("multi-two") for entry in graph["entries"]))


if __name__ == "__main__":
    unittest.main()

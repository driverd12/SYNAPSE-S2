import json
import os
import hashlib
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import capture_daemon
from capture_daemon import (
    CAPTURE_ID_RE,
    STALE_INBOX_TEMP_SECONDS,
    CaptureInboxDaemon,
    redact_capture_text,
    write_capture_drop,
)
from mlx_backend import SpikingAttentionBackend


class RecordingBackend:
    def __init__(self, *, delay: float = 0.0, error: BaseException | None = None):
        self.delay = delay
        self.error = error
        self.calls: list[dict] = []
        self.effects: list[dict] = []
        self._operations: dict[str, tuple[str, dict]] = {}
        self._lock = threading.Lock()

    def capture_conversation(self, **kwargs):
        fingerprint = json.dumps(kwargs, sort_keys=True, separators=(",", ":"))
        with self._lock:
            self.calls.append(kwargs)
        if self.delay:
            time.sleep(self.delay)
        if self.error is not None:
            raise self.error
        with self._lock:
            existing = self._operations.get(kwargs["capture_id"])
            if existing is not None:
                if existing[0] != fingerprint:
                    raise ValueError(
                        "capture_id is already committed for a different capture request"
                    )
                return {**existing[1], "idempotent_replay": True}
            effect_number = len(self.effects) + 1
            result = {
                "capture_id": kwargs["capture_id"],
                "context_id": kwargs["context_id"],
                "source_tag": kwargs["source_tag"],
                "speaker": kwargs["speaker"],
                "event_count": 1,
                "relationship_count": 2,
                "agent_deployment": {
                    "action": "publish-context-event",
                    "context_id": kwargs["context_id"],
                    "event_id": effect_number,
                    "event_type": "conversation-capture",
                    "payload": {"intentionally": "omitted from compact receipt"},
                },
                "idempotent_replay": False,
            }
            self.effects.append(kwargs)
            self._operations[kwargs["capture_id"]] = (fingerprint, result)
            return result


class FailOnceForCaptureBackend(RecordingBackend):
    def __init__(self, capture_id: str):
        super().__init__()
        self.capture_id = capture_id
        self.failed = False

    def capture_conversation(self, **kwargs):
        if kwargs["capture_id"] == self.capture_id and not self.failed:
            self.failed = True
            with self._lock:
                self.calls.append(kwargs)
            raise RuntimeError("simulated second-record backend failure")
        return super().capture_conversation(**kwargs)


class CrashBeforeProcessedMoveDaemon(CaptureInboxDaemon):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.crashed = False

    def _move_file(self, path: Path, destination_dir: Path) -> Path:
        if destination_dir.name == "capture_processed" and not self.crashed:
            self.crashed = True
            raise KeyboardInterrupt("simulated crash after durable capture receipt")
        return super()._move_file(path, destination_dir)


class FailProcessedMoveOnceDaemon(CaptureInboxDaemon):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.failed = False

    def _move_file(self, path: Path, destination_dir: Path) -> Path:
        if destination_dir.name == "capture_processed" and not self.failed:
            self.failed = True
            raise OSError("simulated archive failure")
        return super()._move_file(path, destination_dir)


class CaptureInboxDaemonTests(unittest.TestCase):
    def test_redacts_common_secret_shapes(self):
        text = (
            "api_key=sk-test-secret123 token: ghp_abcdefghijklmnopqrstuvwxyz123456 "
            "password=hunter2 "
            '{"client_secret": "plain-secret-value"} '
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart"
        )

        redacted, count = redact_capture_text(text)

        self.assertGreaterEqual(count, 3)
        self.assertNotIn("sk-test-secret123", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", redacted)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("plain-secret-value", redacted)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

    def test_v2_drop_has_canonical_identity_and_propagates_it(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            capture_id = "s2cap_0123456789abcdef0123456789abcdef"
            drop_path = write_capture_drop(
                root=root,
                context_id="demo",
                source_tag="v2-session",
                speaker="codex",
                text="A durable v2 capture payload.",
                metadata={"surface": "unit-test"},
                capture_id=capture_id,
            )
            payload = json.loads(drop_path.read_text(encoding="utf-8"))
            result = CaptureInboxDaemon(root=root, backend=backend).process_once()

        self.assertEqual(payload["version"], 2)
        self.assertEqual(payload["capture_id"], capture_id)
        self.assertRegex(payload["capture_id"], CAPTURE_ID_RE)
        self.assertNotIn("input_sha256", payload)
        self.assertEqual(result["processed_file_count"], 1)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(backend.calls[0]["capture_id"], capture_id)
        self.assertEqual(backend.calls[0]["metadata"]["capture_id"], capture_id)
        self.assertNotIn("input_sha256", backend.calls[0]["metadata"])

    def test_status_and_preflight_do_not_construct_mlx_backend(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            inbox = root / "capture_inbox"
            inbox.mkdir(parents=True, exist_ok=True)
            raw_payload = json.dumps(
                {
                    "version": 2,
                    "capture_id": "s2cap_99999999999999999999999999999999",
                    "text": "api_key=sk-preflight-secret-123456",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            (inbox / "lazy-secret.json").write_text(raw_payload, encoding="utf-8")
            raw_sha256 = hashlib.sha256(raw_payload.encode()).hexdigest()
            with patch(
                "capture_daemon.mlx_backend.get_backend",
                side_effect=AssertionError("backend must remain lazy"),
            ):
                daemon = CaptureInboxDaemon(root=root)
                status = daemon.status()
                preflight = daemon.preflight()

        self.assertEqual(status["pending_file_count"], 1)
        self.assertEqual(status["processing_file_count"], 0)
        selected = preflight["selected_files"][0]
        serialized_preflight = json.dumps(preflight, sort_keys=True)
        self.assertNotIn("sha256", selected)
        self.assertRegex(selected["transport_token"], r"^[0-9a-f]{64}$")
        self.assertRegex(selected["request_fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(selected["fingerprint_mode"], "post-redaction-request")
        self.assertNotIn(raw_sha256, serialized_preflight)
        self.assertNotIn("sk-preflight-secret-123456", serialized_preflight)

    def test_concurrent_workers_atomically_claim_one_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend(delay=0.05)
            write_capture_drop(root=root, text="Only one worker may capture this file.")
            daemons = [
                CaptureInboxDaemon(root=root, backend=backend),
                CaptureInboxDaemon(root=root, backend=backend),
            ]
            barrier = threading.Barrier(2)
            results: list[dict] = []

            def run(daemon):
                barrier.wait()
                results.append(daemon.process_once())

            threads = [threading.Thread(target=run, args=(daemon,)) for daemon in daemons]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)

            status = daemons[0].status()

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(sum(item["processed_file_count"] for item in results), 1)
        self.assertEqual(status["pending_file_count"], 0)
        self.assertEqual(status["processing_file_count"], 0)
        self.assertEqual(status["processed_file_count"], 1)

    def test_malformed_preflight_uses_only_transport_metadata_token(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            inbox = root / "capture_inbox"
            inbox.mkdir(parents=True, exist_ok=True)
            raw = '{"text":"api_key=sk-malformed-secret-123456"'
            (inbox / "malformed.json").write_text(raw, encoding="utf-8")
            raw_sha256 = hashlib.sha256(raw.encode()).hexdigest()

            preflight = CaptureInboxDaemon(
                root=root,
                backend=RecordingBackend(),
            ).preflight()

        selected = preflight["selected_files"][0]
        serialized = json.dumps(preflight, sort_keys=True)
        self.assertEqual(selected["fingerprint_mode"], "transport-metadata-only")
        self.assertEqual(selected["request_fingerprint"], "")
        self.assertRegex(selected["transport_token"], r"^[0-9a-f]{64}$")
        self.assertNotIn(raw_sha256, serialized)
        self.assertNotIn("sk-malformed-secret-123456", serialized)

    def test_stale_inbox_temps_are_quarantined_without_ingestion_or_content_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            stale_content = '{"text":"api_key=sk-stale-temp-secret-123456"'
            stale_path = inbox / "stale.json.tmp"
            stale_path.write_text(stale_content, encoding="utf-8")
            fresh_path = inbox / "fresh.json.tmp"
            fresh_path.write_text('{"text":"still-being-written"', encoding="utf-8")
            atomic_fresh_path = inbox / (
                ".capture.json.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp"
            )
            atomic_fresh_path.write_text("atomic writer temp", encoding="utf-8")
            outside = root / "outside.json"
            outside.write_text('{"text":"do-not-follow"}', encoding="utf-8")
            symlink_path = inbox / "linked.json.tmp"
            os.symlink(outside, symlink_path)
            real_now = time.time()
            observed_now = real_now + STALE_INBOX_TEMP_SECONDS + 60.0
            os.utime(fresh_path, (observed_now, observed_now))
            os.utime(atomic_fresh_path, (observed_now, observed_now))
            raw_sha256 = hashlib.sha256(stale_content.encode()).hexdigest()

            with patch("capture_daemon.time.time", return_value=observed_now):
                before = daemon.status()
                result = daemon.process_once()
                retry = daemon.process_once()
                after = daemon.status()

            evidence_path = next(
                (root / "capture_errors").glob(
                    "stale-temp-stale.json.tmp.evidence.json"
                )
            )
            evidence_text = evidence_path.read_text(encoding="utf-8")
            evidence = json.loads(evidence_text)

            self.assertEqual(before["pending_file_count"], 0)
            self.assertEqual(before["inbox_temp_file_count"], 4)
            self.assertEqual(before["fresh_inbox_temp_file_count"], 2)
            self.assertEqual(before["stale_inbox_temp_file_count"], 1)
            self.assertEqual(before["ignored_inbox_temp_file_count"], 1)
            self.assertEqual(result["quarantined_stale_temp_count"], 1)
            self.assertEqual(result["temp_quarantine_evidence_error_count"], 0)
            self.assertEqual(result["inbox_temp_file_count"], 3)
            self.assertEqual(result["fresh_inbox_temp_file_count"], 2)
            self.assertEqual(result["stale_inbox_temp_file_count"], 0)
            self.assertEqual(result["ignored_inbox_temp_file_count"], 1)
            self.assertEqual(retry["quarantined_stale_temp_count"], 0)
            self.assertEqual(len(backend.calls), 0)
            self.assertEqual(after["processed_file_count"], 0)
            self.assertFalse(stale_path.exists())
            self.assertTrue(fresh_path.exists())
            self.assertTrue(atomic_fresh_path.exists())
            self.assertTrue(symlink_path.is_symlink())
            self.assertTrue(
                (root / "capture_errors" / "stale-temp-stale.json.tmp").exists()
            )
            self.assertEqual(after["last_result"], result)
            self.assertEqual(evidence["artifact_type"], "stale-capture-inbox-temp")
            self.assertEqual(evidence["temp_kind"], "legacy-write-temp")
            self.assertFalse(evidence["content_inspected"])
            self.assertFalse(evidence["content_digest_recorded"])
            self.assertRegex(evidence["transport_token"], r"^[0-9a-f]{64}$")
            self.assertNotIn("sk-stale-temp-secret-123456", evidence_text)
            self.assertNotIn(raw_sha256, evidence_text)

    def test_duplicate_capture_ids_in_batch_are_rejected_before_effect(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            capture_id = "s2cap_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            (inbox / "duplicate.json").write_text(
                json.dumps(
                    [
                        {"version": 2, "capture_id": capture_id, "text": "one"},
                        {"version": 2, "capture_id": capture_id, "text": "two"},
                    ]
                ),
                encoding="utf-8",
            )

            result = daemon.process_once()
            retry = daemon.process_once()

        self.assertEqual(len(backend.calls), 0)
        self.assertEqual(result["error_file_count"], 1)
        self.assertIn("duplicate capture_id", result["errors"][0]["error"])
        self.assertEqual(retry["error_file_count"], 0)

    def test_legacy_id_is_persisted_before_capture_and_reused_on_recovery(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            interrupted_backend = RecordingBackend(
                error=KeyboardInterrupt("simulated process death")
            )
            daemon = CaptureInboxDaemon(root=root, backend=interrupted_backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            (inbox / "legacy.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "text": "Legacy capture survives process interruption.",
                        "input_sha256": "raw-input-hash-must-not-be-identity",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(KeyboardInterrupt):
                daemon.process_once()
            processing_files = list(
                (root / "capture_processing").glob("s2claim_*/*.json")
            )
            self.assertEqual(len(processing_files), 1)
            persisted = json.loads(processing_files[0].read_text(encoding="utf-8"))
            first_capture_id = interrupted_backend.calls[0]["capture_id"]

            recovery_backend = RecordingBackend()
            result = CaptureInboxDaemon(
                root=root,
                backend=recovery_backend,
            ).process_once()

        self.assertRegex(persisted["capture_id"], CAPTURE_ID_RE)
        self.assertNotIn("input_sha256", persisted)
        self.assertEqual(persisted["capture_id"], first_capture_id)
        self.assertEqual(recovery_backend.calls[0]["capture_id"], first_capture_id)
        self.assertEqual(result["processed_file_count"], 1)

    def test_crash_after_receipt_recovers_without_second_backend_effect(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            write_capture_drop(root=root, text="Receipt closes archive-move crash gap.")
            crashing = CrashBeforeProcessedMoveDaemon(root=root, backend=backend)

            with self.assertRaises(KeyboardInterrupt):
                crashing.process_once()
            self.assertEqual(len(backend.calls), 1)
            self.assertEqual(len(list((root / "capture_receipts").glob("*.json"))), 1)
            self.assertEqual(
                len(list((root / "capture_processing").glob("s2claim_*/*.json"))),
                1,
            )

            result = CaptureInboxDaemon(root=root, backend=backend).process_once()

        self.assertEqual(len(backend.calls), 2)
        self.assertEqual(len(backend.effects), 1)
        self.assertEqual(result["processed_file_count"], 1)
        self.assertEqual(result["idempotent_capture_count"], 1)
        self.assertTrue(result["captures"][0]["receipt_replay"])

    def test_receipt_write_failure_leaves_cleanup_pending_then_recovers(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            write_capture_drop(root=root, text="Receipt persistence may fail after commit.")
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            original_write = capture_daemon._atomic_write_private_text
            failed = False

            def fail_one_receipt(path, text):
                nonlocal failed
                if path.parent.name == "capture_receipts" and not failed:
                    failed = True
                    raise OSError("simulated receipt fsync failure")
                return original_write(path, text)

            with patch(
                "capture_daemon._atomic_write_private_text",
                side_effect=fail_one_receipt,
            ):
                first = daemon.process_once()

            self.assertEqual(first["error_file_count"], 0)
            self.assertEqual(first["deferred_file_count"], 1)
            self.assertEqual(len(backend.effects), 1)
            self.assertEqual(
                len(list((root / "capture_processing").glob("s2claim_*/*.json"))),
                1,
            )
            self.assertEqual(
                list((root / "capture_errors").glob("*.error.json")),
                [],
            )

            recovered = CaptureInboxDaemon(root=root, backend=backend).process_once()

        self.assertEqual(len(backend.effects), 1)
        self.assertEqual(len(backend.calls), 2)
        self.assertEqual(recovered["processed_file_count"], 1)
        self.assertEqual(recovered["error_file_count"], 0)
        self.assertEqual(recovered["idempotent_capture_count"], 1)

    def test_archive_failure_leaves_cleanup_pending_then_recovers(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            write_capture_drop(root=root, text="Archive cleanup follows durable commit.")
            first = FailProcessedMoveOnceDaemon(
                root=root,
                backend=backend,
            ).process_once()

            self.assertEqual(first["error_file_count"], 0)
            self.assertEqual(first["deferred_file_count"], 1)
            self.assertEqual(len(backend.effects), 1)
            self.assertEqual(
                len(list((root / "capture_processing").glob("s2claim_*/*.json"))),
                1,
            )

            recovered = CaptureInboxDaemon(root=root, backend=backend).process_once()

        self.assertEqual(len(backend.effects), 1)
        self.assertEqual(len(backend.calls), 2)
        self.assertEqual(recovered["processed_file_count"], 1)
        self.assertEqual(recovered["error_file_count"], 0)

    def test_transport_receipt_cannot_suppress_capture_missing_from_backend_ledger(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=first_backend)
            write_capture_drop(root=root, text="Backend ledger remains authoritative.")
            first = daemon.process_once()
            processed_path = next((root / "capture_processed").glob("*.json"))
            replay_text = processed_path.read_text(encoding="utf-8")

            restored_backend = RecordingBackend()
            inbox = root / "capture_inbox"
            (inbox / "restored-copy.json").write_text(replay_text, encoding="utf-8")
            restored = CaptureInboxDaemon(
                root=root,
                backend=restored_backend,
            ).process_once()

        self.assertEqual(first["processed_file_count"], 1)
        self.assertEqual(len(first_backend.effects), 1)
        self.assertEqual(len(restored_backend.calls), 1)
        self.assertEqual(len(restored_backend.effects), 1)
        self.assertEqual(restored["processed_file_count"], 1)
        self.assertFalse(restored["captures"][0]["idempotent_replay"])
        self.assertTrue(restored["captures"][0]["receipt_replay"])

    def test_receipt_fingerprint_uses_only_post_redaction_request(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 2,
                "capture_id": "s2cap_dddddddddddddddddddddddddddddddd",
                "text": "api_key=sk-super-secret-123456789",
                "metadata": {
                    "password": "password=hunter2",
                    "input_sha256": "untrusted-raw-digest",
                },
            }
            raw_payload = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            )
            raw_payload_sha256 = hashlib.sha256(raw_payload.encode()).hexdigest()
            (inbox / "secret.json").write_text(raw_payload, encoding="utf-8")

            result = daemon.process_once()
            receipt_text = next(
                (root / "capture_receipts").glob("*.json")
            ).read_text(encoding="utf-8")
            processed_text = next(
                (root / "capture_processed").glob("*.json")
            ).read_text(encoding="utf-8")

        self.assertEqual(result["processed_file_count"], 1)
        self.assertNotIn("sk-super-secret-123456789", receipt_text)
        self.assertNotIn("hunter2", receipt_text)
        self.assertNotIn("untrusted-raw-digest", receipt_text)
        self.assertNotIn(raw_payload_sha256, receipt_text)
        self.assertNotIn('"payload_sha256"', receipt_text)
        self.assertIn('"request_fingerprint"', receipt_text)
        self.assertNotIn("sk-super-secret-123456789", processed_text)
        self.assertNotIn("input_sha256", processed_text)
        self.assertIn("[REDACTED_SECRET]", backend.calls[0]["text"])

    def test_replayed_payload_is_suppressed_by_capture_receipt(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 2,
                "capture_id": "s2cap_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "text": "The same transport payload may be delivered twice.",
            }
            (inbox / "replay-one.json").write_text(json.dumps(payload), encoding="utf-8")
            (inbox / "replay-two.json").write_text(json.dumps(payload), encoding="utf-8")

            result = daemon.process_once()

        self.assertEqual(len(backend.calls), 2)
        self.assertEqual(len(backend.effects), 1)
        self.assertEqual(result["processed_file_count"], 2)
        self.assertEqual(result["captured_payload_count"], 2)
        self.assertEqual(result["idempotent_capture_count"], 1)

    def test_reused_capture_id_with_different_payload_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            capture_id = "s2cap_cccccccccccccccccccccccccccccccc"
            first = {"version": 2, "capture_id": capture_id, "text": "first"}
            second = {"version": 2, "capture_id": capture_id, "text": "second"}
            (inbox / "one.json").write_text(json.dumps(first), encoding="utf-8")
            (inbox / "two.json").write_text(json.dumps(second), encoding="utf-8")

            result = daemon.process_once()

        self.assertEqual(len(backend.calls), 2)
        self.assertEqual(len(backend.effects), 1)
        self.assertEqual(result["processed_file_count"], 1)
        self.assertEqual(result["error_file_count"], 1)
        self.assertIn("different", result["errors"][0]["error"])

    def test_backend_error_is_quarantined_and_not_automatically_retried(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend(error=RuntimeError("backend unavailable"))
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            write_capture_drop(root=root, text="A failed capture must be quarantined.")

            result = daemon.process_once()
            retry = daemon.process_once()

        self.assertEqual(result["error_file_count"], 1)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(retry["processed_file_count"], 0)
        self.assertEqual(retry["error_file_count"], 0)

    def test_legacy_jsonl_ids_are_unique_and_persisted_before_effect(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend(error=KeyboardInterrupt("stop after prepare"))
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            (inbox / "legacy.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"text": "same", "input_sha256": "discard-one"}),
                        json.dumps({"text": "same", "input_sha256": "discard-two"}),
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaises(KeyboardInterrupt):
                daemon.process_once()
            claimed = next(
                (root / "capture_processing").glob("s2claim_*/*.jsonl")
            )
            payloads = [
                json.loads(line)
                for line in claimed.read_text(encoding="utf-8").splitlines()
                if line
            ]

        self.assertEqual(len(payloads), 2)
        self.assertEqual(len({item["capture_id"] for item in payloads}), 2)
        self.assertTrue(all(CAPTURE_ID_RE.fullmatch(item["capture_id"]) for item in payloads))
        self.assertTrue(all("input_sha256" not in item for item in payloads))

    def test_identical_legacy_drops_receive_distinct_random_ids(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            legacy = json.dumps({"version": 1, "text": "identical legacy payload"})
            (inbox / "legacy-one.json").write_text(legacy, encoding="utf-8")
            (inbox / "legacy-two.json").write_text(legacy, encoding="utf-8")

            result = daemon.process_once()

        capture_ids = {call["capture_id"] for call in backend.calls}
        self.assertEqual(result["processed_file_count"], 2)
        self.assertEqual(len(backend.effects), 2)
        self.assertEqual(len(capture_ids), 2)
        self.assertTrue(all(CAPTURE_ID_RE.fullmatch(item) for item in capture_ids))

    def test_legacy_text_sidecar_preserves_identity_and_defaults_across_rename(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            interrupted = RecordingBackend(
                error=KeyboardInterrupt("stop after text identity persistence")
            )
            daemon = CaptureInboxDaemon(root=root, backend=interrupted)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            (inbox / "operator-notes.txt").write_text(
                "password=hunter2 survives only as redacted text",
                encoding="utf-8",
            )

            with self.assertRaises(KeyboardInterrupt):
                daemon.process_once()
            claim_dir = next((root / "capture_processing").glob("s2claim_*"))
            claimed_text = next(claim_dir.glob("*.txt"))
            identity = json.loads(
                (claim_dir / ".capture-identity.json").read_text(encoding="utf-8")
            )
            self.assertNotIn("hunter2", claimed_text.read_text(encoding="utf-8"))
            renamed_text = claim_dir / "renamed-notes.txt"
            claimed_text.rename(renamed_text)

            recovered_backend = RecordingBackend()
            recovered = CaptureInboxDaemon(
                root=root,
                backend=recovered_backend,
            ).process_once()

        self.assertEqual(recovered["processed_file_count"], 1)
        self.assertEqual(
            recovered_backend.calls[0]["capture_id"],
            identity["capture_id"],
        )
        self.assertEqual(recovered_backend.calls[0]["source_tag"], "operator-notes")
        self.assertNotIn("hunter2", recovered_backend.calls[0]["text"])

    def test_processing_debris_is_removed_or_quarantined_before_effect(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            processing = daemon.paths()["processing_dir"]
            processing.mkdir(parents=True, exist_ok=True)
            empty_claim = processing / (
                "s2claim_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            )
            empty_claim.mkdir()
            old_time = time.time() - 120
            os.utime(empty_claim, (old_time, old_time))
            malformed_claim = processing / (
                "s2claim_ffffffffffffffffffffffffffffffff"
            )
            malformed_claim.mkdir()
            for index in (1, 2):
                (malformed_claim / f"payload-{index}.json").write_text(
                    json.dumps({"version": 1, "text": f"payload {index}"}),
                    encoding="utf-8",
                )
            before = daemon.status()

            result = daemon.process_once()
            after = daemon.status()

        self.assertEqual(before["processing_empty_claim_count"], 1)
        self.assertEqual(before["processing_malformed_claim_count"], 1)
        self.assertEqual(result["repaired_empty_claim_count"], 1)
        self.assertEqual(result["quarantined_claim_count"], 1)
        self.assertEqual(len(backend.effects), 0)
        self.assertEqual(after["processing_empty_claim_count"], 0)
        self.assertEqual(after["processing_malformed_claim_count"], 0)

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
            pending_text = drop_path.read_text(encoding="utf-8")
            drop_mode = drop_path.stat().st_mode & 0o777

            result = daemon.process_once()
            empty_poll = daemon.process_once()
            graph = backend.list_memory_graph(context_id="demo", limit=20)
            status = daemon.status()
            processed_file_texts = [
                path.read_text(encoding="utf-8")
                for path in (root / "capture_processed").glob("*.json")
            ]

        self.assertEqual(result["processed_file_count"], 1)
        self.assertEqual(drop_mode, 0o600)
        self.assertNotIn("sk-test-secret123", pending_text)
        self.assertIn("[REDACTED_SECRET]", pending_text)
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
        self.assertTrue(processed_file_texts)
        self.assertTrue(all("sk-test-secret123" not in text for text in processed_file_texts))

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

    def test_partial_jsonl_failure_sidecar_audits_committed_prefix_for_safe_requeue(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_capture_id = "s2cap_11111111111111111111111111111111"
            second_capture_id = "s2cap_22222222222222222222222222222222"
            backend = FailOnceForCaptureBackend(second_capture_id)
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            (inbox / "partial.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "version": 2,
                                "capture_id": first_capture_id,
                                "text": "First record commits before the later failure.",
                            }
                        ),
                        json.dumps(
                            {
                                "version": 2,
                                "capture_id": second_capture_id,
                                "text": "Second record fails once and is safe to retry.",
                            }
                        ),
                    ]
                ),
                encoding="utf-8",
            )

            first = daemon.process_once()
            sidecar_path = next(
                (root / "capture_errors").glob("partial.jsonl.error.json")
            )
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            quarantined = root / "capture_errors" / "partial.jsonl"
            os.replace(quarantined, inbox / "partial-retry.jsonl")
            repaired = daemon.process_once()

        self.assertEqual(first["processed_file_count"], 0)
        self.assertEqual(first["error_file_count"], 1)
        self.assertEqual(first["captured_payload_count"], 1)
        self.assertEqual(sidecar["batch_atomicity"], "per-record")
        self.assertEqual(sidecar["batch_record_count"], 2)
        self.assertEqual(sidecar["failed_record_index"], 1)
        self.assertEqual(sidecar["failed_capture_id"], second_capture_id)
        self.assertEqual(sidecar["committed_capture_count"], 1)
        self.assertEqual(sidecar["committed_capture_ids"], [first_capture_id])
        self.assertEqual(sidecar["committed_event_count"], 1)
        self.assertEqual(sidecar["committed_relationship_count"], 2)
        self.assertEqual(sidecar["idempotent_replay_count"], 0)
        self.assertEqual(sidecar["receipt_replay_count"], 0)
        self.assertEqual(
            sidecar["committed_captures"],
            [
                {
                    "capture_id": first_capture_id,
                    "context_id": "default",
                    "source_tag": "capture-daemon",
                    "event_count": 1,
                    "relationship_count": 2,
                    "idempotent_replay": False,
                    "receipt_replay": False,
                }
            ],
        )
        self.assertEqual(repaired["processed_file_count"], 1)
        self.assertEqual(repaired["error_file_count"], 0)
        self.assertEqual(repaired["captured_payload_count"], 2)
        self.assertEqual(repaired["idempotent_capture_count"], 1)
        self.assertEqual(len(backend.effects), 2)
        self.assertEqual(
            {effect["capture_id"] for effect in backend.effects},
            {first_capture_id, second_capture_id},
        )

    def test_process_once_rejects_symlink_payloads(self):
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
            secret_file = root / "outside-secret.txt"
            secret_file.write_text("api_key=sk-symlink-secret123", encoding="utf-8")
            link_path = inbox / "linked-secret.txt"
            os.symlink(secret_file, link_path)

            result = daemon.process_once()
            graph = backend.list_memory_graph(context_id="demo", limit=20)

        self.assertEqual(result["processed_file_count"], 0)
        self.assertEqual(result["error_file_count"], 0)
        self.assertEqual(graph["entry_count"], 0)


if __name__ == "__main__":
    unittest.main()

import json
import os
import hashlib
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import capture_daemon
from capture_daemon import (
    CAPTURE_ID_RE,
    CAPTURE_DEFERRED_DIR_NAME,
    STALE_INBOX_TEMP_SECONDS,
    CaptureInboxDaemon,
    begin_capture_replacement_freeze,
    redact_capture_text,
    release_capture_replacement_freeze,
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


class BatchRecordingBackend(RecordingBackend):
    def __init__(self):
        super().__init__()
        self.batch_entry_count = 0
        self.batch_exit_count = 0
        self.in_batch = False
        self.batch_observations: list[bool] = []

    @contextmanager
    def capture_batch(self):
        self.batch_entry_count += 1
        self.in_batch = True
        try:
            yield
        finally:
            self.in_batch = False
            self.batch_exit_count += 1

    def capture_conversation(self, **kwargs):
        self.batch_observations.append(self.in_batch)
        return super().capture_conversation(**kwargs)


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
    def test_first_use_backend_initialization_occurs_outside_capture_lock(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root)
            daemon.prepare_transport()
            invalid = root / "capture_inbox" / "invalid.json"
            invalid.write_text("{not-json", encoding="utf-8")
            invalid.chmod(0o600)
            original_lock = daemon._exclusive_lock
            state = {"lock_depth": 0, "backend_calls": 0}

            @contextmanager
            def observed_lock(*args, **kwargs):
                with original_lock(*args, **kwargs) as acquired:
                    if acquired:
                        state["lock_depth"] += 1
                    try:
                        yield acquired
                    finally:
                        if acquired:
                            state["lock_depth"] -= 1

            def backend_factory():
                self.assertEqual(state["lock_depth"], 0)
                state["backend_calls"] += 1
                return RecordingBackend()

            with (
                patch.object(daemon, "_exclusive_lock", side_effect=observed_lock),
                patch.object(
                    capture_daemon.mlx_backend,
                    "get_backend",
                    side_effect=backend_factory,
                ),
            ):
                result = daemon.process_once(max_files=1)

            self.assertEqual(state["backend_calls"], 1)
            self.assertEqual(state["lock_depth"], 0)
            self.assertEqual(result["error_file_count"], 1)

    def test_capture_lock_rejects_wrong_mode_symlink_and_hardlink(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())

            wrong_mode = root / "wrong-mode.lock"
            wrong_mode.write_text("preserve", encoding="utf-8")
            wrong_mode.chmod(0o644)
            wrong_mode_inode = wrong_mode.stat().st_ino
            with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
                with daemon._exclusive_lock(wrong_mode, blocking=True):
                    self.fail("unsafe lock must not be acquired")
            self.assertEqual(wrong_mode.stat().st_mode & 0o777, 0o644)
            self.assertEqual(wrong_mode.stat().st_ino, wrong_mode_inode)

            hardlink_target = root / "hardlink-target"
            hardlink_target.write_text("preserve", encoding="utf-8")
            hardlink_target.chmod(0o600)
            hardlink = root / "hardlink.lock"
            os.link(hardlink_target, hardlink)
            with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
                with daemon._exclusive_lock(hardlink, blocking=True):
                    self.fail("hard-linked lock must not be acquired")
            self.assertEqual(hardlink_target.stat().st_nlink, 2)

            symlink_target = root / "symlink-target"
            symlink_target.write_text("preserve", encoding="utf-8")
            symlink_target.chmod(0o600)
            symlink = root / "symlink.lock"
            symlink.symlink_to(symlink_target)
            with self.assertRaises(OSError):
                with daemon._exclusive_lock(symlink, blocking=True):
                    self.fail("symlink lock must not be acquired")
            self.assertEqual(symlink_target.read_text(encoding="utf-8"), "preserve")

    def test_capture_root_rejects_credential_shaped_path(self):
        with TemporaryDirectory() as tmp:
            marker = "SYNTHETIC_CAPTURE_ROOT_SECRET_42"
            unsafe = Path(tmp) / f"password={marker}"
            with self.assertRaises(ValueError) as raised:
                CaptureInboxDaemon(root=unsafe)

        self.assertNotIn(marker, str(raised.exception))
        self.assertFalse(unsafe.exists())

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
                metadata={
                    "surface": "unit-test",
                    "input_sha256": "raw-input-equality-oracle",
                    "nested": {"payload_sha256": "nested-equality-oracle"},
                    "sha256": "verified-artifact-checksum",
                },
                capture_id=capture_id,
            )
            payload = json.loads(drop_path.read_text(encoding="utf-8"))
            result = CaptureInboxDaemon(root=root, backend=backend).process_once()

        self.assertEqual(payload["version"], 2)
        self.assertEqual(payload["capture_id"], capture_id)
        self.assertRegex(payload["capture_id"], CAPTURE_ID_RE)
        self.assertNotIn("input_sha256", payload)
        self.assertNotIn("input_sha256", payload["metadata"])
        self.assertNotIn("payload_sha256", payload["metadata"]["nested"])
        self.assertEqual(
            payload["metadata"]["sha256"],
            "verified-artifact-checksum",
        )
        self.assertEqual(result["processed_file_count"], 1)
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(backend.calls[0]["capture_id"], capture_id)
        self.assertEqual(backend.calls[0]["metadata"]["capture_id"], capture_id)
        self.assertNotIn("input_sha256", backend.calls[0]["metadata"])

    def test_process_once_uses_one_backend_refresh_batch_for_all_claims(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = BatchRecordingBackend()
            for index in range(2):
                write_capture_drop(
                    root=root,
                    context_id="batch-test",
                    source_tag="batch-refresh",
                    speaker="codex",
                    text=f"Capture batch event {index}.",
                    capture_id=f"s2cap_{index + 1:032x}",
                )

            result = CaptureInboxDaemon(
                root=root,
                backend=backend,
            ).process_once(max_files=2)

        self.assertEqual(result["processed_file_count"], 2)
        self.assertEqual(backend.batch_entry_count, 1)
        self.assertEqual(backend.batch_exit_count, 1)
        self.assertEqual(backend.batch_observations, [True, True])

    def test_replacement_freeze_defers_and_recovers_late_capture(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            freeze = begin_capture_replacement_freeze(
                root=root,
                ttl_seconds=600,
            )
            deferred_path = write_capture_drop(
                root=root,
                context_id="freeze-test",
                source_tag="late-boundary",
                speaker="codex",
                text="A boundary arriving during signed recovery is durable.",
                capture_id="s2cap_" + ("9" * 32),
            )
            self.assertEqual(
                deferred_path.parent.resolve(),
                (root / CAPTURE_DEFERRED_DIR_NAME).resolve(),
            )
            self.assertEqual(
                list((root / "capture_inbox").iterdir()),
                [],
            )

            thaw = release_capture_replacement_freeze(
                root=root,
                freeze_id=str(freeze["freeze_id"]),
                require_main_queue_empty=True,
            )
            restored = root / "capture_inbox" / deferred_path.name
            restored_exists = restored.is_file()
            deferred_exists = deferred_path.exists()

        self.assertTrue(thaw["released"])
        self.assertEqual(thaw["deferred_file_count"], 1)
        self.assertTrue(restored_exists)
        self.assertFalse(deferred_exists)

    def test_replacement_freeze_rejects_unsafe_deferred_payload(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            freeze = begin_capture_replacement_freeze(
                root=root,
                ttl_seconds=600,
            )
            unsafe = root / CAPTURE_DEFERRED_DIR_NAME / "unsafe.json"
            unsafe.write_text("{}", encoding="utf-8")
            unsafe.chmod(0o644)

            with self.assertRaisesRegex(ValueError, "payload is unsafe"):
                release_capture_replacement_freeze(
                    root=root,
                    freeze_id=str(freeze["freeze_id"]),
                    require_main_queue_empty=True,
                )

    def test_expired_replacement_freeze_recovers_deferred_before_write(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            begin_capture_replacement_freeze(
                root=root,
                ttl_seconds=0.01,
            )
            deferred_path = write_capture_drop(
                root=root,
                context_id="freeze-test",
                source_tag="late-boundary",
                speaker="codex",
                text="This record is initially deferred.",
                capture_id="s2cap_" + ("7" * 32),
            )
            time.sleep(0.02)
            current_path = write_capture_drop(
                root=root,
                context_id="freeze-test",
                source_tag="post-expiry",
                speaker="codex",
                text="This record triggers safe deferred recovery.",
                capture_id="s2cap_" + ("8" * 32),
            )

            inbox_names = sorted(
                path.name for path in (root / "capture_inbox").iterdir()
            )
            freeze_path = (
                root
                / "capture_locks"
                / capture_daemon.CAPTURE_REPLACEMENT_FREEZE_NAME
            )

        self.assertEqual(
            inbox_names,
            sorted((deferred_path.name, current_path.name)),
        )
        self.assertFalse(freeze_path.exists())

    def test_status_and_preflight_do_not_construct_mlx_backend(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            inbox = root / "capture_inbox"
            inbox.mkdir(parents=True, exist_ok=True)
            inbox.chmod(0o700)
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

    def test_processed_archive_scrub_handles_json_and_jsonl_privately(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            processed = daemon.paths()["processed_dir"]
            processed.mkdir(parents=True, mode=0o700)
            first_id = "s2cap_11111111111111111111111111111111"
            second_id = "s2cap_22222222222222222222222222222222"
            third_id = "s2cap_33333333333333333333333333333333"
            json_path = processed / "legacy-object.json"
            jsonl_path = processed / "legacy-batch.jsonl"
            json_path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "capture_id": first_id,
                        "text": "password=legacy-archive-secret",
                        "input_sha256": "raw-input-equality-oracle",
                        "sha256": "verified-operational-checksum",
                        "metadata": {
                            "api_key": "legacy-metadata-secret",
                            "raw_text_sha256": "nested-equality-oracle",
                        },
                    }
                ),
                encoding="utf-8",
            )
            jsonl_path.write_text(
                "\n".join(
                    json.dumps(item)
                    for item in (
                        {
                            "version": 2,
                            "capture_id": second_id,
                            "text": "authorization=legacy-one",
                            "payload_sha256": "payload-oracle",
                            "sha256": "keep-one",
                        },
                        {
                            "version": 2,
                            "capture_id": third_id,
                            "text": "safe archive text",
                            "metadata": {
                                "source_text_sha256": "source-oracle",
                            },
                            "sha256": "keep-two",
                        },
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            json_path.chmod(0o644)
            jsonl_path.chmod(0o644)

            result = daemon.process_once()
            scrubbed_json = json.loads(json_path.read_text(encoding="utf-8"))
            scrubbed_jsonl = [
                json.loads(line)
                for line in jsonl_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            json_mode = json_path.stat().st_mode & 0o777
            jsonl_mode = jsonl_path.stat().st_mode & 0o777

        self.assertEqual(result["processed_archive_scrub_schema"], "capture-processed-scrub.v1")
        self.assertEqual(result["processed_archive_scanned_count"], 2)
        self.assertEqual(result["processed_archive_scrubbed_count"], 2)
        self.assertEqual(result["processed_archive_scrub_error_count"], 0)
        self.assertEqual(result["processed_archive_raw_digest_removed_count"], 4)
        self.assertEqual(result["processed_archive_post_pass_unsafe_count"], 0)
        self.assertEqual(result["processed_archive_post_pass_unverified_count"], 0)
        self.assertEqual(backend.calls, [])
        self.assertEqual(scrubbed_json["capture_id"], first_id)
        self.assertEqual(
            [record["capture_id"] for record in scrubbed_jsonl],
            [second_id, third_id],
        )
        self.assertEqual(scrubbed_json["sha256"], "verified-operational-checksum")
        self.assertEqual(scrubbed_jsonl[0]["sha256"], "keep-one")
        self.assertEqual(scrubbed_jsonl[1]["sha256"], "keep-two")
        serialized = json.dumps([scrubbed_json, *scrubbed_jsonl], sort_keys=True)
        for marker in (
            "legacy-archive-secret",
            "legacy-metadata-secret",
            "legacy-one",
            "raw-input-equality-oracle",
            "nested-equality-oracle",
            "payload-oracle",
            "source-oracle",
        ):
            self.assertNotIn(marker, serialized)
        self.assertEqual(json_mode, 0o600)
        self.assertEqual(jsonl_mode, 0o600)

    def test_processed_archive_scrub_does_not_rewrite_already_clean_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            processed = daemon.paths()["processed_dir"]
            processed.mkdir(parents=True, mode=0o700)
            archive = processed / "clean.json"
            archive.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "capture_id": "s2cap_44444444444444444444444444444444",
                        "text": "already clean",
                        "sha256": "legitimate-backup-checksum",
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            archive.chmod(0o644)
            original = archive.read_bytes()
            original_stat = archive.stat()

            first = daemon.process_once()
            second = daemon.process_once()
            final_stat = archive.stat()
            final_bytes = archive.read_bytes()
            final_mode = final_stat.st_mode & 0o777

        self.assertEqual(first["processed_archive_clean_count"], 1)
        self.assertEqual(first["processed_archive_scrubbed_count"], 0)
        self.assertEqual(second["processed_archive_scanned_count"], 0)
        self.assertEqual(second["processed_archive_clean_count"], 0)
        self.assertEqual(second["processed_archive_scrubbed_count"], 0)
        self.assertEqual(final_bytes, original)
        self.assertEqual(final_stat.st_ino, original_stat.st_ino)
        self.assertEqual(final_stat.st_mtime_ns, original_stat.st_mtime_ns)
        self.assertEqual(final_mode, 0o600)

    def test_processed_archive_scrub_includes_legacy_text(self):
        marker = "SYNTHETIC_LEGACY_PROCESSED_TEXT_SECRET_42"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            processed = daemon.paths()["processed_dir"]
            processed.mkdir(parents=True, mode=0o700)
            archive = processed / "legacy-capture.txt"
            archive.write_text(
                f"password={marker}\ninput_sha256={'a' * 64}\nsafe line\n",
                encoding="utf-8",
            )
            archive.chmod(0o644)

            result = daemon.process_once()
            persisted = archive.read_text(encoding="utf-8")
            mode = archive.stat().st_mode & 0o777

        self.assertEqual(result["processed_archive_scanned_count"], 1)
        self.assertEqual(result["processed_archive_scrubbed_count"], 1)
        self.assertEqual(result["processed_archive_scrub_error_count"], 0)
        self.assertNotIn(marker, persisted)
        self.assertNotIn("input_sha256", persisted)
        self.assertIn("safe line", persisted)
        self.assertEqual(mode, 0o600)

    def test_processed_archive_scrub_refuses_symlink_without_following_it(self):
        marker = "SYNTHETIC_PROCESSED_SYMLINK_SECRET_42"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            processed = daemon.paths()["processed_dir"]
            processed.mkdir(parents=True, mode=0o700)
            outside = root / "outside.json"
            outside.write_text(
                json.dumps(
                    {
                        "capture_id": "s2cap_55555555555555555555555555555555",
                        "text": f"password={marker}",
                        "input_sha256": "outside-oracle",
                    }
                ),
                encoding="utf-8",
            )
            before = outside.read_bytes()
            os.symlink(outside, processed / "linked.json")

            result = daemon.process_once()
            after = outside.read_bytes()

        self.assertEqual(result["processed_archive_scanned_count"], 1)
        self.assertEqual(result["processed_archive_symlink_refusal_count"], 1)
        self.assertEqual(result["processed_archive_scrub_error_count"], 1)
        self.assertEqual(result["processed_archive_post_pass_unverified_count"], 1)
        self.assertNotIn(marker, json.dumps(result, sort_keys=True))
        self.assertEqual(after, before)

    def test_processed_archive_interrupted_replace_retries_cleanly(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            processed = daemon.paths()["processed_dir"]
            processed.mkdir(parents=True, mode=0o700)
            archive = processed / "retry.json"
            archive.write_text(
                json.dumps(
                    {
                        "capture_id": "s2cap_66666666666666666666666666666666",
                        "text": "password=retry-secret",
                        "input_sha256": "retry-oracle",
                    }
                ),
                encoding="utf-8",
            )

            with patch(
                "capture_daemon._atomic_rewrite_private_text_at",
                side_effect=OSError("simulated interrupted atomic replacement"),
            ):
                first = daemon.process_once()
            still_legacy = archive.read_text(encoding="utf-8")
            retry = daemon.process_once()
            repaired = archive.read_text(encoding="utf-8")
            temporary_files = list(processed.glob(".*.tmp"))

        self.assertEqual(first["processed_archive_scrubbed_count"], 0)
        self.assertEqual(first["processed_archive_scrub_error_count"], 1)
        self.assertEqual(first["processed_archive_post_pass_unsafe_count"], 1)
        self.assertIn("input_sha256", still_legacy)
        self.assertEqual(retry["processed_archive_scrubbed_count"], 1)
        self.assertEqual(retry["processed_archive_scrub_error_count"], 0)
        self.assertEqual(retry["processed_archive_post_pass_unsafe_count"], 0)
        self.assertNotIn("input_sha256", repaired)
        self.assertNotIn("retry-secret", repaired)
        self.assertEqual(temporary_files, [])

    def test_processed_archive_post_pass_zero_invariant_is_idempotent(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            processed = daemon.paths()["processed_dir"]
            processed.mkdir(parents=True, mode=0o700)
            archive = processed / "nested.json"
            archive.write_text(
                json.dumps(
                    {
                        "capture_id": "s2cap_77777777777777777777777777777777",
                        "text": "Authorization: Bearer residual-secret-value",
                        "metadata": {
                            "nested": [
                                {
                                    "raw_input_sha256": "nested-oracle",
                                    "password": "nested-secret",
                                }
                            ]
                        },
                        "sha256": "retain-this-operational-checksum",
                    }
                ),
                encoding="utf-8",
            )

            first = daemon.process_once()
            persisted = json.loads(archive.read_text(encoding="utf-8"))
            sanitized, _, remaining_digests = daemon._sanitize_processed_archive(
                persisted
            )
            second = daemon.process_once()

        self.assertEqual(first["processed_archive_scrubbed_count"], 1)
        self.assertEqual(first["processed_archive_post_pass_unsafe_count"], 0)
        self.assertEqual(first["processed_archive_post_pass_unverified_count"], 0)
        self.assertEqual(sanitized, persisted)
        self.assertEqual(remaining_digests, 0)
        self.assertEqual(
            persisted["sha256"],
            "retain-this-operational-checksum",
        )
        self.assertEqual(second["processed_archive_scrubbed_count"], 0)
        self.assertEqual(second["processed_archive_scanned_count"], 0)
        self.assertEqual(second["processed_archive_clean_count"], 0)
        self.assertEqual(second["processed_archive_scrub_error_count"], 0)

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

    def test_capture_filename_is_never_echoed_hashed_or_archived(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            inbox = root / "capture_inbox"
            inbox.mkdir(parents=True)
            marker = "SYNTHETIC_FILENAME_SECRET_42"
            source = inbox / f"password={marker}.json"
            source.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "capture_id": "s2cap_78787878787878787878787878787878",
                        "text": "ordinary capture text",
                    }
                ),
                encoding="utf-8",
            )
            alias = inbox / "ordinary-alias.json"
            os.link(source, alias)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            source_stat = source.lstat()
            alias_stat = alias.lstat()
            self.assertEqual(
                daemon._preflight_transport_token(path=source, stat_result=source_stat),
                daemon._preflight_transport_token(path=alias, stat_result=alias_stat),
            )
            alias.unlink()

            preflight = daemon.preflight()
            result = daemon.process_once()
            rendered = json.dumps({"preflight": preflight, "result": result})
            durable_paths = [str(path.relative_to(root)) for path in root.rglob("*")]
            durable_text = "\n".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in root.rglob("*")
                if path.is_file()
            )

        self.assertEqual(result["processed_file_count"], 1)
        self.assertRegex(
            preflight["selected_files"][0]["file"],
            r"^capture-[0-9a-f]{16}\.json$",
        )
        self.assertNotIn(marker, rendered)
        self.assertNotIn(marker, "\n".join(durable_paths))
        self.assertNotIn(marker, durable_text)

    def test_existing_capture_root_permissions_are_preserved(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "shared-root"
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            write_capture_drop(root=root, text="ordinary capture")
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.process_once()
            root_mode = root.stat().st_mode & 0o777
            inbox_mode = daemon.paths()["inbox_dir"].stat().st_mode & 0o777

        self.assertEqual(root_mode, 0o755)
        self.assertEqual(inbox_mode, 0o700)

    def test_owned_transport_directory_symlink_is_rejected_without_following(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            root.mkdir()
            outside = Path(tmp) / "outside"
            outside.mkdir()
            sentinel = outside / "must-survive.txt"
            sentinel.write_text("outside sentinel", encoding="utf-8")
            os.symlink(outside, root / "capture_processed")

            status = CaptureInboxDaemon(
                root=root,
                backend=RecordingBackend(),
            ).status()

            self.assertEqual(
                sentinel.read_text(encoding="utf-8"),
                "outside sentinel",
            )
            self.assertFalse(status["transport_ready"])
            self.assertIn("processed_dir", status["unsafe_transport_directories"])

    def test_owned_transport_directory_non_directory_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "capture_inbox").write_text("not a directory", encoding="utf-8")

            status = CaptureInboxDaemon(
                root=root,
                backend=RecordingBackend(),
            ).status()
            self.assertFalse(status["transport_ready"])
            self.assertIn("inbox_dir", status["unsafe_transport_directories"])

    def test_stale_inbox_temps_are_quarantined_without_ingestion_or_content_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            inbox.chmod(0o700)
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
                    "temp-discard-evidence-*.evidence.json"
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
            self.assertFalse(
                (root / "capture_errors" / "stale-temp-stale.json.tmp").exists()
            )
            self.assertEqual(
                after["last_result"],
                daemon._compact_process_result(retry),
            )
            self.assertEqual(evidence["artifact_type"], "stale-capture-inbox-temp")
            self.assertEqual(evidence["temp_kind"], "legacy-write-temp")
            self.assertFalse(evidence["content_inspected"])
            self.assertFalse(evidence["content_digest_recorded"])
            self.assertFalse(evidence["raw_payload_retained"])
            self.assertEqual(
                evidence["disposition"],
                "discarded-without-content-inspection",
            )
            self.assertNotIn("transport_token", evidence)
            self.assertNotIn("sk-stale-temp-secret-123456", evidence_text)
            self.assertNotIn(raw_sha256, evidence_text)

    def test_malformed_raw_payload_is_discarded_after_content_free_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)
            marker = "SYNTHETIC_ONLY_SECRET_VALUE_42"
            malformed = inbox / "malformed.json"
            malformed.write_text(
                f'{{"text":"password={marker}"',
                encoding="utf-8",
            )

            result = daemon.process_once()
            malformed_exists = malformed.exists()
            error_files = list((root / "capture_errors").iterdir())
            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for path in error_files
                if path.is_file()
            )

        self.assertEqual(result["error_file_count"], 1)
        self.assertEqual(len(backend.calls), 0)
        self.assertFalse(malformed_exists)
        self.assertTrue(error_files)
        self.assertNotIn(marker, combined)
        self.assertIn('"raw_payload_retained": false', combined)
        self.assertIn('"payload_disposition": "raw-payload-discarded"', combined)

    def test_interrupted_detached_discard_recovers_and_corrects_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True)
            marker = "SYNTHETIC_DETACHED_RAW_SECRET_42"
            stale = inbox / "interrupted.json.tmp"
            stale.write_text(f"password={marker}", encoding="utf-8")
            observed_now = time.time() + STALE_INBOX_TEMP_SECONDS + 60.0
            real_unlink = Path.unlink

            def fail_detached_unlink(path, *args, **kwargs):
                if path.name.startswith(".s2-discard-"):
                    raise OSError("simulated interrupted discard")
                return real_unlink(path, *args, **kwargs)

            with patch("capture_daemon.time.time", return_value=observed_now):
                with patch(
                    "capture_daemon.Path.unlink",
                    autospec=True,
                    side_effect=fail_detached_unlink,
                ):
                    interrupted = daemon.process_once()
            staged = list((root / "capture_errors").glob(".s2-discard-*.tmp"))
            pending_evidence = next((root / "capture_errors").glob("*.json"))
            pending = json.loads(pending_evidence.read_text(encoding="utf-8"))

            recovered = daemon.process_once()
            staged_exists_after_recovery = staged[0].exists()
            final_evidence = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "capture_errors").glob("*.json")
                if path.is_file()
            ]

        self.assertEqual(interrupted["discarded_stale_temp_count"], 0)
        self.assertEqual(interrupted["temp_quarantine_evidence_error_count"], 1)
        self.assertEqual(len(staged), 1)
        self.assertTrue(pending["raw_payload_retained"])
        self.assertEqual(recovered["recovered_detached_discard_count"], 1)
        self.assertFalse(any(item.get("raw_payload_retained") for item in final_evidence))
        self.assertFalse(staged_exists_after_recovery)
        self.assertNotIn(marker, json.dumps(final_evidence, sort_keys=True))

    def test_post_delete_evidence_crash_is_reconciled_on_retry(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True)
            stale = inbox / "crash-finalize.json.tmp"
            stale.write_text("password=synthetic-crash-secret", encoding="utf-8")
            observed_now = time.time() + STALE_INBOX_TEMP_SECONDS + 60.0
            real_write = capture_daemon._atomic_write_private_text
            crashed = False

            def crash_final_evidence(path, text):
                nonlocal crashed
                if (
                    not crashed
                    and path.parent.name == "capture_errors"
                    and '"raw_payload_retained": false' in text
                ):
                    crashed = True
                    raise KeyboardInterrupt("simulated crash after durable unlink")
                return real_write(path, text)

            with patch("capture_daemon.time.time", return_value=observed_now):
                with patch(
                    "capture_daemon._atomic_write_private_text",
                    side_effect=crash_final_evidence,
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        daemon.process_once()

            evidence_path = next((root / "capture_errors").glob("*.json"))
            pending = json.loads(evidence_path.read_text(encoding="utf-8"))
            staged_after_crash = list(
                (root / "capture_errors").glob(".s2-discard-*.tmp")
            )
            CaptureInboxDaemon(root=root, backend=RecordingBackend()).process_once()
            final_evidence = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "capture_errors").glob("*.json")
            ]

        self.assertTrue(pending["raw_payload_retained"])
        self.assertEqual(staged_after_crash, [])
        self.assertTrue(final_evidence)
        self.assertFalse(any(item.get("raw_payload_retained") for item in final_evidence))

    def test_rejected_raw_payload_unlink_failure_keeps_truthful_pending_evidence(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True)
            (inbox / "malformed.json").write_text(
                '{"text":"password=synthetic-unlink-secret"',
                encoding="utf-8",
            )
            real_unlink = Path.unlink
            failed = False

            def fail_once(path, *args, **kwargs):
                nonlocal failed
                if not failed and path.name.startswith(".s2-discard-"):
                    failed = True
                    raise OSError("simulated rejected-payload unlink failure")
                return real_unlink(path, *args, **kwargs)

            with patch(
                "capture_daemon.Path.unlink",
                autospec=True,
                side_effect=fail_once,
            ):
                interrupted = daemon.process_once()
            pending_path = next((root / "capture_errors").glob("capture-error-*.json"))
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            staged = list((root / "capture_errors").glob(".s2-discard-*.tmp"))

            recovered = CaptureInboxDaemon(
                root=root,
                backend=RecordingBackend(),
            ).process_once()
            final_evidence = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "capture_errors").glob("*.json")
            ]

        self.assertEqual(interrupted["error_file_count"], 1)
        self.assertTrue(pending["raw_payload_retained"])
        self.assertEqual(len(staged), 1)
        self.assertEqual(recovered["recovered_detached_discard_count"], 1)
        self.assertFalse(any(item.get("raw_payload_retained") for item in final_evidence))

    def test_malformed_claim_tree_cleanup_failure_recovers_truthfully(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            processing = daemon.paths()["processing_dir"]
            processing.mkdir(parents=True)
            claim = processing / ("s2claim_" + "d" * 32)
            claim.mkdir()
            for ordinal in (1, 2):
                (claim / f"payload-{ordinal}.json").write_text(
                    json.dumps({"version": 1, "text": f"payload {ordinal}"}),
                    encoding="utf-8",
                )

            with patch(
                "capture_daemon._remove_tree_without_following_links",
                side_effect=OSError("simulated durable rmtree failure"),
            ):
                daemon.process_once()
            pending_path = next((root / "capture_errors").glob("*.error.json"))
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            staged_trees = list(
                (root / "capture_errors").glob(".s2-discard-tree-*.tmp")
            )

            recovered = CaptureInboxDaemon(
                root=root,
                backend=RecordingBackend(),
            ).process_once()
            final_evidence = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "capture_errors").glob("*.json")
            ]

        self.assertTrue(pending["raw_payload_retained"])
        self.assertEqual(len(staged_trees), 1)
        self.assertEqual(recovered["recovered_detached_discard_count"], 1)
        self.assertFalse(staged_trees[0].exists())
        self.assertFalse(any(item.get("raw_payload_retained") for item in final_evidence))

    def test_legacy_raw_stale_temp_quarantine_is_scrubbed_without_reading_content(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            error_dir = daemon.paths()["error_dir"]
            error_dir.mkdir(parents=True, exist_ok=True)
            marker = "SYNTHETIC_ONLY_SECRET_VALUE_42"
            legacy_raw = error_dir / "stale-temp-old.json.tmp"
            legacy_raw.write_text(f"api_key={marker}", encoding="utf-8")

            result = daemon.process_once()
            legacy_raw_exists = legacy_raw.exists()
            evidence_files = list(error_dir.glob("temp-discard-evidence-*.evidence.json"))
            evidence_text = evidence_files[0].read_text(encoding="utf-8")

        self.assertEqual(result["discarded_legacy_raw_error_count"], 1)
        self.assertFalse(legacy_raw_exists)
        self.assertEqual(len(evidence_files), 1)
        self.assertNotIn(marker, evidence_text)
        self.assertIn('"content_inspected": false', evidence_text)
        self.assertIn('"raw_payload_retained": false', evidence_text)

    def test_legacy_discard_evidence_scrub_removes_string_digest_oracles(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            error_dir = daemon.paths()["error_dir"]
            error_dir.mkdir(parents=True)
            marker = "a" * 64
            legacy = error_dir / "legacy.error.json"
            legacy.write_text(
                json.dumps(
                    {
                        "artifact_type": "stale-capture-inbox-temp",
                        "discard_operation_id": "b" * 32,
                        "content_inspected": False,
                        "content_digest_recorded": False,
                        "raw_payload_retained": False,
                        "disposition": "recovered-discard-complete",
                        "reason": f"payload_sha256={marker}",
                        "error": {"detail": f'contentDigest="{marker}"'},
                    }
                ),
                encoding="utf-8",
            )

            result = daemon._scrub_legacy_temp_evidence_artifacts(daemon.paths())
            evidence = list(error_dir.glob("*.json"))
            combined = "\n".join(
                path.read_text(encoding="utf-8") for path in evidence
            )

        self.assertEqual(result["scrubbed"], 1)
        self.assertEqual(result["errors"], 0)
        self.assertEqual(len(evidence), 1)
        self.assertNotIn(marker, combined)
        self.assertNotIn("payload_sha256", combined)
        self.assertNotIn("contentDigest", combined)
        self.assertIn("[REMOVED_RAW_DIGEST_FIELD]", combined)

    def test_claim_tree_cleanup_never_follows_nested_symlinks(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "must-survive.txt"
            sentinel.write_text("outside sentinel", encoding="utf-8")
            claim = root / ("s2claim_" + "9" * 32)
            claim.mkdir()
            (claim / "ordinary.txt").write_text("claim data", encoding="utf-8")
            os.symlink(outside, claim / "swapped-child")

            capture_daemon._remove_tree_without_following_links(
                claim,
                parent_dir=root,
            )

            self.assertFalse(claim.exists())
            self.assertTrue(sentinel.exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "outside sentinel")

    def test_claim_tree_cleanup_rejects_target_outside_owned_parent(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            owned = root / "owned"
            owned.mkdir()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "must-survive.txt"
            sentinel.write_text("outside sentinel", encoding="utf-8")

            with self.assertRaises(ValueError):
                capture_daemon._remove_tree_without_following_links(
                    outside,
                    parent_dir=owned,
                )

            self.assertEqual(
                sentinel.read_text(encoding="utf-8"),
                "outside sentinel",
            )

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

    def test_processed_archive_collision_never_overwrites_racing_destination(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.prepare_transport()
            claim = daemon.paths()["processing_dir"] / ("s2claim_" + "c" * 32)
            claim.mkdir(mode=0o700)
            source = claim / "payload.json"
            source.write_text("new archive", encoding="utf-8")
            processed = daemon.paths()["processed_dir"]
            real_link = os.link
            collided = False

            def race_once(src, dst, *args, **kwargs):
                nonlocal collided
                if not collided:
                    collided = True
                    Path(dst).write_text("racing archive", encoding="utf-8")
                    raise FileExistsError("simulated archive reservation collision")
                return real_link(src, dst, *args, **kwargs)

            with patch("capture_daemon.os.link", side_effect=race_once):
                destination = daemon._move_file(source, processed)

            racing = processed / "payload.json"
            archived_text = destination.read_text(encoding="utf-8")
            racing_text = racing.read_text(encoding="utf-8")
            destination_mode = destination.stat().st_mode & 0o777
            source_exists = source.exists()

        self.assertTrue(collided)
        self.assertNotEqual(destination, racing)
        self.assertEqual(racing_text, "racing archive")
        self.assertEqual(archived_text, "new archive")
        self.assertFalse(source_exists)
        self.assertEqual(destination_mode, 0o600)

    def test_processed_archive_link_unlink_crash_reuses_reserved_inode(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.prepare_transport()
            claim = daemon.paths()["processing_dir"] / ("s2claim_" + "b" * 32)
            claim.mkdir(mode=0o700)
            source = claim / "payload.json"
            source.write_text("archive once", encoding="utf-8")
            processed = daemon.paths()["processed_dir"]
            real_unlink = Path.unlink
            failed = False

            def fail_source_once(path, *args, **kwargs):
                nonlocal failed
                if not failed and path == source:
                    failed = True
                    raise OSError("simulated crash before source unlink")
                return real_unlink(path, *args, **kwargs)

            with patch(
                "capture_daemon.Path.unlink",
                autospec=True,
                side_effect=fail_source_once,
            ):
                with self.assertRaises(OSError):
                    daemon._move_file(source, processed)
            linked_before_retry = list(processed.iterdir())

            recovered = daemon._move_file(source, processed)
            linked_after_retry = list(processed.iterdir())
            source_exists = source.exists()
            recovered_text = recovered.read_text(encoding="utf-8")

        self.assertTrue(failed)
        self.assertEqual(len(linked_before_retry), 1)
        self.assertEqual(len(linked_after_retry), 1)
        self.assertFalse(source_exists)
        self.assertEqual(recovered_text, "archive once")

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

    def test_unknown_top_level_fields_never_survive_capture_archives(self):
        marker = "SYNTHETIC_ONLY_TOP_LEVEL_CAPTURE_SECRET_42"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            inbox = daemon.paths()["inbox_dir"]
            inbox.mkdir(parents=True, exist_ok=True)

            def payload(capture_id: str, text: str) -> dict[str, object]:
                return {
                    "version": 2,
                    "capture_id": capture_id,
                    "text": text,
                    "password": marker,
                    "extra": f"Authorization: Bearer {marker}",
                    "nested_unknown": {"api_key": marker},
                }

            (inbox / "object.json").write_text(
                json.dumps(
                    payload(
                        "s2cap_10101010101010101010101010101010",
                        "Object payload.",
                    )
                ),
                encoding="utf-8",
            )
            (inbox / "list.json").write_text(
                json.dumps(
                    [
                        payload(
                            "s2cap_20202020202020202020202020202020",
                            "List payload.",
                        )
                    ]
                ),
                encoding="utf-8",
            )
            (inbox / "batch.jsonl").write_text(
                json.dumps(
                    payload(
                        "s2cap_30303030303030303030303030303030",
                        "JSONL payload.",
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            result = daemon.process_once()
            archived = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (root / "capture_processed").iterdir()
                if path.is_file()
            )

            claim_dir = root / "capture_processing" / (
                "s2claim_" + "4" * 32
            )
            claim_dir.mkdir(parents=True)
            legacy_path = claim_dir / "legacy.txt"
            legacy_path.write_text("Legacy safe text.", encoding="utf-8")
            (claim_dir / ".capture-identity.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "capture_id": "s2cap_40404040404040404040404040404040",
                        "source_tag": "legacy",
                        "password": marker,
                        "extra": f"Authorization: ApiKey {marker}",
                    }
                ),
                encoding="utf-8",
            )
            daemon._prepare_payload_document(legacy_path)
            legacy_identity = (claim_dir / ".capture-identity.json").read_text(
                encoding="utf-8"
            )

        self.assertEqual(result["processed_file_count"], 3)
        self.assertNotIn(marker, archived)
        self.assertNotIn('"password"', archived)
        self.assertNotIn('"extra"', archived)
        self.assertNotIn('"nested_unknown"', archived)
        self.assertNotIn(marker, legacy_identity)
        self.assertNotIn('"password"', legacy_identity)
        self.assertNotIn('"extra"', legacy_identity)
        self.assertTrue(
            all(call["metadata"]["capture_daemon"] is True for call in backend.calls)
        )

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
        self.assertEqual(
            recovered_backend.calls[0]["source_tag"],
            "legacy-text-capture",
        )
        self.assertNotIn("hunter2", recovered_backend.calls[0]["text"])

    def test_processing_debris_is_removed_or_quarantined_before_effect(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            backend = RecordingBackend()
            daemon = CaptureInboxDaemon(root=root, backend=backend)
            processing = daemon.paths()["processing_dir"]
            processing.mkdir(parents=True, exist_ok=True)
            processing.chmod(0o700)
            empty_claim = processing / (
                "s2claim_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            )
            empty_claim.mkdir(mode=0o700)
            old_time = time.time() - 120
            os.utime(empty_claim, (old_time, old_time))
            malformed_claim = processing / (
                "s2claim_ffffffffffffffffffffffffffffffff"
            )
            malformed_claim.mkdir(mode=0o700)
            for index in (1, 2):
                (malformed_claim / f"payload-{index}.json").write_text(
                    json.dumps({"version": 1, "text": f"payload {index}"}),
                    encoding="utf-8",
                )
                (malformed_claim / f"payload-{index}.json").chmod(0o600)
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

    def test_processing_diagnostics_fail_closed_on_rogue_entries(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.prepare_transport()
            processing = daemon.paths()["processing_dir"]
            rogue_file = processing / "not-a-claim"
            rogue_file.write_text("not a claim", encoding="utf-8")
            rogue_file.chmod(0o600)
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            os.symlink(outside, processing / ("s2claim_" + "a" * 32))
            unsafe_claim = processing / ("s2claim_" + "b" * 32)
            unsafe_claim.mkdir(mode=0o755)

            status = daemon.status()

        self.assertEqual(status["processing_file_count"], 0)
        self.assertEqual(status["processing_empty_claim_count"], 0)
        self.assertEqual(status["processing_malformed_claim_count"], 3)

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
                (root / "capture_errors").glob("capture-error-*.json")
            )
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            quarantined = next(
                path
                for path in (root / "capture_errors").glob("*.jsonl")
                if path.is_file()
            )
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

    def test_terminal_error_evidence_is_history_and_resolves_to_private_archive(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.prepare_transport()
            evidence_path = root / "capture_errors" / "terminal.evidence.json"
            evidence_path.write_text(
                json.dumps(
                    {
                        "artifact_type": "stale-capture-inbox-temp",
                        "discard_operation_id": "a" * 32,
                        "content_inspected": False,
                        "content_digest_recorded": False,
                        "raw_payload_retained": False,
                        "disposition": "recovered-discard-complete",
                    }
                ),
                encoding="utf-8",
            )
            evidence_path.chmod(0o600)

            status_before = daemon.status()
            preflight = daemon.error_resolution_preflight(
                reason="reviewed terminal discard evidence",
            )
            resolved = daemon.resolve_error_artifacts(
                preflight_token=preflight["preflight_token"],
                reason="reviewed terminal discard evidence",
                confirm=True,
            )
            status_after = daemon.status()

        self.assertEqual(status_before["terminal_error_evidence_count"], 1)
        self.assertEqual(status_before["unresolved_error_count"], 0)
        self.assertEqual(status_before["error_file_count"], 0)
        self.assertNotIn(evidence_path.name, json.dumps(preflight))
        self.assertFalse(preflight["source_filenames_returned"])
        self.assertFalse(preflight["content_returned"])
        self.assertEqual(resolved["resolved_count"], 1)
        self.assertEqual(status_after["resolved_error_count"], 1)
        self.assertEqual(status_after["terminal_error_evidence_count"], 0)
        self.assertEqual(status_after["error_resolution_pending_count"], 0)

    def test_historical_error_requires_explicit_scope_and_stale_token_is_fenced(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.prepare_transport()
            error_dir = root / "capture_errors"
            legacy = error_dir / "legacy.error.json"
            legacy.write_text(
                json.dumps(
                    {
                        "file": "sanitized-legacy-payload.json",
                        "error": "historical parser failure",
                        "failed_at": 1.0,
                    }
                ),
                encoding="utf-8",
            )
            legacy.chmod(0o600)

            terminal_only = daemon.error_resolution_preflight(
                reason="reviewed historical diagnostic",
            )
            scoped = daemon.error_resolution_preflight(
                reason="reviewed historical diagnostic",
                include_historical=True,
            )
            legacy.touch()
            with self.assertRaisesRegex(ValueError, "changed after preflight"):
                daemon.resolve_error_artifacts(
                    preflight_token=scoped["preflight_token"],
                    reason="reviewed historical diagnostic",
                    include_historical=True,
                    confirm=True,
                )
            refreshed = daemon.error_resolution_preflight(
                reason="reviewed historical diagnostic",
                include_historical=True,
            )
            resolved = daemon.resolve_error_artifacts(
                preflight_token=refreshed["preflight_token"],
                reason="reviewed historical diagnostic",
                include_historical=True,
                confirm=True,
            )

        self.assertEqual(terminal_only["selected_count"], 0)
        self.assertFalse(terminal_only["ready_to_resolve"])
        self.assertEqual(scoped["historical_evidence_count"], 1)
        self.assertEqual(resolved["historical_resolved_count"], 1)

    def test_unsafe_error_artifacts_block_governed_resolution(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.prepare_transport()
            error_dir = root / "capture_errors"
            unsafe = error_dir / "unsafe.json"
            unsafe.write_text(
                json.dumps(
                    {
                        "artifact_type": "rejected-raw-capture-payload",
                        "raw_payload_retained": True,
                        "disposition": "raw-payload-detached-pending-discard",
                    }
                ),
                encoding="utf-8",
            )
            unsafe.chmod(0o600)

            preflight = daemon.error_resolution_preflight(
                reason="must not archive retained raw payload",
                include_historical=True,
            )
            with self.assertRaisesRegex(ValueError, "unsafe capture error artifacts"):
                daemon.resolve_error_artifacts(
                    preflight_token=preflight["preflight_token"],
                    reason="must not archive retained raw payload",
                    include_historical=True,
                    confirm=True,
                )

        self.assertEqual(preflight["unsafe_error_count"], 1)
        self.assertFalse(preflight["ready_to_resolve"])

    def test_forged_prepared_resolution_cannot_archive_unsafe_artifact(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            paths = daemon.paths()
            daemon.prepare_transport()
            unsafe = paths["error_dir"] / "unsafe.json"
            unsafe.write_text(
                json.dumps(
                    {
                        "artifact_type": "rejected-raw-capture-payload",
                        "raw_payload_retained": True,
                        "disposition": "raw-payload-detached-pending-discard",
                    }
                ),
                encoding="utf-8",
            )
            unsafe.chmod(0o600)
            diagnostics = daemon._error_artifact_diagnostics(paths)
            record = diagnostics["records"][0]
            resolution_id = "b" * 32
            reason = "forged recovery attempt"
            source_identity = record["token"]
            token_payload = {
                "schema": capture_daemon.ERROR_RESOLUTION_SCHEMA,
                "reason": reason,
                "include_historical": True,
                "selected_source_tokens": [source_identity],
                "unsafe_error_count": 0,
            }
            forged_token = hashlib.sha256(
                json.dumps(
                    token_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            manifest_path = paths["error_resolution_dir"] / (
                f"resolution-{resolution_id}.json"
            )
            daemon._write_error_resolution_manifest(
                manifest_path,
                {
                    "schema": capture_daemon.ERROR_RESOLUTION_SCHEMA,
                    "resolution_id": resolution_id,
                    "state": "prepared",
                    "reason": reason,
                    "include_historical": True,
                    "preflight_fence": forged_token,
                    "confirmation_recorded": True,
                    "raw_content_stored": False,
                    "source_filenames_stored": False,
                    "raw_equality_oracle_stored": False,
                    "created_at": time.time(),
                    "items": [
                        {
                            "item_id": "c" * 32,
                            "source_identity": source_identity,
                            "source_suffix": ".json",
                            "category": "historical",
                            "archive_name": f"resolved-{'d' * 32}.json",
                            "expected": daemon._error_resolution_expected_stat(
                                record["stat"]
                            ),
                            "moved": False,
                        }
                    ],
                },
            )

            recovered = daemon._reconcile_error_resolutions(paths)

            self.assertEqual(recovered["failed_count"], 1)
            self.assertTrue(unsafe.exists())
            self.assertEqual(daemon._capture_files(paths["error_archive_dir"]), [])
            self.assertEqual(
                json.loads(manifest_path.read_text(encoding="utf-8"))["state"],
                "prepared",
            )

    def test_confirmed_prepared_resolution_recovers_after_interrupted_move(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            daemon = CaptureInboxDaemon(root=root, backend=RecordingBackend())
            daemon.prepare_transport()
            evidence = root / "capture_errors" / "terminal.evidence.json"
            evidence.write_text(
                json.dumps(
                    {
                        "artifact_type": "stale-capture-inbox-temp",
                        "discard_operation_id": "e" * 32,
                        "content_inspected": False,
                        "content_digest_recorded": False,
                        "raw_payload_retained": False,
                        "disposition": "recovered-discard-complete",
                    }
                ),
                encoding="utf-8",
            )
            evidence.chmod(0o600)
            preflight = daemon.error_resolution_preflight(reason="reviewed evidence")
            with (
                patch.object(
                    daemon,
                    "_move_error_resolution_item",
                    side_effect=OSError("simulated interruption"),
                ),
                self.assertRaisesRegex(OSError, "simulated interruption"),
            ):
                daemon.resolve_error_artifacts(
                    preflight_token=preflight["preflight_token"],
                    reason="reviewed evidence",
                    confirm=True,
                )

            recovered = daemon._reconcile_error_resolutions(daemon.paths())
            status = daemon.status()

        self.assertEqual(recovered["completed_count"], 1)
        self.assertEqual(recovered["moved_count"], 1)
        self.assertEqual(recovered["failed_count"], 0)
        self.assertEqual(status["resolved_error_count"], 1)
        self.assertEqual(status["error_resolution_pending_count"], 0)


if __name__ == "__main__":
    unittest.main()

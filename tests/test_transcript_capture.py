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
    _exclusive_file_lock,
)


class TranscriptCaptureManagerTests(unittest.TestCase):
    def test_transcript_lock_rejects_wrong_mode_symlink_and_hardlink(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)

            wrong_mode = root / "wrong-mode.lock"
            wrong_mode.write_text("preserve", encoding="utf-8")
            wrong_mode.chmod(0o644)
            wrong_mode_inode = wrong_mode.stat().st_ino
            with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
                with _exclusive_file_lock(wrong_mode, blocking=True):
                    self.fail("unsafe lock must not be acquired")
            self.assertEqual(wrong_mode.stat().st_mode & 0o777, 0o644)
            self.assertEqual(wrong_mode.stat().st_ino, wrong_mode_inode)

            hardlink_target = root / "hardlink-target"
            hardlink_target.write_text("preserve", encoding="utf-8")
            hardlink_target.chmod(0o600)
            hardlink = root / "hardlink.lock"
            os.link(hardlink_target, hardlink)
            with self.assertRaisesRegex(RuntimeError, "identity is unsafe"):
                with _exclusive_file_lock(hardlink, blocking=True):
                    self.fail("hard-linked lock must not be acquired")
            self.assertEqual(hardlink_target.stat().st_nlink, 2)

            symlink_target = root / "symlink-target"
            symlink_target.write_text("preserve", encoding="utf-8")
            symlink_target.chmod(0o600)
            symlink = root / "symlink.lock"
            symlink.symlink_to(symlink_target)
            with self.assertRaises(OSError):
                with _exclusive_file_lock(symlink, blocking=True):
                    self.fail("symlink lock must not be acquired")
            self.assertEqual(symlink_target.read_text(encoding="utf-8"), "preserve")

    def test_transcript_lock_never_creates_multiple_missing_parent_levels(self):
        with TemporaryDirectory() as tmp:
            nested = Path(tmp) / "missing" / "nested" / "unsafe.lock"
            with self.assertRaises(FileNotFoundError):
                with _exclusive_file_lock(nested, blocking=True):
                    self.fail("lock parent chain must not be created broadly")
            self.assertFalse((Path(tmp) / "missing").exists())

    def test_capture_root_rejects_credential_shaped_path(self):
        with TemporaryDirectory() as tmp:
            marker = "SYNTHETIC_TRANSCRIPT_ROOT_SECRET_42"
            unsafe = Path(tmp) / f"password={marker}"
            with self.assertRaises(ValueError) as raised:
                TranscriptCaptureManager(root=unsafe)

        self.assertNotIn(marker, str(raised.exception))
        self.assertFalse(unsafe.exists())

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

    def test_file_source_metadata_is_redacted_before_durable_state(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            transcript = Path(tmp) / "ordinary-session.log"
            transcript.write_text("ordinary transcript\n", encoding="utf-8")
            marker = "SYNTHETIC_ONLY_SECRET_VALUE_42"

            manager.register_file_source(
                source_id="metadata-boundary",
                path=transcript,
                context_id="demo",
                metadata={
                    "apiKey": marker,
                    "safe": "preserved",
                    "input_sha256": "raw-input-equality-oracle",
                    "nested": {"payload_sha256": "nested-equality-oracle"},
                    "sha256": "verified-operational-checksum",
                },
                confirmed=True,
            )
            state_text = manager.paths()["source_state_path"].read_text(
                encoding="utf-8"
            )
            state = json.loads(state_text)
            metadata = state["sources"]["metadata-boundary"]["metadata"]

        self.assertNotIn(marker, state_text)
        self.assertEqual(metadata["apiKey"], "[REDACTED_SECRET]")
        self.assertEqual(metadata["safe"], "preserved")
        self.assertNotIn("input_sha256", metadata)
        self.assertNotIn("payload_sha256", metadata["nested"])
        self.assertEqual(metadata["sha256"], "verified-operational-checksum")

    def test_registered_source_fails_closed_when_ancestor_is_replaced_by_symlink(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            parent = Path(tmp) / "watched"
            parent.mkdir()
            transcript = parent / "session.log"
            transcript.write_text("registered line\n", encoding="utf-8")
            manager.register_file_source(
                source_id="ancestor-boundary",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )

            original_parent = Path(tmp) / "watched-original"
            parent.rename(original_parent)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            marker = "SYNTHETIC_OUTSIDE_SENTINEL_42"
            (outside / "session.log").write_text(marker, encoding="utf-8")
            parent.symlink_to(outside, target_is_directory=True)

            result = manager.poll_sources(source_id="ancestor-boundary")
            database_text = (Path(tmp) / "memory.sqlite3").read_bytes()

        self.assertEqual(result["captured_source_count"], 0)
        self.assertEqual(len(result["errors"]), 1)
        self.assertNotIn(marker.encode("utf-8"), database_text)

    def test_credential_shaped_source_path_is_never_persisted_or_echoed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            marker = "SYNTHETIC_PATH_SECRET_42"
            parent = Path(tmp) / f"password={marker}"
            parent.mkdir()
            transcript = parent / "session.log"
            transcript.write_text("ordinary line\n", encoding="utf-8")

            with self.assertRaises(ValueError) as raised:
                manager.register_file_source(
                    source_id="unsafe-path",
                    path=transcript,
                    context_id="demo",
                    confirmed=True,
                )
            durable = "".join(
                candidate.read_text(encoding="utf-8", errors="replace")
                for candidate in root.rglob("*")
                if candidate.is_file()
            ) if root.exists() else ""

        self.assertNotIn(marker, str(raised.exception))
        self.assertNotIn(marker, durable)

    def test_legacy_source_with_secret_identity_is_dropped_with_lineage(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            root.mkdir(mode=0o700)
            marker = "SYNTHETIC_LEGACY_SOURCE_SECRET_42"
            source_id = "legacy-safe-id"
            state = {
                "version": 3,
                "sources": {
                    source_id: {
                        "source_id": source_id,
                        "path": f"/tmp/password={marker}/session.log",
                        "context_id": "default",
                        "source_tag": "transcript-source",
                        "speaker": "operator",
                    }
                },
            }
            state_path = root / "transcript_sources.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            lineage_digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:32]
            lineage_path = (
                root / "transcript_source_lineages" / f"{lineage_digest}.json"
            )
            lineage_path.parent.mkdir(parents=True)
            lineage_path.write_text(json.dumps({"source_id": source_id}), encoding="utf-8")

            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            manager.repair_legacy_state()
            listed = manager.list_sources()
            rewritten = state_path.read_text(encoding="utf-8")
            first_migration = state_path.read_bytes()
            second_manager = TranscriptCaptureManager(
                root=root,
                backend=self.make_backend(tmp),
            )
            second_manager.repair_legacy_state()
            second_migration = state_path.read_bytes()
            state_mode = state_path.stat().st_mode & 0o777
            retained_backups = list(root.glob("*.bak"))

        self.assertEqual(listed["source_count"], 0)
        self.assertNotIn(marker, rewritten)
        self.assertFalse(lineage_path.exists())
        self.assertEqual(first_migration, second_migration)
        self.assertEqual(state_mode, 0o600)
        self.assertFalse(retained_backups)

    def test_legacy_source_migration_rolls_back_without_retained_raw_backup(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            root.mkdir(mode=0o700)
            marker = "SYNTHETIC_ROLLBACK_SECRET_42"
            source_id = "legacy-rollback"
            state_path = root / "transcript_sources.json"
            original_state = json.dumps(
                {
                    "version": 3,
                    "sources": {
                        source_id: {
                            "source_id": source_id,
                            "path": f"/tmp/password={marker}/session.log",
                            "context_id": "default",
                            "source_tag": "transcript-source",
                            "speaker": "operator",
                        }
                    },
                }
            ).encode("utf-8")
            state_path.write_bytes(original_state)
            lineage_digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:32]
            lineage_path = (
                root / "transcript_source_lineages" / f"{lineage_digest}.json"
            )
            lineage_path.parent.mkdir(parents=True)
            original_lineage = b'{"source_id":"legacy-rollback"}'
            lineage_path.write_bytes(original_lineage)

            from transcript_capture import _atomic_write_json as real_atomic_write_json

            def write_then_fail(path, payload):
                real_atomic_write_json(path, payload)
                raise OSError("injected post-replace migration failure")

            with patch(
                "transcript_capture._atomic_write_json",
                side_effect=write_then_fail,
            ):
                with self.assertRaisesRegex(OSError, "post-replace"):
                    manager = TranscriptCaptureManager(
                        root=root,
                        backend=self.make_backend(tmp),
                    )
                    manager.repair_legacy_state()

            restored_state = state_path.read_bytes()
            restored_lineage = lineage_path.read_bytes()
            retained_backups = [
                candidate
                for candidate in root.rglob("*")
                if candidate.suffix in {".bak", ".tmp"}
            ]

        self.assertEqual(restored_state, original_state)
        self.assertEqual(restored_lineage, original_lineage)
        self.assertFalse(retained_backups)

    def test_existing_capture_root_permissions_are_not_changed(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "shared-capture-root"
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            transcript = Path(tmp) / "ordinary-session.log"
            transcript.write_text("ordinary transcript\n", encoding="utf-8")
            manager.register_file_source(
                source_id="permission-boundary",
                path=transcript,
                context_id="demo",
                confirmed=True,
            )
            mode = root.stat().st_mode & 0o777

        self.assertEqual(mode, 0o755)

    def test_app_metadata_and_legacy_state_are_redacted_before_echo(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            manager = TranscriptCaptureManager(
                root=root,
                backend=self.make_backend(tmp),
                running_app_provider=lambda: [
                    {
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                ],
            )
            marker = "SYNTHETIC_ONLY_SECRET_VALUE_42"
            attached = manager.connect_running_app(
                app_name="Codex",
                bundle_id="com.openai.codex",
                pid=4242,
                context_id="demo",
                metadata={"clientSecret": marker, "safe": "preserved"},
                confirmed=True,
            )
            state_path = manager.paths()["app_state_path"]
            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            persisted["connections"][attached["connection_id"]]["metadata"][
                "authorization"
            ] = marker
            persisted["connections"][attached["connection_id"]]["metadata"][
                "raw_text_sha256"
            ] = "legacy-raw-equality-oracle"
            state_path.write_text(json.dumps(persisted), encoding="utf-8")

            migrated_manager = TranscriptCaptureManager(
                root=root,
                backend=self.make_backend(tmp),
                running_app_provider=manager.running_app_provider,
            )
            migrated_manager.repair_legacy_state()
            listed = migrated_manager.list_app_connections()
            scrubbed_text = state_path.read_text(encoding="utf-8")
            rendered = json.dumps({"attached": attached, "listed": listed})
            state_mode = state_path.stat().st_mode & 0o777
            first_migration = state_path.read_bytes()
            second_manager = TranscriptCaptureManager(
                root=root,
                backend=self.make_backend(tmp),
                running_app_provider=manager.running_app_provider,
            )
            second_manager.repair_legacy_state()
            second_migration = state_path.read_bytes()

        self.assertNotIn(marker, rendered)
        self.assertNotIn(marker, scrubbed_text)
        metadata = listed["connections"][0]["metadata"]
        self.assertEqual(metadata["clientSecret"], "[REDACTED_SECRET]")
        self.assertEqual(metadata["authorization"], "[REDACTED_SECRET]")
        self.assertEqual(metadata["safe"], "preserved")
        self.assertNotIn("raw_text_sha256", metadata)
        self.assertEqual(state_mode, 0o600)
        self.assertEqual(first_migration, second_migration)

    def test_state_reads_are_side_effect_free_until_explicit_initialization_migration(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            root.mkdir(mode=0o700)
            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            marker = "SYNTHETIC_LEGACY_READ_SECRET_42"
            source_id = "legacy-read-only"
            source_state = {
                "version": 3,
                "sources": {
                    source_id: {
                        "source_id": source_id,
                        "path": f"/tmp/password={marker}/session.log",
                        "context_id": "default",
                        "source_tag": "transcript-source",
                        "speaker": "operator",
                        "metadata": {"input_sha256": "legacy-source-oracle"},
                    }
                },
            }
            source_path = manager.paths()["source_state_path"]
            source_path.write_text(json.dumps(source_state), encoding="utf-8")
            lineage_path = manager._source_lineage_path(source_id)
            lineage_path.parent.mkdir(parents=True, exist_ok=True)
            lineage_path.write_text("legacy lineage", encoding="utf-8")

            app_id = "app_legacy_read"
            app_state = {
                "version": 1,
                "connections": {
                    app_id: {
                        "connection_id": app_id,
                        "app_name": "Codex",
                        "bundle_id": "com.openai.codex",
                        "context_id": "default",
                        "source_tag": "app-connect",
                        "speaker": "operator",
                        "metadata": {
                            "authorization": marker,
                            "payload_sha256": "legacy-app-oracle",
                        },
                    }
                },
            }
            app_path = manager.paths()["app_state_path"]
            app_path.write_text(json.dumps(app_state), encoding="utf-8")
            source_before = source_path.read_bytes()
            app_before = app_path.read_bytes()

            read_sources = manager._read_state()
            read_apps = manager._read_app_state()

            source_after = source_path.read_bytes()
            app_after = app_path.read_bytes()
            lineage_still_exists = lineage_path.exists()

        self.assertEqual(source_before, source_after)
        self.assertEqual(app_before, app_after)
        self.assertTrue(lineage_still_exists)
        self.assertEqual(read_sources["sources"], {})
        app_metadata = read_apps["connections"][app_id]["metadata"]
        self.assertEqual(app_metadata["authorization"], "[REDACTED_SECRET]")
        self.assertNotIn("payload_sha256", app_metadata)

    def test_state_files_reject_symlink_targets_at_initialization(self):
        with TemporaryDirectory() as tmp:
            for state_name in ("transcript_sources.json", "app_connections.json"):
                with self.subTest(state_name=state_name):
                    root = Path(tmp) / state_name.replace(".", "-")
                    root.mkdir()
                    target = Path(tmp) / f"target-{state_name}"
                    original = b'{"version": 1, "sentinel": "outside"}'
                    target.write_bytes(original)
                    (root / state_name).symlink_to(target)

                    manager = TranscriptCaptureManager(
                        root=root,
                        backend=self.make_backend(tmp),
                    )
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "regular non-symlink file",
                    ):
                        manager.repair_legacy_state()

                    self.assertEqual(target.read_bytes(), original)

    def test_stale_state_reader_cannot_overwrite_new_registration_or_cursor(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            stale_manager = TranscriptCaptureManager(root=root, backend=backend)
            writer_manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "stale-reader.log"
            transcript.write_text("existing\n", encoding="utf-8")
            initial = writer_manager.register_file_source(
                source_id="stale-reader",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            state_path = writer_manager.paths()["source_state_path"]
            legacy = json.loads(state_path.read_text(encoding="utf-8"))
            legacy["sources"]["stale-reader"]["metadata"] = {
                "input_sha256": "stale-reader-equality-oracle"
            }
            state_path.write_text(json.dumps(legacy), encoding="utf-8")

            snapshot_read = threading.Event()
            release_reader = threading.Event()
            original_canonicalize = stale_manager._canonicalize_source_state

            def block_after_stale_read(parsed):
                canonical = original_canonicalize(parsed)
                snapshot_read.set()
                if not release_reader.wait(timeout=5):
                    raise RuntimeError("test timed out waiting to release stale reader")
                return canonical

            stale_manager._canonicalize_source_state = block_after_stale_read  # type: ignore[method-assign]
            reader_result: dict[str, object] = {}

            def run_stale_reader():
                try:
                    reader_result["value"] = stale_manager.list_sources()
                except BaseException as exc:  # pragma: no cover - surfaced below
                    reader_result["error"] = exc

            reader = threading.Thread(target=run_stale_reader, daemon=True)
            reader.start()
            self.assertTrue(snapshot_read.wait(timeout=5))

            replacement = writer_manager.register_file_source(
                source_id="stale-reader",
                path=transcript,
                context_id="demo",
                confirmed=True,
            )
            transcript.write_text("existing\nnew durable delta\n", encoding="utf-8")
            writer_manager.poll_sources(source_id="stale-reader")
            committed_before_release = writer_manager.list_sources()["sources"][0]

            release_reader.set()
            reader.join(timeout=5)
            self.assertFalse(reader.is_alive())
            if "error" in reader_result:
                raise reader_result["error"]  # type: ignore[misc]
            committed_after_release = writer_manager.list_sources()["sources"][0]

        self.assertNotEqual(initial["source_instance_id"], replacement["source_instance_id"])
        self.assertEqual(
            committed_after_release["source_instance_id"],
            replacement["source_instance_id"],
        )
        self.assertEqual(
            committed_after_release["registration_generation"],
            replacement["registration_generation"],
        )
        self.assertGreater(committed_after_release["cursor"], replacement["cursor"])
        self.assertEqual(committed_after_release, committed_before_release)

    def test_concurrent_app_connect_commits_do_not_lose_connections(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            apps = [
                {"app_name": "Codex", "bundle_id": "com.openai.codex", "pid": 4242},
                {"app_name": "Terminal", "bundle_id": "com.apple.Terminal", "pid": 4343},
            ]
            first_manager = TranscriptCaptureManager(
                root=root,
                backend=backend,
                running_app_provider=lambda: apps,
            )
            second_manager = TranscriptCaptureManager(
                root=root,
                backend=backend,
                running_app_provider=lambda: apps,
            )
            first_write_entered = threading.Event()
            release_first_write = threading.Event()
            second_call_started = threading.Event()
            second_read_entered = threading.Event()
            original_first_write = first_manager._write_app_state
            original_second_read = second_manager._read_app_state

            def block_first_write(state):
                first_write_entered.set()
                if not release_first_write.wait(timeout=5):
                    raise RuntimeError("test timed out waiting to release app commit")
                return original_first_write(state)

            def observe_second_read():
                second_read_entered.set()
                return original_second_read()

            first_manager._write_app_state = block_first_write  # type: ignore[method-assign]
            second_manager._read_app_state = observe_second_read  # type: ignore[method-assign]
            results: dict[str, object] = {}

            def connect(manager, key, app_name, bundle_id, pid):
                try:
                    if key == "second":
                        second_call_started.set()
                    results[key] = manager.connect_running_app(
                        app_name=app_name,
                        bundle_id=bundle_id,
                        pid=pid,
                        confirmed=True,
                    )
                except BaseException as exc:  # pragma: no cover - surfaced below
                    results[f"{key}_error"] = exc

            first = threading.Thread(
                target=connect,
                args=(first_manager, "first", "Codex", "com.openai.codex", 4242),
                daemon=True,
            )
            second = threading.Thread(
                target=connect,
                args=(second_manager, "second", "Terminal", "com.apple.Terminal", 4343),
                daemon=True,
            )
            first.start()
            self.assertTrue(first_write_entered.wait(timeout=5))
            second.start()
            try:
                self.assertTrue(second_call_started.wait(timeout=5))
                self.assertFalse(second_read_entered.wait(timeout=0.1))
            finally:
                release_first_write.set()
            first.join(timeout=5)
            second.join(timeout=5)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            for key in ("first_error", "second_error"):
                if key in results:
                    raise results[key]  # type: ignore[misc]
            listed = first_manager.list_app_connections()

        self.assertEqual(listed["connection_count"], 2)
        self.assertEqual(
            {item["app_name"] for item in listed["connections"]},
            {"Codex", "Terminal"},
        )

    def test_secret_shaped_app_identifiers_are_skipped_and_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            marker = "SYNTHETIC_APP_SECRET_42"
            manager = TranscriptCaptureManager(
                root=root,
                backend=self.make_backend(tmp),
                running_app_provider=lambda: [
                    {
                        "app_name": f"password={marker}",
                        "bundle_id": "com.example.safe",
                        "pid": 4242,
                    }
                ],
            )

            detected = manager.detect_running_apps()
            with self.assertRaises(ValueError) as raised:
                manager.connect_running_app(
                    app_name=f"password={marker}",
                    bundle_id="com.example.safe",
                    pid=4242,
                    confirmed=True,
                    allow_manual=True,
                )
            durable = "".join(
                candidate.read_text(encoding="utf-8", errors="replace")
                for candidate in root.rglob("*")
                if candidate.is_file()
            ) if root.exists() else ""

        self.assertEqual(detected["app_count"], 0)
        self.assertNotIn(marker, str(raised.exception))
        self.assertNotIn(marker, durable)

    def test_file_tail_source_rejects_common_credential_store_paths(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            manager = TranscriptCaptureManager(root=root, backend=self.make_backend(tmp))
            sensitive_paths = [
                Path(tmp) / ".docker" / "config.json",
                Path(tmp) / ".kube" / "audit.log",
                Path(tmp) / ".config" / "gcloud" / "application_default_credentials.json",
                Path(tmp) / ".azure" / "accessTokens.json",
                Path(tmp) / ".aws" / "operator.log",
            ]
            for path in sensitive_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic credential-store sentinel\n", encoding="utf-8")

            for index, path in enumerate(sensitive_paths):
                with self.subTest(path=path):
                    with self.assertRaisesRegex(ValueError, "sensitive-looking path"):
                        manager.register_file_source(
                            source_id=f"sensitive-store-{index}",
                            path=path,
                            context_id="demo",
                            confirmed=True,
                        )

            ordinary = Path(tmp) / "cloud-platform-notes" / "aws-azure-gcloud.log"
            ordinary.parent.mkdir()
            ordinary.write_text("ordinary transcript\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="ordinary-cloud-notes",
                path=ordinary,
                context_id="demo",
                confirmed=True,
            )

        self.assertEqual(registered["path"], str(ordinary.resolve()))

    def test_file_tail_poll_rejects_source_replaced_by_symlink(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "registered.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="symlink-swap",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            replacement = Path(tmp) / "replacement.log"
            replacement.write_text("synthetic replacement sentinel\n", encoding="utf-8")
            transcript.unlink()
            transcript.symlink_to(replacement)

            result = manager.poll_sources(source_id="symlink-swap")
            saved = manager.list_sources()["sources"][0]

        self.assertEqual(result["captured_source_count"], 0)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(saved["cursor"], registered["cursor"])

    def test_file_tail_poll_rejects_file_changed_between_validation_and_open(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "racing.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="racing-source",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            transcript.write_text("existing\nlegitimate delta\n", encoding="utf-8")
            canonical_transcript = transcript.resolve()
            replacement = Path(tmp) / "racing-replacement.log"
            replacement.write_text("synthetic replacement sentinel\n", encoding="utf-8")
            real_open = os.open
            swapped = False
            source_open_flags = 0

            def swap_then_open(path, flags, *args, **kwargs):
                nonlocal source_open_flags, swapped
                if (
                    not swapped
                    and str(path) == canonical_transcript.name
                    and kwargs.get("dir_fd") is not None
                ):
                    source_open_flags = int(flags)
                    replacement.replace(transcript)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with patch("transcript_capture.os.open", side_effect=swap_then_open):
                result = manager.poll_sources(source_id="racing-source")
            saved = manager.list_sources()["sources"][0]

        self.assertTrue(swapped)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(source_open_flags & os.O_NOFOLLOW)
        self.assertEqual(result["captured_source_count"], 0)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(saved["cursor"], registered["cursor"])

    def test_file_tail_poll_rejects_size_change_between_validation_and_open(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "growing-race.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="growing-race",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            transcript.write_text("existing\nfirst delta\n", encoding="utf-8")
            canonical_transcript = transcript.resolve()
            original_inode = transcript.stat().st_ino
            real_open = os.open
            changed = False

            def grow_then_open(path, flags, *args, **kwargs):
                nonlocal changed
                if (
                    not changed
                    and str(path) == canonical_transcript.name
                    and kwargs.get("dir_fd") is not None
                ):
                    transcript.write_text(
                        "existing\nfirst delta\nsecond racing delta\n",
                        encoding="utf-8",
                    )
                    changed = True
                return real_open(path, flags, *args, **kwargs)

            with patch("transcript_capture.os.open", side_effect=grow_then_open):
                result = manager.poll_sources(source_id="growing-race")
            saved = manager.list_sources()["sources"][0]
            after_inode = transcript.stat().st_ino

        self.assertTrue(changed)
        self.assertEqual(after_inode, original_inode)
        self.assertEqual(result["captured_source_count"], 0)
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(saved["cursor"], registered["cursor"])

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

    def test_fresh_manager_repairs_crash_after_aggregate_before_lineage_commit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "lineage-crash.log"
            transcript.write_text("existing\n", encoding="utf-8")
            initial = manager.register_file_source(
                source_id="lineage-crash",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            original_persist = manager._persist_source_lineage

            def fail_after_aggregate(_source):
                raise OSError("injected crash after aggregate commit")

            manager._persist_source_lineage = fail_after_aggregate  # type: ignore[method-assign]
            with self.assertRaisesRegex(OSError, "after aggregate"):
                manager.register_file_source(
                    source_id="lineage-crash",
                    path=transcript,
                    context_id="demo",
                    confirmed=True,
                )
            manager._persist_source_lineage = original_persist  # type: ignore[method-assign]

            committed_state = json.loads(
                manager.paths()["source_state_path"].read_text(encoding="utf-8")
            )["sources"]["lineage-crash"]
            stale_lineage = json.loads(
                manager._source_lineage_path("lineage-crash").read_text(
                    encoding="utf-8"
                )
            )
            self.assertNotEqual(
                committed_state["source_instance_id"],
                stale_lineage["source_instance_id"],
            )

            repaired_manager = TranscriptCaptureManager(root=root, backend=backend)
            repaired_manager.repair_legacy_state()
            repaired_lineage = json.loads(
                repaired_manager._source_lineage_path("lineage-crash").read_text(
                    encoding="utf-8"
                )
            )
            repaired_lineage_mode = (
                repaired_manager._source_lineage_path("lineage-crash").stat().st_mode
                & 0o777
            )
            transcript.write_text("existing\nresumed after repair\n", encoding="utf-8")
            resumed = repaired_manager.poll_sources(source_id="lineage-crash")
            final_source = repaired_manager.list_sources()["sources"][0]
            final_lineage = json.loads(
                repaired_manager._source_lineage_path("lineage-crash").read_text(
                    encoding="utf-8"
                )
            )
            repaired_state_mode = (
                repaired_manager.paths()["source_state_path"].stat().st_mode & 0o777
            )

        self.assertNotEqual(
            initial["source_instance_id"],
            committed_state["source_instance_id"],
        )
        self.assertEqual(
            repaired_lineage["source_instance_id"],
            committed_state["source_instance_id"],
        )
        self.assertEqual(
            repaired_lineage["registration_generation"],
            committed_state["registration_generation"],
        )
        self.assertEqual(resumed["captured_source_count"], 1)
        self.assertEqual(
            final_lineage["source_instance_id"],
            final_source["source_instance_id"],
        )
        self.assertEqual(final_lineage["cursor"], final_source["cursor"])
        self.assertEqual(final_lineage["stream_generation"], final_source["stream_generation"])
        self.assertEqual(repaired_state_mode, 0o600)
        self.assertEqual(repaired_lineage_mode, 0o600)

    def test_initialization_privately_scrubs_legacy_lineage_raw_digests(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            backend = self.make_backend(tmp)
            manager = TranscriptCaptureManager(root=root, backend=backend)
            transcript = Path(tmp) / "legacy-lineage.log"
            transcript.write_text("existing\n", encoding="utf-8")
            registered = manager.register_file_source(
                source_id="legacy-lineage",
                path=transcript,
                context_id="demo",
                confirmed=True,
                start_at_end=True,
            )
            lineage_path = manager._source_lineage_path("legacy-lineage")
            legacy_lineage = json.loads(lineage_path.read_text(encoding="utf-8"))
            legacy_lineage["input_sha256"] = "legacy-lineage-equality-oracle"
            lineage_path.write_text(json.dumps(legacy_lineage), encoding="utf-8")
            lineage_path.chmod(0o644)

            repaired_manager = TranscriptCaptureManager(root=root, backend=backend)
            repaired_manager.repair_legacy_state()
            repaired_text = lineage_path.read_text(encoding="utf-8")
            repaired_source = repaired_manager.list_sources()["sources"][0]
            repaired_mode = lineage_path.stat().st_mode & 0o777

        self.assertNotIn("input_sha256", repaired_text)
        self.assertNotIn("legacy-lineage-equality-oracle", repaired_text)
        self.assertEqual(repaired_mode, 0o600)
        self.assertEqual(
            repaired_source["source_instance_id"],
            registered["source_instance_id"],
        )
        self.assertEqual(repaired_source["cursor"], registered["cursor"])

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

    def test_accessibility_snapshot_revalidates_exact_live_app_identity(self):
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
                        "bundle_id": "com.openai.codex",
                        "pid": 4242,
                    }
                )

        self.assertEqual(calls[0][-3:], ["Codex", "4242", "com.openai.codex"])
        self.assertIn("application processes whose unix id is appPid", calls[0][2])
        self.assertIn("bundle identifier of targetProcess", calls[0][2])
        self.assertIn("Application: Codex", snapshot)
        self.assertNotIn("missing value", snapshot)
        self.assertEqual(snapshot.count("Window 1: Codex"), 1)

    def test_accessibility_snapshot_rejects_pid_reuse_or_identity_substitution(self):
        mismatches = [
            {
                "app_name": "Passwords",
                "bundle_id": "com.apple.Passwords",
                "pid": 4242,
            },
            {
                "app_name": "Codex",
                "bundle_id": "com.example.substitute",
                "pid": 4242,
            },
            {
                "app_name": "Codex",
                "bundle_id": "com.openai.codex",
                "pid": 9001,
            },
        ]
        for live_app in mismatches:
            with self.subTest(live_app=live_app), TemporaryDirectory() as tmp:
                manager = TranscriptCaptureManager(
                    root=Path(tmp) / "capture-root",
                    backend=self.make_backend(tmp),
                )
                manager._detect_visible_application_processes = lambda: [  # type: ignore[method-assign]
                    live_app
                ]
                with patch("transcript_capture.subprocess.run") as run:
                    with self.assertRaisesRegex(ValueError, "app identity changed"):
                        manager._snapshot_app_accessibility(
                            {
                                "app_name": "Codex",
                                "bundle_id": "com.openai.codex",
                                "pid": 4242,
                            }
                        )
                run.assert_not_called()

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

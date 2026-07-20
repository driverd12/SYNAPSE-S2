import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from capture_daemon import (
    GLOBAL_CAPTURE_LOCK,
    CaptureInboxDaemon,
    write_capture_drop,
)
from memory_store import (
    BACKUP_RECEIPT_SCHEMA,
    BACKUP_RESTORE_RECEIPT_SCHEMA,
    BACKUP_SCHEMA_COMPATIBILITY_REGISTRY,
    BACKUP_SCHEMA_CONTRACT_VERSION,
    DurableMemoryStore,
    _json_dumps,
    capture_request_fingerprint,
)
from mlx_backend import SpikingAttentionBackend
from recovery_manager import (
    CAPTURE_ARCHIVE_MANIFEST_SCHEMA,
    RECOVERY_BUNDLE_RESTORE_SCHEMA,
    RECOVERY_BUNDLE_SCHEMA,
    RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
    VerifiedRecoveryManager,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerifiedBackupRecoveryTests(unittest.TestCase):
    @staticmethod
    def _seed_store(root: Path, *, large: bool = False) -> tuple[DurableMemoryStore, Path]:
        db_path = root / "synapse-memory.sqlite3"
        store = DurableMemoryStore(db_path)
        store.upsert_entry(
            tag="verified-backup-fixture",
            context_id="backup-tests",
            source_text=(
                "A deterministic non-secret recovery fixture. " * (25_000 if large else 1)
            ),
            metadata={"classification": "synthetic", "sequence": 1},
            embedding_dimensions=8,
            spike_indices=[1, 3],
            neuron_indices=[2, 4],
            registered_at=100.0,
        )
        return store, db_path

    @staticmethod
    def _backup(store: DurableMemoryStore, root: Path, name: str = "verified.sqlite3"):
        return store.backup(root / name, purpose="unit-test", pinned=False)

    @staticmethod
    def _capture_backed_bundle(root: Path) -> tuple[
        VerifiedRecoveryManager,
        dict,
        str,
    ]:
        capture_root = root
        capture_id = "s2cap_51515151515151515151515151515151"
        backend = SpikingAttentionBackend(
            dimension=32,
            num_neurons=24,
            default_top_k=4,
            recall_count=4,
            compile_graph=False,
            state_path=root / "runtime-state.json",
            memory_path=root / "memory.sqlite3",
        )
        write_capture_drop(
            root=capture_root,
            context_id="recovery-tests",
            source_tag="paired-recovery",
            speaker="codex",
            text=(
                "The paired recovery fixture commits an exactly-once capture. "
                "Its processed payload and receipt must remain tied to SQLite."
            ),
            metadata={"surface": "verified-recovery-test"},
            capture_id=capture_id,
        )
        process_result = CaptureInboxDaemon(
            root=capture_root,
            backend=backend,
        ).process_once()
        if process_result["processed_file_count"] != 1:
            raise AssertionError("capture-backed recovery fixture did not process")
        manager = VerifiedRecoveryManager(
            backend.memory_store,
            capture_root=capture_root,
        )
        bundle = manager.create_bundle(
            root / "paired-recovery.sqlite3",
            purpose="unit-test",
            pinned=True,
        )
        return manager, bundle, capture_id

    @staticmethod
    def _capture_manifest(path: str | Path) -> dict:
        with tarfile.open(path, mode="r:gz") as archive:
            member = archive.getmember("capture-manifest.json")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise AssertionError("capture manifest is unreadable")
            return json.loads(extracted.read().decode("utf-8"))

    @staticmethod
    def _rewrite_signed_bundle_with_processed_request_mismatch(
        manager: VerifiedRecoveryManager,
        bundle: dict,
        capture_id: str,
    ) -> dict[str, object]:
        """Re-sign a structurally valid bundle with one semantic request mismatch.

        The database snapshot and its signed receipt remain pristine.  Only a
        privacy-safe metadata value in the processed capture is changed; the
        capture manifest, archive digest, and outer bundle signature are then
        rebuilt.  A verifier that checks signatures, member digests, counts,
        and capture-ID membership but not the canonical request binding would
        incorrectly accept this fixture.
        """

        capture_path = Path(bundle["capture_archive_path"])
        receipt_path = Path(bundle["bundle_receipt_path"])
        database_path = Path(bundle["backup_path"])
        members: dict[str, bytes] = {}
        with tarfile.open(capture_path, mode="r:gz") as archive:
            for member in archive.getmembers():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise AssertionError("capture bundle member is unreadable")
                members[member.name] = extracted.read()

        manifest = json.loads(members.pop("capture-manifest.json").decode("utf-8"))
        processed_records = [
            record
            for record in manifest["files"]
            if str(record["relative_path"]).startswith("capture_processed/")
            and capture_id in record["capture_ids"]
        ]
        if len(processed_records) != 1:
            raise AssertionError("fixture must contain one processed capture record")
        processed_record = processed_records[0]
        processed_member = "capture/" + str(processed_record["relative_path"])
        payload = json.loads(members[processed_member].decode("utf-8"))
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            raise AssertionError("processed fixture metadata is not an object")
        metadata["surface"] = "signed-semantic-mismatch"
        mutated_bytes = (
            json.dumps(payload, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        members[processed_member] = mutated_bytes
        processed_record["size_bytes"] = len(mutated_bytes)
        processed_record["sha256"] = hashlib.sha256(mutated_bytes).hexdigest()

        canonical_request = manager.daemon._canonical_capture_request(payload)
        mutated_fingerprint = capture_request_fingerprint(
            text=canonical_request["text"],
            context_id=canonical_request["context_id"],
            source_tag=canonical_request["source_tag"],
            speaker=canonical_request["speaker"],
            surprise_threshold=canonical_request["surprise_threshold"],
            min_segment_sentences=canonical_request["min_segment_sentences"],
            metadata=canonical_request["metadata"],
        )
        database_uri = database_path.resolve().as_uri() + "?mode=ro&immutable=1"
        with closing(sqlite3.connect(database_uri, uri=True)) as snapshot:
            row = snapshot.execute(
                "SELECT request_fingerprint FROM capture_operations "
                "WHERE capture_id = ?",
                (capture_id,),
            ).fetchone()
        if row is None:
            raise AssertionError("fixture has no authoritative capture ledger row")
        ledger_fingerprint = str(row[0])
        if mutated_fingerprint == ledger_fingerprint:
            raise AssertionError("fixture mutation did not change request identity")

        manifest["total_bytes"] = sum(
            int(record["size_bytes"]) for record in manifest["files"]
        )
        manifest_seed = {
            key: value for key, value in manifest.items() if key != "manifest_sha256"
        }
        manifest["manifest_sha256"] = hashlib.sha256(
            _json_dumps(manifest_seed).encode("utf-8")
        ).hexdigest()
        manifest_bytes = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

        rewritten_path = capture_path.with_name(f".{capture_path.name}.request-mismatch")
        with tarfile.open(
            rewritten_path,
            mode="w:gz",
            format=tarfile.PAX_FORMAT,
        ) as archive:
            for name, data in (("capture-manifest.json", manifest_bytes), *members.items()):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o600
                member.mtime = 0
                archive.addfile(member, io.BytesIO(data))
        rewritten_path.chmod(0o600)
        os.replace(rewritten_path, capture_path)
        capture_path.chmod(0o600)

        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["capture_sha256"] = hashlib.sha256(
            capture_path.read_bytes()
        ).hexdigest()
        receipt["capture_size_bytes"] = capture_path.stat().st_size
        receipt["capture_manifest_sha256"] = manifest["manifest_sha256"]
        receipt["capture_file_count"] = manifest["file_count"]
        receipt["capture_total_bytes"] = manifest["total_bytes"]
        manager.store._authenticate_receipt(receipt)
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        receipt_path.chmod(0o600)
        return {
            "ledger_fingerprint": ledger_fingerprint,
            "mutated_fingerprint": mutated_fingerprint,
            "reconciliation": dict(manifest["reconciliation"]),
        }

    @staticmethod
    def _retention_manager(root: Path) -> VerifiedRecoveryManager:
        store = DurableMemoryStore(root / "memory.sqlite3")
        manager = VerifiedRecoveryManager(store, capture_root=root)
        manager.daemon.status()
        return manager

    @staticmethod
    def _retention_bundle(
        manager: VerifiedRecoveryManager,
        *,
        created_at: float,
        pinned: bool = False,
    ) -> dict:
        with mock.patch("recovery_manager.time.time", return_value=created_at):
            return manager.create_bundle(
                purpose="retention-test",
                pinned=pinned,
            )

    @staticmethod
    def _file_snapshot(directory: Path) -> dict[str, tuple[str, int]]:
        return {
            path.name: (
                hashlib.sha256(path.read_bytes()).hexdigest(),
                path.stat().st_mode & 0o777,
            )
            for path in directory.iterdir()
            if path.is_file() and not path.is_symlink()
        }

    @staticmethod
    def _directory_identity_snapshot(directory: Path) -> dict[str, tuple]:
        snapshot: dict[str, tuple] = {}
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            metadata = os.lstat(path)
            if path.is_symlink():
                snapshot[path.name] = (
                    "symlink",
                    os.readlink(path),
                    metadata.st_mode & 0o777,
                    metadata.st_uid,
                    metadata.st_nlink,
                )
            elif path.is_file():
                snapshot[path.name] = (
                    "file",
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    metadata.st_mode & 0o777,
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_uid,
                    metadata.st_nlink,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_ctime_ns,
                )
            else:
                snapshot[path.name] = (
                    "other",
                    metadata.st_mode,
                    metadata.st_dev,
                    metadata.st_ino,
                )
        return snapshot

    @staticmethod
    def _write_manifest_only_archive(source: Path, output: Path) -> dict:
        with tarfile.open(source, mode="r:gz") as archive:
            manifest_member = archive.getmember("capture-manifest.json")
            extracted = archive.extractfile(manifest_member)
            if extracted is None:
                raise AssertionError("capture manifest is unreadable")
            manifest_raw = extracted.read()
            manifest = json.loads(manifest_raw.decode("utf-8"))
        with tarfile.open(output, mode="w:gz") as archive:
            member = tarfile.TarInfo("capture-manifest.json")
            member.size = len(manifest_raw)
            member.mode = 0o600
            member.mtime = 0
            archive.addfile(member, io.BytesIO(manifest_raw))
        output.chmod(0o600)
        return manifest

    def _assert_not_verified_after_live_artifact_mutation(self, operation) -> None:
        try:
            result = operation()
        except (OSError, ValueError, RuntimeError):
            return
        self.assertFalse(
            bool(result.get("verified")),
            "a cached retirement response must not claim verified=true after "
            "its live artifacts change",
        )

    def test_backup_publishes_private_immutable_receipt_and_never_overwrites(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            result = self._backup(store, root)
            backup_path = Path(result["backup_path"])
            receipt_path = Path(result["receipt_path"])
            receipt_text = receipt_path.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)

            self.assertEqual(receipt["schema"], BACKUP_RECEIPT_SCHEMA)
            self.assertEqual(receipt["artifact_name"], backup_path.name)
            self.assertEqual(receipt["artifact_sha256"], result["sha256"])
            self.assertEqual(receipt["artifact_size_bytes"], backup_path.stat().st_size)
            self.assertRegex(receipt["receipt_digest"], _SHA256_RE)
            self.assertTrue(result["verified"])
            self.assertEqual(backup_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(backup_path.is_symlink())
            self.assertFalse(receipt_path.is_symlink())
            self.assertNotIn(str(db_path), receipt_text)

            artifact_before = backup_path.read_bytes()
            receipt_before = receipt_path.read_bytes()
            with self.assertRaises(FileExistsError):
                self._backup(store, root)
            self.assertEqual(backup_path.read_bytes(), artifact_before)
            self.assertEqual(receipt_path.read_bytes(), receipt_before)

    def test_verify_rejects_tampered_backup_wrong_digest_and_tampered_receipt(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)

            wrong_digest_result = self._backup(store, root, "wrong-digest.sqlite3")
            with self.assertRaises((ValueError, RuntimeError)):
                store.verify_backup(
                    wrong_digest_result["backup_path"],
                    expected_sha256="0" * 64,
                    receipt_path=wrong_digest_result["receipt_path"],
                )

            tampered_artifact_result = self._backup(store, root, "tampered.sqlite3")
            tampered_path = Path(tampered_artifact_result["backup_path"])
            artifact = bytearray(tampered_path.read_bytes())
            self.assertGreater(len(artifact), 0)
            artifact[-1] ^= 0x01
            tampered_path.write_bytes(artifact)
            tampered_path.chmod(0o600)
            with self.assertRaises((ValueError, RuntimeError)):
                store.verify_backup(
                    tampered_path,
                    receipt_path=tampered_artifact_result["receipt_path"],
                )

            tampered_receipt_result = self._backup(store, root, "receipt.sqlite3")
            receipt_path = Path(tampered_receipt_result["receipt_path"])
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["artifact_sha256"] = "f" * 64
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)
            with self.assertRaises((ValueError, RuntimeError)):
                store.verify_backup(
                    tampered_receipt_result["backup_path"],
                    receipt_path=receipt_path,
                )

    def test_verify_rejects_symlink_and_ambiguous_sqlite_sidecars(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            result = self._backup(store, root)
            backup_path = Path(result["backup_path"])
            alias_path = root / "backup-alias.sqlite3"
            alias_path.symlink_to(backup_path)

            with self.assertRaises((ValueError, RuntimeError)):
                store.verify_backup(
                    alias_path,
                    expected_sha256=result["sha256"],
                )

            for suffix in ("-wal", "-shm"):
                with self.subTest(sidecar=suffix):
                    sidecar_path = Path(f"{backup_path}{suffix}")
                    sidecar_path.write_bytes(b"ambiguous-sidecar")
                    sidecar_path.chmod(0o600)
                    try:
                        with self.assertRaises((ValueError, RuntimeError)):
                            store.verify_backup(
                                backup_path,
                                receipt_path=result["receipt_path"],
                            )
                    finally:
                        sidecar_path.unlink()

    def test_isolated_restore_is_exact_private_receipted_and_no_overwrite(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            backup = self._backup(store, root)
            backup_path = Path(backup["backup_path"])
            restored_path = root / "isolated-restore.sqlite3"

            restored = store.restore_backup(
                backup_path,
                restored_path,
                expected_sha256=backup["sha256"],
                receipt_path=backup["receipt_path"],
                confirm=True,
            )
            restore_receipt_path = Path(restored["restore_receipt_path"])
            restore_receipt = json.loads(
                restore_receipt_path.read_text(encoding="utf-8")
            )

            self.assertTrue(restored["verified"])
            self.assertEqual(restored["restore_path"], str(restored_path))
            self.assertEqual(restored["sha256"], backup["sha256"])
            self.assertEqual(restored_path.read_bytes(), backup_path.read_bytes())
            self.assertEqual(restored_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(restore_receipt_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(restore_receipt["schema"], BACKUP_RESTORE_RECEIPT_SCHEMA)
            self.assertEqual(restore_receipt["artifact_sha256"], backup["sha256"])
            self.assertRegex(restore_receipt["receipt_digest"], _SHA256_RE)
            self.assertFalse(Path(f"{restored_path}-wal").exists())
            self.assertFalse(Path(f"{restored_path}-shm").exists())

            existing_bytes = restored_path.read_bytes()
            with self.assertRaises(FileExistsError):
                store.restore_backup(
                    backup_path,
                    restored_path,
                    receipt_path=backup["receipt_path"],
                    confirm=True,
                )
            self.assertEqual(restored_path.read_bytes(), existing_bytes)

            live_before = hashlib.sha256(db_path.read_bytes()).hexdigest()
            with self.assertRaises((FileExistsError, ValueError, RuntimeError)):
                store.restore_backup(
                    backup_path,
                    db_path,
                    receipt_path=backup["receipt_path"],
                    confirm=True,
                )
            self.assertEqual(hashlib.sha256(db_path.read_bytes()).hexdigest(), live_before)

    def test_restore_requires_explicit_confirmation_and_rejects_symlink_target(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            backup = self._backup(store, root)
            target = root / "unconfirmed.sqlite3"

            with self.assertRaises((ValueError, RuntimeError)):
                store.restore_backup(
                    backup["backup_path"],
                    target,
                    receipt_path=backup["receipt_path"],
                    confirm=False,
                )
            self.assertFalse(target.exists())

            protected = root / "protected.sqlite3"
            protected.write_bytes(b"protected")
            alias = root / "restore-alias.sqlite3"
            alias.symlink_to(protected)
            with self.assertRaises((FileExistsError, ValueError, RuntimeError)):
                store.restore_backup(
                    backup["backup_path"],
                    alias,
                    receipt_path=backup["receipt_path"],
                    confirm=True,
                )
            self.assertEqual(protected.read_bytes(), b"protected")

    def test_secret_shaped_durable_data_blocks_backup_and_untrusted_snapshot(self):
        marker = "SYNTHETIC_BACKUP_SECRET_MUST_NEVER_ECHO_42"
        secret_value = f"api_key='{marker}'"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "UPDATE memory_entries SET source_text = ?",
                    (secret_value,),
                )
                conn.commit()

            blocked_path = root / "blocked.sqlite3"
            with mock.patch("memory_store.LOGGER.exception") as logged:
                with self.assertRaises((ValueError, RuntimeError)) as raised:
                    store.backup(blocked_path, purpose="unit-test", pinned=False)
            rendered_failure = f"{raised.exception!s}\n{logged.mock_calls!r}"
            self.assertNotIn(marker, rendered_failure)
            self.assertFalse(blocked_path.exists())
            self.assertEqual(list(root.glob("blocked.sqlite3*.receipt.json")), [])

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            clean = self._backup(store, root, "clean.sqlite3")
            untrusted_path = root / "untrusted-secret.sqlite3"
            untrusted_path.write_bytes(Path(clean["backup_path"]).read_bytes())
            untrusted_path.chmod(0o600)
            with closing(sqlite3.connect(untrusted_path)) as conn:
                conn.execute(
                    "UPDATE memory_entries SET source_text = ?",
                    (secret_value,),
                )
                conn.commit()
            expected_digest = hashlib.sha256(untrusted_path.read_bytes()).hexdigest()

            with mock.patch("memory_store.LOGGER.exception") as logged:
                with self.assertRaises((ValueError, RuntimeError)) as raised:
                    store.verify_backup(
                        untrusted_path,
                        expected_sha256=expected_digest,
                        receipt_path=None,
                    )
            rendered_failure = f"{raised.exception!s}\n{logged.mock_calls!r}"
            self.assertNotIn(marker, rendered_failure)

    def test_online_backup_is_coherent_while_wal_writer_commits(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root, large=True)
            writer_started = threading.Event()
            stop_writer = threading.Event()
            writer_errors: list[BaseException] = []
            counter_lock = threading.Lock()
            committed_count = 0

            def write_during_backup() -> None:
                nonlocal committed_count
                try:
                    with closing(sqlite3.connect(db_path, timeout=10.0)) as conn:
                        conn.execute("PRAGMA busy_timeout = 10000")
                        self.assertEqual(
                            str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                            "wal",
                        )
                        sequence = 0
                        while not stop_writer.is_set():
                            sequence += 1
                            conn.execute(
                                """
                                INSERT INTO store_metadata (key, value_json, updated_at)
                                VALUES ('backup-wal-sequence', ?, ?)
                                ON CONFLICT(key) DO UPDATE SET
                                    value_json = excluded.value_json,
                                    updated_at = excluded.updated_at
                                """,
                                (json.dumps(sequence), float(sequence)),
                            )
                            conn.commit()
                            with counter_lock:
                                committed_count = sequence
                            writer_started.set()
                            time.sleep(0.0005)
                except BaseException as exc:  # pragma: no cover - diagnostic path
                    writer_errors.append(exc)
                    writer_started.set()

            worker = threading.Thread(
                target=write_during_backup,
                name="backup-wal-writer",
                daemon=True,
            )
            worker.start()
            self.assertTrue(writer_started.wait(timeout=5.0))
            with counter_lock:
                count_before = committed_count
            try:
                backup = self._backup(store, root, "wal-coherent.sqlite3")
            finally:
                stop_writer.set()
                worker.join(timeout=10.0)
            self.assertFalse(worker.is_alive())
            self.assertFalse(writer_errors)
            with counter_lock:
                count_after = committed_count
            self.assertGreater(count_after, count_before)

            verification = store.verify_backup(
                backup["backup_path"],
                expected_sha256=backup["sha256"],
                receipt_path=backup["receipt_path"],
            )
            self.assertTrue(verification["verified"])
            with closing(sqlite3.connect(backup["backup_path"])) as snapshot:
                self.assertEqual(
                    snapshot.execute("PRAGMA quick_check").fetchall(),
                    [("ok",)],
                )
                self.assertEqual(snapshot.execute("PRAGMA foreign_key_check").fetchall(), [])
                snapshot_sequence = int(
                    json.loads(
                        snapshot.execute(
                            "SELECT value_json FROM store_metadata WHERE key = ?",
                            ("backup-wal-sequence",),
                        ).fetchone()[0]
                    )
                )
            self.assertGreaterEqual(snapshot_sequence, 1)
            self.assertLessEqual(snapshot_sequence, count_after)

    def test_paired_bundle_round_trip_preserves_capture_ledger_consistency(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, capture_id = self._capture_backed_bundle(root)

            verified = manager.verify_bundle(bundle["bundle_receipt_path"])
            restored = manager.restore_bundle_isolated(
                bundle["bundle_receipt_path"],
                root / "isolated-recovery",
                confirm=True,
            )

            self.assertEqual(bundle["bundle_schema"], RECOVERY_BUNDLE_SCHEMA)
            self.assertTrue(bundle["bundle_verified"])
            self.assertTrue(verified["verified"])
            self.assertTrue(verified["receipt_identity_trusted"])
            self.assertTrue(restored["verified"])
            self.assertEqual(restored["missing_transport_ledger_count"], 0)
            proof = json.loads(
                Path(restored["recovery_proof_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(proof["schema"], RECOVERY_BUNDLE_RESTORE_SCHEMA)
            self.assertGreaterEqual(proof["transport_receipt_capture_count"], 1)
            self.assertGreaterEqual(proof["processed_capture_count"], 1)

            restored_root = Path(restored["restore_root"])
            with closing(sqlite3.connect(restored_root / "memory.sqlite3")) as conn:
                ledger_rows = conn.execute(
                    "SELECT capture_id, protocol FROM capture_operations"
                ).fetchall()
            self.assertIn((capture_id, "capture.v2"), ledger_rows)
            receipt_text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (restored_root / "capture-root" / "capture_receipts").glob(
                    "*.json"
                )
            )
            processed_text = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (restored_root / "capture-root" / "capture_processed").glob(
                    "*.json"
                )
            )
            self.assertIn(capture_id, receipt_text)
            self.assertIn(capture_id, processed_text)

    def test_signed_bundle_rejects_processed_request_fingerprint_mismatch(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, capture_id = self._capture_backed_bundle(root)
            evidence = self._rewrite_signed_bundle_with_processed_request_mismatch(
                manager,
                bundle,
                capture_id,
            )

            self.assertNotEqual(
                evidence["ledger_fingerprint"],
                evidence["mutated_fingerprint"],
            )
            reconciliation = evidence["reconciliation"]
            self.assertEqual(reconciliation["ledger_capture_count"], 1)
            self.assertEqual(
                reconciliation["missing_authoritative_ledger_count"],
                0,
            )
            with self.assertRaisesRegex(
                (ValueError, RuntimeError),
                "request|fingerprint|ledger|binding",
            ):
                manager.verify_bundle(bundle["bundle_receipt_path"])

    def test_isolated_restore_cannot_publish_proof_for_request_fingerprint_mismatch(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, capture_id = self._capture_backed_bundle(root)
            self._rewrite_signed_bundle_with_processed_request_mismatch(
                manager,
                bundle,
                capture_id,
            )
            output_root = root / "request-mismatch-restore"

            with self.assertRaisesRegex(
                (ValueError, RuntimeError),
                "request|fingerprint|ledger|binding",
            ):
                manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    output_root,
                    confirm=True,
                )

            self.assertFalse(output_root.exists())
            self.assertFalse((output_root / "recovery-proof.receipt.json").exists())

    def test_capture_archive_rejects_traversal_symlink_and_tampering(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            manager = VerifiedRecoveryManager(
                store,
                capture_root=root,
            )
            manager.daemon.status()
            bundle = manager.create_bundle(
                root / "archive-fixture.sqlite3",
                purpose="unit-test",
            )
            archive_path = Path(bundle["capture_archive_path"])
            manifest = self._capture_manifest(archive_path)

            alias_path = root / "capture-alias.tar.gz"
            alias_path.symlink_to(archive_path)
            with self.assertRaises((ValueError, RuntimeError)):
                manager._verify_capture_archive(
                    alias_path,
                    expected_sha256=bundle["capture_archive_sha256"],
                    expected_manifest_sha256=manifest["manifest_sha256"],
                )

            tampered = bytearray(archive_path.read_bytes())
            tampered[-1] ^= 0x01
            archive_path.write_bytes(tampered)
            archive_path.chmod(0o600)
            with self.assertRaises((ValueError, RuntimeError, tarfile.TarError)):
                manager._verify_capture_archive(
                    archive_path,
                    expected_sha256=bundle["capture_archive_sha256"],
                    expected_manifest_sha256=manifest["manifest_sha256"],
                )

            traversal_path = root / "traversal.tar.gz"
            content = b'{"capture_id":"s2cap_61616161616161616161616161616161"}'
            traversal_seed = {
                "schema": CAPTURE_ARCHIVE_MANIFEST_SCHEMA,
                "file_count": 1,
                "total_bytes": len(content),
                "database_binding": manifest["database_binding"],
                "reconciliation": {
                    "ledger_capture_count": 0,
                    "ledger_backed_file_count": 0,
                    "replay_required_capture_count": 1,
                    "replay_required_file_count": 1,
                    "identifierless_replay_file_count": 0,
                    "legacy_snapshot_file_count": 0,
                    "governance_evidence_file_count": 0,
                    "unclassified_file_count": 0,
                    "missing_authoritative_ledger_count": 0,
                },
                "files": [
                    {
                        "relative_path": "../escape.json",
                        "category": "v2-capture-payload",
                        "capture_ids": [
                            "s2cap_61616161616161616161616161616161"
                        ],
                        "replay_disposition": "replay-required",
                        "size_bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "mode": 0o600,
                    }
                ],
            }
            traversal_manifest = {
                **traversal_seed,
                "manifest_sha256": hashlib.sha256(
                    _json_dumps(traversal_seed).encode("utf-8")
                ).hexdigest(),
            }
            with tarfile.open(traversal_path, mode="w:gz") as archive_handle:
                manifest_bytes = (
                    json.dumps(traversal_manifest, sort_keys=True) + "\n"
                ).encode("utf-8")
                manifest_info = tarfile.TarInfo("capture-manifest.json")
                manifest_info.size = len(manifest_bytes)
                archive_handle.addfile(manifest_info, io.BytesIO(manifest_bytes))
                content_info = tarfile.TarInfo("capture/../escape.json")
                content_info.size = len(content)
                archive_handle.addfile(content_info, io.BytesIO(content))
            traversal_path.chmod(0o600)
            traversal_sha256 = hashlib.sha256(traversal_path.read_bytes()).hexdigest()
            with self.assertRaises((ValueError, RuntimeError)):
                manager._verify_capture_archive(
                    traversal_path,
                    expected_sha256=traversal_sha256,
                    expected_manifest_sha256=traversal_manifest["manifest_sha256"],
                    ledger_ids=set(),
                    database_binding=manifest["database_binding"],
                )

    def test_capture_producer_waits_for_global_maintenance_lock(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "capture-root"
            daemon = CaptureInboxDaemon(root=root)
            paths = daemon.paths()
            daemon._ensure_transport_dirs(paths)
            producer_started = threading.Event()
            producer_finished = threading.Event()
            producer_errors: list[BaseException] = []
            produced_paths: list[Path] = []

            def produce() -> None:
                producer_started.set()
                try:
                    produced_paths.append(
                        write_capture_drop(
                            root=root,
                            context_id="recovery-tests",
                            source_tag="lock-fencing",
                            speaker="codex",
                            text="Producer publication waits for the recovery snapshot gate.",
                            capture_id="s2cap_71717171717171717171717171717171",
                        )
                    )
                except BaseException as exc:  # pragma: no cover - diagnostic path
                    producer_errors.append(exc)
                finally:
                    producer_finished.set()

            worker = threading.Thread(target=produce, name="capture-lock-producer")
            with daemon._exclusive_lock(
                paths["lock_dir"] / GLOBAL_CAPTURE_LOCK,
                blocking=True,
            ) as acquired:
                self.assertTrue(acquired)
                worker.start()
                self.assertTrue(producer_started.wait(timeout=2.0))
                self.assertFalse(producer_finished.wait(timeout=0.15))
                self.assertEqual(list(paths["inbox_dir"].glob("*.json")), [])
            self.assertTrue(producer_finished.wait(timeout=5.0))
            worker.join(timeout=5.0)

            self.assertFalse(worker.is_alive())
            self.assertFalse(producer_errors)
            self.assertEqual(len(produced_paths), 1)
            self.assertTrue(produced_paths[0].is_file())

    def test_cross_store_bundle_requires_both_reviewed_digests(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _manager, bundle, _capture_id = self._capture_backed_bundle(root)
            foreign_root = root / "foreign-store"
            foreign_store = DurableMemoryStore(foreign_root / "memory.sqlite3")
            foreign_manager = VerifiedRecoveryManager(
                foreign_store,
                capture_root=foreign_root / "capture-root",
            )
            receipt_path = bundle["bundle_receipt_path"]
            database_sha256 = bundle["sha256"]
            capture_sha256 = bundle["capture_archive_sha256"]

            for supplied in (
                {},
                {"expected_database_sha256": database_sha256},
                {"expected_capture_sha256": capture_sha256},
            ):
                with self.subTest(supplied=sorted(supplied)):
                    with self.assertRaises(ValueError):
                        foreign_manager.verify_bundle(receipt_path, **supplied)

            verified = foreign_manager.verify_bundle(
                receipt_path,
                expected_database_sha256=database_sha256,
                expected_capture_sha256=capture_sha256,
            )
            self.assertTrue(verified["verified"])
            self.assertFalse(verified["receipt_identity_trusted"])
            self.assertTrue(verified["reviewed_digests_verified"])

    def test_schema_trigger_and_dropped_table_snapshots_are_not_restore_eligible(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            backup = self._backup(store, root)
            pristine = Path(backup["backup_path"]).read_bytes()

            candidates = {
                "trigger": """
                    CREATE TRIGGER forged_recovery_trigger
                    AFTER INSERT ON memory_entries BEGIN SELECT 1; END
                """,
                "dropped-table": "DROP TABLE memory_relationships",
            }
            for name, statement in candidates.items():
                with self.subTest(candidate=name):
                    candidate = root / f"{name}.sqlite3"
                    candidate.write_bytes(pristine)
                    candidate.chmod(0o600)
                    with closing(sqlite3.connect(candidate)) as conn:
                        conn.execute("PRAGMA journal_mode = DELETE")
                        conn.execute(statement)
                        conn.commit()
                    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                    with self.assertRaises(RuntimeError):
                        store.verify_backup(candidate, expected_sha256=digest)

    def test_live_database_hardlink_is_rejected_before_verification(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            alias_path = root / "live-hardlink.sqlite3"
            os.link(db_path, alias_path)
            digest = hashlib.sha256(alias_path.read_bytes()).hexdigest()

            with self.assertRaisesRegex(ValueError, "must not alias"):
                store.verify_backup(alias_path, expected_sha256=digest)

    def test_forged_receipt_with_recomputed_digest_fails_signature_verification(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            backup = self._backup(store, root)
            receipt_path = Path(backup["receipt_path"])
            forged = json.loads(receipt_path.read_text(encoding="utf-8"))
            forged["purpose"] = "forged-purpose"
            forged["receipt_digest"] = store._canonical_payload_digest(forged)
            receipt_path.write_text(
                json.dumps(forged, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "signature verification"):
                store.verify_backup(
                    backup["backup_path"],
                    receipt_path=receipt_path,
                )

    def test_identifierless_replay_file_has_explicit_reconciliation_counts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            manager = VerifiedRecoveryManager(store, capture_root=root)
            paths = manager.daemon.paths()
            manager.daemon.status()
            identifierless = paths["inbox_dir"] / "legacy-identifierless.json"
            identifierless.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "text": "Legacy capture remains explicitly queued for replay.",
                        "context_id": "backup-tests",
                        "source_tag": "legacy-replay",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            identifierless.chmod(0o600)

            bundle = manager.create_bundle(
                root / "identifierless.sqlite3",
                purpose="unit-test",
            )
            verified = manager.verify_bundle(bundle["bundle_receipt_path"])
            manifest = self._capture_manifest(bundle["capture_archive_path"])
            reconciliation = manifest["reconciliation"]

            self.assertTrue(verified["verified"])
            self.assertEqual(reconciliation["ledger_capture_count"], 0)
            self.assertEqual(reconciliation["replay_required_capture_count"], 0)
            self.assertEqual(reconciliation["replay_required_file_count"], 1)
            self.assertEqual(reconciliation["identifierless_replay_file_count"], 1)
            self.assertEqual(reconciliation["missing_authoritative_ledger_count"], 0)
            record = next(
                record
                for record in manifest["files"]
                if record["relative_path"].endswith("legacy-identifierless.json")
            )
            self.assertEqual(record["capture_ids"], [])
            self.assertEqual(record["replay_disposition"], "replay-required")

            restored = manager.restore_bundle_isolated(
                bundle["bundle_receipt_path"],
                root / "identifierless-restore",
                confirm=True,
            )
            restored_file = (
                Path(restored["capture_restore_path"])
                / "capture_inbox"
                / identifierless.name
            )
            self.assertTrue(restored_file.is_file())
            self.assertEqual(restored["missing_transport_ledger_count"], 0)

    def test_duplicate_processed_payload_and_receipt_files_are_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, _bundle, _capture_id = self._capture_backed_bundle(root)
            paths = manager.daemon.paths()

            processed = next(paths["processed_dir"].glob("*.json"))
            duplicate_processed = processed.with_name("duplicate-processed.json")
            duplicate_processed.write_bytes(processed.read_bytes())
            duplicate_processed.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "duplicate cross-file"):
                manager.create_bundle(
                    root / "duplicate-processed.sqlite3",
                    purpose="unit-test",
                )
            duplicate_processed.unlink()

            receipt = next(paths["receipt_dir"].glob("*.json"))
            duplicate_receipt = receipt.with_name("duplicate-receipt.json")
            duplicate_receipt.write_bytes(receipt.read_bytes())
            duplicate_receipt.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "duplicate cross-file"):
                manager.create_bundle(
                    root / "duplicate-receipt.sqlite3",
                    purpose="unit-test",
                )

    def test_capture_root_provenance_is_bound_and_override_is_explicit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, _capture_id = self._capture_backed_bundle(root)
            receipt_path = Path(bundle["bundle_receipt_path"])
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            manifest = self._capture_manifest(bundle["capture_archive_path"])
            binding = manifest["database_binding"]

            self.assertEqual(receipt["capture_root_provenance"], "canonical-store-parent")
            self.assertEqual(
                binding["capture_root_provenance"],
                receipt["capture_root_provenance"],
            )
            self.assertEqual(
                binding["capture_root_identity_digest"],
                receipt["capture_root_identity_digest"],
            )
            self.assertRegex(receipt["capture_root_identity_digest"], _SHA256_RE)
            self.assertTrue(manager.verify_bundle(receipt_path)["verified"])

            receipt["capture_root_provenance"] = "explicit-noncanonical"
            manager.store._authenticate_receipt(receipt)
            receipt_path.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "database binding mismatch"):
                manager.verify_bundle(receipt_path)

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store_root = root / "store"
            capture_root = root / "external-capture"
            store = DurableMemoryStore(store_root / "memory.sqlite3")
            CaptureInboxDaemon(root=capture_root).status()
            strict = VerifiedRecoveryManager(store, capture_root=capture_root)
            with self.assertRaisesRegex(ValueError, "explicit noncanonical override"):
                strict.create_bundle(
                    store_root / "strict.sqlite3",
                    purpose="unit-test",
                )

            overridden = VerifiedRecoveryManager(
                store,
                capture_root=capture_root,
                allow_noncanonical_capture_root=True,
            )
            bundle = overridden.create_bundle(
                store_root / "overridden.sqlite3",
                purpose="unit-test",
            )
            receipt = json.loads(
                Path(bundle["bundle_receipt_path"]).read_text(encoding="utf-8")
            )
            manifest = self._capture_manifest(bundle["capture_archive_path"])
            self.assertEqual(
                receipt["capture_root_provenance"],
                "explicit-noncanonical",
            )
            self.assertEqual(
                manifest["database_binding"]["capture_root_identity_digest"],
                receipt["capture_root_identity_digest"],
            )
            self.assertTrue(overridden.verify_bundle(bundle["bundle_receipt_path"])["verified"])

    def test_registered_prior_schema_restores_then_migrates_to_current_contract(self):
        prior_contract_version = "s2-schema-v4-test"
        migration_key = "secret_content_scrub_v3"
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(
                    "DELETE FROM store_migrations WHERE key = ?",
                    (migration_key,),
                )
                conn.commit()
            with closing(sqlite3.connect(db_path)) as conn:
                conn.row_factory = sqlite3.Row
                schema = store._sqlite_schema_fingerprint(conn)
                migrations = sorted(
                    str(row[0])
                    for row in conn.execute(
                        "SELECT key FROM store_migrations ORDER BY key"
                    ).fetchall()
                )
                prior_contract = {
                    "schema_sha256": str(schema["sha256"]),
                    "table_count": int(schema["table_count"]),
                    "index_count": int(schema["index_count"]),
                    "migration_set_sha256": hashlib.sha256(
                        _json_dumps(migrations).encode("utf-8")
                    ).hexdigest(),
                    "migration_count": len(migrations),
                    "application_id": int(
                        conn.execute("PRAGMA application_id").fetchone()[0]
                    ),
                    "user_version": int(
                        conn.execute("PRAGMA user_version").fetchone()[0]
                    ),
                }

            with mock.patch.dict(
                BACKUP_SCHEMA_COMPATIBILITY_REGISTRY,
                {prior_contract_version: prior_contract},
                clear=False,
            ):
                # Simulate the N runtime's backup connection: it knows its
                # registered contract but cannot run the N+1 startup migration.
                with mock.patch.object(
                    store,
                    "_connect",
                    side_effect=store._connect_existing_write,
                ):
                    prior_backup = store.backup(
                        root / "prior-schema.sqlite3",
                        purpose="compatibility-test",
                    )
                self.assertEqual(
                    prior_backup["schema_contract_version"],
                    prior_contract_version,
                )
                restored_path = root / "prior-schema-restored.sqlite3"
                restored = store.restore_backup(
                    prior_backup["backup_path"],
                    restored_path,
                    receipt_path=prior_backup["receipt_path"],
                    confirm=True,
                )
                self.assertEqual(
                    restored_path.read_bytes(),
                    Path(prior_backup["backup_path"]).read_bytes(),
                )
                self.assertEqual(restored["sha256"], prior_backup["sha256"])

                migrated_store = DurableMemoryStore(restored_path)
                with closing(sqlite3.connect(restored_path)) as conn:
                    self.assertEqual(
                        conn.execute(
                            "SELECT COUNT(*) FROM store_migrations WHERE key = ?",
                            (migration_key,),
                        ).fetchone()[0],
                        1,
                    )
                    self.assertEqual(
                        conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0],
                        1,
                    )
                migrated_backup = migrated_store.backup(
                    root / "current-schema-recertified.sqlite3",
                    purpose="compatibility-test",
                )
                self.assertEqual(
                    migrated_backup["schema_contract_version"],
                    BACKUP_SCHEMA_CONTRACT_VERSION,
                )
                self.assertTrue(migrated_backup["verified"])

    def test_retention_preserves_sole_latest_keep_latest_and_pinned_bundles(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            sole = self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=0,
                evaluation_time=evaluation_time,
            )
            self.assertEqual(plan["verified_bundle_count"], 1)
            self.assertEqual(plan["protected_bundle_count"], 1)
            self.assertEqual(plan["retire_bundle_count"], 0)
            sole_plan = plan["bundles"][0]
            self.assertEqual(
                sole_plan["bundle_receipt_name"],
                Path(sole["bundle_receipt_path"]).name,
            )
            self.assertIn("latest-verified", sole_plan["protection_reasons"])
            self.assertIn("within-keep-latest", sole_plan["protection_reasons"])

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            oldest = self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            pinned = self._retention_bundle(
                manager,
                created_at=evaluation_time - (90 * day),
                pinned=True,
            )
            second_latest = self._retention_bundle(
                manager,
                created_at=evaluation_time - (80 * day),
            )
            latest = self._retention_bundle(
                manager,
                created_at=evaluation_time - (70 * day),
            )
            plan = manager.plan_retention(
                keep_latest=2,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            by_name = {
                bundle["bundle_receipt_name"]: bundle
                for bundle in plan["bundles"]
            }
            oldest_plan = by_name[Path(oldest["bundle_receipt_path"]).name]
            pinned_plan = by_name[Path(pinned["bundle_receipt_path"]).name]
            second_plan = by_name[Path(second_latest["bundle_receipt_path"]).name]
            latest_plan = by_name[Path(latest["bundle_receipt_path"]).name]

            self.assertEqual(oldest_plan["disposition"], "retire")
            self.assertEqual(pinned_plan["disposition"], "protect")
            self.assertIn("pinned", pinned_plan["protection_reasons"])
            self.assertEqual(second_plan["disposition"], "protect")
            self.assertIn("within-keep-latest", second_plan["protection_reasons"])
            self.assertEqual(latest_plan["disposition"], "protect")
            self.assertIn("latest-verified", latest_plan["protection_reasons"])
            self.assertEqual(plan["retire_bundle_count"], 1)
            self.assertTrue(plan["apply_permitted"])

    def test_retention_moves_only_old_unpinned_bundle_to_private_quarantine(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            oldest = self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            pinned = self._retention_bundle(
                manager,
                created_at=evaluation_time - (90 * day),
                pinned=True,
            )
            latest = self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            candidate = next(
                bundle
                for bundle in plan["bundles"]
                if bundle["disposition"] == "retire"
            )
            self.assertEqual(
                candidate["bundle_receipt_name"],
                Path(oldest["bundle_receipt_path"]).name,
            )
            source_directory = root / "backups" / "verified"
            protected_names = {
                artifact["name"]
                for bundle in plan["bundles"]
                if bundle["disposition"] == "protect"
                for artifact in bundle["artifacts"]
            }

            applied = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )
            quarantine = Path(applied["quarantine_path"])
            retired_bundle = quarantine / candidate["bundle_id"]

            self.assertEqual(applied["retired_bundle_count"], 1)
            self.assertEqual(applied["retired_artifact_count"], 4)
            self.assertTrue(applied["recoverable"])
            self.assertTrue(applied["verified"])
            self.assertEqual(quarantine.stat().st_mode & 0o777, 0o700)
            for artifact in candidate["artifacts"]:
                source = source_directory / artifact["name"]
                retired = retired_bundle / artifact["name"]
                self.assertFalse(source.exists())
                self.assertTrue(retired.is_file())
                self.assertEqual(retired.stat().st_mode & 0o777, 0o600)
                self.assertEqual(
                    hashlib.sha256(retired.read_bytes()).hexdigest(),
                    artifact["sha256"],
                )
            for name in protected_names:
                self.assertTrue((source_directory / name).is_file())
            journal_root = root / "backups" / "retirement-journals"
            for receipt in (
                journal_root / f"{plan['plan_token']}.prepared.receipt.json",
                Path(applied["completion_receipt_path"]),
            ):
                self.assertTrue(receipt.is_file())
                self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertTrue(Path(pinned["bundle_receipt_path"]).is_file())
            self.assertTrue(Path(latest["bundle_receipt_path"]).is_file())

    def test_retention_stale_plan_token_blocks_without_moving_files(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (90 * day),
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (80 * day),
            )
            source_directory = root / "backups" / "verified"
            before = self._file_snapshot(source_directory)

            with self.assertRaisesRegex(RuntimeError, "changed after planning"):
                manager.apply_retention(
                    plan_token=plan["plan_token"],
                    cutoff_created_at=plan["cutoff_created_at"],
                    keep_latest=1,
                    max_age_days=30,
                    confirm=True,
                )

            self.assertEqual(self._file_snapshot(source_directory), before)
            self.assertFalse((root / "backups" / "retired").exists())

    def test_retention_invalid_or_orphaned_inventory_freezes_apply(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        for corruption in ("orphan", "invalid-receipt"):
            with self.subTest(corruption=corruption), TemporaryDirectory() as tmp:
                root = Path(tmp)
                manager = self._retention_manager(root)
                older = self._retention_bundle(
                    manager,
                    created_at=evaluation_time - (100 * day),
                )
                self._retention_bundle(
                    manager,
                    created_at=evaluation_time - (90 * day),
                )
                source_directory = root / "backups" / "verified"
                if corruption == "orphan":
                    orphan = source_directory / "orphan.sqlite3"
                    orphan.write_bytes(b"orphaned-recovery-artifact")
                    orphan.chmod(0o600)
                else:
                    receipt = Path(older["bundle_receipt_path"])
                    payload = json.loads(receipt.read_text(encoding="utf-8"))
                    payload["receipt_digest"] = "0" * 64
                    receipt.write_text(
                        json.dumps(payload, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    receipt.chmod(0o600)
                plan = manager.plan_retention(
                    keep_latest=1,
                    max_age_days=30,
                    evaluation_time=evaluation_time,
                )
                before = self._file_snapshot(source_directory)

                self.assertFalse(plan["apply_permitted"])
                if corruption == "orphan":
                    self.assertGreaterEqual(plan["orphan_artifact_count"], 1)
                else:
                    self.assertGreaterEqual(plan["blocked_receipt_count"], 1)
                with self.assertRaisesRegex(RuntimeError, "retention is blocked"):
                    manager.apply_retention(
                        plan_token=plan["plan_token"],
                        cutoff_created_at=plan["cutoff_created_at"],
                        keep_latest=1,
                        max_age_days=30,
                        confirm=True,
                    )
                self.assertEqual(self._file_snapshot(source_directory), before)
                self.assertFalse((root / "backups" / "retired").exists())

    def test_retention_mid_move_failure_rolls_back_exact_source_files(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            candidate = next(
                bundle
                for bundle in plan["bundles"]
                if bundle["disposition"] == "retire"
            )
            source_directory = root / "backups" / "verified"
            before = self._file_snapshot(source_directory)
            original_rename = os.rename
            retirement_moves = 0

            def fail_second_retirement_move(source, destination):
                nonlocal retirement_moves
                destination_path = Path(destination)
                if "retired" in destination_path.parts:
                    retirement_moves += 1
                    if retirement_moves == 2:
                        raise OSError("simulated mid-move retirement failure")
                return original_rename(source, destination)

            with mock.patch(
                "recovery_manager.os.rename",
                side_effect=fail_second_retirement_move,
            ):
                with self.assertRaisesRegex(OSError, "simulated mid-move"):
                    manager.apply_retention(
                        plan_token=plan["plan_token"],
                        cutoff_created_at=plan["cutoff_created_at"],
                        keep_latest=1,
                        max_age_days=30,
                        confirm=True,
                    )

            self.assertEqual(retirement_moves, 2)
            self.assertEqual(self._file_snapshot(source_directory), before)
            quarantine = root / "backups" / "retired" / plan["plan_token"]
            self.assertFalse(quarantine.exists())
            journal_root = root / "backups" / "retirement-journals"
            self.assertTrue(
                (journal_root / f"{plan['plan_token']}.prepared.receipt.json").is_file()
            )
            self.assertFalse(
                (journal_root / f"{plan['plan_token']}.completed.receipt.json").exists()
            )
            self.assertTrue(
                (journal_root / f"{plan['plan_token']}.recovered.receipt.json").is_file()
            )
            for artifact in candidate["artifacts"]:
                self.assertTrue((source_directory / artifact["name"]).is_file())

    def test_retention_preserves_newest_cutover_ready_when_latest_has_replay_debt(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            oldest_clean = self._retention_bundle(
                manager,
                created_at=evaluation_time - (110 * day),
            )
            newest_clean = self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            identifierless = (
                manager.daemon.paths()["inbox_dir"] / "legacy-replay-debt.json"
            )
            identifierless.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "text": "This legacy transport file still requires replay.",
                        "context_id": "backup-tests",
                        "source_tag": "legacy-replay",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            identifierless.chmod(0o600)
            latest_with_debt = self._retention_bundle(
                manager,
                created_at=evaluation_time - (90 * day),
            )

            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=0,
                evaluation_time=evaluation_time,
            )
            by_name = {
                bundle["bundle_receipt_name"]: bundle for bundle in plan["bundles"]
            }
            oldest_plan = by_name[Path(oldest_clean["bundle_receipt_path"]).name]
            clean_plan = by_name[Path(newest_clean["bundle_receipt_path"]).name]
            debt_plan = by_name[Path(latest_with_debt["bundle_receipt_path"]).name]

            self.assertFalse(debt_plan["cutover_ready"])
            self.assertEqual(debt_plan["replay_required_file_count"], 1)
            self.assertEqual(debt_plan["disposition"], "protect")
            self.assertIn("latest-verified", debt_plan["protection_reasons"])
            self.assertTrue(clean_plan["cutover_ready"])
            self.assertEqual(clean_plan["disposition"], "protect")
            self.assertIn("newest-cutover-ready", clean_plan["protection_reasons"])
            self.assertEqual(oldest_plan["disposition"], "retire")
            self.assertEqual(plan["retire_bundle_count"], 1)

    def test_retention_plan_receipt_is_signed_and_decision_digest_is_deterministic(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )

            first = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            second = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            receipt_path = Path(first["plan_receipt_path"])
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            seed_keys = {
                "schema",
                "directory",
                "repository_identity",
                "keep_latest",
                "max_age_days",
                "cutoff_created_at",
                "evaluation_time",
                "expires_at",
                "bundles",
                "blocked_receipts",
                "orphan_artifact_names",
                "overlapping_artifact_names",
                "overlapping_inode_artifact_names",
                "colliding_artifact_names",
                "ambiguous_artifact_names",
            }
            recomputed_decision = hashlib.sha256(
                _json_dumps({key: receipt[key] for key in seed_keys}).encode("utf-8")
            ).hexdigest()

            self.assertEqual(first["plan_token"], second["plan_token"])
            self.assertEqual(first["decision_digest"], second["decision_digest"])
            self.assertEqual(first["decision_digest"], recomputed_decision)
            self.assertEqual(first["plan_token"], receipt["receipt_digest"])
            self.assertEqual(
                receipt["receipt_digest"],
                manager.store._canonical_payload_digest(receipt),
            )
            self.assertTrue(manager.store._verify_receipt_authenticator(receipt))
            self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt_path.stat().st_nlink, 1)
            self.assertEqual(
                manager._read_retention_plan(first["plan_token"])["decision_digest"],
                first["decision_digest"],
            )

            signature = receipt["receipt_signature"]
            receipt["receipt_signature"] = (
                ("A" if signature[0] != "A" else "B") + signature[1:]
            )
            receipt_path.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "signature verification failed"):
                manager._read_retention_plan(first["plan_token"])

    def test_retention_hardlink_symlink_and_orphan_freeze_is_non_mutating(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            older = self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            source_directory = root / "backups" / "verified"
            original_database = Path(older["backup_path"])
            hardlink = source_directory / "unexpected-hardlink.sqlite3"
            os.link(original_database, hardlink)
            symlink = source_directory / "unexpected-symlink.sqlite3.capture.tar.gz"
            symlink.symlink_to(original_database.name)
            orphan = source_directory / "unexpected-orphan.sqlite3"
            orphan.write_bytes(b"unclaimed recovery artifact")
            orphan.chmod(0o600)

            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            before = self._directory_identity_snapshot(source_directory)

            self.assertFalse(plan["apply_permitted"])
            self.assertGreaterEqual(plan["blocked_receipt_count"], 1)
            self.assertIn(hardlink.name, plan["ambiguous_artifact_names"])
            self.assertIn(symlink.name, plan["ambiguous_artifact_names"])
            self.assertIn(orphan.name, plan["orphan_artifact_names"])
            with self.assertRaisesRegex(RuntimeError, "retention is blocked"):
                manager.apply_retention(
                    plan_token=plan["plan_token"],
                    cutoff_created_at=plan["cutoff_created_at"],
                    keep_latest=1,
                    max_age_days=30,
                    confirm=True,
                )

            self.assertEqual(
                self._directory_identity_snapshot(source_directory),
                before,
            )
            self.assertFalse((root / "backups" / "retired").exists())

    def test_retention_apply_is_idempotent_after_completion(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            first = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )
            quarantine = Path(first["quarantine_path"])
            after_first = self._directory_identity_snapshot(
                root / "backups" / "verified"
            )
            quarantine_files = self._file_snapshot(
                quarantine / next(
                    bundle["bundle_id"]
                    for bundle in plan["bundles"]
                    if bundle["disposition"] == "retire"
                )
            )

            second = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )

            self.assertEqual(first["state"], "completed")
            self.assertEqual(second["state"], "already-completed")
            self.assertEqual(
                second["retired_bundle_count"], first["retired_bundle_count"]
            )
            self.assertEqual(
                second["retired_artifact_count"], first["retired_artifact_count"]
            )
            self.assertEqual(
                Path(second["quarantine_path"]).resolve(),
                quarantine.resolve(),
            )
            self.assertEqual(
                self._directory_identity_snapshot(root / "backups" / "verified"),
                after_first,
            )
            self.assertEqual(
                self._file_snapshot(
                    quarantine / next(
                        bundle["bundle_id"]
                        for bundle in plan["bundles"]
                        if bundle["disposition"] == "retire"
                    )
                ),
                quarantine_files,
            )

    def test_retention_zero_candidate_apply_is_idempotent_without_fake_path(self):
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - 86_400.0,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )

            first = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )
            second = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )

            self.assertEqual(first["state"], "completed")
            self.assertEqual(second["state"], "already-completed")
            self.assertEqual(first["retired_bundle_count"], 0)
            self.assertEqual(second["retired_bundle_count"], 0)
            self.assertIsNone(first["quarantine_path"])
            self.assertIsNone(second["quarantine_path"])

    def test_retention_restore_roundtrip_and_retries_are_idempotent(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            source_directory = root / "backups" / "verified"
            before = self._file_snapshot(source_directory)
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            candidate = next(
                bundle
                for bundle in plan["bundles"]
                if bundle["disposition"] == "retire"
            )
            applied = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )

            restored = manager.restore_retired(
                plan_token=plan["plan_token"],
                confirm=True,
            )
            retried_restore = manager.restore_retired(
                plan_token=plan["plan_token"],
                confirm=True,
            )
            retried_apply = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )

            self.assertEqual(restored["state"], "restored")
            self.assertEqual(retried_restore["state"], "already-restored")
            self.assertEqual(retried_apply["state"], "already-restored")
            self.assertEqual(
                restored["restored_bundle_count"], applied["retired_bundle_count"]
            )
            self.assertEqual(
                restored["restored_artifact_count"],
                applied["retired_artifact_count"],
            )
            self.assertEqual(self._file_snapshot(source_directory), before)
            self.assertTrue(
                manager.verify_bundle(
                    source_directory / candidate["bundle_receipt_name"]
                )["verified"]
            )
            quarantine = Path(applied["quarantine_path"])
            self.assertFalse(
                any(
                    path.is_file() or path.is_symlink()
                    for path in quarantine.rglob("*")
                )
            )

    def test_retention_restore_recovers_interrupted_prepared_journal(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            source_directory = root / "backups" / "verified"
            before = self._file_snapshot(source_directory)
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )
            journal_root = manager._retirement_journal_root()
            completed = manager._read_retirement_receipt(
                journal_root / f"{plan['plan_token']}.completed.receipt.json",
                expected_state="completed",
            )
            moves = completed["moves"]
            restore_prepared = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "restore-prepared",
                "plan_token": plan["plan_token"],
                "completion_receipt_digest": completed["receipt_digest"],
                "move_count": len(moves),
                "moves": moves,
                "created_at": evaluation_time,
            }
            manager.store._authenticate_receipt(restore_prepared)
            restore_prepared_path = journal_root / (
                f"{plan['plan_token']}.restore-prepared.receipt.json"
            )
            manager.store._write_private_json_exclusive(
                restore_prepared_path,
                restore_prepared,
            )
            store_root = manager.store.db_path.parent.resolve()
            interrupted_move = moves[0]
            os.rename(
                store_root / interrupted_move["destination_relative"],
                store_root / interrupted_move["source_relative"],
            )

            restored = manager.restore_retired(
                plan_token=plan["plan_token"],
                confirm=True,
            )

            recovered_path = journal_root / (
                f"{plan['plan_token']}.restore-recovered.receipt.json"
            )
            recovered = manager._read_retirement_receipt(
                recovered_path,
                expected_state="restore-recovered",
            )
            self.assertEqual(restored["state"], "restored")
            self.assertEqual(recovered["move_count"], len(moves))
            self.assertEqual(
                recovered["restore_prepared_receipt_digest"],
                restore_prepared["receipt_digest"],
            )
            self.assertEqual(self._file_snapshot(source_directory), before)

    def test_retention_expired_plan_fails_without_moving_artifacts(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            source_directory = root / "backups" / "verified"
            before = self._directory_identity_snapshot(source_directory)

            with mock.patch(
                "recovery_manager.time.time",
                return_value=plan["expires_at"] + 1,
            ):
                with self.assertRaisesRegex(RuntimeError, "plan expired"):
                    manager.apply_retention(
                        plan_token=plan["plan_token"],
                        cutoff_created_at=plan["cutoff_created_at"],
                        keep_latest=1,
                        max_age_days=30,
                        confirm=True,
                    )

            self.assertEqual(
                self._directory_identity_snapshot(source_directory),
                before,
            )
            self.assertFalse((root / "backups" / "retired").exists())

    def test_retention_survivor_mutation_rejects_before_first_move(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (110 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            latest = self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            latest_plan = next(
                bundle
                for bundle in plan["bundles"]
                if bundle["bundle_receipt_name"]
                == Path(latest["bundle_receipt_path"]).name
            )
            mutable_artifact = next(
                artifact
                for artifact in latest_plan["artifacts"]
                if artifact["name"] != latest_plan["bundle_receipt_name"]
            )
            source_directory = root / "backups" / "verified"
            survivor_path = source_directory / mutable_artifact["name"]
            survivor_metadata = survivor_path.stat()
            os.utime(
                survivor_path,
                ns=(
                    survivor_metadata.st_atime_ns,
                    survivor_metadata.st_mtime_ns + 1_000_000_000,
                ),
            )
            after_mutation = self._directory_identity_snapshot(source_directory)

            with self.assertRaisesRegex(RuntimeError, "changed after planning"):
                manager.apply_retention(
                    plan_token=plan["plan_token"],
                    cutoff_created_at=plan["cutoff_created_at"],
                    keep_latest=1,
                    max_age_days=30,
                    confirm=True,
                )

            self.assertEqual(
                self._directory_identity_snapshot(source_directory),
                after_mutation,
            )
            self.assertFalse((root / "backups" / "retired").exists())

    def test_retention_recovers_incomplete_prepared_journal_before_apply(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            candidate = next(
                bundle
                for bundle in plan["bundles"]
                if bundle["disposition"] == "retire"
            )
            store_root = manager.store.db_path.parent.resolve()
            source_directory = manager._retention_directory(None)
            before = self._file_snapshot(source_directory)
            retirement_root = store_root / "backups" / "retired"
            manager.store._ensure_directory(retirement_root, owned=True)
            quarantine = retirement_root / plan["plan_token"]
            os.mkdir(quarantine, mode=0o700)
            bundle_directory = quarantine / candidate["bundle_id"]
            os.mkdir(bundle_directory, mode=0o700)
            ordered_artifacts = sorted(
                candidate["artifacts"],
                key=lambda artifact: (
                    artifact["name"] == candidate["bundle_receipt_name"],
                    artifact["name"].encode("utf-8"),
                ),
            )
            moves = [
                {
                    "bundle_id": candidate["bundle_id"],
                    "bundle_receipt_name": candidate["bundle_receipt_name"],
                    "source_relative": str(
                        (source_directory / artifact["name"]).relative_to(store_root)
                    ),
                    "destination_relative": str(
                        (bundle_directory / artifact["name"]).relative_to(store_root)
                    ),
                    "artifact": artifact,
                }
                for artifact in ordered_artifacts
            ]
            prepared = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "prepared",
                "plan_token": plan["plan_token"],
                "decision_digest": plan["decision_digest"],
                "source_directory": str(source_directory.relative_to(store_root)),
                "quarantine_relative": str(quarantine.relative_to(store_root)),
                "bundle_count": 1,
                "artifact_count": len(moves),
                "moves": moves,
                "created_at": evaluation_time,
            }
            manager.store._authenticate_receipt(prepared)
            journal_root = manager._retirement_journal_root()
            prepared_path = (
                journal_root / f"{plan['plan_token']}.prepared.receipt.json"
            )
            manager.store._write_private_json_exclusive(prepared_path, prepared)
            first_move = moves[0]
            os.rename(
                store_root / first_move["source_relative"],
                store_root / first_move["destination_relative"],
            )

            with self.assertRaisesRegex(RuntimeError, "rolled back"):
                manager.apply_retention(
                    plan_token=plan["plan_token"],
                    cutoff_created_at=plan["cutoff_created_at"],
                    keep_latest=1,
                    max_age_days=30,
                    confirm=True,
                )

            recovered_path = (
                journal_root / f"{plan['plan_token']}.recovered.receipt.json"
            )
            recovered = manager._read_retirement_receipt(
                recovered_path,
                expected_state="recovered",
            )
            self.assertEqual(recovered["move_count"], len(moves))
            self.assertEqual(self._file_snapshot(source_directory), before)
            self.assertFalse(
                any(
                    path.is_file() or path.is_symlink()
                    for path in quarantine.rglob("*")
                )
            )
            self.assertFalse(
                (journal_root / f"{plan['plan_token']}.completed.receipt.json").exists()
            )

    def test_restore_rejects_manifest_only_archive_swapped_after_verification(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, _capture_id = self._capture_backed_bundle(root)
            capture_path = Path(bundle["capture_archive_path"])
            subset_archive = root / "manifest-only-swap.tar.gz"
            manifest = self._write_manifest_only_archive(
                capture_path,
                subset_archive,
            )
            self.assertGreater(len(manifest["files"]), 0)
            output_root = root / "swapped-archive-restore"
            original_extract = manager._extract_capture_archive

            def swap_before_extract(archive_path, extraction_manifest, target):
                os.replace(subset_archive, archive_path)
                return original_extract(archive_path, extraction_manifest, target)

            with mock.patch.object(
                manager,
                "_extract_capture_archive",
                side_effect=swap_before_extract,
            ):
                with self.assertRaises(
                    (EOFError, OSError, ValueError, RuntimeError, tarfile.TarError)
                ):
                    manager.restore_bundle_isolated(
                        bundle["bundle_receipt_path"],
                        output_root,
                        confirm=True,
                    )

            self.assertFalse(output_root.exists())
            self.assertFalse((output_root / "recovery-proof.receipt.json").exists())

    def test_capture_extraction_requires_complete_manifest_membership(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, _capture_id = self._capture_backed_bundle(root)
            capture_path = Path(bundle["capture_archive_path"])
            subset_archive = root / "manifest-only-extraction.tar.gz"
            manifest = self._write_manifest_only_archive(
                capture_path,
                subset_archive,
            )
            self.assertGreater(len(manifest["files"]), 0)
            target = root / "incomplete-capture-extraction"

            with self.assertRaises((ValueError, RuntimeError)):
                manager._extract_capture_archive(subset_archive, manifest, target)

            self.assertFalse(target.exists())

    def test_restore_truncation_after_verification_cannot_publish_proof(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, _capture_id = self._capture_backed_bundle(root)
            capture_path = Path(bundle["capture_archive_path"])
            output_root = root / "truncated-archive-restore"
            original_extract = manager._extract_capture_archive

            def truncate_before_extract(archive_path, extraction_manifest, target):
                data = archive_path.read_bytes()
                archive_path.write_bytes(data[: max(1, len(data) // 2)])
                archive_path.chmod(0o600)
                return original_extract(archive_path, extraction_manifest, target)

            with mock.patch.object(
                manager,
                "_extract_capture_archive",
                side_effect=truncate_before_extract,
            ):
                with self.assertRaises(
                    (EOFError, OSError, ValueError, RuntimeError, tarfile.TarError)
                ):
                    manager.restore_bundle_isolated(
                        bundle["bundle_receipt_path"],
                        output_root,
                        confirm=True,
                    )

            self.assertFalse(output_root.exists())
            self.assertFalse((output_root / "recovery-proof.receipt.json").exists())

    def test_interrupted_paired_publication_is_reconciled_without_lane_orphans(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            crash_script = """
import os
import sys
from pathlib import Path

from memory_store import DurableMemoryStore
from recovery_manager import VerifiedRecoveryManager

root = Path(sys.argv[1])
store = DurableMemoryStore(root / "memory.sqlite3")
store.upsert_entry(
    tag="crash-publication-fixture",
    context_id="backup-tests",
    source_text="Deterministic interrupted paired publication fixture.",
    metadata={"classification": "synthetic"},
    embedding_dimensions=8,
    spike_indices=[1],
    neuron_indices=[2],
    registered_at=100.0,
)
manager = VerifiedRecoveryManager(store, capture_root=root)
manager.daemon.status()
original_write = manager._write_capture_archive

def crash_after_archive(*args, **kwargs):
    result = original_write(*args, **kwargs)
    os._exit(91)

manager._write_capture_archive = crash_after_archive
manager.create_bundle(purpose="interrupted-publication")
"""
            environment = dict(os.environ)
            environment["SYNAPSE_S2_BACKUP_MIN_FREE_BYTES"] = "0"
            crashed = subprocess.run(
                [sys.executable, "-c", crash_script, str(root)],
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(crashed.returncode, 91, crashed.stderr)
            verified_directory = root / "backups" / "verified"
            crashed_artifacts = [
                path
                for path in verified_directory.iterdir()
                if path.is_file() and not path.is_symlink()
            ]
            self.assertGreaterEqual(len(crashed_artifacts), 3)
            self.assertFalse(
                any(path.name.endswith(".bundle.receipt.json") for path in crashed_artifacts)
            )

            manager = VerifiedRecoveryManager(
                DurableMemoryStore(root / "memory.sqlite3"),
                capture_root=root,
            )
            manager.daemon.status()
            completed = manager.create_bundle(purpose="post-crash-retry")
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=1_800_000_000.0,
            )

            self.assertTrue(completed["bundle_verified"])
            self.assertTrue(plan["apply_permitted"])
            self.assertEqual(plan["orphan_artifact_names"], [])
            self.assertEqual(plan["blocked_receipts"], [])
            claimed = {
                artifact["name"]
                for bundle_plan in plan["bundles"]
                for artifact in bundle_plan["artifacts"]
            }
            recognized = {
                path.name
                for path in verified_directory.iterdir()
                if path.name.endswith(".sqlite3")
                or path.name.endswith(".sqlite3.receipt.json")
                or path.name.endswith(".sqlite3.capture.tar.gz")
                or path.name.endswith(".sqlite3.bundle.receipt.json")
            }
            self.assertEqual(recognized, claimed)

    def test_empty_preparedless_retirement_quarantine_is_reused_on_retry(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            retirement_root = manager.store.db_path.parent.resolve() / "backups" / "retired"
            manager.store._ensure_directory(retirement_root, owned=True)
            quarantine = retirement_root / plan["plan_token"]
            os.mkdir(quarantine, mode=0o700)
            manager.store._fsync_directory(quarantine)
            journal_root = manager._retirement_journal_root()
            self.assertFalse(
                (journal_root / f"{plan['plan_token']}.prepared.receipt.json").exists()
            )

            applied = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )
            retried = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )

            self.assertEqual(applied["state"], "completed")
            self.assertEqual(retried["state"], "already-completed")
            self.assertTrue(applied["verified"])

    def test_partial_retirement_rollback_is_idempotently_recovered_after_recopy(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            candidate = next(
                bundle
                for bundle in plan["bundles"]
                if bundle["disposition"] == "retire"
            )
            store_root = manager.store.db_path.parent.resolve()
            source_directory = manager._retention_directory(None)
            before = self._file_snapshot(source_directory)
            retirement_root = store_root / "backups" / "retired"
            manager.store._ensure_directory(retirement_root, owned=True)
            quarantine = retirement_root / plan["plan_token"]
            os.mkdir(quarantine, mode=0o700)
            bundle_directory = quarantine / candidate["bundle_id"]
            os.mkdir(bundle_directory, mode=0o700)
            ordered_artifacts = sorted(
                candidate["artifacts"],
                key=lambda artifact: (
                    artifact["name"] == candidate["bundle_receipt_name"],
                    artifact["name"].encode("utf-8"),
                ),
            )
            moves = [
                {
                    "bundle_id": candidate["bundle_id"],
                    "bundle_receipt_name": candidate["bundle_receipt_name"],
                    "source_relative": str(
                        (source_directory / artifact["name"]).relative_to(store_root)
                    ),
                    "destination_relative": str(
                        (bundle_directory / artifact["name"]).relative_to(store_root)
                    ),
                    "artifact": artifact,
                }
                for artifact in ordered_artifacts
            ]
            prepared = {
                "schema": RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
                "state": "prepared",
                "plan_token": plan["plan_token"],
                "decision_digest": plan["decision_digest"],
                "source_directory": str(source_directory.relative_to(store_root)),
                "quarantine_relative": str(quarantine.relative_to(store_root)),
                "bundle_count": 1,
                "artifact_count": len(moves),
                "moves": moves,
                "created_at": evaluation_time,
            }
            manager.store._authenticate_receipt(prepared)
            journal_root = manager._retirement_journal_root()
            manager.store._write_private_json_exclusive(
                journal_root / f"{plan['plan_token']}.prepared.receipt.json",
                prepared,
            )
            for move in moves[:2]:
                os.rename(
                    store_root / move["source_relative"],
                    store_root / move["destination_relative"],
                )
            recopied_move = moves[1]
            recopied_source = store_root / recopied_move["source_relative"]
            recopied_destination = store_root / recopied_move["destination_relative"]
            recopied_source.write_bytes(recopied_destination.read_bytes())
            recopied_source.chmod(int(recopied_move["artifact"]["mode"]))
            recopied_destination.unlink()
            self.assertNotEqual(
                os.lstat(recopied_source).st_ino,
                int(recopied_move["artifact"]["inode"]),
            )

            for _attempt in range(2):
                with self.assertRaisesRegex(RuntimeError, "rolled back"):
                    manager.apply_retention(
                        plan_token=plan["plan_token"],
                        cutoff_created_at=plan["cutoff_created_at"],
                        keep_latest=1,
                        max_age_days=30,
                        confirm=True,
                    )

            recovered_path = (
                journal_root / f"{plan['plan_token']}.recovered.receipt.json"
            )
            self.assertTrue(recovered_path.is_file())
            self.assertEqual(self._file_snapshot(source_directory), before)
            self.assertFalse(
                any(
                    path.is_file() or path.is_symlink()
                    for path in quarantine.rglob("*")
                )
            )

    def test_already_completed_retention_revalidates_quarantined_artifacts(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            applied = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )
            completion = manager._read_retirement_receipt(
                Path(applied["completion_receipt_path"]),
                expected_state="completed",
            )
            mutable_move = next(
                move
                for move in completion["moves"]
                if move["artifact"]["name"] != move["bundle_receipt_name"]
            )
            quarantined = manager.store.db_path.parent.resolve() / mutable_move[
                "destination_relative"
            ]
            quarantined.write_bytes(b"corrupted retired artifact")
            quarantined.chmod(0o600)

            self._assert_not_verified_after_live_artifact_mutation(
                lambda: manager.apply_retention(
                    plan_token=plan["plan_token"],
                    cutoff_created_at=plan["cutoff_created_at"],
                    keep_latest=1,
                    max_age_days=30,
                    confirm=True,
                )
            )

    def test_already_restored_retention_revalidates_restored_artifacts(self):
        day = 86_400.0
        evaluation_time = 1_800_000_000.0
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = self._retention_manager(root)
            self._retention_bundle(
                manager,
                created_at=evaluation_time - (100 * day),
            )
            self._retention_bundle(
                manager,
                created_at=evaluation_time - day,
            )
            plan = manager.plan_retention(
                keep_latest=1,
                max_age_days=30,
                evaluation_time=evaluation_time,
            )
            applied = manager.apply_retention(
                plan_token=plan["plan_token"],
                cutoff_created_at=plan["cutoff_created_at"],
                keep_latest=1,
                max_age_days=30,
                confirm=True,
            )
            manager.restore_retired(
                plan_token=plan["plan_token"],
                confirm=True,
            )
            completion = manager._read_retirement_receipt(
                Path(applied["completion_receipt_path"]),
                expected_state="completed",
            )
            mutable_move = next(
                move
                for move in completion["moves"]
                if move["artifact"]["name"] != move["bundle_receipt_name"]
            )
            restored_source = manager.store.db_path.parent.resolve() / mutable_move[
                "source_relative"
            ]
            restored_source.write_bytes(b"corrupted restored artifact")
            restored_source.chmod(0o600)

            self._assert_not_verified_after_live_artifact_mutation(
                lambda: manager.restore_retired(
                    plan_token=plan["plan_token"],
                    confirm=True,
                )
            )
            self._assert_not_verified_after_live_artifact_mutation(
                lambda: manager.apply_retention(
                    plan_token=plan["plan_token"],
                    cutoff_created_at=plan["cutoff_created_at"],
                    keep_latest=1,
                    max_age_days=30,
                    confirm=True,
                )
            )

    def test_database_only_backup_cannot_publish_into_verified_bundle_lane(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            verified_directory = root / "backups" / "verified"
            verified_directory.mkdir(mode=0o700, parents=True)
            output = verified_directory / "database-only.sqlite3"

            with self.assertRaisesRegex(
                ValueError,
                "verified|paired|reserved|database-only|recovery lane",
            ):
                store.backup(output, purpose="database-only-contract")

            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + ".receipt.json").exists())

    def test_shared_manager_repository_lock_serializes_threads(self):
        with TemporaryDirectory() as tmp:
            manager = self._retention_manager(Path(tmp))
            holder_entered = threading.Event()
            contender_attempted = threading.Event()
            contender_entered = threading.Event()
            release_holder = threading.Event()
            failures: list[BaseException] = []

            def holder() -> None:
                try:
                    with manager._repository_lock():
                        holder_entered.set()
                        if not release_holder.wait(5):
                            raise TimeoutError("holder release timed out")
                except BaseException as exc:
                    failures.append(exc)

            def contender() -> None:
                try:
                    if not holder_entered.wait(5):
                        raise TimeoutError("holder did not acquire repository lock")
                    contender_attempted.set()
                    with manager._repository_lock():
                        contender_entered.set()
                except BaseException as exc:
                    failures.append(exc)

            holder_thread = threading.Thread(target=holder)
            contender_thread = threading.Thread(target=contender)
            holder_thread.start()
            contender_thread.start()
            entered_while_held = False
            try:
                self.assertTrue(contender_attempted.wait(5))
                entered_while_held = contender_entered.wait(0.25)
            finally:
                release_holder.set()
                holder_thread.join(timeout=5)
                contender_thread.join(timeout=5)

            self.assertFalse(
                entered_while_held,
                "a second thread entered the shared manager repository lock concurrently",
            )
            self.assertTrue(contender_entered.is_set())
            self.assertFalse(holder_thread.is_alive())
            self.assertFalse(contender_thread.is_alive())
            self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()

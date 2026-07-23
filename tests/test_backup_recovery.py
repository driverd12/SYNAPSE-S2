import hashlib
import io
import json
import os
import re
import shutil
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

import fcntl

from capture_daemon import (
    GLOBAL_CAPTURE_LOCK,
    CaptureInboxDaemon,
    write_capture_drop,
)
from core_authority import CoreAuthorityError, CoreAuthorityLease
from core_request_journal import (
    JOURNAL_BINDING_SCHEMA,
    JOURNAL_SCHEMA_IDENTITY,
    CoreRequestJournal,
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
    GUARDED_RECOVERY_TRANSACTION_SCHEMA,
    LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA,
    RECOVERY_BUNDLE_RESTORE_SCHEMA,
    RECOVERY_BUNDLE_SCHEMA,
    RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA,
    RECOVERY_RETIREMENT_RECEIPT_SCHEMA,
    VerifiedRecoveryManager,
)


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerifiedBackupRecoveryTests(unittest.TestCase):
    DANS_MBP_LEGACY_V5_SCHEMA_VERSION = "s2-schema-v5-dans-mbp-20260723"
    DANS_MBP_LEGACY_V5_SCHEMA_SHA256 = (
        "338c97e56aaab242f0d23143288d2825d3e12c22389612d7fda97cde90b225f8"
    )

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

    @classmethod
    def _dans_mbp_legacy_schema_fingerprint_patch(cls):
        original = DurableMemoryStore._sqlite_schema_fingerprint

        def alternate_v5_fingerprint(conn: sqlite3.Connection) -> dict:
            schema = dict(original(conn))
            user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if (
                user_version == 5
                and schema.get("sha256")
                == BACKUP_SCHEMA_COMPATIBILITY_REGISTRY["s2-schema-v5"][
                    "schema_sha256"
                ]
            ):
                schema["sha256"] = cls.DANS_MBP_LEGACY_V5_SCHEMA_SHA256
            return schema

        return mock.patch.object(
            DurableMemoryStore,
            "_sqlite_schema_fingerprint",
            staticmethod(alternate_v5_fingerprint),
        )

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
            state_path=root / "runtime_state.json",
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
    def _offline_guarded_manager(
        manager: VerifiedRecoveryManager,
        *,
        capture_root: Path,
    ) -> tuple[VerifiedRecoveryManager, DurableMemoryStore, CoreAuthorityLease]:
        db_path = manager.store.db_path
        runtime_state_path = manager.runtime_state_path
        manager.store.close()
        authority = CoreAuthorityLease.acquire_core(
            db_path,
            timeout_seconds=0.0,
            instance_id="guarded-recovery-test",
        )
        try:
            store = DurableMemoryStore.open_existing_for_core_maintenance(
                db_path,
                authority_lease=authority,
            )
            guarded = VerifiedRecoveryManager(
                store,
                capture_root=capture_root,
                runtime_state_path=runtime_state_path,
            )
            return guarded, store, authority
        except BaseException:
            authority.close()
            raise

    @staticmethod
    def _capture_manifest(path: str | Path) -> dict:
        with tarfile.open(path, mode="r:gz") as archive:
            member = archive.getmember("capture-manifest.json")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise AssertionError("capture manifest is unreadable")
            return json.loads(extracted.read().decode("utf-8"))

    @staticmethod
    def _claim_governed_store(
        db_path: Path,
        *,
        instance_id: str,
    ) -> tuple[DurableMemoryStore, CoreAuthorityLease, CoreRequestJournal, dict]:
        authority = CoreAuthorityLease.acquire_core(
            db_path,
            timeout_seconds=0.0,
            instance_id=instance_id,
        )
        try:
            store = DurableMemoryStore(db_path, authority_lease=authority)
            inspection = store.inspect_core_authority_preclaim()
            preclaim = inspection["logical_snapshot"]
            previous_epoch = int(inspection["previous_epoch"])
            journal = CoreRequestJournal(
                db_path.parent / "core" / "requests.sqlite3",
                authority_epoch=f"epoch-{previous_epoch + 1}",
                store_identity=str(inspection["store_identity"]),
            )
            journal_binding = journal.binding()
            claim = store.claim_core_authority(
                instance_id=authority.instance_id,
                config_fingerprint=hashlib.sha256(
                    instance_id.encode("utf-8")
                ).hexdigest(),
                build_id="backup-recovery-test",
                protocol_version="synapse-core.v1",
                expected_store_identity=str(inspection["store_identity"]),
                request_journal_id=str(journal_binding["journal_id"]),
                request_journal_binding_schema=str(journal_binding["schema"]),
                request_journal_schema_version=int(
                    journal_binding["journal_schema_version"]
                ),
                expected_preclaim_logical_snapshot_sha256=str(
                    preclaim["sha256"]
                ),
                expected_previous_epoch=previous_epoch,
                expected_next_epoch=previous_epoch + 1,
                root_generation_id="generation-" + ("b" * 24),
                embedding_space_identity="b" * 64,
                attestation_receipt_digest="b" * 64,
                attestation_expires_at_unix_ms=int(time.time() * 1000) + 60_000,
            )
            runtime_state_path = db_path.parent / "runtime_state.json"
            runtime_state_path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "global_enabled": True,
                        "context_overrides": {},
                        "cortex_sessions": {},
                        "runtime_state_repair": {},
                        "memory_db_path": str(db_path),
                        "updated_at": 100.0,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            runtime_state_path.chmod(0o600)
            return store, authority, journal, claim
        except BaseException:
            authority.close()
            raise

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

    def test_unsafe_resolved_archive_quarantine_unblocks_paired_bundle(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            daemon = CaptureInboxDaemon(root=root)
            paths = daemon.paths()
            archive_dir = paths["error_archive_dir"] / "historical" / "nested"
            archive_dir.mkdir(parents=True, exist_ok=True)
            unsafe = archive_dir / "resolved-unsafe-evidence.json"
            unsafe.write_text(
                json.dumps({"api_key": "SYNTHETIC_ONLY_ARCHIVE_SECRET"}),
                encoding="utf-8",
            )
            unsafe.chmod(0o600)
            manager = VerifiedRecoveryManager(store, capture_root=root)
            before_database = db_path.read_bytes()

            with self.assertRaisesRegex(RuntimeError, "secret hygiene"):
                manager.create_bundle(
                    root / "blocked-by-archive.sqlite3",
                    purpose="unit-test",
                    pinned=True,
                )

            preflight = daemon.unsafe_archived_error_quarantine_preflight(
                reason="unit-test archive quarantine"
            )
            quarantine = daemon.quarantine_unsafe_archived_error_artifacts(
                preflight_token=preflight["preflight_token"],
                reason="unit-test archive quarantine",
                confirm=True,
            )
            bundle = manager.create_bundle(
                root / "unblocked.sqlite3",
                purpose="unit-test",
                pinned=True,
            )
            verified = manager.verify_bundle(bundle["bundle_receipt_path"])

            self.assertEqual(db_path.read_bytes(), before_database)
            self.assertEqual(preflight["selected_count"], 1)
            self.assertEqual(quarantine["quarantined_count"], 1)
            self.assertEqual(quarantine["remaining_unsafe_archived_error_count"], 0)
            self.assertTrue(bundle["bundle_verified"])
            self.assertTrue(verified["verified"])

    def test_dans_mbp_legacy_v5_schema_contract_paired_bundle_and_preclaim(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            CaptureInboxDaemon(root=root).status()
            manager = VerifiedRecoveryManager(store, capture_root=root)
            before_bytes = db_path.read_bytes()

            with self._dans_mbp_legacy_schema_fingerprint_patch():
                bundle = manager.create_bundle(
                    root / "dans-mbp-legacy-v5.sqlite3",
                    purpose="dans-mbp-schema-compatibility-test",
                    pinned=True,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])
                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "dans-mbp-isolated-restore",
                    confirm=True,
                )

                self.assertEqual(db_path.read_bytes(), before_bytes)
                self.assertTrue(bundle["bundle_verified"])
                self.assertEqual(
                    bundle["schema_sha256"],
                    self.DANS_MBP_LEGACY_V5_SCHEMA_SHA256,
                )
                self.assertEqual(
                    bundle["schema_contract_version"],
                    self.DANS_MBP_LEGACY_V5_SCHEMA_VERSION,
                )
                self.assertTrue(verified["verified"])
                self.assertEqual(
                    verified["database"]["schema_contract_version"],
                    self.DANS_MBP_LEGACY_V5_SCHEMA_VERSION,
                )
                self.assertTrue(restored["verified"])

                restored_db = Path(restored["restore_root"]) / "memory.sqlite3"
                authority = CoreAuthorityLease.acquire_core(
                    restored_db,
                    timeout_seconds=0.0,
                    instance_id="dans-mbp-schema-compatibility-test",
                )
                try:
                    restored_store = DurableMemoryStore(
                        restored_db,
                        authority_lease=authority,
                    )
                    inspection = restored_store.inspect_core_authority_preclaim()
                    preclaim = inspection["logical_snapshot"]
                    self.assertEqual(
                        inspection["schema_identity"],
                        "sqlite-53324442-v5",
                    )
                    restored_store.claim_core_authority(
                        instance_id=authority.instance_id,
                        config_fingerprint="d" * 64,
                        build_id="dans-mbp-schema-compatibility-test",
                        protocol_version="synapse-core.v1",
                        expected_store_identity=str(inspection["store_identity"]),
                        request_journal_id="journal-" + ("d" * 24),
                        request_journal_binding_schema=JOURNAL_BINDING_SCHEMA,
                        request_journal_schema_version=3,
                        expected_preclaim_logical_snapshot_sha256=str(
                            preclaim["sha256"]
                        ),
                        expected_previous_epoch=0,
                        expected_next_epoch=1,
                        root_generation_id="generation-" + ("d" * 24),
                        embedding_space_identity="d" * 64,
                        attestation_receipt_digest="d" * 64,
                        attestation_expires_at_unix_ms=int(time.time() * 1000)
                        + 60_000,
                    )
                finally:
                    authority.close()

    def test_guarded_recovery_transaction_holds_capture_lock_through_yield(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, _bundle, _capture_id = self._capture_backed_bundle(root)
            manager, maintenance_store, maintenance_authority = (
                self._offline_guarded_manager(manager, capture_root=root)
            )
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
                            source_tag="guarded-recovery-lock",
                            speaker="codex",
                            text=(
                                "The producer must remain fenced until operator "
                                "evidence publication exits the guarded scope."
                            ),
                            capture_id=(
                                "s2cap_81818181818181818181818181818181"
                            ),
                        )
                    )
                except BaseException as exc:  # pragma: no cover - diagnostic path
                    producer_errors.append(exc)
                finally:
                    producer_finished.set()

            worker = threading.Thread(
                target=produce,
                name="guarded-recovery-producer",
            )
            try:
                with mock.patch.object(
                    subprocess,
                    "run",
                    side_effect=AssertionError(
                        "guarded recovery must not spawn CLI child processes"
                    ),
                ), mock.patch.object(
                    manager,
                    "_guarded_recovery_postflight_locked",
                    wraps=manager._guarded_recovery_postflight_locked,
                ) as postflight:
                    with manager.guarded_recovery_transaction(
                        root / "guarded-restore",
                        path=root / "guarded.sqlite3",
                        purpose="unit-test",
                    ) as publication:
                        evidence = publication.evidence
                        worker.start()
                        self.assertTrue(producer_started.wait(timeout=2.0))
                        self.assertFalse(producer_finished.wait(timeout=0.15))
                        self.assertEqual(
                            evidence["schema"],
                            GUARDED_RECOVERY_TRANSACTION_SCHEMA,
                        )
                        self.assertTrue(evidence["verified"])
                        self.assertTrue(evidence["cutover_ready"])
                        self.assertEqual(evidence["pending_file_count"], 0)
                        self.assertEqual(evidence["processing_file_count"], 0)
                        self.assertEqual(evidence["replay_required_file_count"], 0)
                        self.assertEqual(
                            evidence["capture_ledger_before"]["audit_revision"],
                            evidence["capture_ledger_after"]["audit_revision"],
                        )
                        self.assertEqual(
                            evidence["capture_transport_before"][
                                "transport_revision"
                            ],
                            evidence["capture_transport_after"][
                                "transport_revision"
                            ],
                        )
                        publication.publish(
                            lambda published_evidence: (
                                self.assertFalse(
                                    producer_finished.wait(timeout=0.15)
                                ),
                                json.dumps(published_evidence, sort_keys=True),
                            )
                        )
                self.assertEqual(postflight.call_count, 2)
            finally:
                maintenance_store.close()
                maintenance_authority.close()

            self.assertTrue(producer_finished.wait(timeout=5.0))
            worker.join(timeout=5.0)
            self.assertFalse(worker.is_alive())
            self.assertFalse(producer_errors)
            self.assertEqual(len(produced_paths), 1)
            self.assertTrue(produced_paths[0].is_file())
            self.assertIn("capture_transport_at_publication", evidence)
            self.assertIn("publication_gate_completed_at", evidence)

    def test_guarded_recovery_rejects_shared_local_authority_before_artifacts(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, _bundle, _capture_id = self._capture_backed_bundle(root)
            target = root / "must-not-publish.sqlite3"
            restore_root = root / "must-not-restore"
            try:
                with self.assertRaisesRegex(
                    CoreAuthorityError,
                    "authoritative core lease is not active",
                ):
                    with manager.guarded_recovery_transaction(
                        restore_root,
                        path=target,
                        purpose="unit-test",
                    ):
                        self.fail("shared local authority must not enter the guard")
                self.assertFalse(target.exists())
                self.assertFalse(restore_root.exists())
            finally:
                manager.store.close()

    def test_guarded_recovery_revalidates_core_lease_before_publication(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, _bundle, _capture_id = self._capture_backed_bundle(root)
            manager, maintenance_store, maintenance_authority = (
                self._offline_guarded_manager(manager, capture_root=root)
            )
            try:
                with self.assertRaisesRegex(
                    CoreAuthorityError,
                    "lease is not active",
                ):
                    with manager.guarded_recovery_transaction(
                        root / "closed-lease-restore",
                        path=root / "closed-lease.sqlite3",
                        purpose="unit-test",
                    ) as publication:
                        maintenance_authority.close()
                        publication.publish(lambda _evidence: None)
                self.assertFalse(publication.published)
            finally:
                maintenance_store.close()
                maintenance_authority.close()

    def test_guarded_recovery_capture_lock_contention_fails_without_waiting(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, _bundle, _capture_id = self._capture_backed_bundle(root)
            manager, maintenance_store, maintenance_authority = (
                self._offline_guarded_manager(manager, capture_root=root)
            )
            lock_path = manager.daemon.paths()["lock_dir"] / GLOBAL_CAPTURE_LOCK
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import fcntl,os,sys,time; "
                        "fd=os.open(sys.argv[1],os.O_RDWR); "
                        "fcntl.flock(fd,fcntl.LOCK_EX); "
                        "print('locked',flush=True); time.sleep(10)"
                    ),
                    str(lock_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "locked")
                started = time.monotonic()
                with self.assertRaisesRegex(
                    RuntimeError,
                    "capture maintenance lock is busy",
                ):
                    with manager.guarded_recovery_transaction(
                        root / "contended-restore",
                        path=root / "contended.sqlite3",
                        purpose="unit-test",
                    ):
                        self.fail("contended capture guard must not yield")
                self.assertLess(time.monotonic() - started, 1.0)
            finally:
                child.terminate()
                child.wait(timeout=5.0)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()
                maintenance_store.close()
                maintenance_authority.close()

    def test_guarded_recovery_transaction_covers_authoritative_v6(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _bundle, _capture_id = self._capture_backed_bundle(root)
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store, authority, journal, claim = self._claim_governed_store(
                db_path,
                instance_id="guarded-recovery-authority",
            )
            journal.close()
            store.close()
            authority.close()
            maintenance_authority = CoreAuthorityLease.acquire_core(
                db_path,
                timeout_seconds=0.0,
                instance_id="guarded-v6-maintenance",
            )
            try:
                maintenance_store = (
                    DurableMemoryStore.open_existing_for_core_maintenance(
                        db_path,
                        authority_lease=maintenance_authority,
                    )
                )
                manager = VerifiedRecoveryManager(
                    maintenance_store,
                    capture_root=root,
                )
                with manager.guarded_recovery_transaction(
                    root / "guarded-v6-restore",
                    path=root / "guarded-v6.sqlite3",
                    purpose="unit-test",
                ) as publication:
                    evidence = publication.evidence
                    self.assertEqual(
                        evidence["verification"]["governance_mode"],
                        "authoritative-v6",
                    )
                    self.assertEqual(
                        evidence["verification"]["store_generation"],
                        claim["authority_epoch"],
                    )
                    self.assertTrue(
                        evidence["verification"]["request_journal"]["verified"]
                    )
                    self.assertTrue(
                        evidence["verification"]["runtime_state"]["verified"]
                    )
                    publication.publish(lambda published: json.dumps(published))
                self.assertTrue(publication.published)
                self.assertTrue(evidence["restore"]["cutover_ready"])
            finally:
                maintenance_store.close()
                maintenance_authority.close()

    def test_guarded_recovery_rejects_pending_and_processing_before_artifacts(self):
        for state in ("pending", "processing"):
            with self.subTest(state=state), TemporaryDirectory() as tmp:
                root = Path(tmp)
                store, _db_path = self._seed_store(root)
                manager = VerifiedRecoveryManager(store, capture_root=root)
                paths = manager.daemon.paths()
                manager.daemon._ensure_transport_dirs(paths)
                pending_path = write_capture_drop(
                    root=root,
                    context_id="recovery-tests",
                    source_tag="guarded-recovery-preflight",
                    speaker="codex",
                    text="Unconsumed capture work must block guarded recovery.",
                    capture_id=(
                        "s2cap_82828282828282828282828282828282"
                        if state == "pending"
                        else "s2cap_83838383838383838383838383838383"
                    ),
                )
                if state == "processing":
                    claimed = manager.daemon._claim_inbox_file(
                        inbox_path=pending_path,
                        inbox_dir=paths["inbox_dir"],
                        processing_dir=paths["processing_dir"],
                    )
                    self.assertIsNotNone(claimed)
                manager, maintenance_store, maintenance_authority = (
                    self._offline_guarded_manager(
                        manager,
                        capture_root=root,
                    )
                )
                bundle_path = root / f"guarded-{state}.sqlite3"
                restore_root = root / f"guarded-{state}-restore"
                try:
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "capture transport is not quiescent",
                    ):
                        with manager.guarded_recovery_transaction(
                            restore_root,
                            path=bundle_path,
                            purpose="unit-test",
                        ):
                            self.fail("non-quiescent guarded recovery must not yield")
                    self.assertFalse(restore_root.exists())
                    self.assertEqual(list(root.glob(bundle_path.name + "*")), [])
                finally:
                    maintenance_store.close()
                    maintenance_authority.close()

    def test_guarded_recovery_does_not_initialize_missing_capture_transport(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            manager = VerifiedRecoveryManager(store, capture_root=root)
            transport_paths = manager.daemon.paths()
            self.assertFalse(transport_paths["inbox_dir"].exists())
            manager, maintenance_store, maintenance_authority = (
                self._offline_guarded_manager(manager, capture_root=root)
            )
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "requires an existing safe capture transport",
                ):
                    with manager.guarded_recovery_transaction(
                        root / "missing-transport-restore",
                        path=root / "missing-transport.sqlite3",
                        purpose="unit-test",
                    ):
                        self.fail("missing transport must not enter guarded recovery")
                for key in (
                    "inbox_dir",
                    "processing_dir",
                    "processed_dir",
                    "error_dir",
                    "error_archive_dir",
                    "error_resolution_dir",
                    "receipt_dir",
                    "lock_dir",
                ):
                    self.assertFalse(transport_paths[key].exists())
            finally:
                maintenance_store.close()
                maintenance_authority.close()

    def test_guarded_recovery_detects_runtime_drift_before_lock_release(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, _bundle, _capture_id = self._capture_backed_bundle(root)
            manager, maintenance_store, maintenance_authority = (
                self._offline_guarded_manager(manager, capture_root=root)
            )
            runtime_state_path = root / "runtime_state.json"
            try:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "runtime state changed during guarded recovery",
                ):
                    with manager.guarded_recovery_transaction(
                        root / "guarded-drift-restore",
                        path=root / "guarded-drift.sqlite3",
                        purpose="unit-test",
                    ) as publication:
                        runtime_state = json.loads(
                            runtime_state_path.read_text(encoding="utf-8")
                        )
                        runtime_state["updated_at"] = float(
                            runtime_state["updated_at"]
                        ) + 1.0
                        runtime_state_path.write_text(
                            json.dumps(runtime_state, indent=2, sort_keys=True)
                            + "\n",
                            encoding="utf-8",
                        )
                        runtime_state_path.chmod(0o600)
                        publication.publish(lambda _evidence: None)
            finally:
                maintenance_store.close()
                maintenance_authority.close()

    def test_capture_maintenance_lock_reentry_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            manager = VerifiedRecoveryManager(store, capture_root=root)
            manager.daemon._ensure_transport_dirs(manager.daemon.paths())
            with manager._repository_lock():
                with manager._capture_maintenance_lock():
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "must not be reacquired",
                    ):
                        with manager._capture_maintenance_lock():
                            self.fail("capture maintenance lock reentry must fail")

    def test_governed_bundle_restores_exact_request_journal_and_binding_receipt(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _legacy_bundle, _capture_id = self._capture_backed_bundle(
                root
            )
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store, authority, journal, claim = self._claim_governed_store(
                db_path,
                instance_id="core-recovery-epoch-one",
            )
            try:
                decision = journal.accept(
                    caller="backup-test",
                    request_id="request-one",
                    operation="capture_session",
                    request_fingerprint="1" * 64,
                )
                self.assertEqual(decision.disposition, "accepted")
                journal.finish(
                    caller="backup-test",
                    request_id="request-one",
                    operation="capture_session",
                    request_fingerprint="1" * 64,
                    result={"stored": True},
                    safe_error_code=None,
                )
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "governed.sqlite3",
                    purpose="unit-test",
                    pinned=True,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])
                self.assertEqual(verified["governance_mode"], "authoritative-v6")
                self.assertEqual(verified["store_generation"], claim["authority_epoch"])
                self.assertTrue(verified["request_journal"]["verified"])
                self.assertTrue(verified["request_journal_binding"]["verified"])
                expected_journal_id = str(journal.binding()["journal_id"])
                self.assertEqual(
                    verified["request_journal"]["journal_id"],
                    expected_journal_id,
                )
                self.assertEqual(
                    verified["request_journal"]["schema_identity"],
                    JOURNAL_SCHEMA_IDENTITY,
                )
                self.assertEqual(
                    verified["request_journal_binding"]["request_journal_id"],
                    expected_journal_id,
                )
                self.assertEqual(
                    verified["request_journal_binding"]["journal_schema_identity"],
                    JOURNAL_SCHEMA_IDENTITY,
                )
                bundle_receipt = json.loads(
                    Path(bundle["bundle_receipt_path"]).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    bundle_receipt["request_journal_id"], expected_journal_id
                )
                self.assertEqual(
                    bundle_receipt["request_journal_schema_identity"],
                    JOURNAL_SCHEMA_IDENTITY,
                )
                source_binding_receipt = json.loads(
                    Path(bundle["request_journal_binding_receipt_path"]).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    journal.binding()["schema"], JOURNAL_BINDING_SCHEMA
                )
                self.assertEqual(
                    source_binding_receipt["schema"],
                    RECOVERY_REQUEST_JOURNAL_BINDING_SCHEMA,
                )
                self.assertNotEqual(
                    source_binding_receipt["schema"], JOURNAL_BINDING_SCHEMA
                )

                with self.assertRaisesRegex(
                    ValueError,
                    "paired request-journal evidence",
                ):
                    store.restore_backup(
                        bundle["backup_path"],
                        root / "unsafe-database-only-v6.sqlite3",
                        receipt_path=bundle["receipt_path"],
                        confirm=True,
                    )

                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "governed-restore",
                    confirm=True,
                )
                restored_root = Path(restored["restore_root"])
                restored_journal = Path(restored["request_journal_restore_path"])
                restored_binding = Path(
                    restored["request_journal_binding_receipt_path"]
                )
                self.assertEqual(restored_journal.name, "requests.sqlite3")
                self.assertTrue(restored_binding.is_file())
                self.assertEqual(restored_journal.stat().st_mode & 0o777, 0o600)
                self.assertEqual(restored_binding.stat().st_mode & 0o777, 0o600)
                with closing(sqlite3.connect(restored_journal)) as conn:
                    row = conn.execute(
                        "SELECT state, authority_epoch FROM request_journal "
                        "WHERE caller = ? AND request_id = ?",
                        ("backup-test", "request-one"),
                    ).fetchone()
                self.assertEqual(row, ("completed", claim["authority_epoch"]))
                proof = json.loads(
                    Path(restored["recovery_proof_path"]).read_text(encoding="utf-8")
                )
                self.assertEqual(proof["governance_mode"], "authoritative-v6")
                self.assertEqual(
                    proof["request_journal_artifact_relative"],
                    "core/requests.sqlite3",
                )
                self.assertEqual(
                    proof["request_journal_binding_receipt_relative"],
                    "core/requests.sqlite3.binding.receipt.json",
                )
                self.assertTrue(proof["request_journal_binding_verified"])
                self.assertEqual(proof["request_journal_id"], expected_journal_id)
                self.assertEqual(
                    proof["request_journal_schema_identity"],
                    JOURNAL_SCHEMA_IDENTITY,
                )
                restored_binding_payload = json.loads(
                    restored_binding.read_text(encoding="utf-8")
                )
                self.assertEqual(
                    restored_binding_payload["request_journal_id"],
                    expected_journal_id,
                )
                self.assertEqual(
                    restored_binding_payload["request_journal_schema_identity"],
                    JOURNAL_SCHEMA_IDENTITY,
                )
                original_restored_binding = restored_binding.read_bytes()
                for field, value, error_type in (
                    (
                        "request_journal_id",
                        "journal-" + "d" * 24,
                        RuntimeError,
                    ),
                    (
                        "request_journal_schema_identity",
                        "sqlite-5332524a-v4",
                        ValueError,
                    ),
                ):
                    with self.subTest(restored_binding_field=field):
                        tampered = json.loads(
                            original_restored_binding.decode("utf-8")
                        )
                        tampered[field] = value
                        manager.store._authenticate_receipt(tampered)
                        restored_binding.write_text(
                            json.dumps(tampered, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8",
                        )
                        restored_binding.chmod(0o600)
                        with self.assertRaises(error_type):
                            manager.verify_restored_request_journal_binding(
                                restored_root
                            )
                        restored_binding.write_bytes(original_restored_binding)
                        restored_binding.chmod(0o600)
                self.assertEqual(
                    proof["request_journal_binding_receipt_digest"],
                    restored["request_journal_binding"]["receipt_digest"],
                )
                self.assertEqual(
                    restored["request_journal_binding"]["request_journal_id"],
                    expected_journal_id,
                )
                self.assertEqual(
                    restored["request_journal_binding"][
                        "request_journal_schema_identity"
                    ],
                    JOURNAL_SCHEMA_IDENTITY,
                )
                self.assertTrue(proof["cutover_ready"])
            finally:
                journal.close()
                store.close()
                authority.close()

    def test_governed_bundle_rejects_missing_corrupt_swapped_and_mismatched_journal(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _legacy_bundle, _capture_id = self._capture_backed_bundle(
                root
            )
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store, authority, journal, _claim = self._claim_governed_store(
                db_path,
                instance_id="core-recovery-adversarial",
            )
            try:
                journal.accept(
                    caller="backup-test",
                    request_id="request-original",
                    operation="capture_session",
                    request_fingerprint="2" * 64,
                )
                journal.finish(
                    caller="backup-test",
                    request_id="request-original",
                    operation="capture_session",
                    request_fingerprint="2" * 64,
                    result={"stored": True},
                    safe_error_code=None,
                )
                manager = VerifiedRecoveryManager(store, capture_root=root)
                first = manager.create_bundle(
                    root / "governed-first.sqlite3",
                    purpose="unit-test",
                )
                journal.accept(
                    caller="backup-test",
                    request_id="request-later",
                    operation="capture_session",
                    request_fingerprint="3" * 64,
                )
                journal.finish(
                    caller="backup-test",
                    request_id="request-later",
                    operation="capture_session",
                    request_fingerprint="3" * 64,
                    result={"stored": True},
                    safe_error_code=None,
                )
                second = manager.create_bundle(
                    root / "governed-second.sqlite3",
                    purpose="unit-test",
                )
                first_journal = Path(first["request_journal_path"])
                binding_path = Path(first["request_journal_binding_receipt_path"])
                original_journal = first_journal.read_bytes()
                original_binding = binding_path.read_bytes()

                held = first_journal.with_name(first_journal.name + ".held")
                first_journal.rename(held)
                with self.assertRaises((OSError, ValueError, RuntimeError)):
                    manager.verify_bundle(first["bundle_receipt_path"])
                held.rename(first_journal)

                first_journal.write_bytes(b"not-a-sqlite-journal")
                first_journal.chmod(0o600)
                with self.assertRaises((OSError, ValueError, RuntimeError, sqlite3.Error)):
                    manager.verify_bundle(first["bundle_receipt_path"])
                first_journal.write_bytes(original_journal)
                first_journal.chmod(0o600)

                first_journal.write_bytes(Path(second["request_journal_path"]).read_bytes())
                first_journal.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "digest|journal|binding"):
                    manager.verify_bundle(first["bundle_receipt_path"])
                first_journal.write_bytes(original_journal)
                first_journal.chmod(0o600)

                binding_payload = json.loads(original_binding.decode("utf-8"))
                binding_payload["store_generation"] = "epoch-999"
                manager.store._authenticate_receipt(binding_payload)
                binding_path.write_text(
                    json.dumps(binding_payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                binding_path.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "journal|generation|binding"):
                    manager.verify_bundle(first["bundle_receipt_path"])
                binding_path.write_bytes(original_binding)
                binding_path.chmod(0o600)

                for field, value, error_type in (
                    (
                        "request_journal_id",
                        "journal-" + "f" * 24,
                        RuntimeError,
                    ),
                    (
                        "journal_schema_identity",
                        "sqlite-5332524a-v4",
                        ValueError,
                    ),
                    (
                        "schema",
                        JOURNAL_BINDING_SCHEMA,
                        ValueError,
                    ),
                ):
                    with self.subTest(binding_field=field):
                        binding_payload = json.loads(original_binding.decode("utf-8"))
                        binding_payload[field] = value
                        manager.store._authenticate_receipt(binding_payload)
                        binding_path.write_text(
                            json.dumps(binding_payload, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8",
                        )
                        binding_path.chmod(0o600)
                        with self.assertRaises(error_type):
                            manager.verify_bundle(first["bundle_receipt_path"])
                        binding_path.write_bytes(original_binding)
                        binding_path.chmod(0o600)

                bundle_receipt_path = Path(first["bundle_receipt_path"])
                original_bundle_receipt = bundle_receipt_path.read_bytes()
                for field, value, error_type in (
                    (
                        "request_journal_id",
                        "journal-" + "e" * 24,
                        RuntimeError,
                    ),
                    (
                        "request_journal_schema_identity",
                        "sqlite-5332524a-v4",
                        ValueError,
                    ),
                ):
                    with self.subTest(bundle_field=field):
                        bundle_payload = json.loads(
                            original_bundle_receipt.decode("utf-8")
                        )
                        bundle_payload[field] = value
                        manager.store._authenticate_receipt(bundle_payload)
                        bundle_receipt_path.write_text(
                            json.dumps(bundle_payload, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8",
                        )
                        bundle_receipt_path.chmod(0o600)
                        with self.assertRaises(error_type):
                            manager.verify_bundle(bundle_receipt_path)
                        bundle_receipt_path.write_bytes(original_bundle_receipt)
                        bundle_receipt_path.chmod(0o600)

                binding_held = binding_path.with_name(binding_path.name + ".held")
                binding_path.rename(binding_held)
                with self.assertRaises((OSError, ValueError, RuntimeError)):
                    manager.verify_bundle(first["bundle_receipt_path"])
                binding_held.rename(binding_path)
                self.assertTrue(manager.verify_bundle(first["bundle_receipt_path"])["verified"])
            finally:
                journal.close()
                store.close()
                authority.close()

    def test_newer_generation_journal_cannot_be_paired_with_older_governed_database(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _legacy_bundle, _capture_id = self._capture_backed_bundle(
                root
            )
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store_one, authority_one, journal_one, claim_one = (
                self._claim_governed_store(
                    db_path,
                    instance_id="core-recovery-generation-one",
                )
            )
            manager_one = VerifiedRecoveryManager(store_one, capture_root=root)
            first = manager_one.create_bundle(
                root / "generation-one.sqlite3",
                purpose="unit-test",
            )
            journal_one.close()
            store_one.close()
            authority_one.close()

            store_two, authority_two, journal_two, claim_two = (
                self._claim_governed_store(
                    db_path,
                    instance_id="core-recovery-generation-two",
                )
            )
            try:
                self.assertGreater(
                    int(claim_two["authority_epoch_number"]),
                    int(claim_one["authority_epoch_number"]),
                )
                journal_two.accept(
                    caller="backup-test",
                    request_id="request-new-generation",
                    operation="capture_session",
                    request_fingerprint="4" * 64,
                )
                journal_two.finish(
                    caller="backup-test",
                    request_id="request-new-generation",
                    operation="capture_session",
                    request_fingerprint="4" * 64,
                    result={"stored": True},
                    safe_error_code=None,
                )
                manager_two = VerifiedRecoveryManager(store_two, capture_root=root)
                second = manager_two.create_bundle(
                    root / "generation-two.sqlite3",
                    purpose="unit-test",
                )
                first_journal = Path(first["request_journal_path"])
                original = first_journal.read_bytes()
                first_binding_path = Path(
                    first["request_journal_binding_receipt_path"]
                )
                original_binding = first_binding_path.read_bytes()
                first_receipt_path = Path(first["bundle_receipt_path"])
                original_receipt = first_receipt_path.read_bytes()
                second_verified = manager_two.verify_bundle(
                    second["bundle_receipt_path"]
                )
                second_journal = second_verified["request_journal"]
                first_journal.write_bytes(Path(second["request_journal_path"]).read_bytes())
                first_journal.chmod(0o600)
                forged_binding = json.loads(original_binding.decode("utf-8"))
                forged_binding.update(
                    {
                        "journal_sha256": str(second_journal["sha256"]),
                        "journal_size_bytes": int(second_journal["size_bytes"]),
                        "journal_application_id": int(
                            second_journal["application_id"]
                        ),
                        "journal_schema_version": int(
                            second_journal["schema_version"]
                        ),
                        "journal_schema_sha256": str(
                            second_journal["schema_sha256"]
                        ),
                        "journal_row_count": int(second_journal["row_count"]),
                        "journal_state_counts": dict(
                            second_journal["state_counts"]
                        ),
                        "journal_current_authority_epoch_row_count": 0,
                        "journal_maximum_observed_authority_epoch": int(
                            second_journal[
                                "maximum_observed_authority_epoch"
                            ]
                        ),
                    }
                )
                manager_two.store._authenticate_receipt(forged_binding)
                first_binding_path.write_text(
                    json.dumps(forged_binding, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                first_binding_path.chmod(0o600)
                forged_bundle = json.loads(original_receipt.decode("utf-8"))
                forged_bundle.update(
                    {
                        "request_journal_sha256": str(second_journal["sha256"]),
                        "request_journal_size_bytes": int(
                            second_journal["size_bytes"]
                        ),
                        "request_journal_binding_receipt_digest": str(
                            forged_binding["receipt_digest"]
                        ),
                        "request_journal_schema_version": int(
                            second_journal["schema_version"]
                        ),
                        "request_journal_schema_sha256": str(
                            second_journal["schema_sha256"]
                        ),
                        "request_journal_row_count": int(
                            second_journal["row_count"]
                        ),
                        "request_journal_current_authority_epoch_row_count": 0,
                        "request_journal_maximum_observed_authority_epoch": int(
                            second_journal[
                                "maximum_observed_authority_epoch"
                            ]
                        ),
                    }
                )
                manager_two.store._authenticate_receipt(forged_bundle)
                first_receipt_path.write_text(
                    json.dumps(forged_bundle, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                first_receipt_path.chmod(0o600)
                with self.assertRaisesRegex(
                    RuntimeError,
                    "newer store authority generation",
                ):
                    manager_two.verify_bundle(first["bundle_receipt_path"])
                first_journal.write_bytes(original)
                first_journal.chmod(0o600)
                first_binding_path.write_bytes(original_binding)
                first_binding_path.chmod(0o600)
                first_receipt_path.write_bytes(original_receipt)
                first_receipt_path.chmod(0o600)

                legacy_receipt_path = first_receipt_path
                current_receipt = json.loads(original_receipt.decode("utf-8"))
                legacy_receipt = {
                    key: value
                    for key, value in current_receipt.items()
                    if key in manager_two._legacy_bundle_receipt_expected_keys()
                }
                legacy_receipt["schema"] = "synapse-s2.recovery-bundle.v1"
                manager_two.store._authenticate_receipt(legacy_receipt)
                legacy_receipt_path.write_text(
                    json.dumps(legacy_receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                legacy_receipt_path.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "legacy|pre-governed v5"):
                    manager_two.verify_bundle(legacy_receipt_path)
                legacy_receipt_path.write_bytes(original_receipt)
                legacy_receipt_path.chmod(0o600)
            finally:
                journal_two.close()
                store_two.close()
                authority_two.close()

    def test_legacy_v1_bundle_proof_is_accepted_only_for_pre_governed_v5(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, _capture_id = self._capture_backed_bundle(root)
            receipt_path = Path(bundle["bundle_receipt_path"])
            current = json.loads(receipt_path.read_text(encoding="utf-8"))
            legacy = {
                key: value
                for key, value in current.items()
                if key in manager._legacy_bundle_receipt_expected_keys()
            }
            legacy["schema"] = "synapse-s2.recovery-bundle.v1"
            manager.store._authenticate_receipt(legacy)
            receipt_path.write_text(
                json.dumps(legacy, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)

            restored = manager.restore_bundle_isolated(
                receipt_path,
                root / "legacy-v1-restore",
                confirm=True,
            )
            proof = json.loads(
                Path(restored["recovery_proof_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(proof["schema"], LEGACY_RECOVERY_BUNDLE_RESTORE_SCHEMA)
            self.assertEqual(proof["governance_mode"], "pre-governed-v5")
            self.assertEqual(proof["store_generation"], "legacy-v5")
            self.assertFalse(proof["request_journal_binding_verified"])
            self.assertIsNone(proof["request_journal_artifact_relative"])
            self.assertTrue(proof["cutover_ready"])

    def test_governed_bundle_rejects_noncanonical_request_journal_identifiers(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _legacy_bundle, _capture_id = self._capture_backed_bundle(
                root
            )
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store, authority, journal, _claim = self._claim_governed_store(
                db_path,
                instance_id="core-recovery-identifiers",
            )
            try:
                journal.accept(
                    caller="backup-test",
                    request_id="request-valid",
                    operation="capture_session",
                    request_fingerprint="5" * 64,
                )
                journal.close()
                journal_path = db_path.parent / "core" / "requests.sqlite3"
                with closing(sqlite3.connect(journal_path)) as conn:
                    conn.execute(
                        "UPDATE request_journal SET operation = ?",
                        ("invalid operation",),
                    )
                    conn.commit()
                manager = VerifiedRecoveryManager(store, capture_root=root)
                with self.assertRaisesRegex(RuntimeError, "invalid durable row"):
                    manager.create_bundle(
                        root / "invalid-journal-identifier.sqlite3",
                        purpose="unit-test",
                    )
            finally:
                journal.close()
                store.close()
                authority.close()

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

    def test_cross_store_bundle_requires_every_reviewed_artifact_digest(self):
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
            receipt = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
            runtime_sha256 = receipt["runtime_state_sha256"]

            for supplied in (
                {},
                {"expected_database_sha256": database_sha256},
                {"expected_capture_sha256": capture_sha256},
                {"expected_runtime_state_sha256": runtime_sha256},
                {
                    "expected_database_sha256": database_sha256,
                    "expected_capture_sha256": capture_sha256,
                },
                {
                    "expected_database_sha256": database_sha256,
                    "expected_runtime_state_sha256": runtime_sha256,
                },
                {
                    "expected_capture_sha256": capture_sha256,
                    "expected_runtime_state_sha256": runtime_sha256,
                },
            ):
                with self.subTest(supplied=sorted(supplied)):
                    with self.assertRaises(ValueError):
                        foreign_manager.verify_bundle(receipt_path, **supplied)

            verified = foreign_manager.verify_bundle(
                receipt_path,
                expected_database_sha256=database_sha256,
                expected_capture_sha256=capture_sha256,
                expected_runtime_state_sha256=runtime_sha256,
            )
            with self.assertRaisesRegex(ValueError, "runtime-state digest"):
                foreign_manager.verify_bundle(
                    receipt_path,
                    expected_database_sha256=database_sha256,
                    expected_capture_sha256=capture_sha256,
                    expected_runtime_state_sha256="f" * 64,
                )
            self.assertTrue(verified["verified"])
            self.assertFalse(verified["receipt_identity_trusted"])
            self.assertTrue(verified["reviewed_digests_verified"])
            restored = foreign_manager.restore_bundle_isolated(
                receipt_path,
                foreign_root / "reviewed-restore",
                expected_database_sha256=database_sha256,
                expected_capture_sha256=capture_sha256,
                expected_runtime_state_sha256=runtime_sha256,
                confirm=True,
            )
            self.assertTrue(restored["verified"])
            restored_runtime = json.loads(
                Path(restored["runtime_state_restore_path"]).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                restored_runtime["global_enabled"],
                receipt["runtime_state_global_enabled"],
            )

    def test_foreign_bundle_runtime_pin_semantics_fail_before_materialization(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _manager, bundle, _capture_id = self._capture_backed_bundle(root)
            receipt_path = Path(bundle["bundle_receipt_path"])
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            foreign_root = root / "foreign-runtime-review"
            foreign_manager = VerifiedRecoveryManager(
                DurableMemoryStore(foreign_root / "memory.sqlite3"),
                capture_root=foreign_root / "capture-root",
            )
            reviewed = {
                "expected_database_sha256": str(receipt["database_sha256"]),
                "expected_capture_sha256": str(receipt["capture_sha256"]),
            }

            for label, runtime_digest in (
                ("missing", None),
                ("malformed", "not-a-sha256"),
                ("mismatched", "f" * 64),
            ):
                output_root = foreign_root / f"rejected-{label}"
                arguments = dict(reviewed)
                if runtime_digest is not None:
                    arguments["expected_runtime_state_sha256"] = runtime_digest
                with self.subTest(runtime_digest=label):
                    with self.assertRaises(ValueError):
                        foreign_manager.restore_bundle_isolated(
                            receipt_path,
                            output_root,
                            confirm=True,
                            **arguments,
                        )
                    self.assertFalse(output_root.exists())

            absent_root = root / "runtime-absent-source"
            absent_store, _absent_db = self._seed_store(absent_root)
            absent_manager = VerifiedRecoveryManager(
                absent_store,
                capture_root=absent_root,
            )
            absent_bundle = absent_manager.create_bundle(
                absent_root / "runtime-absent.sqlite3",
                purpose="unit-test",
                pinned=True,
            )
            absent_receipt = json.loads(
                Path(absent_bundle["bundle_receipt_path"]).read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(absent_receipt["runtime_state_required"])
            absent_foreign_root = root / "runtime-absent-foreign"
            absent_foreign = VerifiedRecoveryManager(
                DurableMemoryStore(absent_foreign_root / "memory.sqlite3"),
                capture_root=absent_foreign_root / "capture-root",
            )
            absent_reviewed = {
                "expected_database_sha256": str(
                    absent_receipt["database_sha256"]
                ),
                "expected_capture_sha256": str(absent_receipt["capture_sha256"]),
            }
            self.assertTrue(
                absent_foreign.verify_bundle(
                    absent_bundle["bundle_receipt_path"],
                    **absent_reviewed,
                )["verified"]
            )
            absent_output = absent_foreign_root / "extraneous-runtime-pin"
            with self.assertRaisesRegex(ValueError, "does not contain"):
                absent_foreign.restore_bundle_isolated(
                    absent_bundle["bundle_receipt_path"],
                    absent_output,
                    expected_runtime_state_sha256="a" * 64,
                    confirm=True,
                    **absent_reviewed,
                )
            self.assertFalse(absent_output.exists())

    def test_foreign_restore_rejects_bundle_receipt_swap_after_verification(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_manager, bundle, _capture_id = self._capture_backed_bundle(root)
            receipt_path = Path(bundle["bundle_receipt_path"])
            original_receipt = receipt_path.read_bytes()
            receipt = json.loads(original_receipt.decode("utf-8"))
            reviewed = {
                "expected_database_sha256": str(receipt["database_sha256"]),
                "expected_capture_sha256": str(receipt["capture_sha256"]),
                "expected_runtime_state_sha256": str(
                    receipt["runtime_state_sha256"]
                ),
            }
            foreign_root = root / "foreign-receipt-swap"
            foreign_manager = VerifiedRecoveryManager(
                DurableMemoryStore(foreign_root / "memory.sqlite3"),
                capture_root=foreign_root / "capture-root",
            )
            original_verify = foreign_manager._verify_bundle_locked

            def verify_then_swap(*args, **kwargs):
                verified = original_verify(*args, **kwargs)
                swapped = json.loads(original_receipt.decode("utf-8"))
                swapped["purpose"] = "post-verification-swap"
                source_manager.store._authenticate_receipt(swapped)
                receipt_path.write_text(
                    json.dumps(swapped, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                receipt_path.chmod(0o600)
                return verified

            output_root = foreign_root / "receipt-swap-proof"
            try:
                with mock.patch.object(
                    foreign_manager,
                    "_verify_bundle_locked",
                    side_effect=verify_then_swap,
                ), self.assertRaisesRegex(RuntimeError, "receipt changed"):
                    foreign_manager.restore_bundle_isolated(
                        receipt_path,
                        output_root,
                        confirm=True,
                        **reviewed,
                    )
                self.assertFalse(output_root.exists())
            finally:
                receipt_path.write_bytes(original_receipt)
                receipt_path.chmod(0o600)

    def test_foreign_governed_bundle_requires_and_accepts_all_four_pins(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _legacy_bundle, _capture_id = (
                self._capture_backed_bundle(root)
            )
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store, authority, journal, _claim = self._claim_governed_store(
                db_path,
                instance_id="core-foreign-reviewed-recovery",
            )
            try:
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "foreign-reviewed-governed.sqlite3",
                    purpose="unit-test",
                    pinned=True,
                )
                receipt = json.loads(
                    Path(bundle["bundle_receipt_path"]).read_text(encoding="utf-8")
                )
            finally:
                journal.close()
                store.close()
                authority.close()

            foreign_root = root / "foreign-governed-store"
            foreign_manager = VerifiedRecoveryManager(
                DurableMemoryStore(foreign_root / "memory.sqlite3"),
                capture_root=foreign_root / "capture-root",
            )
            reviewed = {
                "expected_database_sha256": str(receipt["database_sha256"]),
                "expected_capture_sha256": str(receipt["capture_sha256"]),
                "expected_request_journal_sha256": str(
                    receipt["request_journal_sha256"]
                ),
                "expected_runtime_state_sha256": str(
                    receipt["runtime_state_sha256"]
                ),
            }
            for omitted in tuple(reviewed):
                with self.subTest(omitted=omitted):
                    incomplete = {
                        key: value
                        for key, value in reviewed.items()
                        if key != omitted
                    }
                    with self.assertRaises(ValueError):
                        foreign_manager.verify_bundle(
                            bundle["bundle_receipt_path"],
                            **incomplete,
                        )

            rejected_output = foreign_root / "missing-runtime-proof"
            without_runtime = dict(reviewed)
            without_runtime.pop("expected_runtime_state_sha256")
            with self.assertRaises(ValueError):
                foreign_manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    rejected_output,
                    confirm=True,
                    **without_runtime,
                )
            self.assertFalse(rejected_output.exists())

            verified = foreign_manager.verify_bundle(
                bundle["bundle_receipt_path"],
                **reviewed,
            )
            self.assertTrue(verified["verified"])
            self.assertFalse(verified["receipt_identity_trusted"])
            self.assertTrue(verified["reviewed_digests_verified"])
            restored = foreign_manager.restore_bundle_isolated(
                bundle["bundle_receipt_path"],
                foreign_root / "reviewed-governed-proof",
                confirm=True,
                **reviewed,
            )
            self.assertTrue(restored["verified"])
            self.assertTrue(restored["request_journal_binding"]["verified"])
            self.assertTrue(Path(restored["runtime_state_restore_path"]).is_file())

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

    def test_private_lock_directory_and_database_modes_fail_closed_without_repair(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, db_path = self._seed_store(root)
            lock_root = root / "lock-contract"
            lock_root.mkdir(mode=0o700)

            created_lock = lock_root / "created.lock"
            descriptor = store._acquire_file_lock(
                created_lock,
                mode=fcntl.LOCK_EX,
                timeout_seconds=0.0,
            )
            store._release_file_lock(descriptor)
            self.assertEqual(created_lock.stat().st_mode & 0o777, 0o600)

            wrong_mode = lock_root / "wrong-mode.lock"
            wrong_mode.write_text("", encoding="utf-8")
            wrong_mode.chmod(0o644)
            with self.assertRaises(PermissionError):
                store._acquire_file_lock(
                    wrong_mode,
                    mode=fcntl.LOCK_EX,
                    timeout_seconds=0.0,
                )
            self.assertEqual(wrong_mode.stat().st_mode & 0o777, 0o644)

            symlink_target = lock_root / "symlink-target.lock"
            symlink_target.write_text("", encoding="utf-8")
            symlink_target.chmod(0o600)
            symlink_lock = lock_root / "symlink.lock"
            symlink_lock.symlink_to(symlink_target.name)
            with self.assertRaises(PermissionError):
                store._acquire_file_lock(
                    symlink_lock,
                    mode=fcntl.LOCK_EX,
                    timeout_seconds=0.0,
                )
            self.assertTrue(symlink_lock.is_symlink())

            hardlink_source = lock_root / "hardlink-source.lock"
            hardlink_source.write_text("", encoding="utf-8")
            hardlink_source.chmod(0o600)
            hardlink_lock = lock_root / "hardlink.lock"
            os.link(hardlink_source, hardlink_lock)
            with self.assertRaises(PermissionError):
                store._acquire_file_lock(
                    hardlink_lock,
                    mode=fcntl.LOCK_EX,
                    timeout_seconds=0.0,
                )
            self.assertEqual(hardlink_source.stat().st_nlink, 2)

            unsafe_directory = root / "preexisting-shared-directory"
            unsafe_directory.mkdir(mode=0o700)
            unsafe_directory.chmod(0o755)
            with self.assertRaises(PermissionError):
                store._ensure_directory(unsafe_directory, owned=True)
            self.assertEqual(unsafe_directory.stat().st_mode & 0o777, 0o755)

            db_path.chmod(0o644)
            with self.assertRaises(CoreAuthorityError):
                store.recompute_logical_snapshot_digest()
            self.assertEqual(db_path.stat().st_mode & 0o777, 0o644)
            db_path.chmod(0o600)

    def test_database_logical_digest_detects_equal_size_non_highwater_mutation(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, _db_path = self._seed_store(root)
            before = store.recompute_logical_snapshot_digest()
            with closing(store._connect_existing_write()) as conn:
                cursor = conn.execute(
                    "UPDATE memory_entries "
                    "SET source_text = 'B' || substr(source_text, 2) "
                    "WHERE context_id = ? AND tag = ?",
                    ("backup-tests", "verified-backup-fixture"),
                )
                self.assertEqual(cursor.rowcount, 1)
            after = store.recompute_logical_snapshot_digest()

            self.assertEqual(before["table_count"], after["table_count"])
            self.assertEqual(before["column_count"], after["column_count"])
            self.assertEqual(before["row_count"], after["row_count"])
            self.assertEqual(before["value_bytes"], after["value_bytes"])
            self.assertNotEqual(before["sha256"], after["sha256"])

    def test_governed_exact_digests_runtime_rebinding_and_restore_binding_are_strict(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _legacy_bundle, _capture_id = self._capture_backed_bundle(
                root
            )
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store, authority, journal, claim = self._claim_governed_store(
                db_path,
                instance_id="core-recovery-exact-digests",
            )
            try:
                journal.accept(
                    caller="backup-test",
                    request_id="request-exact",
                    operation="capture_session",
                    request_fingerprint="a" * 64,
                )
                journal.finish(
                    caller="backup-test",
                    request_id="request-exact",
                    operation="capture_session",
                    request_fingerprint="a" * 64,
                    result={"stored": True},
                    safe_error_code=None,
                )
                journal.close()
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "exact-digests.sqlite3",
                    purpose="unit-test",
                    pinned=True,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])

                journal_before = manager.recompute_request_journal_logical_digest(
                    maximum_authority_epoch=int(claim["authority_epoch_number"])
                )
                journal_path = db_path.parent / "core" / "requests.sqlite3"
                with closing(sqlite3.connect(journal_path)) as conn:
                    conn.execute(
                        "UPDATE request_journal SET request_fingerprint = ? "
                        "WHERE caller = ? AND request_id = ?",
                        ("b" * 64, "backup-test", "request-exact"),
                    )
                    conn.commit()
                journal_after = manager.recompute_request_journal_logical_digest(
                    maximum_authority_epoch=int(claim["authority_epoch_number"])
                )
                self.assertEqual(journal_before["row_count"], journal_after["row_count"])
                self.assertEqual(journal_before["state_counts"], journal_after["state_counts"])
                self.assertEqual(
                    journal_before["logical_snapshot_value_bytes"],
                    journal_after["logical_snapshot_value_bytes"],
                )
                self.assertNotEqual(
                    journal_before["logical_snapshot_sha256"],
                    journal_after["logical_snapshot_sha256"],
                )

                runtime_before = manager.recompute_live_runtime_state_binding(
                    required=True
                )
                runtime_path = db_path.parent / "runtime_state.json"
                runtime_payload = json.loads(runtime_path.read_text(encoding="utf-8"))
                runtime_payload["global_enabled"] = False
                runtime_path.write_text(
                    json.dumps(runtime_payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                runtime_path.chmod(0o600)
                runtime_after = manager.recompute_live_runtime_state_binding(
                    required=True
                )
                self.assertEqual(
                    runtime_before["context_override_count"],
                    runtime_after["context_override_count"],
                )
                self.assertEqual(
                    runtime_before["cortex_session_count"],
                    runtime_after["cortex_session_count"],
                )
                self.assertNotEqual(
                    runtime_before["canonical_sha256"],
                    runtime_after["canonical_sha256"],
                )

                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "strict-binding-restore",
                    confirm=True,
                )
                restore_root = Path(restored["restore_root"])
                restored_runtime_path = Path(restored["runtime_state_restore_path"])
                restored_runtime = json.loads(
                    restored_runtime_path.read_text(encoding="utf-8")
                )
                self.assertEqual(
                    restored_runtime["memory_db_path"],
                    str(restore_root / "memory.sqlite3"),
                )
                self.assertNotEqual(
                    restored_runtime["memory_db_path"],
                    str(db_path),
                )
                proof = json.loads(
                    Path(restored["recovery_proof_path"]).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    proof["source_runtime_state_canonical_sha256"],
                    verified["runtime_state"]["canonical_sha256"],
                )
                self.assertEqual(
                    proof["runtime_state_memory_db_path"],
                    str(restore_root / "memory.sqlite3"),
                )

                binding_path = Path(restored["request_journal_binding_receipt_path"])
                original_binding = binding_path.read_bytes()
                original_payload = json.loads(original_binding.decode("utf-8"))
                manager.verify_restored_request_journal_binding(
                    restore_root,
                    expected_store_identity=verified["store_identity"],
                    expected_store_generation=verified["store_generation"],
                    expected_source_request_journal_binding_receipt_digest=verified[
                        "request_journal_binding"
                    ]["receipt_digest"],
                )

                forged_source = dict(original_payload)
                forged_source[
                    "source_request_journal_binding_receipt_digest"
                ] = "f" * 64
                manager.store._authenticate_receipt(forged_source)
                binding_path.write_text(
                    json.dumps(forged_source, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                binding_path.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "source chain"):
                    manager.verify_restored_request_journal_binding(
                        restore_root,
                        expected_source_request_journal_binding_receipt_digest=verified[
                            "request_journal_binding"
                        ]["receipt_digest"],
                    )

                binding_path.write_bytes(original_binding)
                binding_path.chmod(0o600)
                forged_generation = dict(original_payload)
                forged_generation["store_generation"] = "epoch-999"
                manager.store._authenticate_receipt(forged_generation)
                binding_path.write_text(
                    json.dumps(forged_generation, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                binding_path.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, "store generation"):
                    manager.verify_restored_request_journal_binding(
                        restore_root,
                        expected_store_generation=verified["store_generation"],
                    )

                binding_path.write_bytes(original_binding)
                binding_path.chmod(0o600)
                hidden_binding = binding_path.with_suffix(".withheld")
                binding_path.rename(hidden_binding)
                with self.assertRaises(FileNotFoundError):
                    manager.verify_restored_request_journal_binding(restore_root)
                hidden_binding.rename(binding_path)

                restored_journal = restore_root / "core" / "requests.sqlite3"
                hidden_journal = restored_journal.with_suffix(".withheld")
                restored_journal.rename(hidden_journal)
                with self.assertRaises(FileNotFoundError):
                    manager.verify_restored_request_journal_binding(restore_root)
                hidden_journal.rename(restored_journal)

                original_runtime = restored_runtime_path.read_bytes()
                bad_runtime = dict(restored_runtime)
                bad_runtime["memory_db_path"] = str(restore_root / "wrong.sqlite3")
                restored_runtime_path.write_text(
                    json.dumps(bad_runtime, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                restored_runtime_path.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    manager.verify_restored_request_journal_binding(restore_root)
                restored_runtime_path.write_bytes(original_runtime)
                restored_runtime_path.chmod(0o600)
            finally:
                journal.close()
                store.close()
                authority.close()

    def test_live_restored_binding_detects_a_wal_only_database_mutation(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_manager, _legacy_bundle, _capture_id = self._capture_backed_bundle(
                root
            )
            db_path = legacy_manager.store.db_path
            legacy_manager.store.close()
            store, authority, journal, _claim = self._claim_governed_store(
                db_path,
                instance_id="core-recovery-live-wal",
            )
            try:
                journal.close()
                manager = VerifiedRecoveryManager(store, capture_root=root)
                bundle = manager.create_bundle(
                    root / "live-wal.sqlite3",
                    purpose="unit-test",
                    pinned=True,
                )
                verified = manager.verify_bundle(bundle["bundle_receipt_path"])
                restored = manager.restore_bundle_isolated(
                    bundle["bundle_receipt_path"],
                    root / "live-wal-restore",
                    confirm=True,
                )
                restore_root = Path(restored["restore_root"])
                restored_db = restore_root / "memory.sqlite3"
                binding_path = Path(restored["request_journal_binding_receipt_path"])

                # A promoted restore retains the local recovery trust root.
                shutil.copytree(
                    db_path.parent / "recovery-keys",
                    restore_root / "recovery-keys",
                )
                (restore_root / "recovery-keys").chmod(0o700)
                for key_path in (restore_root / "recovery-keys").iterdir():
                    key_path.chmod(0o600)

                with closing(sqlite3.connect(restored_db)) as conn:
                    self.assertEqual(
                        str(conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower(),
                        "wal",
                    )
                    conn.execute("PRAGMA wal_autocheckpoint = 0")
                    conn.commit()

                    # WAL mode changes SQLite's base-file header. Rebind that
                    # representation without changing any logical memory.
                    binding = json.loads(binding_path.read_text(encoding="utf-8"))
                    binding["memory_sha256"] = hashlib.sha256(
                        restored_db.read_bytes()
                    ).hexdigest()
                    binding["memory_size_bytes"] = restored_db.stat().st_size
                    manager.store._authenticate_receipt(binding)
                    binding_path.write_text(
                        json.dumps(binding, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    binding_path.chmod(0o600)

                    promoted_store = DurableMemoryStore.open_existing_for_audit(
                        restored_db
                    )
                    promoted_manager = VerifiedRecoveryManager(
                        promoted_store,
                        capture_root=restore_root / "capture-root",
                        runtime_state_path=restore_root / "runtime_state.json",
                    )
                    promoted_manager.verify_restored_request_journal_binding(
                        restore_root,
                        expected_store_identity=verified["store_identity"],
                        expected_store_generation=verified["store_generation"],
                    )

                    cursor = conn.execute(
                        "UPDATE memory_entries "
                        "SET source_text = 'W' || substr(source_text, 2) "
                        "WHERE memory_id = ("
                        "SELECT memory_id FROM memory_entries ORDER BY memory_id LIMIT 1"
                        ")",
                    )
                    self.assertEqual(cursor.rowcount, 1)
                    conn.commit()
                    self.assertTrue(Path(str(restored_db) + "-wal").is_file())
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "does not match its targets",
                    ):
                        promoted_manager.verify_restored_request_journal_binding(
                            restore_root
                        )
            finally:
                journal.close()
                store.close()
                authority.close()

    def test_live_capture_manifest_detects_new_unacknowledged_transport_bytes(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager, bundle, _capture_id = self._capture_backed_bundle(root)
            verified = manager.verify_bundle(bundle["bundle_receipt_path"])
            before = manager.recompute_live_capture_manifest(
                database_binding=verified["capture_database_binding"]
            )
            self.assertEqual(
                before["manifest_sha256"],
                verified["capture_manifest_sha256"],
            )

            write_capture_drop(
                root=root,
                context_id="recovery-tests",
                source_tag="post-backup-stale-evidence",
                speaker="codex",
                text="A new durable capture arrived after the signed recovery point.",
                metadata={"surface": "live-attestation-test"},
                capture_id="s2cap_61616161616161616161616161616161",
            )
            after = manager.recompute_live_capture_manifest(
                database_binding=verified["capture_database_binding"]
            )
            self.assertEqual(after["file_count"], before["file_count"] + 1)
            self.assertNotEqual(after["manifest_sha256"], before["manifest_sha256"])

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
            manager.daemon._ensure_transport_dirs(paths)
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
                compatibility_backup = migrated_store.backup(
                    root / "v5-compatible-recertified.sqlite3",
                    purpose="compatibility-test",
                )
                self.assertEqual(
                    compatibility_backup["schema_contract_version"],
                    "s2-schema-v5",
                )
                migrated_store.close()
                store.close()
                authority = CoreAuthorityLease.acquire_core(
                    restored_path,
                    timeout_seconds=0.0,
                    instance_id="core-backup-contract-test",
                )
                migrated_store = DurableMemoryStore(
                    restored_path,
                    authority_lease=authority,
                )
                inspection = migrated_store.inspect_core_authority_preclaim()
                preclaim = inspection["logical_snapshot"]
                migrated_store.claim_core_authority(
                    instance_id=authority.instance_id,
                    config_fingerprint="c" * 64,
                    build_id="backup-contract-test",
                    protocol_version="synapse-core.v1",
                    expected_store_identity=str(inspection["store_identity"]),
                    request_journal_id="journal-" + ("c" * 24),
                    request_journal_binding_schema=(
                        "synapse-s2.request-journal-binding.v1"
                    ),
                    request_journal_schema_version=3,
                    expected_preclaim_logical_snapshot_sha256=str(
                        preclaim["sha256"]
                    ),
                    expected_previous_epoch=0,
                    expected_next_epoch=1,
                    root_generation_id="generation-" + ("c" * 24),
                    embedding_space_identity="c" * 64,
                    attestation_receipt_digest="c" * 64,
                    attestation_expires_at_unix_ms=int(time.time() * 1000) + 60_000,
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
                authority.close()

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
